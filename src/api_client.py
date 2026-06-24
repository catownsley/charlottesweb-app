"""Shared HTTP plumbing for external API service clients.

Each external integration (OSV, NVD, and others) needs the same things:
retry with backoff on transient failures, a request timeout, sanitized
error logging, and JSON parsing. Rather than duplicate that loop in every
service, the common skeleton lives here. Subclasses declare only what is
genuinely specific to their API by setting a few class attributes and, when
needed, overriding `_handle_status`.
"""

import logging
import time
from typing import Any, ClassVar

import requests

from src.utils import sanitize_log_value

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Base error for an external API failure. Subclasses set their own."""

    pass


class BaseApiClient:
    """Base class for services that call an external HTTP/JSON API.

    Subclasses set ``service_name`` and ``error_class`` (and optionally
    ``timeout_seconds`` / ``backoff_seconds``). To declare which responses are
    retryable or fatal, override ``_handle_status``. The default behavior is to
    retry on any 5xx response.
    """

    service_name: ClassVar[str] = "API"
    error_class: ClassVar[type[Exception]] = ApiError
    timeout_seconds: ClassVar[int] = 30
    backoff_seconds: ClassVar[int] = 2

    def __init__(self, max_retries: int = 3) -> None:
        self.max_retries = max_retries
        self.headers: dict[str, str] = {}

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a request with retry on transient failures, returning parsed JSON.

        Raises ``error_class`` if the API stays unreachable or returns an error
        across all attempts.
        """
        last_error: Exception | None = None
        attempts = max(1, self.max_retries)

        for attempt in range(attempts):
            try:
                response = requests.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=self.headers or None,
                    timeout=self.timeout_seconds,
                )

                retry_after = self._handle_status(response, attempt, attempts)
                if retry_after is not None:
                    last_error = self.error_class(
                        f"{self.service_name} returned {response.status_code}"
                    )
                    if attempt < attempts - 1:
                        time.sleep(retry_after)
                        continue
                    raise last_error

                response.raise_for_status()
                return response.json()

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(
                    "%s request failed (attempt %d/%d): %s",
                    self.service_name,
                    attempt + 1,
                    attempts,
                    sanitize_log_value(str(e)),
                )
                if attempt < attempts - 1:
                    time.sleep(self.backoff_seconds * (attempt + 1))

        raise self.error_class(
            f"{self.service_name} failed after {attempts} attempts: {last_error}"
        )

    def _handle_status(
        self, response: requests.Response, attempt: int, attempts: int
    ) -> float | None:
        """Inspect a response before it is parsed.

        Return the number of seconds to wait before retrying, or ``None`` to
        proceed to ``raise_for_status()`` and JSON parsing. May raise
        ``error_class`` to abort immediately without retrying.

        Default: retry on any 5xx response.
        """
        if response.status_code >= 500:
            return self.backoff_seconds * (attempt + 1)
        return None
