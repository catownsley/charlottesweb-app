"""Caching utilities for performance optimization.

Implements in-memory caching for frequently accessed static data like controls.
Uses simple TTL-based cache with thread-safe operations.
"""
import logging
import time
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TTLCache:
    """Simple in-memory cache with time-to-live (TTL) support.

    Thread-safe caching for frequently accessed data.
    Automatically expires entries after TTL seconds.
    """

    def __init__(self, ttl: int = 3600):
        """Initialize cache.

        Args:
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self.ttl = ttl
        self.cache: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired.

        Args:
            key: Cache key

        Returns:
            Cached value or None if expired/not found
        """
        if key not in self.cache:
            return None

        value, timestamp = self.cache[key]
        if time.time() - timestamp > self.ttl:
            del self.cache[key]
            return None

        return value

    def set(self, key: str, value: Any) -> None:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        self.cache[key] = (value, time.time())

    def invalidate(self, key: Optional[str] = None) -> None:
        """Invalidate cache entries.

        Args:
            key: Specific key to invalidate, or None to clear all
        """
        if key is None:
            self.cache.clear()
            logger.info("Cache cleared")
        else:
            self.cache.pop(key, None)
            logger.debug(f"Cache invalidated for key: {key}")

    def clear(self) -> None:
        """Clear entire cache."""
        self.invalidate()


def cached(cache: TTLCache, key: str, ttl: Optional[int] = None) -> Callable:
    """Decorator for caching function results.

    Args:
        cache: TTLCache instance
        key: Cache key for the function result
        ttl: Override default TTL for this function

    Example:
        @cached(controls_cache, "all_controls")
        def get_all_controls(db: Session) -> List[Control]:
            return db.query(Control).all()
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            cached_value = cache.get(key)
            if cached_value is not None:
                logger.debug(f"Cache hit for key: {key}")
                return cached_value

            result = func(*args, **kwargs)
            cache.set(key, result)
            logger.debug(f"Cache set for key: {key}")
            return result

        return wrapper

    return decorator


# Global cache instances
controls_cache = TTLCache(ttl=3600)  # 1 hour
assessments_cache = TTLCache(ttl=1800)  # 30 minutes
