"""Pagination utilities for list endpoints.

Supports cursor-based and offset-based pagination for list operations.
Helps manage large datasets efficiently.
"""
from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    """Standard pagination parameters for list endpoints."""

    skip: int = Field(0, ge=0, description="Number of items to skip")
    limit: int = Field(50, ge=1, le=1000, description="Max items to return (max 1000)")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    items: List[T]
    total: int = Field(description="Total items available")
    skip: int = Field(description="Items skipped")
    limit: int = Field(description="Items returned")
    has_more: bool = Field(description="Whether more items exist")

    @staticmethod
    def create(items: List[T], total: int, skip: int, limit: int) -> "PaginatedResponse[T]":
        """Create paginated response.

        Args:
            items: List of items for this page
            total: Total count of all items
            skip: Number of items skipped
            limit: Limit for this page

        Returns:
            PaginatedResponse instance
        """
        return PaginatedResponse(
            items=items,
            total=total,
            skip=skip,
            limit=limit,
            has_more=(skip + limit) < total,
        )
