"""Zero-execution CPython 3.12 AST consumer routing and feature-flag analyzer (ADR-0001 §§3.3, 12.6)."""
from __future__ import annotations

from smart_ads.adapters.consumer.routing_analyzer import (
    Cpython312AstConsumerRoutingAnalyzer,
)

__all__ = [
    "Cpython312AstConsumerRoutingAnalyzer",
]
