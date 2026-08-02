"""Moteur de substituts plausibles (Phase 2)."""

from .classes import DataClass, class_of, priority_of
from .engine import SurrogateCollisionError, SurrogateEngine
from .overlap import resolve_overlaps

__all__ = [
    "DataClass",
    "SurrogateCollisionError",
    "SurrogateEngine",
    "class_of",
    "priority_of",
    "resolve_overlaps",
]
