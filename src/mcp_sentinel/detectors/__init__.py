"""Vulnerability detectors."""

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.detectors.secrets import SecretsDetector

__all__ = [
    "BaseDetector",
    "SecretsDetector",
]
