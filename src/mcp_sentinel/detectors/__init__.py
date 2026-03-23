"""Vulnerability detectors."""

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.detectors.code_injection import CodeInjectionDetector
from mcp_sentinel.detectors.config_security import ConfigSecurityDetector
from mcp_sentinel.detectors.missing_auth import MissingAuthDetector
from mcp_sentinel.detectors.network_binding import NetworkBindingDetector
from mcp_sentinel.detectors.path_traversal import PathTraversalDetector
from mcp_sentinel.detectors.prompt_injection import PromptInjectionDetector
from mcp_sentinel.detectors.secrets import SecretsDetector
from mcp_sentinel.detectors.insecure_deserialization import InsecureDeserializationDetector
from mcp_sentinel.detectors.ssrf import SSRFDetector
from mcp_sentinel.detectors.supply_chain import SupplyChainDetector
from mcp_sentinel.detectors.tool_poisoning import ToolPoisoningDetector
from mcp_sentinel.detectors.weak_crypto import WeakCryptoDetector

__all__ = [
    "BaseDetector",
    "SecretsDetector",
    "CodeInjectionDetector",
    "PromptInjectionDetector",
    "ToolPoisoningDetector",
    "PathTraversalDetector",
    "ConfigSecurityDetector",
    "SSRFDetector",
    "NetworkBindingDetector",
    "MissingAuthDetector",
    "SupplyChainDetector",
    "WeakCryptoDetector",
    "InsecureDeserializationDetector",
]
