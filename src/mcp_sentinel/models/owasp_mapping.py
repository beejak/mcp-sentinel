"""
OWASP Agentic AI Top 10 (2026) mapping for MCP Sentinel findings.

Maps VulnerabilityType values to OWASP ASI categories so that every finding
is annotated with a compliance identifier in all output formats (terminal,
JSON, SARIF).

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from mcp_sentinel.models.vulnerability import VulnerabilityType

# Full ASI catalogue — name and description for each category
OWASP_ASI_CATALOGUE: dict[str, dict[str, str]] = {
    "ASI01": {
        "name": "Prompt Injection",
        "description": (
            "Adversarial inputs injected via tool descriptions, user data, or "
            "external content manipulate agent reasoning and override intended behaviour."
        ),
    },
    "ASI02": {
        "name": "Sensitive Data Exposure",
        "description": (
            "Agents inadvertently expose confidential data — credentials, PII, "
            "proprietary content — through outputs, logs, or tool responses."
        ),
    },
    "ASI03": {
        "name": "Supply Chain Vulnerabilities",
        "description": (
            "Malicious or compromised plugins, tools, models, or dependencies "
            "introduce backdoors or exfiltration paths into the agent stack."
        ),
    },
    "ASI04": {
        "name": "Insecure Direct Tool Invocation",
        "description": (
            "Agents invoke tools without adequate authorisation checks, allowing "
            "privilege escalation or unintended system access."
        ),
    },
    "ASI05": {
        "name": "Improper Output Handling / SSRF",
        "description": (
            "Agent outputs are passed to downstream systems without sanitisation, "
            "enabling SSRF, injection, or unauthorised network access."
        ),
    },
    "ASI06": {
        "name": "Excessive Agency",
        "description": (
            "Agents are granted more permissions, network access, or action scope "
            "than needed, amplifying the blast radius of compromise."
        ),
    },
    "ASI07": {
        "name": "Insecure Cryptography",
        "description": (
            "Use of weak, deprecated, or misapplied cryptographic algorithms "
            "undermines confidentiality and integrity guarantees."
        ),
    },
    "ASI08": {
        "name": "Insecure Deserialization",
        "description": (
            "Deserializing untrusted data with unsafe libraries (pickle, yaml.load, "
            "ObjectInputStream) enables remote code execution."
        ),
    },
    "ASI09": {
        "name": "Improper Error Handling / Path Traversal",
        "description": (
            "Insufficient input validation allows path traversal attacks giving "
            "agents access to files outside the intended scope."
        ),
    },
    "ASI10": {
        "name": "Inadequate Audit and Monitoring",
        "description": (
            "Absence of comprehensive logging for agent actions, tool calls, and "
            "sampling events prevents detection and forensic analysis."
        ),
    },
}

# Primary mapping: VulnerabilityType -> ASI ID
# Where a type spans multiple ASI categories the most specific/primary is used.
_TYPE_TO_ASI: dict[VulnerabilityType, str] = {
    VulnerabilityType.PROMPT_INJECTION:          "ASI01",
    VulnerabilityType.TOOL_POISONING:            "ASI01",
    VulnerabilityType.SECRET_EXPOSURE:           "ASI02",
    VulnerabilityType.CONFIG_SECURITY:           "ASI02",
    VulnerabilityType.SUPPLY_CHAIN:              "ASI03",
    VulnerabilityType.CODE_INJECTION:            "ASI04",
    VulnerabilityType.MISSING_AUTH:              "ASI04",
    VulnerabilityType.SSRF:                      "ASI05",
    VulnerabilityType.NETWORK_BINDING:           "ASI06",
    VulnerabilityType.WEAK_CRYPTO:               "ASI07",
    VulnerabilityType.INSECURE_DESERIALIZATION:  "ASI08",
    VulnerabilityType.PATH_TRAVERSAL:            "ASI09",
    VulnerabilityType.MCP_SAMPLING:              "ASI10",
    VulnerabilityType.XSS:                       "ASI05",
}


def get_asi_id(vuln_type: VulnerabilityType) -> str | None:
    """Return the primary OWASP ASI ID for a vulnerability type, or None."""
    return _TYPE_TO_ASI.get(vuln_type)


def get_asi_name(asi_id: str) -> str | None:
    """Return the ASI category name for an ASI ID, or None."""
    entry = OWASP_ASI_CATALOGUE.get(asi_id)
    return entry["name"] if entry else None


def annotate(vuln_type: VulnerabilityType) -> tuple[str | None, str | None]:
    """
    Return (asi_id, asi_name) for a VulnerabilityType.

    Both values are None if the type has no mapping (should not happen in practice).
    """
    asi_id = get_asi_id(vuln_type)
    asi_name = get_asi_name(asi_id) if asi_id else None
    return asi_id, asi_name


def build_compliance_summary(
    vulnerabilities: list,  # list[Vulnerability] — avoids circular import
) -> dict[str, dict[str, int | str]]:
    """
    Aggregate findings by ASI category.

    Returns a dict keyed by ASI ID with counts and category metadata:

        {
          "ASI01": {"name": "Prompt Injection", "count": 3, "critical": 1, "high": 2},
          ...
        }

    Only categories with at least one finding are included.
    """
    summary: dict[str, dict[str, int | str]] = {}

    for vuln in vulnerabilities:
        asi_id = vuln.owasp_asi_id
        if not asi_id:
            continue

        if asi_id not in summary:
            summary[asi_id] = {
                "name": vuln.owasp_asi_name or "",
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

        summary[asi_id]["count"] = int(summary[asi_id]["count"]) + 1  # type: ignore[arg-type]
        sev = vuln.severity.value.lower()
        if sev in summary[asi_id]:
            summary[asi_id][sev] = int(summary[asi_id][sev]) + 1  # type: ignore[arg-type]

    return dict(sorted(summary.items()))
