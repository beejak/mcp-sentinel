"""
Rug pull detector for MCP security.

Detects stateful tool behavior mutations — the "rug pull" attack class where
an MCP tool behaves safely on the first call (passing any automated scanner
check) but switches to malicious behavior on subsequent calls or after a
time delay.

Three concrete patterns are detectable via static analysis:

1. global_state_mutation  — a module-level counter is incremented inside a tool
   function and used in an if-branch (`if count == 1`), producing different
   behavior per call.

2. first_call_sentinel    — a module-level variable is initialised to None and
   set on the first invocation (`if _var is None: _var = now`), enabling
   call-count-dependent or time-dependent branching.

3. time_based_mutation    — a time delta is computed against the sentinel value
   and compared to a threshold (`if elapsed < _DELAY`), making behavior change
   after a fixed window — specifically designed to evade automated scanners that
   only call tools once.

OWASP Agentic AI Top 10: ASI01 (Prompt Injection / Tool Behaviour Manipulation)
CWE-913: Improper Control of Dynamically-Managed Code Resources
"""

import re
from pathlib import Path
from typing import Optional

from mcp_sentinel.detectors.base import BaseDetector
from mcp_sentinel.models.vulnerability import (
    Confidence,
    Severity,
    Vulnerability,
    VulnerabilityType,
)

# ── Patterns ──────────────────────────────────────────────────────────────────

# 1. global_state_mutation
#    Matches `global <identifier>` followed (within ~5 lines) by an increment or
#    flag assignment, then a call-count conditional.
_GLOBAL_STMT = re.compile(r"^\s*global\s+(\w+)", re.MULTILINE)
_COUNTER_INC = re.compile(r"\b(\w+)\s*\+=\s*1")
_FLAG_SET = re.compile(r"\b(\w+)\s*=\s*True\b")
_CALL_COUNT_COND = re.compile(r"\bif\s+\w+\s*==\s*[12]\b")

# 2. first_call_sentinel
#    Module-level `_var: SomeType | None = None` combined with `if _var is None:`
_SENTINEL_DECL = re.compile(
    r"^(\w+)\s*(?::\s*[\w\s\[\]|]+)?\s*=\s*None\b", re.MULTILINE
)
_SENTINEL_INIT = re.compile(r"\bif\s+(\w+)\s+is\s+None\s*:")

# 3. time_based_mutation
#    `elapsed = time.time() - <var>` or `now - <var>` + comparison to threshold
_TIME_DELTA = re.compile(r"\belapsed\b|\b\w+\s*=\s*(?:time\.time\(\)|now)\s*-\s*\w+")
_TIME_COND = re.compile(r"\bif\s+elapsed\s*[<>]=?\s*\w+|\bif\s+\w+\s*[<>]=?\s*_\w*(?:DELAY|THRESHOLD|WINDOW|TIMEOUT)\w*")

# ── OWASP ─────────────────────────────────────────────────────────────────────
_OWASP_ID = "ASI01"
_OWASP_NAME = "Prompt Injection"


class RugPullDetector(BaseDetector):
    """
    Detector for rug pull / timed evasion attack patterns.

    Fires on Python files that use module-level mutable state to alter
    tool behavior between calls — the hallmark of a rug pull attack.
    """

    def __init__(self) -> None:
        super().__init__(name="RugPullDetector", enabled=True)

    def is_applicable(self, file_path: Path, file_type: Optional[str] = None) -> bool:
        """Only scan Python files — the rug pull pattern is Python-specific."""
        if file_type:
            return file_type == "python"
        return file_path.suffix.lower() == ".py"

    def detect_sync(
        self, file_path: Path, content: str, file_type: Optional[str] = None
    ) -> list[Vulnerability]:
        """Detect rug pull patterns in file content."""
        if self._is_test_file(file_path):
            return []

        vulnerabilities: list[Vulnerability] = []
        lines = content.split("\n")

        # Collect module-level sentinel names (None-initialised variables at indent 0)
        sentinel_names: set[str] = set()
        for m in _SENTINEL_DECL.finditer(content):
            # Only count top-level declarations (no leading whitespace before name)
            line_start = content.rfind("\n", 0, m.start()) + 1
            if m.start() == line_start or content[line_start : m.start()].strip() == "":
                sentinel_names.add(m.group(1))

        # Collect module-level global counter names
        global_names: set[str] = set()
        for m in _GLOBAL_STMT.finditer(content):
            global_names.add(m.group(1))

        # ── Pass 1: global_state_mutation ─────────────────────────────────────
        # Look for `global _var` + `_var += 1` + `if _var == 1` in same function
        in_function_globals: dict[str, int] = {}  # name → line_num of `global` stmt
        for line_num, line in enumerate(lines, start=1):
            g_match = re.match(r"\s*global\s+(\w+)", line)
            if g_match:
                in_function_globals[g_match.group(1)] = line_num

            inc_match = _COUNTER_INC.search(line)
            if inc_match and inc_match.group(1) in in_function_globals:
                name = inc_match.group(1)
                decl_line = in_function_globals[name]
                # Look ahead for call-count conditional
                window = lines[line_num : min(line_num + 15, len(lines))]
                if any(_CALL_COUNT_COND.search(l) for l in window):
                    vulnerabilities.append(self._make_vuln(
                        vuln_type="global_state_mutation",
                        file_path=file_path,
                        line_number=decl_line,
                        code_snippet=lines[decl_line - 1].strip(),
                        title="Rug Pull: Global State Mutation",
                        description=(
                            f"Module-level counter '{name}' is declared globally, incremented "
                            "inside a tool function, and used in a call-count conditional "
                            "(`if count == 1`). This is the rug pull pattern: the tool returns "
                            "a safe response on the first call and switches to malicious behavior "
                            "on subsequent calls. Automated scanners that call each tool once will "
                            "always see the benign version."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        remediation=(
                            "Tool behavior must be stateless and deterministic. "
                            "Remove module-level mutable state from tool implementations. "
                            "If persistent state is required, use an explicit, auditable store "
                            "and ensure tool behavior does not change based on call count."
                        ),
                    ))

        # ── Pass 2: first_call_sentinel ───────────────────────────────────────
        for line_num, line in enumerate(lines, start=1):
            m = _SENTINEL_INIT.search(line)
            if m and m.group(1) in sentinel_names:
                vulnerabilities.append(self._make_vuln(
                    vuln_type="first_call_sentinel",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    title="Rug Pull: First-Call Sentinel Pattern",
                    description=(
                        f"Variable '{m.group(1)}' is initialised to None at module level and "
                        "set on first invocation (`if var is None: var = ...`). This pattern "
                        "enables call-count-dependent or time-dependent behavior — a prerequisite "
                        "for both the classic rug pull (RUG-001) and timed evasion (RUG-002) attacks."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    remediation=(
                        "Avoid module-level mutable state in tool implementations. "
                        "If initialization is genuinely required, make it explicit and auditable, "
                        "and ensure it does not gate different behavioral paths."
                    ),
                ))

        # ── Pass 3: time_based_mutation ───────────────────────────────────────
        for line_num, line in enumerate(lines, start=1):
            if _TIME_DELTA.search(line):
                # Look ahead for a time-based conditional within 10 lines
                window = lines[line_num : min(line_num + 10, len(lines))]
                for ahead_offset, ahead_line in enumerate(window, start=1):
                    if _TIME_COND.search(ahead_line):
                        vulnerabilities.append(self._make_vuln(
                            vuln_type="time_based_mutation",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            title="Rug Pull: Time-Based Behavior Mutation",
                            description=(
                                "A time delta is computed against a module-level sentinel and "
                                "compared to a threshold. This is the timed rug pull pattern (RUG-002): "
                                "the tool behaves safely during a scanner's observation window and "
                                "switches to malicious behavior after a fixed delay. "
                                "This is specifically designed to evade automated scanners that "
                                "complete within seconds."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            remediation=(
                                "Tool behavior must not change based on elapsed time. "
                                "Remove time-delta conditionals that gate different code paths. "
                                "All tool behavior must be identical on the first and every "
                                "subsequent invocation."
                            ),
                        ))
                        break  # one finding per time-delta expression

        return self._deduplicate(vulnerabilities)

    def _make_vuln(
        self,
        vuln_type: str,
        file_path: Path,
        line_number: int,
        code_snippet: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: Confidence,
        remediation: str,
    ) -> Vulnerability:
        return Vulnerability(
            type=VulnerabilityType.TOOL_POISONING,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=code_snippet,
            cwe_id="CWE-913",
            cvss_score=8.8 if severity == Severity.HIGH else (9.1 if severity == Severity.CRITICAL else 6.5),
            remediation=remediation,
            references=[
                "https://cwe.mitre.org/data/definitions/913.html",
                "https://arxiv.org/abs/2506.01333v1",  # ETDI paper
                "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
            ],
            detector=self.name,
            engine="static",
            mitre_attack_ids=["T1027", "T1059"],
            owasp_asi_id=_OWASP_ID,
            owasp_asi_name=_OWASP_NAME,
        )

    @staticmethod
    def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Deduplicate by (file_path, line_number, title)."""
        seen: set[tuple[str, int, str]] = set()
        result = []
        for v in vulns:
            key = (v.file_path, v.line_number, v.title)
            if key not in seen:
                seen.add(key)
                result.append(v)
        return result
