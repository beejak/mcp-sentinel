"""
Unit tests for InsecureDeserializationDetector.

Covers:
- pickle.loads/load() — Python object deserialization
- yaml.load() without SafeLoader
- marshal.loads() on untrusted data
- eval() used for data parsing
- shelve.open() with non-hardcoded path
- jsonpickle.decode()
- Java ObjectInputStream / readObject
- PHP unserialize()
- Node.js eval()/vm for data parsing
- False-positive suppression
- Applicability / file type filtering
- Detector metadata
"""

import pytest
from pathlib import Path

from mcp_sentinel.detectors.insecure_deserialization import InsecureDeserializationDetector
from mcp_sentinel.models.vulnerability import Severity


@pytest.fixture
def detector():
    return InsecureDeserializationDetector()


# ---------------------------------------------------------------------------
# Detector metadata
# ---------------------------------------------------------------------------

def test_detector_name(detector):
    assert detector.name == "InsecureDeserializationDetector"


def test_detector_enabled_by_default(detector):
    assert detector.enabled is True


# ---------------------------------------------------------------------------
# is_applicable
# ---------------------------------------------------------------------------

def test_applicable_python(detector):
    assert detector.is_applicable(Path("server.py")) is True


def test_applicable_javascript(detector):
    assert detector.is_applicable(Path("parse.js")) is True


def test_applicable_typescript(detector):
    assert detector.is_applicable(Path("parse.ts")) is True


def test_applicable_java(detector):
    assert detector.is_applicable(Path("Deserialize.java")) is True


def test_applicable_php(detector):
    assert detector.is_applicable(Path("handler.php")) is True


def test_not_applicable_go(detector):
    assert detector.is_applicable(Path("server.go")) is False


def test_not_applicable_yaml(detector):
    assert detector.is_applicable(Path("config.yaml")) is False


def test_not_applicable_markdown(detector):
    assert detector.is_applicable(Path("README.md")) is False


# ---------------------------------------------------------------------------
# pickle.loads
# ---------------------------------------------------------------------------

async def test_detect_pickle_loads(detector):
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("pickle" in v.title.lower() for v in vulns)
    assert any(v.severity.value == "critical" for v in vulns)


async def test_detect_pickle_load_file(detector):
    content = "obj = pickle.load(f)"
    vulns = await detector.detect(Path("cache.py"), content)
    assert len(vulns) >= 1


async def test_detect_cpickle_loads(detector):
    content = "obj = cPickle.loads(raw_data)"
    vulns = await detector.detect(Path("legacy.py"), content)
    assert len(vulns) >= 1


async def test_pickle_line_number_accuracy(detector):
    content = "import pickle\nimport sys\nresult = pickle.loads(payload)\n"
    vulns = await detector.detect(Path("server.py"), content)
    assert any(v.line_number == 3 for v in vulns)


async def test_pickle_code_snippet_captured(detector):
    content = "result = pickle.loads(user_data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert any("pickle.loads" in v.code_snippet for v in vulns)


# ---------------------------------------------------------------------------
# yaml.load without SafeLoader
# ---------------------------------------------------------------------------

async def test_detect_yaml_load_no_loader(detector):
    content = "config = yaml.load(stream)"
    vulns = await detector.detect(Path("config.py"), content)
    assert len(vulns) >= 1
    assert any("yaml" in v.title.lower() for v in vulns)
    assert any(v.severity.value == "critical" for v in vulns)


async def test_detect_yaml_load_full_loader(detector):
    content = "config = yaml.load(stream, Loader=yaml.FullLoader)"
    vulns = await detector.detect(Path("config.py"), content)
    assert len(vulns) >= 1


async def test_no_false_positive_yaml_safe_load_function(detector):
    content = "config = yaml.safe_load(stream)"
    vulns = await detector.detect(Path("config.py"), content)
    yaml_vulns = [v for v in vulns if "yaml" in v.title.lower()]
    assert len(yaml_vulns) == 0


async def test_no_false_positive_yaml_safeloader_arg(detector):
    content = "config = yaml.load(stream, Loader=yaml.SafeLoader)"
    vulns = await detector.detect(Path("config.py"), content)
    yaml_vulns = [v for v in vulns if "yaml" in v.title.lower()]
    assert len(yaml_vulns) == 0


# ---------------------------------------------------------------------------
# marshal.loads
# ---------------------------------------------------------------------------

async def test_detect_marshal_loads(detector):
    content = "code = marshal.loads(bytecode)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("marshal" in v.title.lower() for v in vulns)
    assert any(v.severity.value == "critical" for v in vulns)


async def test_detect_marshal_load(detector):
    content = "obj = marshal.load(file_handle)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1


# ---------------------------------------------------------------------------
# eval for deserialization
# ---------------------------------------------------------------------------

async def test_detect_eval_on_request_data(detector):
    content = "config = eval(request.body)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("eval" in v.title.lower() for v in vulns)


async def test_detect_eval_on_body(detector):
    content = "result = eval(body)"
    vulns = await detector.detect(Path("handler.py"), content)
    assert len(vulns) >= 1


async def test_no_false_positive_eval_string_literal(detector):
    content = "result = eval('1 + 2')"
    vulns = await detector.detect(Path("calc.py"), content)
    eval_vulns = [v for v in vulns if "eval" in v.title.lower()]
    assert len(eval_vulns) == 0


# ---------------------------------------------------------------------------
# jsonpickle
# ---------------------------------------------------------------------------

async def test_detect_jsonpickle_decode(detector):
    content = "obj = jsonpickle.decode(json_str)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert any("jsonpickle" in v.title.lower() for v in vulns)
    assert any(v.severity.value == "critical" for v in vulns)


# ---------------------------------------------------------------------------
# Java ObjectInputStream
# ---------------------------------------------------------------------------

async def test_detect_java_object_input_stream(detector):
    content = "ObjectInputStream ois = new ObjectInputStream(inputStream);"
    vulns = await detector.detect(Path("Handler.java"), content)
    assert len(vulns) >= 1
    assert any("Java" in v.title or "ObjectInputStream" in v.title for v in vulns)


async def test_detect_java_read_object(detector):
    content = "Object obj = ois.readObject();"
    vulns = await detector.detect(Path("Deserializer.java"), content)
    assert len(vulns) >= 1


async def test_detect_xstream(detector):
    content = "XStream xs = new XStream();"
    vulns = await detector.detect(Path("Config.java"), content)
    assert len(vulns) >= 1


async def test_java_object_stream_not_flagged_in_python(detector):
    content = "ObjectInputStream ois = new ObjectInputStream(inputStream);"
    vulns = await detector.detect(Path("server.py"), content)
    java_vulns = [v for v in vulns if "ObjectInputStream" in v.title]
    assert len(java_vulns) == 0


# ---------------------------------------------------------------------------
# PHP unserialize
# ---------------------------------------------------------------------------

async def test_detect_php_unserialize(detector):
    content = "$obj = unserialize($_POST['data']);"
    vulns = await detector.detect(Path("handler.php"), content)
    assert len(vulns) >= 1
    assert any("PHP" in v.title or "unserialize" in v.title.lower() for v in vulns)
    assert any(v.severity.value == "critical" for v in vulns)


async def test_php_unserialize_not_flagged_in_python(detector):
    content = "result = unserialize(data)"
    vulns = await detector.detect(Path("server.py"), content)
    php_vulns = [v for v in vulns if "PHP" in v.title]
    assert len(php_vulns) == 0


# ---------------------------------------------------------------------------
# Node.js eval / vm
# ---------------------------------------------------------------------------

async def test_detect_vm_run_in_context(detector):
    content = "const result = vm.runInContext(code, sandbox);"
    vulns = await detector.detect(Path("runner.js"), content)
    assert len(vulns) >= 1
    assert any("Node" in v.title or "vm" in v.title.lower() for v in vulns)


async def test_detect_vm_run_in_new_context(detector):
    content = "vm.runInNewContext(userScript, {})"
    vulns = await detector.detect(Path("eval.js"), content)
    assert len(vulns) >= 1


async def test_detect_node_eval_body(detector):
    content = "const result = eval(req.body.script);"
    vulns = await detector.detect(Path("handler.js"), content)
    assert len(vulns) >= 1


# ---------------------------------------------------------------------------
# False-positive suppression
# ---------------------------------------------------------------------------

async def test_no_false_positive_comment(detector):
    content = "# pickle.loads(data) — dangerous, use json instead"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) == 0


async def test_no_false_positive_test_context(detector):
    # Standalone word "test" in context suppresses the finding
    content = "result = pickle.loads(test)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) == 0


async def test_empty_file(detector):
    vulns = await detector.detect(Path("server.py"), "")
    assert vulns == []


async def test_shelve_hardcoded_path_suppressed(detector):
    # shelve with a hardcoded string path is lower risk
    content = 'db = shelve.open("mydata")'
    vulns = await detector.detect(Path("server.py"), content)
    shelve_vulns = [v for v in vulns if "shelve" in v.title.lower()]
    assert len(shelve_vulns) == 0


# ---------------------------------------------------------------------------
# Vulnerability metadata quality
# ---------------------------------------------------------------------------

async def test_vulnerability_type_is_insecure_deserialization(detector):
    from mcp_sentinel.models.vulnerability import VulnerabilityType
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert all(v.type == VulnerabilityType.INSECURE_DESERIALIZATION for v in vulns)


async def test_vulnerability_has_cwe(detector):
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert all(v.cwe_id is not None for v in vulns)


async def test_vulnerability_has_remediation(detector):
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert all(v.remediation for v in vulns)


async def test_vulnerability_has_references(detector):
    content = "config = yaml.load(stream)"
    vulns = await detector.detect(Path("config.py"), content)
    assert all(len(v.references) > 0 for v in vulns)


async def test_vulnerability_has_mitre_attack(detector):
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert all(len(v.mitre_attack_ids) > 0 for v in vulns)


async def test_vulnerability_detector_field(detector):
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert all(v.detector == "InsecureDeserializationDetector" for v in vulns)


async def test_vulnerability_engine_field(detector):
    content = "obj = pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert all(v.engine == "static" for v in vulns)


# ============================================================================
# Edge Case / Variant Coverage
# ============================================================================


async def test_detect_pickle_unpickler(detector):
    """pickle.Unpickler() is equally dangerous as pickle.loads()."""
    content = "obj = pickle.Unpickler(f).load()"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL


async def test_detect_underscore_pickle_loads(detector):
    """_pickle.loads() (C accelerator module) carries the same RCE risk."""
    content = "obj = _pickle.loads(data)"
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL


async def test_detect_shelve_user_controlled_path(detector):
    """shelve.open() with a variable path — attacker could control the db file."""
    content = "db = shelve.open(user_db_path)"
    vulns = await detector.detect(Path("storage.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.HIGH


async def test_detect_jsonpickle_unpickler_decode(detector):
    """jsonpickle.unpickler.decode() is a direct RCE vector."""
    content = "obj = jsonpickle.unpickler.decode(payload)"
    vulns = await detector.detect(Path("api.py"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL


async def test_detect_vm_run_in_this_context(detector):
    """vm.runInThisContext() executes code in the live V8 context — no sandbox."""
    content = "const result = vm.runInThisContext(userCode);"
    vulns = await detector.detect(Path("eval_service.js"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL


async def test_detect_java_object_input_stream_variable(detector):
    """ObjectInputStream typed variable declaration is also caught."""
    content = "ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());"
    vulns = await detector.detect(Path("Server.java"), content)
    assert len(vulns) >= 1
    assert vulns[0].severity == Severity.CRITICAL


async def test_multiple_deser_same_file(detector):
    """Multiple deserialization patterns in one file are all detected."""
    content = (
        "obj = pickle.loads(data)\n"
        "cfg = yaml.load(stream)\n"
        "raw = marshal.loads(payload)\n"
    )
    vulns = await detector.detect(Path("server.py"), content)
    assert len(vulns) >= 3


async def test_not_applicable_ruby(detector):
    """.rb files are excluded."""
    assert not detector.is_applicable(Path("app.rb"))


async def test_not_applicable_shell(detector):
    """.sh files are excluded."""
    assert not detector.is_applicable(Path("deploy.sh"))
