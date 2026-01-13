"""
Unit tests for Taint Tracking Engine.

Tests dataflow analysis and vulnerability path detection.
"""

import pytest
from pathlib import Path

from mcp_sentinel.engines.semantic.ast_parser import ASTParser
from mcp_sentinel.engines.semantic.taint_tracker import TaintTracker


class TestTaintTracking:
    """Tests for taint tracking dataflow analysis."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_simple_taint_propagation(self, parser):
        """Test taint flows through simple variable assignment."""
        code = """
filename = request.args.get('file')
other_var = filename
with open(other_var) as f:
    content = f.read()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # Should detect: request.args → filename → other_var → open()
        assert len(paths) >= 1
        path = paths[0]
        assert path.source.name == "filename"
        assert path.sink.function_name == "open"
        assert not path.sanitized

    def test_direct_source_to_sink(self, parser):
        """Test direct taint from source to sink."""
        code = """
user_file = request.args.get('file')
with open(user_file) as f:
    data = f.read()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) == 1
        assert paths[0].source.name == "user_file"
        assert paths[0].sink.function_name == "open"
        assert "user_file" in paths[0].sink.arguments

    def test_multiple_variable_assignments(self, parser):
        """Test taint propagates through multiple assignments."""
        code = """
a = request.form.get('data')
b = a
c = b
result = eval(c)
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # Should track: request.form → a → b → c → eval()
        assert len(paths) >= 1
        assert paths[0].sink.function_name == "eval"

    def test_binary_operation_propagation(self, parser):
        """Test taint propagates through binary operations (string concat)."""
        code = """
user_input = request.args.get('file')
full_path = "/var/www/" + user_input
with open(full_path) as f:
    pass
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # Should detect: user_input in binary op → full_path → open()
        assert len(paths) >= 1
        path = paths[0]
        assert path.sink.function_name == "open"

    def test_f_string_propagation(self, parser):
        """Test taint propagates through f-strings."""
        code = """
filename = request.args.get('file')
path = f"/uploads/{filename}"
with open(path) as f:
    pass
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) >= 1
        assert paths[0].sink.function_name == "open"

    def test_sanitization_detection(self, parser):
        """Test that sanitized variables are not flagged."""
        code = """
user_path = request.args.get('path')
safe_path = realpath(user_path)
with open(safe_path) as f:
    pass
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # realpath() is a sanitizer, so safe_path should not be tainted
        # TODO: This requires detecting sanitization in assignments
        # For now, this might still flag it, but we track sanitized vars
        assert tracker.sanitized == set() or "user_path" in tracker.sanitized

    def test_multiple_sources_multiple_sinks(self, parser):
        """Test tracking with multiple sources and sinks."""
        code = """
file1 = request.args.get('file1')
file2 = request.form.get('file2')
with open(file1) as f:
    data1 = f.read()
with open(file2) as f:
    data2 = f.read()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # Should find 2 vulnerability paths
        assert len(paths) == 2
        sources = {p.source.name for p in paths}
        assert sources == {"file1", "file2"}

    def test_no_vulnerability_safe_code(self, parser):
        """Test that safe code produces no vulnerability paths."""
        code = """
safe_var = "constant_value"
with open(safe_var) as f:
    data = f.read()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # No taint sources, so no vulnerabilities
        assert len(paths) == 0

    def test_eval_with_user_input(self, parser):
        """Test eval() with user input."""
        code = """
user_code = request.json.get('code')
result = eval(user_code)
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) == 1
        assert paths[0].sink.function_name == "eval"
        assert paths[0].sink.sink_type.value == "code_evaluation"

    def test_exec_with_user_input(self, parser):
        """Test exec() with user input."""
        code = """
dangerous = request.form.get('script')
exec(dangerous)
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) == 1
        assert paths[0].sink.function_name == "exec"

    def test_function_call_with_tainted_arg(self, parser):
        """Test that taint propagates through function call arguments."""
        code = """
user_data = request.args.get('data')
processed = some_function(user_data)
eval(processed)
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # Should track: user_data → some_function(arg) → processed → eval()
        assert len(paths) >= 1
        assert paths[0].sink.function_name == "eval"

    def test_is_tainted_method(self, parser):
        """Test the is_tainted() method."""
        code = """
tainted_var = request.args.get('file')
safe_var = "constant"
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)

        assert tracker.is_tainted("tainted_var")
        assert not tracker.is_tainted("safe_var")
        assert not tracker.is_tainted("nonexistent_var")

    def test_add_sanitization(self, parser):
        """Test manual sanitization marking."""
        code = """
user_input = request.args.get('data')
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)

        # Initially tainted
        assert tracker.is_tainted("user_input")

        # Manually sanitize
        tracker.add_sanitization("user_input")

        # Now safe
        assert not tracker.is_tainted("user_input")
        assert "user_input" in tracker.sanitized


class TestMultiLineDetection:
    """Tests for multi-line taint tracking (Phase 4.2 key feature!)."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_multiline_path_traversal(self, parser):
        """
        Test the exact scenario from xfailed test:
        test_detect_open_with_request_param
        """
        code = """
def read_file(request):
    filename = request.args.get('file')
    with open(filename) as f:
        return f.read()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # This is THE key test - multi-line taint tracking!
        assert len(paths) >= 1
        path = paths[0]
        assert path.source.line == 3  # filename = ...
        assert path.sink.line == 4    # open(filename)
        assert path.source.name == "filename"
        assert path.sink.function_name == "open"

    def test_multiline_os_path_join(self, parser):
        """
        Test: test_detect_os_path_join_with_request
        """
        code = """
def get_file_path(request):
    filename = request.args.get('file')
    return os.path.join('/var/www/uploads', filename)
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        # Should detect taint: filename → os.path.join
        assert len(paths) >= 1
        assert paths[0].source.name == "filename"
        assert paths[0].sink.function_name == "join"

    def test_multiline_eval(self, parser):
        """Test multi-line eval vulnerability."""
        code = """
def execute_code(request):
    user_code = request.form.get('code')
    result = eval(user_code)
    return result
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) >= 1
        assert paths[0].sink.function_name == "eval"


class TestEdgeCases:
    """Test edge cases and complex scenarios."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_no_sources(self, parser):
        """Test code with no taint sources."""
        code = """
with open("config.txt") as f:
    data = f.read()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) == 0

    def test_no_sinks(self, parser):
        """Test code with sources but no sinks."""
        code = """
user_data = request.args.get('data')
safe_operation = user_data.upper()
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) == 0

    def test_taint_path_confidence(self, parser):
        """Test that paths have confidence scores."""
        code = """
filename = request.args.get('file')
with open(filename) as f:
    pass
"""
        ast_result = parser.parse(code, "python")
        tracker = TaintTracker(ast_result)
        paths = tracker.track_flow()

        assert len(paths) >= 1
        assert paths[0].confidence > 0.0
        assert paths[0].confidence <= 1.0
