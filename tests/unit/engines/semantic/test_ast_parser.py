"""
Unit tests for AST Parser.

Tests taint source/sink extraction across Python, JavaScript, and Java.
"""

import pytest
from pathlib import Path

from mcp_sentinel.engines.semantic.ast_parser import ASTParser
from mcp_sentinel.engines.semantic.models import TaintType, SinkType


class TestPythonASTParser:
    """Tests for Python AST parsing."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_parse_simple_python(self, parser):
        """Test parsing simple Python code."""
        code = """
def hello():
    print("Hello World")
"""
        ast_result = parser.parse(code, "python")

        assert ast_result is not None
        assert ast_result.language == "python"
        assert ast_result.raw_ast is not None

    def test_extract_request_args_source(self, parser):
        """Test extraction of request.args taint source."""
        code = """
def handler(request):
    filename = request.args.get('file')
    return filename
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sources) == 1
        source = ast_result.sources[0]
        assert source.name == "filename"
        assert source.line == 3
        assert source.taint_type == TaintType.USER_INPUT
        assert "request.args" in source.origin

    def test_extract_request_form_source(self, parser):
        """Test extraction of request.form taint source."""
        code = """
user_input = request.form.get('data')
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sources) == 1
        assert ast_result.sources[0].name == "user_input"
        assert "request.form" in ast_result.sources[0].origin

    def test_extract_open_sink(self, parser):
        """Test extraction of open() file operation sink."""
        code = """
with open(filename) as f:
    content = f.read()
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sinks) == 1
        sink = ast_result.sinks[0]
        assert sink.function_name == "open"
        assert sink.line == 2
        assert sink.sink_type == SinkType.FILE_OPERATION
        assert "filename" in sink.arguments

    def test_extract_eval_sink(self, parser):
        """Test extraction of eval() code execution sink."""
        code = """
result = eval(user_code)
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sinks) == 1
        sink = ast_result.sinks[0]
        assert sink.function_name == "eval"
        assert sink.sink_type == SinkType.CODE_EVALUATION

    def test_extract_exec_sink(self, parser):
        """Test extraction of exec() code execution sink."""
        code = """
exec(malicious_code)
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sinks) == 1
        assert ast_result.sinks[0].function_name == "exec"
        assert ast_result.sinks[0].sink_type == SinkType.CODE_EVALUATION

    def test_multiline_source_sink(self, parser):
        """Test extraction across multiple lines (the key Phase 4.2 feature)."""
        code = """
def vulnerable(request):
    filename = request.args.get('file')
    with open(filename) as f:
        return f.read()
"""
        ast_result = parser.parse(code, "python")

        # Should find 1 source (request.args.get)
        assert len(ast_result.sources) == 1
        source = ast_result.sources[0]
        assert source.name == "filename"
        assert source.line == 3

        # Should find 1 sink (open)
        assert len(ast_result.sinks) == 1
        sink = ast_result.sinks[0]
        assert sink.function_name == "open"
        assert sink.line == 4
        assert "filename" in sink.arguments

        # Variable tracking: filename should be marked as tainted
        assert "filename" in ast_result.variables
        assert ast_result.variables["filename"]["tainted"] is True

    def test_multiple_sources(self, parser):
        """Test extraction of multiple taint sources."""
        code = """
file1 = request.args.get('file1')
file2 = request.form.get('file2')
data = request.json.get('data')
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sources) == 3
        names = {s.name for s in ast_result.sources}
        assert names == {"file1", "file2", "data"}

    def test_multiple_sinks(self, parser):
        """Test extraction of multiple dangerous sinks."""
        code = """
with open(file1) as f:
    content = f.read()
result = eval(user_code)
exec(malicious)
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sinks) == 3
        funcs = {s.function_name for s in ast_result.sinks}
        assert funcs == {"open", "eval", "exec"}

    def test_environment_variable_source(self, parser):
        """Test extraction of environment variable as taint source."""
        code = """
import os
db_password = os.environ.get('DB_PASS')
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.sources) == 1
        source = ast_result.sources[0]
        assert source.taint_type == TaintType.ENVIRONMENT
        assert "environ" in source.origin

    def test_function_tracking(self, parser):
        """Test that function definitions are tracked."""
        code = """
def handler(request, response):
    pass

def process_data(data):
    pass
"""
        ast_result = parser.parse(code, "python")

        assert len(ast_result.functions) == 2
        func_names = {f["name"] for f in ast_result.functions}
        assert func_names == {"handler", "process_data"}


class TestJavaScriptASTParser:
    """Tests for JavaScript AST parsing (regex-based for now)."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_parse_javascript(self, parser):
        """Test parsing JavaScript code."""
        code = """
function handler(req, res) {
    const filename = req.query.file;
    fs.readFile(filename);
}
"""
        ast_result = parser.parse(code, "javascript")

        assert ast_result is not None
        assert ast_result.language == "javascript"

    def test_extract_req_params_source_js(self, parser):
        """Test extraction of req.params in JavaScript."""
        code = """
const filename = req.params.file;
"""
        ast_result = parser.parse(code, "javascript")

        # Regex-based extraction should find it
        assert len(ast_result.sources) >= 1
        # Check if any source contains req.params
        has_req_params = any("req.params" in s.origin for s in ast_result.sources)
        assert has_req_params

    def test_extract_readfile_sink_js(self, parser):
        """Test extraction of readFile sink in JavaScript."""
        code = """
fs.readFile(userPath, callback);
"""
        ast_result = parser.parse(code, "javascript")

        assert len(ast_result.sinks) >= 1
        has_readfile = any(s.function_name == "readFile" for s in ast_result.sinks)
        assert has_readfile


class TestJavaASTParser:
    """Tests for Java AST parsing (regex-based for now)."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_parse_java(self, parser):
        """Test parsing Java code."""
        code = """
public class Handler {
    public void process(HttpRequest request) {
        String filename = request.getParameter("file");
        new File(filename);
    }
}
"""
        ast_result = parser.parse(code, "java")

        assert ast_result is not None
        assert ast_result.language == "java"

    def test_extract_getparameter_source_java(self, parser):
        """Test extraction of getParameter in Java."""
        code = """
String filename = request.getParameter("file");
"""
        ast_result = parser.parse(code, "java")

        assert len(ast_result.sources) >= 1
        has_getparam = any("getParameter" in s.origin for s in ast_result.sources)
        assert has_getparam

    def test_extract_file_sink_java(self, parser):
        """Test extraction of File constructor in Java."""
        code = """
File file = new File(userPath);
"""
        ast_result = parser.parse(code, "java")

        assert len(ast_result.sinks) >= 1
        has_file = any(s.function_name == "File" for s in ast_result.sinks)
        assert has_file


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_invalid_python_syntax(self, parser):
        """Test handling of invalid Python syntax."""
        code = """
def broken(
    # Missing closing parenthesis
"""
        ast_result = parser.parse(code, "python")

        # Should return None for invalid syntax
        assert ast_result is None

    def test_empty_code(self, parser):
        """Test parsing empty code."""
        code = ""
        ast_result = parser.parse(code, "python")

        # Should parse successfully but have no sources/sinks
        assert ast_result is not None
        assert len(ast_result.sources) == 0
        assert len(ast_result.sinks) == 0

    def test_no_sources_or_sinks(self, parser):
        """Test code with no taint sources or sinks."""
        code = """
def safe_function():
    x = 1 + 2
    return x * 3
"""
        ast_result = parser.parse(code, "python")

        assert ast_result is not None
        assert len(ast_result.sources) == 0
        assert len(ast_result.sinks) == 0

    def test_unsupported_language(self, parser):
        """Test unsupported programming language."""
        code = "fn main() {}"
        ast_result = parser.parse(code, "rust")

        assert ast_result is None
