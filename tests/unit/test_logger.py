import logging
import json
import pytest
from mcp_sentinel.core.logger import setup_logging, JsonFormatter

def test_json_formatter():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None
    )
    formatted = formatter.format(record)
    data = json.loads(formatted)
    assert data["message"] == "Test message"
    assert data["level"] == "INFO"
    assert "timestamp" in data

def test_setup_logging_file(tmp_path):
    log_file = tmp_path / "test.log"
    setup_logging(log_level="DEBUG", log_file=str(log_file), log_to_console=False)
    
    logger = logging.getLogger("test_file_logger")
    logger.debug("Debug message")
    
    # Force flush/close to ensure write
    for handler in logging.getLogger().handlers:
        handler.flush()
        handler.close()
    
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "Debug message" in content
    assert '"level": "DEBUG"' in content

def test_setup_logging_console(capsys):
    # Reset handlers
    logging.getLogger().handlers = []
    
    setup_logging(log_level="INFO", log_file=None, log_to_console=True)
    logger = logging.getLogger("test_console_logger")
    logger.info("Console info")
    
    captured = capsys.readouterr()
    # Rich logs to stdout or stderr depending on config
    assert "Console info" in captured.out or "Console info" in captured.err
