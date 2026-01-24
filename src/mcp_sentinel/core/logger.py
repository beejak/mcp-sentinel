import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Any, Dict

from rich.logging import RichHandler

class JsonFormatter(logging.Formatter):
    """JSON formatter for file logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_record: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_record)

def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    log_to_console: bool = True
) -> None:
    """
    Configure the logging system.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARN, ERROR, FATAL)
        log_file: Path to the log file
        log_to_console: Whether to log to console
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
        
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    root_logger.handlers = []
    
    # Console Handler (Rich)
    if log_to_console:
        console_handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_time=False,
            show_level=True
        )
        console_handler.setLevel(numeric_level)
        # RichHandler has its own formatter
        root_logger.addHandler(console_handler)
        
    # File Handler (Rotating + JSON)
    if log_file:
        log_path = Path(log_file)
        # Ensure directory exists
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 10MB limit, 5 backups
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(JsonFormatter())
        root_logger.addHandler(file_handler)

    # Suppress noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
