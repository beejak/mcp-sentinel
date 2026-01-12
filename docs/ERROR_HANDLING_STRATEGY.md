# Error Handling Strategy

## Overview

This document defines the comprehensive error handling strategy for the MCP Sentinel Python project, including error classification, handling patterns, recovery mechanisms, and monitoring approaches. The strategy ensures robust operation, graceful degradation, and effective debugging capabilities.

## Table of Contents

1. [Error Classification](#error-classification)
2. [Error Handling Patterns](#error-handling-patterns)
3. [Exception Hierarchy](#exception-hierarchy)
4. [Recovery Mechanisms](#recovery-mechanisms)
5. [Logging and Monitoring](#logging-and-monitoring)
6. [Circuit Breaker Implementation](#circuit-breaker-implementation)
7. [Error Reporting](#error-reporting)
8. [Testing Strategy](#testing-strategy)

---

## Error Classification

### Error Categories

```python
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime

class ErrorCategory(Enum):
    """Error classification categories."""
    CONFIGURATION = "configuration"
    VALIDATION = "validation"
    SCANNER = "scanner"
    DETECTOR = "detector"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    MEMORY = "memory"
    TIMEOUT = "timeout"
    PERMISSION = "permission"
    UNKNOWN = "unknown"

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"           # Informational, doesn't affect functionality
    MEDIUM = "medium"     # Affects some functionality but can continue
    HIGH = "high"        # Affects core functionality, limited operation
    CRITICAL = "critical" # System cannot continue operation

class ErrorContext:
    """Context information for error handling."""
    
    def __init__(self, 
                 category: ErrorCategory,
                 severity: ErrorSeverity,
                 component: str,
                 operation: str,
                 file_path: Optional[str] = None,
                 user_message: Optional[str] = None,
                 technical_details: Optional[Dict[str, Any]] = None):
        self.category = category
        self.severity = severity
        self.component = component
        self.operation = operation
        self.file_path = file_path
        self.user_message = user_message
        self.technical_details = technical_details or {}
        self.timestamp = datetime.now()
        self.correlation_id = self._generate_correlation_id()
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID for error tracking."""
        import uuid
        return str(uuid.uuid4())
```

### Error Frequency Classification

```python
class ErrorFrequency:
    """Track error frequency for circuit breaker logic."""
    
    def __init__(self, window_minutes: int = 5, threshold_count: int = 10):
        self.window_minutes = window_minutes
        self.threshold_count = threshold_count
        self.error_counts: Dict[str, List[datetime]] = {}
    
    def record_error(self, error_code: str) -> None:
        """Record error occurrence."""
        now = datetime.now()
        if error_code not in self.error_counts:
            self.error_counts[error_code] = []
        
        self.error_counts[error_code].append(now)
        self._cleanup_old_errors(error_code)
    
    def is_threshold_exceeded(self, error_code: str) -> bool:
        """Check if error threshold is exceeded."""
        self._cleanup_old_errors(error_code)
        return len(self.error_counts.get(error_code, [])) >= self.threshold_count
    
    def _cleanup_old_errors(self, error_code: str) -> None:
        """Remove errors outside the time window."""
        if error_code not in self.error_counts:
            return
        
        cutoff_time = datetime.now() - timedelta(minutes=self.window_minutes)
        self.error_counts[error_code] = [
            error_time for error_time in self.error_counts[error_code]
            if error_time > cutoff_time
        ]
```

---

## Error Handling Patterns

### Retry Pattern

```python
import asyncio
import random
from typing import Callable, Any, Optional
from functools import wraps

class RetryConfig:
    """Configuration for retry operations."""
    
    def __init__(self, 
                 max_attempts: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

def retry_with_backoff(retry_config: Optional[RetryConfig] = None):
    """Decorator for retry logic with exponential backoff."""
    
    if retry_config is None:
        retry_config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(retry_config.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == retry_config.max_attempts - 1:
                        # Final attempt failed
                        raise
                    
                    # Calculate delay with exponential backoff and jitter
                    delay = retry_config.base_delay * (retry_config.exponential_base ** attempt)
                    delay = min(delay, retry_config.max_delay)
                    
                    if retry_config.jitter:
                        delay = delay * (0.5 + random.random())
                    
                    # Log retry attempt
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s")
                    await asyncio.sleep(delay)
            
            # This should never be reached, but just in case
            raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(retry_config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == retry_config.max_attempts - 1:
                        raise
                    
                    delay = retry_config.base_delay * (retry_config.exponential_base ** attempt)
                    delay = min(delay, retry_config.max_delay)
                    
                    if retry_config.jitter:
                        delay = delay * (0.5 + random.random())
                    
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s")
                    time.sleep(delay)
            
            raise last_exception
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator

# Usage example
@retry_with_backoff(RetryConfig(max_attempts=5, base_delay=2.0))
async def scan_file_with_retry(file_path: Path) -> List[Vulnerability]:
    """Scan file with automatic retry on failure."""
    return await detector.scan_file(file_path)
```

### Fallback Pattern

```python
from typing import Callable, List, Any, Optional

class FallbackStrategy:
    """Implements fallback strategies for error recovery."""
    
    def __init__(self, primary_func: Callable, fallback_funcs: List[Callable]):
        self.primary_func = primary_func
        self.fallback_funcs = fallback_funcs
    
    async def execute(self, *args, **kwargs) -> Any:
        """Execute with fallback strategies."""
        
        # Try primary function
        try:
            if asyncio.iscoroutinefunction(self.primary_func):
                return await self.primary_func(*args, **kwargs)
            else:
                return self.primary_func(*args, **kwargs)
        except Exception as primary_error:
            logger.warning(f"Primary function failed: {primary_error}")
            
            # Try fallback functions in order
            for i, fallback_func in enumerate(self.fallback_funcs):
                try:
                    logger.info(f"Trying fallback strategy {i + 1}")
                    if asyncio.iscoroutinefunction(fallback_func):
                        return await fallback_func(*args, **kwargs)
                    else:
                        return fallback_func(*args, **kwargs)
                except Exception as fallback_error:
                    logger.warning(f"Fallback {i + 1} failed: {fallback_error}")
                    continue
            
            # All strategies failed
            raise RuntimeError(f"All strategies failed. Primary error: {primary_error}")

# Fallback implementations
async def scan_file_primary(file_path: Path) -> List[Vulnerability]:
    """Primary scanning implementation."""
    # Full scanning logic
    pass

async def scan_file_lightweight(file_path: Path) -> List[Vulnerability]:
    """Lightweight fallback scanning."""
    # Simplified scanning logic
    pass

async def scan_file_cached(file_path: Path) -> List[Vulnerability]:
    """Cached results fallback."""
    # Return cached results if available
    pass

# Usage
fallback_strategy = FallbackStrategy(
    primary_func=scan_file_primary,
    fallback_funcs=[scan_file_lightweight, scan_file_cached]
)

results = await fallback_strategy.execute(file_path)
```

### Graceful Degradation

```python
class GracefulDegradation:
    """Implements graceful degradation strategies."""
    
    def __init__(self):
        self.degradation_levels = {
            "full": self._full_functionality,
            "reduced": self._reduced_functionality,
            "minimal": self._minimal_functionality,
            "emergency": self._emergency_functionality
        }
        self.current_level = "full"
    
    def set_degradation_level(self, level: str) -> None:
        """Set current degradation level."""
        if level not in self.degradation_levels:
            raise ValueError(f"Invalid degradation level: {level}")
        
        self.current_level = level
        logger.info(f"Degradation level set to: {level}")
    
    async def execute_with_degradation(self, operation: str, *args, **kwargs):
        """Execute operation with current degradation level."""
        handler = self.degradation_levels[self.current_level]
        return await handler(operation, *args, **kwargs)
    
    async def _full_functionality(self, operation: str, *args, **kwargs):
        """Full functionality mode."""
        # Execute all detectors with full analysis
        return await self._execute_all_detectors(*args, **kwargs)
    
    async def _reduced_functionality(self, operation: str, *args, **kwargs):
        """Reduced functionality mode."""
        # Use only high-confidence, fast detectors
        return await self._execute_fast_detectors(*args, **kwargs)
    
    async def _minimal_functionality(self, operation: str, *args, **kwargs):
        """Minimal functionality mode."""
        # Use only critical detectors with basic analysis
        return await self._execute_critical_detectors(*args, **kwargs)
    
    async def _emergency_functionality(self, operation: str, *args, **kwargs):
        """Emergency functionality mode."""
        # Return cached results or basic status only
        return await self._execute_emergency_mode(*args, **kwargs)
```

---

## Exception Hierarchy

### Base Exception Classes

```python
class MCPSentinelError(Exception):
    """Base exception for all MCP Sentinel errors."""
    
    def __init__(self, message: str, error_code: str = None, context: Optional[ErrorContext] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self._generate_error_code()
        self.context = context
        self.timestamp = datetime.now()
    
    def _generate_error_code(self) -> str:
        """Generate error code from class name."""
        class_name = self.__class__.__name__
        return class_name.upper().replace("ERROR", "_ERROR")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context.__dict__ if self.context else None,
            "error_type": self.__class__.__name__
        }

# Configuration Errors
class ConfigurationError(MCPSentinelError):
    """Configuration-related errors."""
    
    def __init__(self, message: str, config_key: str = None, details: Dict[str, Any] = None):
        context = ErrorContext(
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.HIGH,
            component="ConfigurationManager",
            operation="load_configuration",
            user_message="Configuration error. Please check your settings.",
            technical_details=details
        )
        super().__init__(message, context=context)
        self.config_key = config_key

class InvalidConfigError(ConfigurationError):
    """Invalid configuration values."""
    pass

class ConfigNotFoundError(ConfigurationError):
    """Configuration file not found."""
    pass

# Validation Errors
class ValidationError(MCPSentinelError):
    """Input validation errors."""
    
    def __init__(self, message: str, field: str = None, value: Any = None, details: Dict[str, Any] = None):
        context = ErrorContext(
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            component="Validator",
            operation="validate_input",
            user_message="Invalid input. Please check your parameters.",
            technical_details=details
        )
        super().__init__(message, context=context)
        self.field = field
        self.value = value

# Scanner Errors
class ScannerError(MCPSentinelError):
    """Scanner operation errors."""
    
    def __init__(self, message: str, file_path: str = None, details: Dict[str, Any] = None):
        context = ErrorContext(
            category=ErrorCategory.SCANNER,
            severity=ErrorSeverity.HIGH,
            component="ScannerOrchestrator",
            operation="scan_operation",
            file_path=file_path,
            user_message="Scanning operation failed. Check file permissions and path.",
            technical_details=details
        )
        super().__init__(message, context=context)
        self.file_path = file_path

class FileNotFoundError(ScannerError):
    """File or directory not found."""
    pass

class PermissionDeniedError(ScannerError):
    """Permission denied for file operation."""
    pass

class FileTooLargeError(ScannerError):
    """File exceeds maximum size limit."""
    
    def __init__(self, message: str, file_path: str, file_size: int, max_size: int):
        super().__init__(message, file_path=file_path)
        self.file_size = file_size
        self.max_size = max_size

# Detector Errors
class DetectorError(MCPSentinelError):
    """Detector-specific errors."""
    
    def __init__(self, message: str, detector_name: str = None, details: Dict[str, Any] = None):
        context = ErrorContext(
            category=ErrorCategory.DETECTOR,
            severity=ErrorSeverity.MEDIUM,
            component="DetectorManager",
            operation="detector_operation",
            user_message="Detector error. Check detector configuration.",
            technical_details=details
        )
        super().__init__(message, context=context)
        self.detector_name = detector_name

class DetectorNotFoundError(DetectorError):
    """Requested detector not found."""
    pass

class DetectorInitializationError(DetectorError):
    """Detector initialization failed."""
    pass

# Timeout Errors
class TimeoutError(MCPSentinelError):
    """Operation timeout errors."""
    
    def __init__(self, message: str, timeout_seconds: int = None, details: Dict[str, Any] = None):
        context = ErrorContext(
            category=ErrorCategory.TIMEOUT,
            severity=ErrorSeverity.MEDIUM,
            component="TimeoutManager",
            operation="timeout_operation",
            user_message="Operation timed out. Consider increasing timeout values.",
            technical_details=details
        )
        super().__init__(message, context=context)
        self.timeout_seconds = timeout_seconds

# Memory Errors
class MemoryError(MCPSentinelError):
    """Memory-related errors."""
    
    def __init__(self, message: str, memory_usage_mb: int = None, memory_limit_mb: int = None):
        context = ErrorContext(
            category=ErrorCategory.MEMORY,
            severity=ErrorSeverity.CRITICAL,
            component="MemoryManager",
            operation="memory_allocation",
            user_message="Memory limit exceeded. Reduce concurrent operations or file sizes.",
        )
        super().__init__(message, context=context)
        self.memory_usage_mb = memory_usage_mb
        self.memory_limit_mb = memory_limit_mb
```

---

## Recovery Mechanisms

### Auto-Recovery System

```python
class AutoRecovery:
    """Automatic error recovery system."""
    
    def __init__(self):
        self.recovery_strategies = {
            ErrorCategory.FILE_SYSTEM: self._recover_file_system_error,
            ErrorCategory.MEMORY: self._recover_memory_error,
            ErrorCategory.TIMEOUT: self._recover_timeout_error,
            ErrorCategory.NETWORK: self._recover_network_error,
        }
    
    async def attempt_recovery(self, error: MCPSentinelError) -> bool:
        """Attempt to recover from error."""
        if not error.context:
            return False
        
        category = error.context.category
        if category in self.recovery_strategies:
            try:
                return await self.recovery_strategies[category](error)
            except Exception as recovery_error:
                logger.error(f"Recovery failed for {category.value}: {recovery_error}")
                return False
        
        return False
    
    async def _recover_file_system_error(self, error: MCPSentinelError) -> bool:
        """Recover from file system errors."""
        if isinstance(error, PermissionDeniedError):
            # Attempt to fix permissions
            return await self._fix_permissions(error.file_path)
        elif isinstance(error, FileNotFoundError):
            # Check if file exists in alternative location
            return await self._check_alternative_location(error.file_path)
        
        return False
    
    async def _recover_memory_error(self, error: MCPSentinelError) -> bool:
        """Recover from memory errors."""
        # Force garbage collection
        import gc
        gc.collect()
        
        # Reduce memory usage
        if hasattr(error, 'memory_usage_mb') and hasattr(error, 'memory_limit_mb'):
            return await self._reduce_memory_usage()
        
        return False
    
    async def _recover_timeout_error(self, error: MCPSentinelError) -> bool:
        """Recover from timeout errors."""
        # Increase timeout temporarily
        if hasattr(error, 'timeout_seconds'):
            new_timeout = min(error.timeout_seconds * 2, 300)  # Max 5 minutes
            # Apply new timeout to configuration
            return await self._update_timeout(new_timeout)
        
        return False
    
    async def _recover_network_error(self, error: MCPSentinelError) -> bool:
        """Recover from network errors."""
        # Retry with exponential backoff
        return await self._retry_with_backoff(error)
    
    async def _fix_permissions(self, file_path: str) -> bool:
        """Attempt to fix file permissions."""
        try:
            import os
            os.chmod(file_path, 0o644)
            return True
        except Exception:
            return False
    
    async def _check_alternative_location(self, file_path: str) -> bool:
        """Check for file in alternative locations."""
        # Implementation for alternative location checking
        return False
    
    async def _reduce_memory_usage(self) -> bool:
        """Reduce memory usage."""
        # Clear caches, reduce concurrent operations
        return True
    
    async def _update_timeout(self, timeout: int) -> bool:
        """Update timeout configuration."""
        # Implementation for timeout update
        return True
    
    async def _retry_with_backoff(self, error: MCPSentinelError) -> bool:
        """Retry operation with exponential backoff."""
        # Implementation for retry logic
        return True
```

### Health Check System

```python
class HealthCheck:
    """System health monitoring and recovery."""
    
    def __init__(self):
        self.health_status = {
            "scanner": True,
            "detectors": {},
            "memory": True,
            "file_system": True,
            "network": True
        }
        self.error_counts = {}
    
    async def perform_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "components": {}
        }
        
        # Check scanner health
        scanner_health = await self._check_scanner_health()
        health_report["components"]["scanner"] = scanner_health
        
        # Check detector health
        detector_health = await self._check_detector_health()
        health_report["components"]["detectors"] = detector_health
        
        # Check memory health
        memory_health = self._check_memory_health()
        health_report["components"]["memory"] = memory_health
        
        # Check file system health
        fs_health = await self._check_filesystem_health()
        health_report["components"]["file_system"] = fs_health
        
        # Determine overall status
        if any(component["status"] == "unhealthy" for component in health_report["components"].values()):
            health_report["overall_status"] = "unhealthy"
        elif any(component["status"] == "degraded" for component in health_report["components"].values()):
            health_report["overall_status"] = "degraded"
        
        return health_report
    
    async def _check_scanner_health(self) -> Dict[str, Any]:
        """Check scanner component health."""
        try:
            # Test basic scanner functionality
            test_file = Path("/tmp/health_check_test.txt")
            test_file.write_text("test content")
            
            scanner = MCPSentinel()
            results = await scanner.scan_file(test_file)
            
            test_file.unlink()  # Cleanup
            
            return {
                "status": "healthy",
                "details": "Scanner operational"
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": f"Scanner error: {e}"
            }
    
    async def _check_detector_health(self) -> Dict[str, Any]:
        """Check detector health."""
        detector_status = {}
        
        try:
            scanner = MCPSentinel()
            detectors = scanner.get_available_detectors()
            
            for detector_name in detectors:
                try:
                    detector_info = scanner.get_detector_info(detector_name)
                    detector_status[detector_name] = {
                        "status": "healthy",
                        "details": "Detector operational"
                    }
                except Exception as e:
                    detector_status[detector_name] = {
                        "status": "unhealthy",
                        "details": f"Detector error: {e}"
                    }
            
            return detector_status
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": f"Detector manager error: {e}"
            }
    
    def _check_memory_health(self) -> Dict[str, Any]:
        """Check memory health."""
        try:
            import psutil
            
            memory_percent = psutil.virtual_memory().percent
            
            if memory_percent > 90:
                status = "unhealthy"
                details = f"Memory usage critical: {memory_percent}%"
            elif memory_percent > 80:
                status = "degraded"
                details = f"Memory usage high: {memory_percent}%"
            else:
                status = "healthy"
                details = f"Memory usage normal: {memory_percent}%"
            
            return {
                "status": status,
                "details": details,
                "memory_percent": memory_percent
            }
        except Exception as e:
            return {
                "status": "unknown",
                "details": f"Memory check failed: {e}"
            }
    
    async def _check_filesystem_health(self) -> Dict[str, Any]:
        """Check file system health."""
        try:
            # Test file system operations
            test_file = Path("/tmp/fs_health_test.txt")
            test_content = "health check"
            
            # Write test
            test_file.write_text(test_content)
            
            # Read test
            read_content = test_file.read_text()
            
            # Cleanup
            test_file.unlink()
            
            if read_content == test_content:
                return {
                    "status": "healthy",
                    "details": "File system operational"
                }
            else:
                return {
                    "status": "unhealthy",
                    "details": "File system read/write mismatch"
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "details": f"File system error: {e}"
            }
```

---

## Logging and Monitoring

### Structured Logging

```python
import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime

class StructuredLogger:
    """Structured logging for error tracking and analysis."""
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Create JSON formatter
        formatter = logging.Formatter('%(message)s')
        
        # Console handler with JSON output
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def log_error(self, error: MCPSentinelError, context: Optional[Dict[str, Any]] = None) -> None:
        """Log error with structured data."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "ERROR",
            "error_type": error.__class__.__name__,
            "error_code": error.error_code,
            "message": error.message,
            "context": error.context.__dict__ if error.context else None,
            "additional_context": context
        }
        
        self.logger.error(json.dumps(log_entry))
    
    def log_warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log warning with structured data."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "WARNING",
            "message": message,
            "context": context
        }
        
        self.logger.warning(json.dumps(log_entry))
    
    def log_info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log info with structured data."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "INFO",
            "message": message,
            "context": context
        }
        
        self.logger.info(json.dumps(log_entry))
    
    def log_metric(self, metric_name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Log performance metrics."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "METRIC",
            "metric_name": metric_name,
            "value": value,
            "tags": tags or {}
        }
        
        self.logger.info(json.dumps(log_entry))

# Global logger instance
error_logger = StructuredLogger("mcp_sentinel.errors")
```

### Error Metrics Collection

```python
class ErrorMetrics:
    """Collect and track error metrics."""
    
    def __init__(self):
        self.metrics = {
            "error_count": {},
            "error_rate": {},
            "recovery_success_rate": {},
            "mean_time_to_recovery": {},
            "error_severity_distribution": {}
        }
        self.error_times: Dict[str, List[datetime]] = {}
    
    def record_error(self, error: MCPSentinelError) -> None:
        """Record error occurrence."""
        error_code = error.error_code
        
        # Increment error count
        if error_code not in self.metrics["error_count"]:
            self.metrics["error_count"][error_code] = 0
        self.metrics["error_count"][error_code] += 1
        
        # Record error time for rate calculation
        if error_code not in self.error_times:
            self.error_times[error_code] = []
        self.error_times[error_code].append(datetime.now())
        
        # Update severity distribution
        if error.context:
            severity = error.context.severity.value
            if severity not in self.metrics["error_severity_distribution"]:
                self.metrics["error_severity_distribution"][severity] = 0
            self.metrics["error_severity_distribution"][severity] += 1
        
        # Log structured error data
        error_logger.log_error(error)
    
    def record_recovery(self, error_code: str, success: bool, recovery_time: float) -> None:
        """Record recovery attempt."""
        # Update recovery success rate
        if error_code not in self.metrics["recovery_success_rate"]:
            self.metrics["recovery_success_rate"][error_code] = {"success": 0, "total": 0}
        
        self.metrics["recovery_success_rate"][error_code]["total"] += 1
        if success:
            self.metrics["recovery_success_rate"][error_code]["success"] += 1
        
        # Update mean time to recovery
        if error_code not in self.metrics["mean_time_to_recovery"]:
            self.metrics["mean_time_to_recovery"][error_code] = []
        self.metrics["mean_time_to_recovery"][error_code].append(recovery_time)
        
        # Log recovery metric
        error_logger.log_metric(
            "recovery_attempt",
            1.0 if success else 0.0,
            {"error_code": error_code, "success": str(success)}
        )
    
    def get_error_rate(self, error_code: str, time_window_minutes: int = 60) -> float:
        """Calculate error rate for specific error code."""
        if error_code not in self.error_times:
            return 0.0
        
        cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
        recent_errors = [
            error_time for error_time in self.error_times[error_code]
            if error_time > cutoff_time
        ]
        
        return len(recent_errors) / time_window_minutes
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all error metrics."""
        summary = {}
        
        for metric_name, metric_data in self.metrics.items():
            if metric_name == "mean_time_to_recovery":
                # Calculate average recovery time
                summary[metric_name] = {
                    error_code: sum(times) / len(times) if times else 0
                    for error_code, times in metric_data.items()
                }
            elif metric_name == "recovery_success_rate":
                # Calculate success percentage
                summary[metric_name] = {
                    error_code: (data["success"] / data["total"] * 100) if data["total"] > 0 else 0
                    for error_code, data in metric_data.items()
                }
            else:
                summary[metric_name] = metric_data.copy()
        
        # Add error rates
        summary["error_rates"] = {
            error_code: self.get_error_rate(error_code)
            for error_code in self.metrics["error_count"].keys()
        }
        
        return summary
```

---

## Circuit Breaker Implementation

### Circuit Breaker Pattern

```python
from enum import Enum
import asyncio
from typing import Callable, Any, Optional

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing fast
    HALF_OPEN = "half_open"  # Testing if service recovered

class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 expected_exception: type = Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
        self.error_frequency = ErrorFrequency()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Call function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker attempting reset (half-open)")
            else:
                raise MCPSentinelError(
                    "Circuit breaker is open",
                    error_code="CIRCUIT_BREAKER_OPEN",
                    context=ErrorContext(
                        category=ErrorCategory.NETWORK,
                        severity=ErrorSeverity.HIGH,
                        component="CircuitBreaker",
                        operation="protected_call"
                    )
                )
        
        try:
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            
            if self.state == CircuitState.HALF_OPEN:
                self._on_success()
            elif self.state == CircuitState.CLOSED:
                self._reset_failure_count()
            
            return result
            
        except self.expected_exception as e:
            self._on_failure(e)
            
            if self.state == CircuitState.HALF_OPEN:
                # Still failing, go back to open
                self.state = CircuitState.OPEN
                logger.warning("Circuit breaker reset failed, returning to open state")
            
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        
        time_since_failure = (datetime.now() - self.last_failure_time).total_seconds()
        return time_since_failure >= self.recovery_timeout
    
    def _on_success(self) -> None:
        """Handle successful call."""
        self.state = CircuitState.CLOSED
        self._reset_failure_count()
        logger.info("Circuit breaker reset successful, returning to closed state")
    
    def _on_failure(self, error: Exception) -> None:
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        logger.warning(f"Circuit breaker failure {self.failure_count}/{self.failure_threshold}: {error}")
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.error("Circuit breaker threshold exceeded, opening circuit")
    
    def _reset_failure_count(self) -> None:
        """Reset failure count on success."""
        self.failure_count = 0
        self.last_failure_time = None

# Circuit breaker manager for multiple components
class CircuitBreakerManager:
    """Manages circuit breakers for different components."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
    
    def get_circuit_breaker(self, name: str, **config) -> CircuitBreaker:
        """Get or create circuit breaker for component."""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(**config)
        
        return self.circuit_breakers[name]
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status of all circuit breakers."""
        status = {}
        for name, cb in self.circuit_breakers.items():
            status[name] = {
                "state": cb.state.value,
                "failure_count": cb.failure_count,
                "last_failure_time": cb.last_failure_time.isoformat() if cb.last_failure_time else None
            }
        return status
```

---

## Error Reporting

### Error Report Generation

```python
class ErrorReporter:
    """Generate comprehensive error reports."""
    
    def __init__(self, metrics_collector: ErrorMetrics):
        self.metrics = metrics_collector
    
    def generate_error_report(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive error report."""
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "time_range_hours": time_range_hours,
                "report_version": "1.0"
            },
            "summary": self._generate_summary(),
            "error_breakdown": self._generate_error_breakdown(),
            "recovery_analysis": self._generate_recovery_analysis(),
            "recommendations": self._generate_recommendations(),
            "detailed_errors": self._get_detailed_errors(time_range_hours)
        }
        
        return report
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate error summary."""
        metrics_summary = self.metrics.get_metrics_summary()
        
        total_errors = sum(metrics_summary["error_count"].values())
        recovery_success_rate = self._calculate_overall_recovery_rate(metrics_summary)
        
        return {
            "total_errors": total_errors,
            "error_rate_per_hour": self._calculate_overall_error_rate(),
            "recovery_success_rate": recovery_success_rate,
            "most_frequent_error": self._get_most_frequent_error(),
            "severity_distribution": metrics_summary.get("error_severity_distribution", {})
        }
    
    def _generate_error_breakdown(self) -> Dict[str, Any]:
        """Generate detailed error breakdown."""
        metrics_summary = self.metrics.get_metrics_summary()
        
        breakdown = {
            "by_error_code": {},
            "by_category": self._categorize_errors(),
            "by_time": self._get_temporal_distribution(),
            "trending_errors": self._get_trending_errors()
        }
        
        for error_code, count in metrics_summary["error_count"].items():
            breakdown["by_error_code"][error_code] = {
                "count": count,
                "rate_per_hour": self.metrics.get_error_rate(error_code),
                "recovery_rate": metrics_summary.get("recovery_success_rate", {}).get(error_code, 0),
                "mean_recovery_time": metrics_summary.get("mean_time_to_recovery", {}).get(error_code, 0)
            }
        
        return breakdown
    
    def _generate_recovery_analysis(self) -> Dict[str, Any]:
        """Analyze recovery effectiveness."""
        metrics_summary = self.metrics.get_metrics_summary()
        
        return {
            "overall_recovery_success_rate": self._calculate_overall_recovery_rate(metrics_summary),
            "recovery_by_error_type": metrics_summary.get("recovery_success_rate", {}),
            "mean_recovery_times": metrics_summary.get("mean_time_to_recovery", {}),
            "recovery_improvements": self._identify_recovery_improvements()
        }
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate actionable recommendations."""
        recommendations = []
        
        metrics_summary = self.metrics.get_metrics_summary()
        
        # High error rate recommendations
        for error_code, rate in self._get_high_error_rates():
            recommendations.append({
                "type": "high_error_rate",
                "priority": "high",
                "error_code": error_code,
                "current_rate": rate,
                "recommendation": self._get_recommendation_for_error_rate(error_code, rate)
            })
        
        # Low recovery rate recommendations
        for error_code, recovery_rate in metrics_summary.get("recovery_success_rate", {}).items():
            if recovery_rate < 50:  # Less than 50% recovery success
                recommendations.append({
                    "type": "low_recovery_rate",
                    "priority": "medium",
                    "error_code": error_code,
                    "current_recovery_rate": recovery_rate,
                    "recommendation": f"Improve recovery strategy for {error_code}"
                })
        
        # Performance recommendations
        slow_recoveries = [
            (error_code, time) for error_code, time in 
            metrics_summary.get("mean_time_to_recovery", {}).items()
            if time > 30  # More than 30 seconds
        ]
        
        for error_code, recovery_time in slow_recoveries:
            recommendations.append({
                "type": "slow_recovery",
                "priority": "low",
                "error_code": error_code,
                "current_recovery_time": recovery_time,
                "recommendation": f"Optimize recovery time for {error_code}"
            })
        
        return recommendations
    
    def _calculate_overall_recovery_rate(self, metrics_summary: Dict[str, Any]) -> float:
        """Calculate overall recovery success rate."""
        recovery_rates = metrics_summary.get("recovery_success_rate", {})
        if not recovery_rates:
            return 0.0
        
        total_success = sum(data["success"] for data in recovery_rates.values())
        total_attempts = sum(data["total"] for data in recovery_rates.values())
        
        return (total_success / total_attempts * 100) if total_attempts > 0 else 0.0
    
    def _calculate_overall_error_rate(self) -> float:
        """Calculate overall error rate across all error types."""
        total_errors = sum(self.metrics.get_metrics_summary()["error_count"].values())
        return total_errors / 24  # Assuming 24-hour window
    
    def _get_most_frequent_error(self) -> Optional[str]:
        """Get the most frequent error code."""
        error_counts = self.metrics.get_metrics_summary()["error_count"]
        return max(error_counts.items(), key=lambda x: x[1])[0] if error_counts else None
    
    def _categorize_errors(self) -> Dict[str, int]:
        """Categorize errors by category."""
        # Implementation for error categorization
        return {}
    
    def _get_temporal_distribution(self) -> Dict[str, Any]:
        """Get temporal distribution of errors."""
        # Implementation for temporal analysis
        return {}
    
    def _get_trending_errors(self) -> List[Dict[str, Any]]:
        """Identify trending errors (increasing frequency)."""
        # Implementation for trend analysis
        return []
    
    def _get_high_error_rates(self) -> List[tuple]:
        """Get errors with high error rates."""
        # Implementation for high error rate detection
        return []
    
    def _get_recommendation_for_error_rate(self, error_code: str, rate: float) -> str:
        """Get specific recommendation for high error rate."""
        # Implementation for specific recommendations
        return f"Investigate and address root cause of high error rate for {error_code}"
    
    def _identify_recovery_improvements(self) -> List[Dict[str, Any]]:
        """Identify potential recovery improvements."""
        # Implementation for recovery improvement suggestions
        return []
    
    def _get_detailed_errors(self, time_range_hours: int) -> List[Dict[str, Any]]:
        """Get detailed error information for specified time range."""
        # Implementation for detailed error retrieval
        return []
```

---

## Testing Strategy

### Error Injection Testing

```python
class ErrorInjection:
    """Inject errors for testing error handling."""
    
    def __init__(self):
        self.injection_points = {
            "file_system": self._inject_file_system_error,
            "memory": self._inject_memory_error,
            "network": self._inject_network_error,
            "timeout": self._inject_timeout_error,
            "detector": self._inject_detector_error
        }
    
    def inject_error(self, error_type: str, **kwargs) -> None:
        """Inject specific type of error."""
        if error_type not in self.injection_points:
            raise ValueError(f"Unknown error type: {error_type}")
        
        self.injection_points[error_type](**kwargs)
    
    def _inject_file_system_error(self, error_subtype: str = "permission_denied"):
        """Inject file system error."""
        if error_subtype == "permission_denied":
            # Temporarily modify file permissions
            pass
        elif error_subtype == "file_not_found":
            # Create scenario where file doesn't exist
            pass
        elif error_subtype == "disk_full":
            # Simulate disk full condition
            pass
    
    def _inject_memory_error(self, memory_limit_mb: int = 100):
        """Inject memory error."""
        # Allocate large amount of memory to trigger memory errors
        large_data = bytearray(memory_limit_mb * 1024 * 1024)
        return large_data
    
    def _inject_network_error(self, timeout_seconds: int = 1):
        """Inject network error."""
        # Simulate network timeout
        time.sleep(timeout_seconds)
        raise TimeoutError("Simulated network timeout")
    
    def _inject_timeout_error(self, operation_delay: int = 5):
        """Inject timeout error."""
        # Delay operation to trigger timeout
        time.sleep(operation_delay)
    
    def _inject_detector_error(self, detector_name: str = "test_detector"):
        """Inject detector error."""
        # Cause detector to fail
        raise DetectorError(f"Simulated error in {detector_name}", detector_name=detector_name)

# Test scenarios
class ErrorHandlingTestScenarios:
    """Test scenarios for error handling."""
    
    @staticmethod
    async def test_retry_mechanism():
        """Test retry mechanism with injected failures."""
        error_injection = ErrorInjection()
        
        @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=0.1))
        async def failing_operation():
            # Inject failure on first two attempts
            if not hasattr(failing_operation, 'attempt'):
                failing_operation.attempt = 0
            failing_operation.attempt += 1
            
            if failing_operation.attempt <= 2:
                error_injection.inject_error("timeout", operation_delay=0.1)
            
            return "success"
        
        result = await failing_operation()
        assert result == "success"
    
    @staticmethod
    async def test_circuit_breaker():
        """Test circuit breaker with repeated failures."""
        error_injection = ErrorInjection()
        circuit_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
        
        async def consistently_failing_operation():
            error_injection.inject_error("file_system", error_subtype="file_not_found")
        
        # First few calls should fail but not trigger circuit breaker
        for i in range(2):
            try:
                await circuit_breaker.call(consistently_failing_operation)
                assert False, "Operation should have failed"
            except MCPSentinelError:
                pass
        
        # Next call should trigger circuit breaker
        try:
            await circuit_breaker.call(consistently_failing_operation)
            assert False, "Circuit breaker should be open"
        except MCPSentinelError as e:
            assert e.error_code == "CIRCUIT_BREAKER_OPEN"
    
    @staticmethod
    async def test_graceful_degradation():
        """Test graceful degradation under load."""
        degradation = GracefulDegradation()
        
        # Simulate high load condition
        degradation.set_degradation_level("reduced")
        
        # Test that system continues to operate with reduced functionality
        results = await degradation.execute_with_degradation("scan_operation")
        
        # Verify results are still meaningful but potentially less comprehensive
        assert results is not None
        # Additional assertions for degraded functionality
```

### Error Handling Test Suite

```python
import pytest
from unittest.mock import Mock, patch
from pathlib import Path

class TestErrorHandling:
    """Comprehensive error handling test suite."""
    
    @pytest.fixture
    def auto_recovery(self):
        return AutoRecovery()
    
    @pytest.fixture
    def circuit_breaker(self):
        return CircuitBreaker(failure_threshold=3, recovery_timeout=1)
    
    @pytest.fixture
    def error_metrics(self):
        return ErrorMetrics()
    
    @pytest.mark.asyncio
    async def test_error_classification(self):
        """Test error classification system."""
        error = ConfigurationError("Test error", config_key="test_key")
        
        assert error.context.category == ErrorCategory.CONFIGURATION
        assert error.context.severity == ErrorSeverity.HIGH
        assert error.config_key == "test_key"
    
    @pytest.mark.asyncio
    async def test_retry_with_success(self):
        """Test retry mechanism with eventual success."""
        call_count = 0
        
        @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=0.1))
        async def failing_then_succeeding():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception(f"Failure {call_count}")
            return "success"
        
        result = await failing_then_succeeding()
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_exhaustion(self):
        """Test retry mechanism exhaustion."""
        @retry_with_backoff(RetryConfig(max_attempts=2, base_delay=0.1))
        async def consistently_failing():
            raise Exception("Always fails")
        
        with pytest.raises(Exception, match="Always fails"):
            await consistently_failing()
    
    @pytest.mark.asyncio
    async def test_auto_recovery_success(self, auto_recovery):
        """Test successful auto-recovery."""
        # Mock successful recovery
        with patch.object(auto_recovery, '_fix_permissions', return_value=True):
            permission_error = PermissionDeniedError("Permission denied", file_path="/test/file")
            recovered = await auto_recovery.attempt_recovery(permission_error)
            
            assert recovered is True
    
    @pytest.mark.asyncio
    async def test_auto_recovery_failure(self, auto_recovery):
        """Test failed auto-recovery."""
        # Mock failed recovery
        with patch.object(auto_recovery, '_fix_permissions', return_value=False):
            permission_error = PermissionDeniedError("Permission denied", file_path="/test/file")
            recovered = await auto_recovery.attempt_recovery(permission_error)
            
            assert recovered is False
    
    def test_error_metrics_collection(self, error_metrics):
        """Test error metrics collection."""
        # Record some errors
        config_error = ConfigurationError("Config error", config_key="test")
        scanner_error = ScannerError("Scanner error", file_path="/test/file")
        
        error_metrics.record_error(config_error)
        error_metrics.record_error(scanner_error)
        
        # Verify metrics
        summary = error_metrics.get_metrics_summary()
        assert "error_count" in summary
        assert len(summary["error_count"]) == 2
    
    def test_circuit_breaker_state_transitions(self, circuit_breaker):
        """Test circuit breaker state transitions."""
        # Initially closed
        assert circuit_breaker.state == CircuitState.CLOSED
        
        # Simulate failures
        for i in range(3):
            try:
                raise Exception(f"Failure {i}")
            except Exception as e:
                circuit_breaker._on_failure(e)
        
        # Should be open after threshold
        assert circuit_breaker.state == CircuitState.OPEN
    
    @pytest.mark.asyncio
    async def test_health_check_system(self):
        """Test health check system."""
        health_check = HealthCheck()
        
        # Mock health check components
        with patch.object(health_check, '_check_scanner_health', return_value={"status": "healthy"}):
            with patch.object(health_check, '_check_detector_health', return_value={"status": "healthy"}):
                with patch.object(health_check, '_check_memory_health', return_value={"status": "healthy"}):
                    with patch.object(health_check, '_check_filesystem_health', return_value={"status": "healthy"}):
                        report = await health_check.perform_health_check()
                        
                        assert report["overall_status"] == "healthy"
                        assert "components" in report
```

---

## Best Practices Summary

### Error Handling Guidelines

1. **Always provide context**: Include relevant context information in all errors
2. **Use appropriate severity**: Classify errors correctly for proper handling
3. **Implement graceful degradation**: Continue operation with reduced functionality when possible
4. **Log structured error data**: Use structured logging for error analysis
5. **Monitor error metrics**: Track error rates, recovery success, and trends
6. **Test error scenarios**: Include error injection in testing strategy
7. **Document error handling**: Clearly document error handling behavior

### Recovery Strategy Selection

| Error Type | Primary Strategy | Fallback Strategy | Circuit Breaker |
|------------|------------------|-------------------|-----------------|
| **Transient Network** | Retry with backoff | Alternative endpoint | Yes |
| **File System** | Auto-recovery | Graceful degradation | Yes |
| **Memory** | Resource cleanup | Reduced functionality | Yes |
| **Configuration** | Validation + defaults | Safe defaults | No |
| **Validation** | Input correction | User feedback | No |
| **Timeout** | Increase timeout | Partial results | Yes |

### Monitoring and Alerting

- **High error rates**: Alert when error rate exceeds threshold
- **Circuit breaker trips**: Alert when circuit breakers open
- **Recovery failures**: Alert when auto-recovery fails repeatedly
- **Performance degradation**: Alert when error handling impacts performance
- **Error trends**: Monitor for increasing error trends

---

## Related Documents

- [SYSTEM_DESIGN_SPECIFICATION.md](./SYSTEM_DESIGN_SPECIFICATION.md) - System architecture and design patterns
- [PERFORMANCE_REQUIREMENTS.md](./PERFORMANCE_REQUIREMENTS.md) - Performance requirements and error impact
- [API_DESIGN_SPECIFICATION.md](./API_DESIGN_SPECIFICATION.md) - API error handling specifications
- [TEST_STRATEGY.md](./TEST_STRATEGY.md) - Testing strategy including error scenario testing

---

*This error handling strategy should be reviewed and updated regularly based on operational experience and error analysis.*

**Document Version**: 1.0  
**Last Updated**: January 2026  
## Circuit Breaker Implementation

### Circuit Breaker State Machine

```python
from enum import Enum
import asyncio
from typing import Callable, Any, Optional
import time

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing fast
    HALF_OPEN = "half_open" # Testing recovery

class CircuitBreaker:
    """Circuit breaker implementation for fault tolerance."""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 expected_exception: type = Exception,
                 name: str = "default"):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.name = name
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
        self.error_frequency = ErrorFrequency()
        
        # Metrics
        self.success_count = 0
        self.total_calls = 0
        
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Call function with circuit breaker protection."""
        self.total_calls += 1
        
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info(f"Circuit breaker '{self.name}' moving to HALF_OPEN state")
            else:
                raise MCPSentinelError(
                    f"Circuit breaker '{self.name}' is OPEN",
                    error_code="CIRCUIT_BREAKER_OPEN",
                    context=ErrorContext(
                        category=ErrorCategory.NETWORK,
                        severity=ErrorSeverity.HIGH,
                        component="CircuitBreaker",
                        operation="protected_call"
                    )
                )
        
        try:
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Success handling
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure(e)
            
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' reopened due to failure")
            
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        
        return (time.time() - self.last_failure_time) >= self.recovery_timeout
    
    def _on_success(self) -> None:
        """Handle successful call."""
        self.success_count += 1
        
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            logger.info(f"Circuit breaker '{self.name}' reset to CLOSED state")
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success in closed state
            if self.failure_count > 0:
                self.failure_count = max(0, self.failure_count - 1)
    
    def _on_failure(self, exception: Exception) -> None:
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.CLOSED and self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.error(f"Circuit breaker '{self.name}' opened after {self.failure_count} failures")
        
        # Track error frequency
        error_code = getattr(exception, 'error_code', 'UNKNOWN_ERROR')
        self.error_frequency.record_error(error_code)
    
    def get_metrics(self) -> dict:
        """Get circuit breaker metrics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_calls": self.total_calls,
            "failure_rate": self.failure_count / max(1, self.total_calls),
            "last_failure_time": self.last_failure_time
        }

# Circuit breaker manager for multiple breakers
class CircuitBreakerManager:
    """Manages multiple circuit breakers."""
    
    def __init__(self):
        self.breakers: dict[str, CircuitBreaker] = {}
    
    def get_breaker(self, name: str, **config) -> CircuitBreaker:
        """Get or create circuit breaker."""
        if name not in self.breakers:
            self.breakers[name] = CircuitBreaker(name=name, **config)
        return self.breakers[name]
    
    def get_all_metrics(self) -> dict:
        """Get metrics for all circuit breakers."""
        return {name: breaker.get_metrics() for name, breaker in self.breakers.items()}
    
    def reset_breaker(self, name: str) -> bool:
        """Reset specific circuit breaker."""
        if name in self.breakers:
            breaker = self.breakers[name]
            breaker.state = CircuitState.CLOSED
            breaker.failure_count = 0
            breaker.success_count = 0
            return True
        return False
```

## Logging and Monitoring

### Structured Logging

```python
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import traceback

class StructuredLogger:
    """Structured logging for error tracking and analysis."""
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # JSON formatter for structured logs
        formatter = logging.Formatter('%(message)s')
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def _format_log_entry(self, 
                         level: str,
                         message: str,
                         error_context: Optional[ErrorContext] = None,
                         extra_data: Optional[Dict[str, Any]] = None) -> str:
        """Format log entry as JSON."""
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "component": "mcp-sentinel",
            "correlation_id": error_context.correlation_id if error_context else None
        }
        
        if error_context:
            log_entry.update({
                "error_category": error_context.category.value,
                "error_severity": error_context.severity.value,
                "component": error_context.component,
                "operation": error_context.operation,
                "file_path": error_context.file_path
            })
        
        if extra_data:
            log_entry["extra"] = extra_data
        
        return json.dumps(log_entry)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        log_entry = self._format_log_entry("INFO", message, **kwargs)
        self.logger.info(log_entry)
    
    def warning(self, message: str, error_context: Optional[ErrorContext] = None, **kwargs):
        """Log warning message."""
        log_entry = self._format_log_entry("WARNING", message, error_context, **kwargs)
        self.logger.warning(log_entry)
    
    def error(self, error: MCPSentinelError, **kwargs):
        """Log error with full context."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "ERROR",
            "message": str(error),
            "error_code": error.error_code,
            "error_type": error.__class__.__name__,
            "correlation_id": error.context.correlation_id if error.context else None,
            "stack_trace": traceback.format_exc(),
            "context": error.context.__dict__ if error.context else None
        }
        
        if kwargs:
            log_entry.update(kwargs)
        
        self.logger.error(json.dumps(log_entry))
    
    def critical(self, error: MCPSentinelError, **kwargs):
        """Log critical error."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": "CRITICAL",
            "message": str(error),
            "error_code": error.error_code,
            "error_type": error.__class__.__name__,
            "correlation_id": error.context.correlation_id if error.context else None,
            "stack_trace": traceback.format_exc(),
            "context": error.context.__dict__ if error.context else None,
            "requires_immediate_attention": True
        }
        
        if kwargs:
            log_entry.update(kwargs)
        
        self.logger.critical(json.dumps(log_entry))

# Global logger instance
logger = StructuredLogger("mcp-sentinel")
```

### Error Metrics Collection

```python
from collections import defaultdict, deque
import threading
import time

class ErrorMetrics:
    """Collect and track error metrics."""
    
    def __init__(self, window_size: int = 3600):  # 1 hour window
        self.window_size = window_size
        self.error_counts = defaultdict(int)
        self.error_timestamps = defaultdict(lambda: deque(maxlen=window_size))
        self.category_counts = defaultdict(int)
        self.severity_counts = defaultdict(int)
        self._lock = threading.Lock()
    
    def record_error(self, error: MCPSentinelError) -> None:
        """Record error occurrence."""
        with self._lock:
            timestamp = time.time()
            
            # Record by error code
            self.error_counts[error.error_code] += 1
            self.error_timestamps[error.error_code].append(timestamp)
            
            # Record by category and severity
            if error.context:
                self.category_counts[error.context.category.value] += 1
                self.severity_counts[error.context.severity.value] += 1
    
    def get_error_rate(self, error_code: str, time_window: int = 300) -> float:
        """Get error rate for specific error code in time window (seconds)."""
        with self._lock:
            current_time = time.time()
            cutoff_time = current_time - time_window
            
            timestamps = self.error_timestamps[error_code]
            recent_errors = sum(1 for ts in timestamps if ts >= cutoff_time)
            
            return recent_errors / time_window
    
    def get_summary(self) -> dict:
        """Get error summary statistics."""
        with self._lock:
            total_errors = sum(self.error_counts.values())
            
            return {
                "total_errors": total_errors,
                "error_codes": dict(self.error_counts),
                "categories": dict(self.category_counts),
                "severities": dict(self.severity_counts),
                "top_errors": sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            }
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        with self._lock:
            self.error_counts.clear()
            self.error_timestamps.clear()
            self.category_counts.clear()
            self.severity_counts.clear()

# Global error metrics instance
error_metrics = ErrorMetrics()
```

## Error Reporting

### Error Report Generation

```python
from datetime import datetime, timedelta
import json

class ErrorReportGenerator:
    """Generate comprehensive error reports."""
    
    def __init__(self, error_metrics: ErrorMetrics):
        self.error_metrics = error_metrics
    
    def generate_daily_report(self, date: datetime) -> dict:
        """Generate daily error report."""
        
        # Calculate time range
        start_time = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(days=1)
        
        # Get error summary
        summary = self.error_metrics.get_summary()
        
        # Generate report
        report = {
            "report_type": "daily",
            "date": date.isoformat(),
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "recommendations": self._generate_recommendations(summary),
            "trends": self._analyze_trends(summary)
        }
        
        return report
    
    def generate_incident_report(self, incident_id: str, errors: list[MCPSentinelError]) -> dict:
        """Generate incident-specific error report."""
        
        # Analyze incident
        error_analysis = self._analyze_incident(errors)
        
        report = {
            "report_type": "incident",
            "incident_id": incident_id,
            "generated_at": datetime.now().isoformat(),
            "duration": self._calculate_incident_duration(errors),
            "affected_components": error_analysis["affected_components"],
            "root_cause_analysis": error_analysis["root_cause"],
            "impact_assessment": error_analysis["impact"],
            "resolution_steps": error_analysis["resolution"],
            "prevention_measures": error_analysis["prevention"]
        }
        
        return report
    
    def _generate_recommendations(self, summary: dict) -> list[str]:
        """Generate recommendations based on error patterns."""
        recommendations = []
        
        # High error rate recommendations
        if summary["total_errors"] > 100:
            recommendations.append("High error volume detected. Consider implementing additional error handling measures.")
        
        # Category-specific recommendations
        if summary["categories"].get("memory", 0) > 10:
            recommendations.append("Memory errors detected. Review memory usage patterns and consider optimization.")
        
        if summary["categories"].get("timeout", 0) > 5:
            recommendations.append("Timeout errors detected. Review timeout configurations and system performance.")
        
        if summary["categories"].get("file_system", 0) > 20:
            recommendations.append("File system errors detected. Check file permissions and disk space.")
        
        return recommendations
    
    def _analyze_trends(self, summary: dict) -> dict:
        """Analyze error trends."""
        return {
            "error_volume_trend": "increasing" if summary["total_errors"] > 50 else "stable",
            "severity_trend": "concerning" if summary["severities"].get("critical", 0) > 0 else "acceptable",
            "category_distribution": summary["categories"]
        }
    
    def _analyze_incident(self, errors: list[MCPSentinelError]) -> dict:
        """Analyze incident errors."""
        # Implementation for incident analysis
        return {
            "affected_components": list(set(error.context.component for error in errors if error.context)),
            "root_cause": "Multiple component failures detected",
            "impact": f"{len(errors)} errors occurred during incident",
            "resolution": "Review error patterns and implement targeted fixes",
            "prevention": "Implement additional monitoring and alerting"
        }
    
    def _calculate_incident_duration(self, errors: list[MCPSentinelError]) -> str:
        """Calculate incident duration."""
        if not errors:
            return "0 minutes"
        
        timestamps = [error.timestamp for error in errors]
        duration = max(timestamps) - min(timestamps)
        minutes = duration.total_seconds() / 60
        
        return f"{minutes:.1f} minutes"

# Usage example
report_generator = ErrorReportGenerator(error_metrics)
daily_report = report_generator.generate_daily_report(datetime.now())
```

## Testing Strategy

### Error Injection Testing

```python
import pytest
from unittest.mock import Mock, patch
import asyncio

class TestErrorHandling:
    """Test error handling mechanisms."""
    
    @pytest.fixture
    def circuit_breaker(self):
        return CircuitBreaker(failure_threshold=3, recovery_timeout=1)
    
    @pytest.fixture
    def mock_error(self):
        return MCPSentinelError("Test error", error_code="TEST_ERROR")
    
    async def test_circuit_breaker_opens_after_threshold(self, circuit_breaker):
        """Test that circuit breaker opens after failure threshold."""
        
        # Create failing function
        async def failing_func():
            raise Exception("Simulated failure")
        
        # Trigger failures up to threshold
        for i in range(3):
            with pytest.raises(Exception):
                await circuit_breaker.call(failing_func)
        
        # Circuit should be open now
        assert circuit_breaker.state == CircuitState.OPEN
        
        # Next call should fail immediately
        with pytest.raises(MCPSentinelError) as exc_info:
            await circuit_breaker.call(failing_func)
        
        assert "CIRCUIT_BREAKER_OPEN" in str(exc_info.value)
    
    async def test_retry_with_backoff_success(self):
        """Test retry with exponential backoff success."""
        
        call_count = 0
        
        @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=0.1))
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "success"
        
        result = await flaky_function()
        assert result == "success"
        assert call_count == 3
    
    async def test_error_metrics_recording(self, mock_error):
        """Test error metrics recording."""
        
        metrics = ErrorMetrics()
        
        # Record multiple errors
        for i in range(5):
            metrics.record_error(mock_error)
        
        summary = metrics.get_summary()
        assert summary["total_errors"] == 5
        assert summary["error_codes"]["TEST_ERROR"] == 5
    
    async def test_auto_recovery_attempt(self):
        """Test automatic recovery attempts."""
        
        auto_recovery = AutoRecovery()
        
        # Test file system error recovery
        file_error = PermissionDeniedError("Permission denied", file_path="/test/file")
        
        # Mock the recovery method
        with patch.object(auto_recovery, '_fix_permissions', return_value=True):
            result = await auto_recovery.attempt_recovery(file_error)
            assert result is True
    
    async def test_graceful_degradation(self):
        """Test graceful degradation functionality."""
        
        degradation = GracefulDegradation()
        
        # Test degradation level changes
        degradation.set_degradation_level("reduced")
        assert degradation.current_level == "reduced"
        
        # Test functionality reduction
        # This would test actual functionality reduction in real implementation
        assert degradation.degradation_levels["reduced"] is not None
    
    async def test_structured_logging(self, mock_error):
        """Test structured logging format."""
        
        logger = StructuredLogger("test")
        
        # Test error logging
        with patch.object(logger.logger, 'error') as mock_log:
            logger.error(mock_error, extra_data={"test": "data"})
            
            # Verify JSON structure
            log_call = mock_log.call_args[0][0]
            log_data = json.loads(log_call)
            
            assert log_data["level"] == "ERROR"
            assert log_data["error_code"] == "TEST_ERROR"
            assert log_data["extra"]["test"] == "data"
    
    @pytest.mark.parametrize("error_category,expected_recovery", [
        (ErrorCategory.FILE_SYSTEM, True),
        (ErrorCategory.MEMORY, True),
        (ErrorCategory.TIMEOUT, True),
        (ErrorCategory.NETWORK, True),
        (ErrorCategory.UNKNOWN, False)
    ])
    async def test_recovery_by_category(self, error_category, expected_recovery):
        """Test recovery strategies by error category."""
        
        auto_recovery = AutoRecovery()
        
        # Create error with specific category
        error = MCPSentinelError("Test error")
        error.context = ErrorContext(
            category=error_category,
            severity=ErrorSeverity.MEDIUM,
            component="TestComponent",
            operation="test_operation"
        )
        
        # Mock recovery methods
        with patch.object(auto_recovery, '_recover_file_system_error', return_value=True), \
             patch.object(auto_recovery, '_recover_memory_error', return_value=True), \
             patch.object(auto_recovery, '_recover_timeout_error', return_value=True), \
             patch.object(auto_recovery, '_recover_network_error', return_value=True):
            
            result = await auto_recovery.attempt_recovery(error)
            assert result == expected_recovery

# Integration test for complete error handling flow
@pytest.mark.integration
async def test_complete_error_handling_flow():
    """Test complete error handling flow from detection to recovery."""
    
    # This would be a comprehensive integration test
    # covering error detection, classification, handling, and recovery
    pass
```

### Performance Testing for Error Handling

```python
import time
import asyncio
from typing import List

class ErrorHandlingPerformanceTests:
    """Performance tests for error handling mechanisms."""
    
    async def test_circuit_breaker_performance(self):
        """Test circuit breaker performance under load."""
        
        breaker = CircuitBreaker(failure_threshold=10)
        
        async def successful_operation():
            await asyncio.sleep(0.001)  # Simulate work
            return "success"
        
        async def failing_operation():
            await asyncio.sleep(0.001)
            raise Exception("Simulated failure")
        
        # Measure performance with successful operations
        start_time = time.time()
        tasks = [breaker.call(successful_operation) for _ in range(1000)]
        await asyncio.gather(*tasks)
        success_time = time.time() - start_time
        
        # Measure performance with failing operations
        start_time = time.time()
        tasks = []
        for i in range(100):
            try:
                await breaker.call(failing_operation)
            except:
                pass
        fail_time = time.time() - start_time
        
        # Circuit breaker should add minimal overhead
        assert success_time < 2.0  # Should complete 1000 calls in under 2 seconds
        assert fail_time < 1.0     # Should handle failures quickly
    
    async def test_retry_performance(self):
        """Test retry mechanism performance."""
        
        @retry_with_backoff(RetryConfig(max_attempts=5, base_delay=0.01))
        async def operation_with_retry():
            return "success"
        
        # Measure performance of retry operations
        start_time = time.time()
        tasks = [operation_with_retry() for _ in range(500)]
        await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # Should complete quickly despite retry logic
        assert total_time < 1.0
    
    async def test_error_metrics_performance(self):
        """Test error metrics collection performance."""
        
        metrics = ErrorMetrics()
        
        # Create many errors quickly
        start_time = time.time()
        for i in range(10000):
            error = MCPSentinelError(f"Error {i}", error_code=f"ERROR_{i % 100}")
            metrics.record_error(error)
        
        # Get summary should be fast
        summary_start = time.time()
        summary = metrics.get_summary()
        summary_time = time.time() - summary_start
        
        total_time = time.time() - start_time
        
        # Metrics operations should be efficient
        assert summary_time < 0.1  # Summary should be instant
        assert total_time < 2.0    # Recording 10k errors should be fast
```

---

## Summary

This comprehensive error handling strategy provides:

1. **Robust Error Classification**: Systematic categorization of errors by type and severity
2. **Advanced Recovery Mechanisms**: Automatic recovery for common error scenarios
3. **Circuit Breaker Protection**: Prevents cascade failures and system overload
4. **Comprehensive Monitoring**: Structured logging and metrics collection
5. **Performance Optimization**: Efficient error handling that doesn't impact performance
6. **Testing Framework**: Complete testing strategy for error handling components

The strategy ensures that the MCP Sentinel Python application can handle errors gracefully, maintain system stability, and provide valuable debugging information for developers and operators.

**Status**: Review Ready