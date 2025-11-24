"""
Logging configuration for Domain ASN Mapper.

This module provides structured logging with file rotation,
JSON formatting, and integration with the configuration system.
"""

import logging
import logging.handlers
import json
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs log records as JSON for easy parsing by log aggregation systems.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON-formatted log string
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, 'domain'):
            log_data['domain'] = record.domain
        if hasattr(record, 'job_id'):
            log_data['job_id'] = record.job_id
        if hasattr(record, 'duration'):
            log_data['duration'] = record.duration

        return json.dumps(log_data)


def setup_logging(
    level: str = 'INFO',
    log_file: Optional[str] = None,
    json_format: bool = False,
    max_bytes: int = 10485760,  # 10MB
    backup_count: int = 5
) -> None:
    """
    Set up logging configuration for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (None for console only)
        json_format: Use JSON formatter for structured logs
        max_bytes: Maximum size of log file before rotation
        backup_count: Number of backup files to keep

    Example:
        >>> setup_logging('DEBUG', '/var/log/mapper.log', json_format=True)
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Choose formatter
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    # Console handler (always add)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if log_file specified)
    if log_file:
        # Create log directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        root_logger.info(f"Logging to file: {log_file}")
        root_logger.info(f"Log rotation: {max_bytes} bytes, {backup_count} backups")


def setup_logging_from_config(config: 'Config') -> None:
    """
    Set up logging from configuration object.

    Args:
        config: Configuration instance

    Example:
        >>> from core import get_config
        >>> config = get_config()
        >>> setup_logging_from_config(config)
    """
    logging_config = config.get_section('logging')

    setup_logging(
        level=logging_config.get('level', 'INFO'),
        log_file=logging_config.get('file'),
        json_format=logging_config.get('json_format', False),
        max_bytes=logging_config.get('max_bytes', 10485760),
        backup_count=logging_config.get('backup_count', 5)
    )


class LogContext:
    """
    Context manager for adding extra context to log messages.

    Example:
        >>> with LogContext(domain='example.com', job_id='123'):
        >>>     logger.info("Processing domain")
        # Logs will include domain and job_id fields
    """

    def __init__(self, **kwargs):
        """
        Initialize log context.

        Args:
            **kwargs: Context fields to add to log records
        """
        self.context = kwargs
        self.old_factory = None

    def __enter__(self):
        """Enter context and modify log record factory."""
        self.old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record

        logging.setLogRecordFactory(record_factory)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original log record factory."""
        if self.old_factory:
            logging.setLogRecordFactory(self.old_factory)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Application started")
    """
    return logging.getLogger(name)
