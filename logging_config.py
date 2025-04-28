import logging
import logging.handlers
import json
import os
import colorlog # Added for colored console output
from datetime import datetime

# Ensure logs directory exists
LOG_DIR = 'logs'
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, 'wifi_portal.log')

class JsonFormatter(logging.Formatter):
    """Formats log records as JSON strings."""
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "pathname": record.pathname,
            "lineno": record.lineno,
            "funcName": record.funcName,
        }
        # Add exception info if available
        if record.exc_info:
            # Ensure exc_info is formatted correctly, handling potential NoneType
            log_record['exc_info'] = self.formatException(record.exc_info) if record.exc_info else None
        if record.stack_info:
            log_record['stack_info'] = self.formatStack(record.stack_info)

        # Add extra fields if they exist (e.g., request_id, source_ip)
        standard_keys = {'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename', 'module',
                         'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName', 'created', 'msecs',
                         'relativeCreated', 'thread', 'threadName', 'processName', 'process', 'message', 'asctime'}
        extra_keys = set(record.__dict__.keys()) - standard_keys
        for key in extra_keys:
             if key not in log_record: # Avoid overwriting standard fields if misused
                log_record[key] = record.__dict__[key]


        return json.dumps(log_record, default=str) # Use default=str to handle non-serializable types

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False, # Keep Flask/Werkzeug loggers, but configure them
    "formatters": {
        "json": {
            "()": JsonFormatter,
        },
        "simple": { # Kept for potential future use or fallback
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "colored_console": { # Formatter using colorlog, only coloring INFO level name
            "()": "colorlog.ColoredFormatter",
            # Apply color only around the levelname
            "format": "%(asctime)s - %(name)s - %(log_color)s%(levelname)-8s%(reset)s %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "log_colors": {
                'DEBUG':    'reset', # Use default terminal color
                'INFO':     'green', # Color INFO level green
                'WARNING':  'reset', # Use default terminal color
                'ERROR':    'reset', # Use default terminal color
                'CRITICAL': 'reset', # Use default terminal color
            },
            "secondary_log_colors": {},
            "style": "%"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "colored_console", # Use the modified colored formatter
            "stream": "ext://sys.stdout",
        },
        "file_json": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "json",
            "filename": LOG_FILE,
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8",
        },
        # Placeholder for future centralized logging
        # "central_http": {
        #     "class": "logging.handlers.HTTPHandler",
        #     "level": "INFO",
        #     "host": "your-log-collector.example.com",
        #     "url": "/log-endpoint",
        #     "method": "POST",
        # },
    },
    "loggers": {
        "wifi_portal": { # Main application logger
            "level": "DEBUG",
            "handlers": ["console", "file_json"],
            "propagate": False, # Don't propagate to root logger if handlers are defined
        },
        "werkzeug": { # Flask's internal request/response logger
            "level": "INFO", # Keep Werkzeug logs less verbose unless debugging Flask itself
            "handlers": ["console", "file_json"], # Apply handlers to Werkzeug too
            "propagate": False,
        },
         "dns_spoofer": { # DNS spoofer logger
            "level": "DEBUG",
            "handlers": ["console", "file_json"],
            "propagate": False,
        },
         "credential_decoder": { # Credential decoder logger
            "level": "DEBUG",
            "handlers": ["console", "file_json"],
            "propagate": False,
        },
    },
    "root": { # Catch-all for other libraries if needed
        "level": "WARNING",
        "handlers": ["console", "file_json"],
    },
}