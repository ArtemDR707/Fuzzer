"""
Advanced Logger for Intelligent Fuzzing

This module provides comprehensive logging functionality with
different verbosity levels, log rotation, and colorized output.
"""

import os
import sys
import logging
import logging.handlers
import time
from datetime import datetime

# ANSI color codes for terminal output
COLORS = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'GREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}

# Log levels with custom colors
LOG_COLORS = {
    'DEBUG': COLORS['BLUE'],
    'INFO': COLORS['GREEN'],
    'WARNING': COLORS['WARNING'],
    'ERROR': COLORS['FAIL'],
    'CRITICAL': COLORS['BOLD'] + COLORS['FAIL']
}

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output for terminal."""
    
    def format(self, record):
        levelname = record.levelname
        # Add color codes if the level has a color defined
        if levelname in LOG_COLORS:
            record.levelname = f"{LOG_COLORS[levelname]}{levelname}{COLORS['ENDC']}"
        
        # Special formatting for errors and crashes
        if record.levelno >= logging.ERROR:
            if hasattr(record, 'exc_info') and record.exc_info:
                record.msg = f"{COLORS['BOLD']}{COLORS['FAIL']}[CRASH] {record.msg}{COLORS['ENDC']}"
            else:
                record.msg = f"{COLORS['FAIL']}{record.msg}{COLORS['ENDC']}"
        
        # Special formatting for warnings
        elif record.levelno == logging.WARNING:
            record.msg = f"{COLORS['WARNING']}{record.msg}{COLORS['ENDC']}"
            
        return super().format(record)

def setup_logger(name='fuzzer', log_dir='logs', level=logging.INFO, 
                 console_level=logging.INFO, log_file_level=logging.DEBUG,
                 max_log_size=10*1024*1024, backup_count=5, 
                 timestamp=True, verbose=False):
    """
    Set up a logger with console and file handlers.
    
    Args:
        name: Logger name
        log_dir: Directory to store log files
        level: Overall logging level
        console_level: Console output logging level
        log_file_level: Log file logging level
        max_log_size: Maximum size of each log file in bytes (default: 10MB)
        backup_count: Number of backup log files to keep
        timestamp: Whether to include timestamp in console output
        verbose: Whether to enable verbose output
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create log directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Create timestamp for log filename
    timestamp_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    # Set up file handler with rotation
    log_file = os.path.join(log_dir, f"{name}_{timestamp_str}.log")
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_log_size, backupCount=backup_count
    )
    file_handler.setLevel(log_file_level)
    
    # Detailed formatting for log file
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Set up console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    
    # More concise formatting for console
    if timestamp:
        console_format = '%(asctime)s - %(levelname)s - %(message)s'
    else:
        console_format = '%(levelname)s - %(message)s'
    
    # Use colored formatter for console output
    console_handler.setFormatter(ColoredFormatter(console_format))
    logger.addHandler(console_handler)
    
    # Create a symlink to the latest log file for convenience
    latest_log = os.path.join(log_dir, f"{name}_latest.log")
    try:
        if os.path.exists(latest_log):
            os.remove(latest_log)
        os.symlink(log_file, latest_log)
    except (OSError, AttributeError):
        # Symlinks might not be supported on all platforms
        pass
    
    # Log the start of logging
    logger.info(f"Logging initialized. Log file: {log_file}")
    
    if verbose:
        # Log system information
        import platform
        logger.info(f"System: {platform.system()} {platform.release()} ({platform.version()})")
        logger.info(f"Python: {platform.python_version()}")
        
        # Log available memory
        try:
            import psutil
            memory = psutil.virtual_memory()
            logger.info(f"Memory: {memory.total / (1024**3):.2f}GB total, "
                        f"{memory.available / (1024**3):.2f}GB available "
                        f"({memory.percent}% used)")
        except (ImportError, AttributeError):
            logger.debug("psutil not available, memory information not logged")
    
    return logger

def get_logger(name='fuzzer'):
    """Get an existing logger or create a new one."""
    logger = logging.getLogger(name)
    
    # If logger doesn't have handlers, set it up with defaults
    if not logger.handlers:
        return setup_logger(name)
    
    return logger