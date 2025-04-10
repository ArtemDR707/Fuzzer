"""
Common Utilities for Intelligent Fuzzing

This module provides common utility functions and constants used
throughout the intelligent fuzzing tool.
"""

import os
import re
import random
import string
import tempfile
import subprocess
import logging
import json
import time
from pathlib import Path

# Get logger
logger = logging.getLogger(__name__)

# Constants
SUPPORTED_FORMATS = ['json', 'xml', 'command', 'binary']
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_ITERATIONS = 100
DEFAULT_CORPUS_SIZE = 20
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
DEFAULT_LOG_LEVEL = logging.INFO

# File path constants
DEFAULT_RESULTS_DIR = 'results'
DEFAULT_CORPUS_DIR = 'corpus'
DEFAULT_CRASH_DIR = 'crashes'
DEFAULT_LOG_DIR = 'logs'

def ensure_dir(directory):
    """Ensure a directory exists."""
    os.makedirs(directory, exist_ok=True)
    return directory

def timestamp_str(format_str="%Y%m%d-%H%M%S"):
    """Get a timestamp string."""
    return time.strftime(format_str)

def random_string(length=10, charset=None):
    """Generate a random string."""
    if charset is None:
        charset = string.ascii_letters + string.digits
    return ''.join(random.choice(charset) for _ in range(length))

def create_temp_file(content, suffix=None):
    """Create a temporary file with the given content."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    if isinstance(content, str):
        temp_file.write(content.encode('utf-8'))
    else:
        temp_file.write(content)
    temp_file.close()
    return temp_file.name

def run_command(command, input_data=None, timeout=DEFAULT_TIMEOUT):
    """Run a command and return its output."""
    if isinstance(command, str):
        command = command.split()
    
    logger.debug(f"Running command: {' '.join(command)}")
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_data else None,
            text=True
        )
        
        stdout, stderr = process.communicate(
            input=input_data if isinstance(input_data, str) else None,
            timeout=timeout
        )
        
        return {
            'returncode': process.returncode,
            'stdout': stdout,
            'stderr': stderr,
            'command': command
        }
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        logger.warning(f"Command timed out after {timeout} seconds")
        return {
            'returncode': -1,
            'stdout': stdout,
            'stderr': stderr,
            'command': command,
            'timeout': True
        }
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': str(e),
            'command': command,
            'error': str(e)
        }

def load_json_file(file_path):
    """Load a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON file {file_path}: {e}")
        return {}

def save_json_file(data, file_path, indent=2):
    """Save data to a JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=indent)
        return True
    except Exception as e:
        logger.error(f"Error saving JSON file {file_path}: {e}")
        return False

def is_binary_file(file_path):
    """Check if a file is binary."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            f.read(1024)
        return False
    except UnicodeDecodeError:
        return True

def find_executables(directory, recursive=True):
    """Find executable files in a directory."""
    executables = []
    
    for root, _, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            
            # Check if file is executable
            if os.access(file_path, os.X_OK) and not is_binary_file(file_path):
                executables.append(file_path)
        
        if not recursive:
            break
    
    return executables

def file_signature(file_path):
    """Get the signature of a file."""
    try:
        with open(file_path, 'rb') as f:
            # Read first 8 bytes
            header = f.read(8)
            
            # Convert to hex
            return ''.join(f'{b:02x}' for b in header)
    except Exception as e:
        logger.error(f"Error reading file signature: {e}")
        return None

def detect_file_type(file_path):
    """Detect the type of a file based on its signature."""
    sig = file_signature(file_path)
    if not sig:
        return None
    
    # Check for common file signatures
    if sig.startswith('7f454c46'):
        return 'elf'  # ELF executable
    elif sig.startswith('4d5a'):
        return 'pe'   # Windows PE executable
    elif sig.startswith('ffd8ff'):
        return 'jpeg'  # JPEG image
    elif sig.startswith('89504e47'):
        return 'png'   # PNG image
    elif sig.startswith('504b'):
        return 'zip'   # ZIP archive
    elif sig.startswith('25504446'):
        return 'pdf'   # PDF document
    
    # Try to detect text-based formats
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(1024)
            
            if content.strip().startswith('{') and content.strip().endswith('}'):
                return 'json'
            elif content.strip().startswith('<') and content.strip().endswith('>'):
                return 'xml'
            elif re.match(r'^[a-zA-Z0-9_\-\.]+\s+(-[a-zA-Z]+|--[a-zA-Z0-9\-]+)', content):
                return 'command'
            else:
                return 'text'
    except UnicodeDecodeError:
        return 'binary'

def parse_size_string(size_str):
    """Parse a size string (e.g., '10M', '1G') into bytes."""
    match = re.match(r'^(\d+)([KkMmGg])?$', size_str)
    if not match:
        raise ValueError(f"Invalid size string: {size_str}")
    
    value, unit = match.groups()
    value = int(value)
    
    if unit:
        unit = unit.upper()
        if unit == 'K':
            value *= 1024
        elif unit == 'M':
            value *= 1024 * 1024
        elif unit == 'G':
            value *= 1024 * 1024 * 1024
    
    return value