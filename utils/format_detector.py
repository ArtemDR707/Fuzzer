"""
Format Detector for Intelligent Fuzzing

This module identifies the format of input files to help
select appropriate fuzzing strategies.
"""

import os
import re
import json
import logging
import magic  # python-magic for file type detection
import xml.etree.ElementTree as ET
from enum import Enum, auto

# Get logger
logger = logging.getLogger(__name__)

class InputFormat(Enum):
    """Enum for supported input formats."""
    UNKNOWN = auto()
    TEXT = auto()
    JSON = auto()
    XML = auto()
    BINARY = auto()
    COMMAND = auto()
    # Specific binary formats
    ELF = auto()
    PE = auto()
    ZIP = auto()
    PDF = auto()
    NETWORK_PROTOCOL = auto()
    IMAGE = auto()

class FormatDetector:
    """Detects format of input files."""
    
    def __init__(self):
        """Initialize the format detector."""
        self.magic = magic.Magic(mime=True)
        self.format_stats = {format_type: 0 for format_type in InputFormat}
    
    def detect_format(self, file_path):
        """
        Detect the format of the given file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            InputFormat: Detected format
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return InputFormat.UNKNOWN
        
        # Get file size
        file_size = os.path.getsize(file_path)
        logger.debug(f"Analyzing file: {file_path} ({file_size} bytes)")
        
        # Use magic to get MIME type
        try:
            mime_type = self.magic.from_file(file_path)
            logger.debug(f"MIME type: {mime_type}")
        except Exception as e:
            logger.error(f"Error getting MIME type: {e}")
            mime_type = "application/octet-stream"
        
        # Read a sample of the file
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(min(file_size, 8192))  # Read up to 8KB
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return InputFormat.UNKNOWN
        
        # Try to interpret as text
        try:
            text_sample = sample.decode('utf-8', errors='ignore')
        except Exception:
            text_sample = None
        
        # Detect format based on content and MIME type
        detected_format = self._analyze_content(sample, text_sample, mime_type, file_path)
        
        # Update statistics
        self.format_stats[detected_format] += 1
        
        return detected_format
    
    def _analyze_content(self, binary_sample, text_sample, mime_type, file_path):
        """
        Analyze file content to determine format.
        
        Args:
            binary_sample: Binary data from file
            text_sample: Text data from file (if decodable)
            mime_type: MIME type from magic
            file_path: Path to the file
            
        Returns:
            InputFormat: Detected format
        """
        # Check for binary formats based on MIME type
        if 'application/x-executable' in mime_type or 'application/x-elf' in mime_type:
            return InputFormat.ELF
        
        if 'application/x-dosexec' in mime_type or 'application/x-msdownload' in mime_type:
            return InputFormat.PE
        
        if 'application/zip' in mime_type or 'application/x-zip' in mime_type:
            return InputFormat.ZIP
        
        if 'application/pdf' in mime_type:
            return InputFormat.PDF
        
        if 'image/' in mime_type:
            return InputFormat.IMAGE
        
        # Check for text formats if we have text content
        if text_sample:
            # Check for JSON
            if self._is_json(text_sample):
                return InputFormat.JSON
            
            # Check for XML
            if self._is_xml(text_sample):
                return InputFormat.XML
            
            # Check for command line input
            if self._is_command_line(text_sample):
                return InputFormat.COMMAND
            
            # If none of the specific formats matched but it's text
            if 'text/' in mime_type or mime_type == 'application/json' or mime_type == 'application/xml':
                return InputFormat.TEXT
        
        # If nothing else matched, assume it's binary
        return InputFormat.BINARY
    
    def _is_json(self, text_sample):
        """Check if text appears to be JSON."""
        # Simple heuristic: JSON starts with { or [ and ends with } or ]
        text_sample = text_sample.strip()
        
        if (text_sample.startswith('{') and text_sample.endswith('}')) or \
           (text_sample.startswith('[') and text_sample.endswith(']')):
            # Try to parse it to be sure
            try:
                json.loads(text_sample)
                return True
            except json.JSONDecodeError:
                # It's JSON-like but not valid JSON
                pass
        
        return False
    
    def _is_xml(self, text_sample):
        """Check if text appears to be XML."""
        # Look for XML declaration or tags
        if text_sample.strip().startswith('<?xml') or re.search(r'<[^>]+>[^<]*</[^>]+>', text_sample):
            # Try to parse it to be sure
            try:
                ET.fromstring(text_sample)
                return True
            except ET.ParseError:
                # It's XML-like but not valid XML
                pass
        
        return False
    
    def _is_command_line(self, text_sample):
        """Check if text appears to be command-line input."""
        # Command lines often have programs followed by options
        text_sample = text_sample.strip()
        
        # Look for command-line patterns like: program -opt --long-opt arg
        if re.match(r'^[a-zA-Z0-9_\-\.]+(\s+(-[a-zA-Z]+|--[a-zA-Z0-9\-]+)(\s+\S+)?)+$', text_sample):
            return True
        
        return False
    
    def analyze_directory(self, directory, recursive=False):
        """
        Analyze all files in a directory to determine formats.
        
        Args:
            directory: Directory to analyze
            recursive: Whether to recursively analyze subdirectories
            
        Returns:
            dict: Mapping of file paths to detected formats
        """
        results = {}
        
        if not os.path.isdir(directory):
            logger.error(f"Not a directory: {directory}")
            return results
        
        # Reset statistics
        self.format_stats = {format_type: 0 for format_type in InputFormat}
        
        # Walk through directory
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                results[file_path] = self.detect_format(file_path)
            
            # If not recursive, break after first iteration
            if not recursive:
                break
        
        # Log summary
        logger.info(f"Analyzed {len(results)} files in {directory}")
        for format_type, count in self.format_stats.items():
            if count > 0:
                logger.info(f"  {format_type.name}: {count} files")
        
        return results
    
    def get_format_name(self, format_type):
        """Get the name of a format type."""
        if isinstance(format_type, InputFormat):
            return format_type.name
        return "UNKNOWN"
    
    def suggest_grammar(self, format_type):
        """
        Suggest an appropriate grammar for the detected format.
        
        Args:
            format_type: Detected format
            
        Returns:
            str: Name of the suggested grammar
        """
        format_to_grammar = {
            InputFormat.JSON: 'json',
            InputFormat.XML: 'xml',
            InputFormat.COMMAND: 'command',
            InputFormat.BINARY: 'binary',
            InputFormat.TEXT: 'text',
            InputFormat.ELF: 'binary',
            InputFormat.PE: 'binary',
            InputFormat.ZIP: 'binary',
            InputFormat.PDF: 'binary',
            InputFormat.NETWORK_PROTOCOL: 'network',
            InputFormat.IMAGE: 'binary'
        }
        
        return format_to_grammar.get(format_type, 'generic')