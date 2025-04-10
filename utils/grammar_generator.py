"""
Grammar Generator for Intelligent Fuzzing

This module provides functionality to generate structured inputs
based on detected file types and inferred grammar rules.
"""

import os
import re
import logging
import random
import string
import subprocess
import json
import xml.dom.minidom as minidom
import sys
import magic

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import grammars
from grammars import get_json_grammar, get_xml_grammar, get_command_grammar

logger = logging.getLogger("fuzzer.grammar_generator")

class GrammarGenerator:
    """
    Class for generating structured inputs based on grammar rules.
    """
    
    def __init__(self):
        """Initialize the grammar generator."""
        self.json_grammar = get_json_grammar()
        self.xml_grammar = get_xml_grammar()
        self.command_grammar = get_command_grammar()
        self.mime = None
        try:
            self.mime = magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"Failed to initialize python-magic: {e}")
    
    def detect_input_format(self, executable_path):
        """
        Detect the likely input format for an executable.
        
        Args:
            executable_path: Path to the executable to analyze
            
        Returns:
            str: One of 'json', 'xml', 'command', or 'binary'
        """
        file_name = os.path.basename(executable_path).lower()
        
        # Check file extension
        if file_name.endswith('.json'):
            return 'json'
        elif any(file_name.endswith(ext) for ext in ['.xml', '.html', '.xhtml', '.svg']):
            return 'xml'
        
        # Try to infer from file name patterns
        if any(name in file_name for name in ['json', 'mongo', 'rest', 'api']):
            return 'json'
        
        if any(name in file_name for name in ['xml', 'html', 'svg', 'xslt', 'xpath']):
            return 'xml'
        
        if any(name in file_name for name in ['sh', 'bash', 'cmd', 'command', 'term', 'cli', 'exec']):
            return 'command'
        
        # Default: try command-line first, then binary patterns
        return 'command'
    
    def analyze_binary_format(self, executable_path):
        """
        Try to analyze the binary format by examining file and behavior.
        
        Args:
            executable_path: Path to the executable to analyze
            
        Returns:
            dict: Analysis results including detected format
        """
        analysis = {
            'format': 'binary',
            'confidence': 0.5,
            'file_size': os.path.getsize(executable_path) if os.path.exists(executable_path) else 0,
            'mime_type': None,
            'hints': []
        }
        
        # Try to get MIME type
        try:
            if self.mime:
                analysis['mime_type'] = self.mime.from_file(executable_path)
                
                # Adjust format based on MIME type
                if analysis['mime_type']:
                    if 'json' in analysis['mime_type']:
                        analysis['format'] = 'json'
                        analysis['confidence'] = 0.8
                    elif 'xml' in analysis['mime_type'] or 'html' in analysis['mime_type']:
                        analysis['format'] = 'xml'
                        analysis['confidence'] = 0.8
                    elif 'text' in analysis['mime_type'] or 'script' in analysis['mime_type']:
                        analysis['format'] = 'command'
                        analysis['confidence'] = 0.6
        except Exception as e:
            logger.warning(f"Error analyzing mime type: {e}")
        
        # Try to run file command for additional info
        try:
            output = subprocess.check_output(['file', executable_path], universal_newlines=True)
            if 'json' in output.lower():
                analysis['format'] = 'json'
                analysis['confidence'] = 0.7
                analysis['hints'].append('file command suggests JSON')
            elif 'xml' in output.lower() or 'html' in output.lower():
                analysis['format'] = 'xml'
                analysis['confidence'] = 0.7
                analysis['hints'].append('file command suggests XML')
            elif 'text' in output.lower() or 'script' in output.lower():
                analysis['format'] = 'command'
                analysis['confidence'] = 0.6
                analysis['hints'].append('file command suggests text/script')
            elif 'executable' in output.lower() or 'binary' in output.lower():
                analysis['format'] = 'binary'
                analysis['confidence'] = 0.9
                analysis['hints'].append('file command confirms binary')
        except Exception as e:
            logger.debug(f"Error running file command: {e}")
        
        # Try to examine file content for patterns
        try:
            with open(executable_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB
                
                # Check for JSON patterns
                if content.startswith(b'{') or content.startswith(b'['):
                    try:
                        # Try to parse as JSON
                        if content.decode('utf-8', errors='ignore').strip():
                            json_str = content.decode('utf-8', errors='ignore')
                            json.loads(json_str)
                            analysis['format'] = 'json'
                            analysis['confidence'] = 0.9
                            analysis['hints'].append('content matches JSON syntax')
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
                
                # Check for XML patterns
                if content.startswith(b'<?xml') or content.startswith(b'<'):
                    try:
                        # Try to parse as XML
                        if content.decode('utf-8', errors='ignore').strip():
                            xml_str = content.decode('utf-8', errors='ignore')
                            minidom.parseString(xml_str)
                            analysis['format'] = 'xml'
                            analysis['confidence'] = 0.9
                            analysis['hints'].append('content matches XML syntax')
                    except (Exception):
                        pass
                
                # Check for binary patterns
                non_printable = sum(1 for b in content if b < 32 and b not in (9, 10, 13))
                if non_printable / len(content) > 0.3:
                    analysis['format'] = 'binary'
                    analysis['confidence'] = 0.8
                    analysis['hints'].append('high proportion of non-printable chars')
        except Exception as e:
            logger.warning(f"Error examining file content: {e}")
        
        return analysis
    
    def generate_data(self, executable_path, input_type=None):
        """
        Generate fuzz data for the given executable using appropriate grammar.
        
        Args:
            executable_path: Path to the executable to fuzz
            input_type: Optional explicit input type
            
        Returns:
            tuple: (data, detected_type)
        """
        # Detect input type if not specified
        detected_type = input_type or self.detect_input_format(executable_path)
        
        # Get additional analysis for confirmation
        analysis = self.analyze_binary_format(executable_path)
        
        # If analysis strongly suggests a different format with high confidence
        if analysis['confidence'] > 0.8 and analysis['format'] != detected_type:
            logger.info(f"Adjusting format from {detected_type} to {analysis['format']} based on analysis")
            detected_type = analysis['format']
        
        # Generate appropriate data based on detected type
        if detected_type == 'json':
            data = self.generate_json_data()
        elif detected_type == 'xml':
            data = self.generate_xml_data()
        elif detected_type == 'command':
            data = self.generate_command_data()
        else:  # binary or other
            data = self.generate_binary_data(analysis)
        
        logger.debug(f"Generated {detected_type} data for {executable_path}")
        return data, detected_type
    
    def generate_json_data(self, valid=True):
        """Generate JSON data using the JSON grammar."""
        try:
            json_data = self.json_grammar.generate(num=1, valid=valid)[0]
            return json_data
        except Exception as e:
            logger.error(f"Error generating JSON data: {e}")
            # Fallback to simple JSON
            return json.dumps({"value": random.randint(1, 100)})
    
    def generate_xml_data(self, valid=True):
        """Generate XML data using the XML grammar."""
        try:
            xml_data = self.xml_grammar.generate(num=1, valid=valid)[0]
            return xml_data
        except Exception as e:
            logger.error(f"Error generating XML data: {e}")
            # Fallback to simple XML
            return '<?xml version="1.0" encoding="UTF-8"?>\n<root><value>1</value></root>'
    
    def generate_command_data(self, valid=True):
        """Generate command-line data using the Command grammar."""
        try:
            cmd_data = self.command_grammar.generate(num=1, valid=valid)[0]
            return cmd_data
        except Exception as e:
            logger.error(f"Error generating command data: {e}")
            # Fallback to simple command
            return "--help"
    
    def generate_binary_data(self, analysis=None):
        """Generate binary data based on analysis or using random patterns."""
        try:
            # Size between 16 bytes and 16KB
            size = random.randint(16, 16384)
            
            # Different patterns to try
            pattern_type = random.choice([
                'random',          # Completely random bytes
                'structured',      # Structured binary with header and sections
                'pattern',         # Repeating pattern
                'ascii_heavy',     # Mostly printable ASCII
                'zeros',           # Mostly zeros with some random data
            ])
            
            if pattern_type == 'random':
                # Completely random bytes
                return os.urandom(size)
            
            elif pattern_type == 'structured':
                # Create a structured binary with header and sections
                header = b'FUZZ' + size.to_bytes(4, byteorder='little')
                num_sections = random.randint(1, 5)
                sections = []
                
                for i in range(num_sections):
                    section_size = random.randint(10, size // (num_sections + 1))
                    section_type = random.randint(1, 255).to_bytes(1, byteorder='little')
                    section_data = os.urandom(section_size)
                    section = section_type + section_size.to_bytes(4, byteorder='little') + section_data
                    sections.append(section)
                
                return header + b''.join(sections)
            
            elif pattern_type == 'pattern':
                # Repeating pattern
                pattern_length = random.randint(1, 16)
                pattern = os.urandom(pattern_length)
                repeats = size // pattern_length
                remainder = size % pattern_length
                
                return pattern * repeats + pattern[:remainder]
            
            elif pattern_type == 'ascii_heavy':
                # Mostly printable ASCII
                printable = string.printable.encode('ascii')
                return bytes(random.choice(printable) for _ in range(size))
            
            elif pattern_type == 'zeros':
                # Mostly zeros with some random data
                data = bytearray(size)
                # Add some random data at random positions
                num_random = size // 10
                for _ in range(num_random):
                    pos = random.randint(0, size - 1)
                    data[pos] = random.randint(1, 255)
                
                return bytes(data)
        
        except Exception as e:
            logger.error(f"Error generating binary data: {e}")
            # Fallback to simple binary
            return os.urandom(64)
    
    def infer_grammar_from_samples(self, sample_files, format_type=None):
        """
        Attempt to infer grammar rules from sample files.
        
        Args:
            sample_files: List of paths to sample input files
            format_type: Optional explicit format type
            
        Returns:
            dict: Inferred grammar rules
        """
        # This is a placeholder for a more sophisticated grammar inference
        # In a real implementation, this would analyze patterns across samples
        
        if not sample_files:
            return None
        
        # Try to detect format if not specified
        if not format_type:
            # Check first file to guess format
            try:
                with open(sample_files[0], 'rb') as f:
                    content = f.read(4096)
                
                if content.startswith(b'{') or content.startswith(b'['):
                    format_type = 'json'
                elif content.startswith(b'<?xml') or content.startswith(b'<'):
                    format_type = 'xml'
                else:
                    # Try to detect if it's a command line or binary
                    non_printable = sum(1 for b in content if b < 32 and b not in (9, 10, 13))
                    if non_printable / len(content) > 0.3:
                        format_type = 'binary'
                    else:
                        format_type = 'command'
            except Exception:
                format_type = 'binary'  # Default to binary
        
        # Initialize results
        grammar = {
            'format': format_type,
            'rules': [],
            'tokens': [],
            'patterns': [],
            'confidence': 0.5
        }
        
        # Process samples based on format
        if format_type == 'json':
            self._infer_json_grammar(sample_files, grammar)
        elif format_type == 'xml':
            self._infer_xml_grammar(sample_files, grammar)
        elif format_type == 'command':
            self._infer_command_grammar(sample_files, grammar)
        else:  # binary
            self._infer_binary_grammar(sample_files, grammar)
        
        return grammar
    
    def _infer_json_grammar(self, sample_files, grammar):
        """Infer grammar rules from JSON samples."""
        # Implementation would analyze JSON structure, field names, types, and patterns
        # This is a simplified placeholder
        json_objects = []
        
        for file_path in sample_files:
            try:
                with open(file_path, 'r') as f:
                    json_data = json.load(f)
                    json_objects.append(json_data)
            except Exception as e:
                logger.debug(f"Error parsing JSON sample {file_path}: {e}")
        
        if not json_objects:
            return
        
        # Extract common fields and types
        fields = {}
        for obj in json_objects:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k not in fields:
                        fields[k] = []
                    if isinstance(v, (int, float, str, bool)) or v is None:
                        fields[k].append(type(v).__name__)
        
        # Add field rules
        for field, types in fields.items():
            if types:
                most_common = max(set(types), key=types.count)
                grammar['rules'].append({
                    'field': field,
                    'type': most_common,
                    'frequency': types.count(most_common) / len(types)
                })
        
        grammar['confidence'] = min(0.5 + (len(grammar['rules']) * 0.05), 0.9)
    
    def _infer_xml_grammar(self, sample_files, grammar):
        """Infer grammar rules from XML samples."""
        # Implementation would analyze XML structure, tags, attributes, and patterns
        # This is a simplified placeholder
        xml_elements = []
        
        for file_path in sample_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    dom = minidom.parseString(content)
                    xml_elements.append(dom.documentElement)
            except Exception as e:
                logger.debug(f"Error parsing XML sample {file_path}: {e}")
        
        if not xml_elements:
            return
        
        # Extract common tags and attributes
        tags = {}
        attributes = {}
        
        for root in xml_elements:
            self._process_xml_element(root, tags, attributes)
        
        # Add tag rules
        for tag, count in tags.items():
            grammar['rules'].append({
                'tag': tag,
                'frequency': count / len(xml_elements)
            })
        
        # Add attribute rules
        for attr, count in attributes.items():
            grammar['rules'].append({
                'attribute': attr,
                'frequency': count / len(xml_elements)
            })
        
        grammar['confidence'] = min(0.5 + (len(grammar['rules']) * 0.05), 0.9)
    
    def _process_xml_element(self, element, tags, attributes):
        """Process an XML element to extract tags and attributes."""
        if element.nodeName not in tags:
            tags[element.nodeName] = 0
        tags[element.nodeName] += 1
        
        # Process attributes
        for i in range(element.attributes.length):
            attr = element.attributes.item(i)
            if attr.name not in attributes:
                attributes[attr.name] = 0
            attributes[attr.name] += 1
        
        # Process child elements
        for child in element.childNodes:
            if child.nodeType == child.ELEMENT_NODE:
                self._process_xml_element(child, tags, attributes)
    
    def _infer_command_grammar(self, sample_files, grammar):
        """Infer grammar rules from command-line samples."""
        # Implementation would analyze command patterns, flags, arguments
        # This is a simplified placeholder
        commands = []
        
        for file_path in sample_files:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            commands.append(line)
            except Exception as e:
                logger.debug(f"Error parsing command sample {file_path}: {e}")
        
        if not commands:
            return
        
        # Extract flags and arguments
        flags = {}
        arguments = []
        
        for cmd in commands:
            parts = cmd.split()
            for part in parts:
                if part.startswith('-'):
                    if part not in flags:
                        flags[part] = 0
                    flags[part] += 1
                else:
                    arguments.append(part)
        
        # Add flag rules
        for flag, count in flags.items():
            grammar['rules'].append({
                'flag': flag,
                'frequency': count / len(commands)
            })
        
        # Extract patterns from arguments
        if arguments:
            # Look for numeric patterns
            numeric = [arg for arg in arguments if arg.isdigit()]
            if numeric:
                grammar['patterns'].append({
                    'type': 'numeric',
                    'frequency': len(numeric) / len(arguments)
                })
            
            # Look for path patterns
            paths = [arg for arg in arguments if '/' in arg or '\\' in arg]
            if paths:
                grammar['patterns'].append({
                    'type': 'path',
                    'frequency': len(paths) / len(arguments)
                })
        
        grammar['confidence'] = min(0.5 + (len(grammar['rules']) * 0.05), 0.9)
    
    def _infer_binary_grammar(self, sample_files, grammar):
        """Infer grammar rules from binary samples."""
        # Implementation would analyze binary patterns, headers, structures
        # This is a simplified placeholder
        samples = []
        
        for file_path in sample_files:
            try:
                with open(file_path, 'rb') as f:
                    samples.append(f.read())
            except Exception as e:
                logger.debug(f"Error reading binary sample {file_path}: {e}")
        
        if not samples:
            return
        
        # Look for common prefixes (headers)
        min_length = min(len(sample) for sample in samples)
        prefix_length = min(16, min_length)
        
        prefixes = [sample[:prefix_length] for sample in samples]
        if len(set(prefixes)) < len(prefixes):
            # Some prefixes are the same - might be a header
            common_prefix = max(set(prefixes), key=prefixes.count)
            frequency = prefixes.count(common_prefix) / len(prefixes)
            
            if frequency > 0.5:
                grammar['patterns'].append({
                    'type': 'header',
                    'value': common_prefix.hex(),
                    'frequency': frequency
                })
        
        # Check for structural patterns
        chunk_patterns = []
        for sample in samples:
            # Look for repeating 4-byte chunks
            chunks = [sample[i:i+4] for i in range(0, len(sample) - 4, 4)]
            chunk_counts = {}
            
            for chunk in chunks:
                if chunk not in chunk_counts:
                    chunk_counts[chunk] = 0
                chunk_counts[chunk] += 1
            
            # Find chunks that repeat
            for chunk, count in chunk_counts.items():
                if count > 1:
                    chunk_patterns.append(chunk)
        
        if chunk_patterns:
            # Add most common chunk pattern
            common_chunk = max(set(chunk_patterns), key=chunk_patterns.count)
            frequency = chunk_patterns.count(common_chunk) / len(chunk_patterns)
            
            grammar['patterns'].append({
                'type': 'chunk',
                'value': common_chunk.hex(),
                'frequency': frequency
            })
        
        grammar['confidence'] = min(0.5 + (len(grammar['patterns']) * 0.1), 0.8)