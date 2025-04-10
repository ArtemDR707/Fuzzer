#!/usr/bin/env python3
"""
Format Inferrer for Structure-Aware Fuzzing

This module automatically infers data structure from samples for intelligent fuzzing.
"""

import re
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union

# Import schema components
from .schema_parser import Schema, SchemaNode, SchemaType, ObjectNode, ArrayNode


class FormatInferrer:
    """Infers format and schema from sample data."""
    
    def __init__(self):
        """Initialize the format inferrer."""
        pass
    
    def infer_format(self, samples: List[Union[str, bytes]]) -> str:
        """
        Infer the format of the given samples.
        
        Args:
            samples: List of sample data (strings or bytes)
            
        Returns:
            str: Detected format type ("json", "xml", "text", "binary", "command")
        """
        formats = []
        
        for sample in samples:
            if self._detect_json(sample):
                formats.append("json")
            elif self._detect_xml(sample):
                formats.append("xml")
            elif self._detect_binary(sample):
                formats.append("binary")
            elif self._detect_command(sample):
                formats.append("command")
            else:
                formats.append("text")
        
        # Return the most common format
        if not formats:
            return "text"  # Default to text
        
        # Count occurrences of each format
        format_counts = {}
        for fmt in formats:
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
        
        # Return the most common format
        return max(format_counts.items(), key=lambda x: x[1])[0]
    
    def infer_schema(self, samples: List[Union[str, bytes]], format_type: Optional[str] = None) -> Schema:
        """
        Infer a schema from the given samples.
        
        Args:
            samples: List of sample data (strings or bytes)
            format_type: Optional format type hint (if None, will be inferred)
            
        Returns:
            Schema: Inferred schema
        """
        if not format_type:
            format_type = self.infer_format(samples)
        
        if format_type == "json":
            return self._infer_json_schema(samples)
        elif format_type == "xml":
            return self._infer_xml_schema(samples)
        elif format_type == "text":
            return self._infer_text_schema(samples)
        elif format_type == "binary":
            return self._infer_binary_schema(samples)
        elif format_type == "command":
            return self._infer_command_schema(samples)
        else:
            # Default to text schema
            return self._infer_text_schema(samples)
    
    def _detect_json(self, sample: Union[str, bytes]) -> bool:
        """Detect if a sample is JSON."""
        try:
            # Convert bytes to string if needed
            if isinstance(sample, bytes):
                sample = sample.decode('utf-8', errors='replace')
            
            # Check for JSON objects or arrays
            sample = sample.strip()
            if (sample.startswith('{') and sample.endswith('}')) or \
               (sample.startswith('[') and sample.endswith(']')):
                json.loads(sample)
                return True
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        
        return False
    
    def _detect_xml(self, sample: Union[str, bytes]) -> bool:
        """Detect if a sample is XML."""
        try:
            # Convert bytes to string if needed
            if isinstance(sample, bytes):
                sample = sample.decode('utf-8', errors='replace')
            
            # Check for XML
            sample = sample.strip()
            if sample.startswith('<') and sample.endswith('>'):
                ET.fromstring(sample)
                return True
        except (ET.ParseError, UnicodeDecodeError):
            pass
        
        return False
    
    def _detect_text(self, sample: Union[str, bytes]) -> bool:
        """Detect if a sample is text."""
        try:
            # Convert bytes to string if needed
            if isinstance(sample, bytes):
                sample = sample.decode('utf-8', errors='replace')
            
            # It's text if it's a string and not binary
            return True
        except UnicodeDecodeError:
            return False
    
    def _detect_binary(self, sample: Union[str, bytes]) -> bool:
        """Detect if a sample is binary."""
        if isinstance(sample, bytes):
            # Check if it's likely binary data
            return self._is_likely_binary(sample)
        return False
    
    def _detect_command(self, sample: Union[str, bytes]) -> bool:
        """Detect if a sample is a command-line input."""
        try:
            # Convert bytes to string if needed
            if isinstance(sample, bytes):
                sample = sample.decode('utf-8', errors='replace')
            
            # Check if it looks like a command with options
            sample = sample.strip()
            
            # Command-line format typically has options like -x or --xxx
            if re.search(r'^[a-zA-Z0-9_\-\.]+(\s+(-{1,2}[a-zA-Z0-9_\-]+|\w+))+$', sample):
                return True
        except UnicodeDecodeError:
            pass
        
        return False
    
    def _is_likely_binary(self, sample: Union[str, bytes]) -> bool:
        """Check if a sample is likely binary data."""
        if isinstance(sample, str):
            try:
                sample = sample.encode('utf-8')
            except UnicodeEncodeError:
                return True
        
        # Check for null bytes or high number of non-printable characters
        if b'\x00' in sample:
            return True
        
        # Count non-printable and non-whitespace characters
        non_printable = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
        return non_printable > len(sample) * 0.1
    
    def _infer_json_schema(self, samples: List[Union[str, bytes]]) -> Schema:
        """Infer a schema from JSON samples."""
        parsed_samples = []
        
        for sample in samples:
            try:
                # Convert bytes to string if needed
                if isinstance(sample, bytes):
                    sample = sample.decode('utf-8', errors='replace')
                
                # Parse the JSON
                parsed = json.loads(sample)
                parsed_samples.append(parsed)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
        
        if not parsed_samples:
            # Return a basic JSON schema if no samples could be parsed
            from .schema_parser import json_basic_schema
            return json_basic_schema()
        
        # Infer schema from parsed samples
        root_node = self._infer_json_node_schema(parsed_samples)
        
        return Schema(
            root_node=root_node,
            format_name="json",
            title="Inferred JSON Schema",
            description="Schema inferred from JSON samples"
        )
    
    def _infer_json_node_schema(self, samples: List[Any], max_depth: int = 10) -> SchemaNode:
        """Recursively infer schema for JSON nodes."""
        if max_depth <= 0:
            return SchemaNode(SchemaType.ANY)
        
        # Group samples by type
        types = [self._get_json_type(sample) for sample in samples]
        most_common_type = max(set(types), key=types.count)
        
        if most_common_type == SchemaType.OBJECT:
            return self._infer_object_schema(
                [sample for sample in samples if isinstance(sample, dict)],
                max_depth - 1
            )
        elif most_common_type == SchemaType.ARRAY:
            return self._infer_array_schema(
                [sample for sample in samples if isinstance(sample, list)],
                max_depth - 1
            )
        elif most_common_type == SchemaType.STRING:
            return self._infer_string_schema(
                [sample for sample in samples if isinstance(sample, str)]
            )
        elif most_common_type == SchemaType.INTEGER:
            return self._infer_integer_schema(
                [sample for sample in samples if isinstance(sample, int)]
            )
        elif most_common_type == SchemaType.NUMBER:
            return self._infer_number_schema(
                [sample for sample in samples if isinstance(sample, (int, float))]
            )
        elif most_common_type == SchemaType.BOOLEAN:
            return SchemaNode(SchemaType.BOOLEAN)
        elif most_common_type == SchemaType.NULL:
            return SchemaNode(SchemaType.NULL)
        else:
            return SchemaNode(SchemaType.ANY)
    
    def _infer_object_schema(self, samples: List[Dict], max_depth: int) -> ObjectNode:
        """Infer schema for JSON objects."""
        # Collect all property names across samples
        properties = {}
        required_props = set()
        
        for sample in samples:
            for key, value in sample.items():
                if key not in properties:
                    # Collect values for this property across all samples
                    prop_values = [s.get(key) for s in samples if key in s]
                    properties[key] = self._infer_json_node_schema(prop_values, max_depth)
                
                # Track required properties (present in all samples)
                if all(key in s for s in samples):
                    required_props.add(key)
        
        return ObjectNode(
            properties=properties,
            required_props=list(required_props),
            description="Inferred object"
        )
    
    def _infer_array_schema(self, samples: List[List], max_depth: int) -> ArrayNode:
        """Infer schema for JSON arrays."""
        # Collect all array items across samples
        items = []
        
        for sample in samples:
            items.extend(sample)
        
        # Infer schema for items
        items_schema = self._infer_json_node_schema(items, max_depth)
        
        # Get min and max lengths
        min_length = min(len(sample) for sample in samples) if samples else 0
        max_length = max(len(sample) for sample in samples) if samples else 0
        
        return ArrayNode(
            items=items_schema,
            min_items=min_length,
            max_items=max_length,
            description="Inferred array"
        )
    
    def _infer_string_schema(self, samples: List[str]) -> SchemaNode:
        """Infer schema for JSON strings."""
        # Check for common patterns
        patterns = {}
        
        # Check for common formats
        date_pattern = r'^\d{4}-\d{2}-\d{2}$'
        time_pattern = r'^\d{2}:\d{2}:\d{2}$'
        datetime_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$'
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        url_pattern = r'^https?://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(/.*)?$'
        ipv4_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        uuid_pattern = r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
        
        patterns[date_pattern] = 'date'
        patterns[time_pattern] = 'time'
        patterns[datetime_pattern] = 'date-time'
        patterns[email_pattern] = 'email'
        patterns[url_pattern] = 'uri'
        patterns[ipv4_pattern] = 'ipv4'
        patterns[uuid_pattern] = 'uuid'
        
        # Count regex matches
        format_counts = {}
        
        for sample in samples:
            for pattern, format_name in patterns.items():
                if re.match(pattern, sample):
                    format_counts[format_name] = format_counts.get(format_name, 0) + 1
        
        # Get the most common format if it's prevalent
        detected_format = None
        if format_counts:
            most_common_format = max(format_counts.items(), key=lambda x: x[1])
            if most_common_format[1] > len(samples) * 0.5:
                detected_format = most_common_format[0]
        
        # Get min and max lengths
        min_length = min(len(sample) for sample in samples) if samples else 0
        max_length = max(len(sample) for sample in samples) if samples else 0
        
        # Check for enumeration if small number of unique values
        unique_values = set(samples)
        enum = list(unique_values) if len(unique_values) <= 10 and len(unique_values) < len(samples) * 0.5 else None
        
        return SchemaNode(
            schema_type=SchemaType.STRING,
            format=detected_format,
            enum=enum,
            description="Inferred string"
        )
    
    def _infer_integer_schema(self, samples: List[int]) -> SchemaNode:
        """Infer schema for JSON integers."""
        if not samples:
            return SchemaNode(SchemaType.INTEGER)
        
        # Get min and max values
        minimum = min(samples)
        maximum = max(samples)
        
        # Check for enumeration if small number of unique values
        unique_values = set(samples)
        enum = list(unique_values) if len(unique_values) <= 10 and len(unique_values) < len(samples) * 0.5 else None
        
        return SchemaNode(
            schema_type=SchemaType.INTEGER,
            enum=enum,
            description=f"Integer in range [{minimum}, {maximum}]"
        )
    
    def _infer_number_schema(self, samples: List[Union[int, float]]) -> SchemaNode:
        """Infer schema for JSON numbers."""
        if not samples:
            return SchemaNode(SchemaType.NUMBER)
        
        # Get min and max values
        minimum = min(samples)
        maximum = max(samples)
        
        # Check for enumeration if small number of unique values
        unique_values = set(samples)
        enum = list(unique_values) if len(unique_values) <= 10 and len(unique_values) < len(samples) * 0.5 else None
        
        return SchemaNode(
            schema_type=SchemaType.NUMBER,
            enum=enum,
            description=f"Number in range [{minimum}, {maximum}]"
        )
    
    def _get_json_type(self, value: Any) -> SchemaType:
        """Determine the JSON schema type of a value."""
        if value is None:
            return SchemaType.NULL
        elif isinstance(value, bool):
            return SchemaType.BOOLEAN
        elif isinstance(value, int):
            return SchemaType.INTEGER
        elif isinstance(value, float):
            return SchemaType.NUMBER
        elif isinstance(value, str):
            return SchemaType.STRING
        elif isinstance(value, list):
            return SchemaType.ARRAY
        elif isinstance(value, dict):
            return SchemaType.OBJECT
        else:
            return SchemaType.ANY
    
    def _infer_xml_schema(self, samples: List[Union[str, bytes]]) -> Schema:
        """Infer a schema from XML samples."""
        # Parse XML samples
        parsed_samples = []
        
        for sample in samples:
            try:
                # Convert bytes to string if needed
                if isinstance(sample, bytes):
                    sample = sample.decode('utf-8', errors='replace')
                
                # Parse the XML
                parsed = ET.fromstring(sample)
                parsed_samples.append(parsed)
            except (ET.ParseError, UnicodeDecodeError):
                continue
        
        if not parsed_samples:
            # Return a basic XML schema if no samples could be parsed
            from .schema_parser import xml_basic_schema
            return xml_basic_schema()
        
        # Infer schema from parsed samples
        root_node = self._infer_xml_element_schema(parsed_samples)
        
        return Schema(
            root_node=root_node,
            format_name="xml",
            title="Inferred XML Schema",
            description="Schema inferred from XML samples"
        )
    
    def _infer_xml_element_schema(self, elements: List[ET.Element], max_depth: int = 10) -> SchemaNode:
        """Recursively infer schema for XML elements."""
        # Simple implementation for now
        return ObjectNode(
            properties={
                "element": SchemaNode(SchemaType.ANY, description="XML element")
            },
            description="XML element"
        )
    
    def _infer_text_schema(self, samples: List[Union[str, bytes]]) -> Schema:
        """Infer a schema from text samples."""
        # Convert bytes to strings if needed
        text_samples = []
        
        for sample in samples:
            try:
                if isinstance(sample, bytes):
                    sample = sample.decode('utf-8', errors='replace')
                text_samples.append(sample)
            except UnicodeDecodeError:
                continue
        
        if not text_samples:
            # Return a basic text schema if no samples could be parsed
            from .schema_parser import text_basic_schema
            return text_basic_schema()
        
        # Create a basic text schema
        root_node = SchemaNode(
            schema_type=SchemaType.TEXT,
            description="Text content"
        )
        
        return Schema(
            root_node=root_node,
            format_name="text",
            title="Inferred Text Schema",
            description="Schema inferred from text samples"
        )
    
    def _infer_binary_schema(self, samples: List[Union[str, bytes]]) -> Schema:
        """Infer a schema from binary samples."""
        # Ensure we have bytes
        binary_samples = []
        
        for sample in samples:
            if isinstance(sample, str):
                try:
                    sample = sample.encode('utf-8')
                except UnicodeEncodeError:
                    continue
            
            if isinstance(sample, bytes):
                binary_samples.append(sample)
        
        if not binary_samples:
            # Return a basic binary schema if no samples could be processed
            from .schema_parser import binary_basic_schema
            return binary_basic_schema()
        
        # Create a basic binary schema
        root_node = SchemaNode(
            schema_type=SchemaType.BINARY,
            description="Binary content"
        )
        
        return Schema(
            root_node=root_node,
            format_name="binary",
            title="Inferred Binary Schema",
            description="Schema inferred from binary samples"
        )
    
    def _infer_command_schema(self, samples: List[Union[str, bytes]]) -> Schema:
        """Infer a schema from command-line samples."""
        # Convert bytes to strings if needed
        command_samples = []
        
        for sample in samples:
            try:
                if isinstance(sample, bytes):
                    sample = sample.decode('utf-8', errors='replace')
                command_samples.append(sample)
            except UnicodeDecodeError:
                continue
        
        if not command_samples:
            # Return a basic text schema if no samples could be parsed
            from .schema_parser import text_basic_schema
            return text_basic_schema()
        
        # For now, just use a text schema for commands
        root_node = SchemaNode(
            schema_type=SchemaType.TEXT,
            description="Command-line input"
        )
        
        return Schema(
            root_node=root_node,
            format_name="command",
            title="Inferred Command Schema",
            description="Schema inferred from command-line samples"
        )
    
    def infer_from_files(self, file_paths: List[str], format_type: Optional[str] = None) -> Schema:
        """
        Infer a schema from sample files.
        
        Args:
            file_paths: List of file paths
            format_type: Optional format type hint (if None, will be inferred)
            
        Returns:
            Schema: Inferred schema
        """
        samples = []
        
        for path in file_paths:
            try:
                # Try to read as text first
                with open(path, 'r', encoding='utf-8') as f:
                    samples.append(f.read())
            except UnicodeDecodeError:
                # If that fails, read as binary
                with open(path, 'rb') as f:
                    samples.append(f.read())
            except Exception:
                # Skip this file
                continue
        
        return self.infer_schema(samples, format_type)
