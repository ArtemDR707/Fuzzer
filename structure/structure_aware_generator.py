#!/usr/bin/env python3
"""
Structure-Aware Generator for Intelligent Fuzzing

This module provides generators for various data structures based on schemas.
"""

import os
import json
import random
import string
import datetime
import ipaddress
import uuid
from typing import Any, Dict, List, Optional, Set, Union

# Import schema components
from .schema_parser import Schema, SchemaNode, SchemaType, ObjectNode, ArrayNode


class StructureAwareGenerator:
    """Generator for structure-aware data."""
    
    def __init__(self, schema: Schema):
        """
        Initialize a structure-aware generator.
        
        Args:
            schema: Schema definition for the data to generate
        """
        self.schema = schema
        self.seed = None
        
        # Probabilities
        self.invalid_prob = 0.2
        self.boundary_prob = 0.3
        self.null_prob = 0.1
    
    def set_seed(self, seed: int) -> None:
        """
        Set a random seed for reproducible generation.
        
        Args:
            seed: Random seed value
        """
        self.seed = seed
        random.seed(seed)
    
    def set_probabilities(self, invalid: float = None, boundary: float = None,
                         null: float = None) -> None:
        """
        Set probabilities for various generation strategies.
        
        Args:
            invalid: Probability of generating invalid data (0.0-1.0)
            boundary: Probability of generating boundary values (0.0-1.0)
            null: Probability of generating null values for optional fields (0.0-1.0)
        """
        if invalid is not None:
            self.invalid_prob = max(0.0, min(1.0, invalid))
        
        if boundary is not None:
            self.boundary_prob = max(0.0, min(1.0, boundary))
        
        if null is not None:
            self.null_prob = max(0.0, min(1.0, null))
    
    def generate(self, valid: bool = True) -> Any:
        """
        Generate data according to the schema.
        
        Args:
            valid: Whether to generate valid data (True) or invalid data (False)
            
        Returns:
            Generated data instance
        """
        return self._generate_node(self.schema.root_node, valid)
    
    def _generate_node(self, node: SchemaNode, valid: bool = True,
                      context: Optional[Dict] = None) -> Any:
        """
        Generate data for a specific schema node.
        
        Args:
            node: Schema node to generate data for
            valid: Whether to generate valid data
            context: Optional context for generation (e.g., parent object)
            
        Returns:
            Generated data for this node
        """
        # Handle null for optional nodes
        if not node.required and valid and random.random() < self.null_prob:
            return None
        
        # Generate based on schema type
        if node.schema_type == SchemaType.STRING:
            return self._generate_string(node, valid)
        
        elif node.schema_type == SchemaType.INTEGER:
            return self._generate_integer(node, valid)
        
        elif node.schema_type == SchemaType.NUMBER:
            return self._generate_number(node, valid)
        
        elif node.schema_type == SchemaType.BOOLEAN:
            return self._generate_boolean(node, valid)
        
        elif node.schema_type == SchemaType.ARRAY:
            if isinstance(node, ArrayNode):
                return self._generate_array(node, valid, context)
            else:
                # Fall back to generic array
                items_per_array = random.randint(0, 5)
                return [self._generate_string(SchemaNode(SchemaType.STRING), valid) 
                        for _ in range(items_per_array)]
        
        elif node.schema_type == SchemaType.OBJECT:
            if isinstance(node, ObjectNode):
                return self._generate_object(node, valid, context)
            else:
                # Fall back to generic object
                return {"key": self._generate_string(SchemaNode(SchemaType.STRING), valid)}
        
        elif node.schema_type == SchemaType.NULL:
            if valid:
                return None
            else:
                # Invalid for null type is any non-null value
                return random.choice([0, "", False, [], {}])
        
        elif node.schema_type == SchemaType.TEXT:
            return self._generate_text(node, valid)
        
        elif node.schema_type == SchemaType.BINARY:
            return self._generate_binary(node, valid)
        
        elif node.schema_type == SchemaType.BYTES:
            return self._generate_bytes(node, valid)
        
        else:  # ANY or unknown type
            # Generate a random type
            rand_type = random.choice([
                SchemaType.STRING, SchemaType.INTEGER, SchemaType.NUMBER,
                SchemaType.BOOLEAN, SchemaType.ARRAY, SchemaType.OBJECT, SchemaType.NULL
            ])
            return self._generate_node(SchemaNode(rand_type), valid, context)
    
    def _generate_string(self, node: SchemaNode, valid: bool = True) -> str:
        """Generate a string value."""
        # Check for enumeration
        if node.enum and valid:
            return random.choice(node.enum)
        
        # Check for pattern
        if node.pattern and valid:
            # For simplicity, we'll just return a fixed value based on pattern
            # In a real implementation, you'd use something like exrex to generate from regex
            return f"pattern_{node.pattern}_match"
        
        # Check for format
        if node.format and valid:
            if node.format == 'date':
                return datetime.date.today().isoformat()
            elif node.format == 'time':
                return datetime.datetime.now().strftime('%H:%M:%S')
            elif node.format == 'date-time':
                return datetime.datetime.now().isoformat()
            elif node.format == 'email':
                return f"{self._random_word()}@{self._random_word()}.com"
            elif node.format == 'uri':
                return f"https://{self._random_word()}.com/{self._random_word()}"
            elif node.format == 'ipv4':
                return str(ipaddress.IPv4Address(random.randint(0, 2**32-1)))
            elif node.format == 'uuid':
                return str(uuid.uuid4())
        
        if valid:
            # Generate a valid random string
            word_count = random.randint(1, 5)
            return ' '.join(self._random_word() for _ in range(word_count))
        else:
            # Invalid string generation strategies
            strategies = [
                # Empty string if not allowed
                lambda: "",
                # Very long string
                lambda: 'A' * random.randint(1000, 10000),
                # Format string attack
                lambda: '%s%s%s%s%n%n%n%n',
                # SQL injection
                lambda: "' OR 1=1; --",
                # JavaScript injection
                lambda: "<script>alert('XSS')</script>",
                # Unicode boundary cases
                lambda: "".join(chr(random.randint(0x80, 0x10FFFF)) for _ in range(10)),
                # Null bytes
                lambda: "before\x00after"
            ]
            
            return random.choice(strategies)()
    
    def _generate_integer(self, node: SchemaNode, valid: bool = True) -> Union[int, Any]:
        """Generate an integer value."""
        # Check for enumeration
        if node.enum and valid:
            return random.choice(node.enum)
        
        if valid:
            # Generate a reasonable integer
            return random.randint(-1000, 1000)
        else:
            # Invalid integer generation strategies
            strategies = [
                # Return non-integer
                lambda: random.random(),
                lambda: "123",
                lambda: [],
                # Extreme values
                lambda: 2**63,
                lambda: -(2**63)
            ]
            
            return random.choice(strategies)()
    
    def _generate_number(self, node: SchemaNode, valid: bool = True) -> Union[float, Any]:
        """Generate a number value (float)."""
        # Check for enumeration
        if node.enum and valid:
            return random.choice(node.enum)
        
        if valid:
            # Generate a reasonable float
            return random.uniform(-1000.0, 1000.0)
        else:
            # Invalid number generation strategies
            strategies = [
                # Return non-number
                lambda: "123.45",
                lambda: {},
                # Special values
                lambda: float('inf'),
                lambda: float('nan'),
                lambda: float('-inf')
            ]
            
            return random.choice(strategies)()
    
    def _generate_boolean(self, node: SchemaNode, valid: bool = True) -> Union[bool, Any]:
        """Generate a boolean value."""
        if valid:
            return random.choice([True, False])
        else:
            # Invalid boolean generation strategies
            return random.choice([0, 1, "true", "false", None])
    
    def _generate_array(self, node: ArrayNode, valid: bool = True,
                        context: Optional[Dict] = None) -> Union[List, Any]:
        """Generate an array value."""
        if not valid:
            # Strategies for invalid arrays
            strategies = [
                # Non-array values
                lambda: "not_an_array",
                lambda: 123,
                lambda: {},
                lambda: None,
                # Array with invalid items
                lambda: self._generate_invalid_array_items(node)
            ]
            
            return random.choice(strategies)()
        
        # Determine number of items
        min_items = node.min_items or 0
        max_items = node.max_items or 10
        max_items = max(max_items, min_items)
        
        num_items = random.randint(min_items, max_items)
        
        # Generate items
        items = []
        for _ in range(num_items):
            items.append(self._generate_node(node.items, valid, context))
        
        # Handle unique items constraint
        if node.unique_items and len(items) > 1:
            # Simple implementation for primitive types
            # For more complex types, you'd need a more sophisticated approach
            unique_items = []
            seen = set()
            
            for item in items:
                # Only works for hashable types
                try:
                    item_hash = hash(item) if isinstance(item, (str, int, float, bool, tuple)) else id(item)
                    if item_hash not in seen:
                        seen.add(item_hash)
                        unique_items.append(item)
                except TypeError:
                    # For unhashable types, just add it
                    unique_items.append(item)
            
            # Ensure we meet minimum
            while len(unique_items) < min_items:
                new_item = self._generate_node(node.items, valid, context)
                try:
                    new_hash = hash(new_item) if isinstance(new_item, (str, int, float, bool, tuple)) else id(new_item)
                    if new_hash not in seen:
                        seen.add(new_hash)
                        unique_items.append(new_item)
                except TypeError:
                    unique_items.append(new_item)
            
            return unique_items
        
        return items
    
    def _generate_invalid_array_items(self, node: ArrayNode) -> List:
        """Generate an array with some invalid items."""
        min_items = node.min_items or 0
        max_items = node.max_items or 10
        max_items = max(max_items, min_items)
        
        num_items = random.randint(min_items, max_items)
        
        # Generate a mix of valid and invalid items
        items = []
        for _ in range(num_items):
            is_invalid = random.random() < 0.5
            items.append(self._generate_node(node.items, not is_invalid))
        
        return items
    
    def _generate_object(self, node: ObjectNode, valid: bool = True,
                        context: Optional[Dict] = None) -> Union[Dict, Any]:
        """Generate an object value."""
        if not valid:
            # Strategies for invalid objects
            strategies = [
                # Non-object values
                lambda: "not_an_object",
                lambda: 123,
                lambda: [],
                lambda: None,
                # Object missing required properties
                lambda: self._generate_object_missing_required(node),
                # Object with invalid properties
                lambda: self._generate_object_invalid_props(node, context)
            ]
            
            return random.choice(strategies)()
        
        # Start with an empty object
        result = {}
        
        # Add required properties
        for prop_name in node.required_props:
            if prop_name in node.properties:
                result[prop_name] = self._generate_node(node.properties[prop_name], valid, result)
        
        # Add optional properties
        for prop_name, prop_schema in node.properties.items():
            if prop_name not in result:  # Skip already added required props
                if prop_schema.required or random.random() > 0.5:
                    result[prop_name] = self._generate_node(prop_schema, valid, result)
        
        # Add additional properties if allowed
        if node.additional_properties:
            num_additional = random.randint(0, 3)
            for _ in range(num_additional):
                prop_name = f"additional_{self._random_word()}"
                if prop_name not in result:
                    result[prop_name] = self._generate_node(SchemaNode(SchemaType.STRING), valid, result)
        
        return result
    
    def _generate_object_missing_required(self, node: ObjectNode) -> Dict:
        """Generate an object missing some required properties."""
        # Start with an empty object
        result = {}
        
        # Add some required properties, but not all
        for prop_name in node.required_props:
            if prop_name in node.properties and random.random() > 0.3:
                result[prop_name] = self._generate_node(node.properties[prop_name], True, result)
        
        # Add optional properties
        for prop_name, prop_schema in node.properties.items():
            if prop_name not in result and prop_name not in node.required_props:
                if random.random() > 0.5:
                    result[prop_name] = self._generate_node(prop_schema, True, result)
        
        return result
    
    def _generate_object_invalid_props(self, node: ObjectNode, context: Optional[Dict] = None) -> Dict:
        """Generate an object with some invalid property values."""
        # Start with an empty object
        result = {}
        
        # Add required properties with some invalid values
        for prop_name in node.required_props:
            if prop_name in node.properties:
                # 50% chance of generating invalid value for this property
                is_valid = random.random() > 0.5
                result[prop_name] = self._generate_node(node.properties[prop_name], is_valid, result)
        
        # Add optional properties with some invalid values
        for prop_name, prop_schema in node.properties.items():
            if prop_name not in result:  # Skip already added required props
                if prop_schema.required or random.random() > 0.5:
                    # 50% chance of generating invalid value for this property
                    is_valid = random.random() > 0.5
                    result[prop_name] = self._generate_node(prop_schema, is_valid, result)
        
        return result
    
    def _generate_text(self, node: SchemaNode, valid: bool = True) -> str:
        """Generate a text value."""
        if valid:
            # Generate multi-line text
            num_paragraphs = random.randint(1, 3)
            paragraphs = []
            
            for _ in range(num_paragraphs):
                num_sentences = random.randint(1, 5)
                sentences = []
                
                for _ in range(num_sentences):
                    words = [self._random_word().capitalize() for _ in range(random.randint(3, 15))]
                    sentences.append(' '.join(words) + '.')
                
                paragraphs.append(' '.join(sentences))
            
            return '\n\n'.join(paragraphs)
        else:
            # Invalid text strategies
            strategies = [
                # Binary data in text
                lambda: 'Text with binary: \x00\x01\x02\x03',
                # Very long text
                lambda: 'A' * random.randint(10000, 100000),
                # Text with extreme Unicode
                lambda: "".join(chr(random.randint(0x10000, 0x10FFFF)) for _ in range(100))
            ]
            
            return random.choice(strategies)()
    
    def _generate_binary(self, node: SchemaNode, valid: bool = True) -> bytes:
        """Generate binary data."""
        if valid:
            # Generate random binary data
            size = random.randint(10, 100)
            return bytes(random.randint(0, 255) for _ in range(size))
        else:
            # Invalid binary data - just an empty array for now
            return b''
    
    def _generate_bytes(self, node: SchemaNode, valid: bool = True) -> bytes:
        """Generate bytes data."""
        return self._generate_binary(node, valid)
    
    def _random_word(self, min_length: int = 2, max_length: int = 10) -> str:
        """Generate a random word."""
        length = random.randint(min_length, max_length)
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    def generate_corpus(self, count: int = 20, output_dir: Optional[str] = None,
                       valid_ratio: float = 0.8) -> List:
        """
        Generate a corpus of test data.
        
        Args:
            count: Number of instances to generate
            output_dir: Optional directory to write instances to files
            valid_ratio: Ratio of valid to invalid instances (0.0-1.0)
            
        Returns:
            List of generated instances or file paths
        """
        corpus = []
        
        # Create output directory if specified
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for i in range(count):
            # Determine if this instance should be valid
            valid = random.random() < valid_ratio
            
            # Generate instance
            instance = self.generate(valid=valid)
            
            if output_dir:
                # Write to file
                ext = self._get_file_extension()
                file_path = os.path.join(output_dir, f"corpus_{i:04d}{'_valid' if valid else '_invalid'}{ext}")
                self._write_to_file(file_path, instance)
                corpus.append(file_path)
            else:
                corpus.append(instance)
        
        return corpus
    
    def _get_file_extension(self) -> str:
        """Get the appropriate file extension for this format."""
        format_name = self.schema.format_name.lower()
        
        if format_name == 'json':
            return '.json'
        elif format_name == 'xml':
            return '.xml'
        elif format_name == 'text':
            return '.txt'
        elif format_name == 'binary' or format_name == 'bytes':
            return '.bin'
        elif format_name == 'command':
            return '.cmd'
        else:
            return '.dat'
    
    def _write_to_file(self, file_path: str, instance: Any) -> None:
        """Write an instance to a file in the appropriate format."""
        format_name = self.schema.format_name.lower()
        
        if format_name == 'json':
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(instance, f, indent=2)
        elif format_name == 'binary' or format_name == 'bytes':
            if not isinstance(instance, bytes):
                # Convert to bytes if not already
                if isinstance(instance, str):
                    instance = instance.encode('utf-8')
                else:
                    instance = str(instance).encode('utf-8')
            
            with open(file_path, 'wb') as f:
                f.write(instance)
        else:
            # Default to string representation
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(str(instance))


def get_generator_for_format(format_name: str) -> StructureAwareGenerator:
    """
    Get an appropriate generator for the given format.
    
    Args:
        format_name: Name of the format
        
    Returns:
        StructureAwareGenerator for that format
    """
    # Create basic schema for the format
    if format_name == 'json':
        from .schema_parser import json_basic_schema
        schema = json_basic_schema()
    elif format_name == 'xml':
        from .schema_parser import xml_basic_schema
        schema = xml_basic_schema()
    elif format_name == 'text':
        from .schema_parser import text_basic_schema
        schema = text_basic_schema()
    elif format_name == 'binary':
        from .schema_parser import binary_basic_schema
        schema = binary_basic_schema()
    else:
        # Default to text
        from .schema_parser import text_basic_schema
        schema = text_basic_schema()
    
    return StructureAwareGenerator(schema)