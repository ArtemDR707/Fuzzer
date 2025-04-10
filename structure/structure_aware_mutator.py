#!/usr/bin/env python3
"""
Structure-Aware Mutator for Intelligent Fuzzing

This module provides mutators for various data structures based on schemas.
"""

import os
import json
import random
import string
import re
import datetime
from typing import Any, Dict, List, Optional, Set, Union

# Import schema components
from .schema_parser import Schema, SchemaNode, SchemaType, ObjectNode, ArrayNode


class StructureAwareMutator:
    """Mutator for structure-aware data."""
    
    def __init__(self, schema: Schema, seed_data: Any = None):
        """
        Initialize a structure-aware mutator.
        
        Args:
            schema: Schema definition for the data to mutate
            seed_data: Initial seed data to mutate (optional)
        """
        self.schema = schema
        self.seed_data = seed_data
        
        # Settings
        self.mutation_count = 3  # Number of mutations to apply
        self.aggressive_prob = 0.2  # Probability of aggressive mutations
    
    def set_seed_data(self, seed_data: Any) -> None:
        """
        Set the seed data for mutation.
        
        Args:
            seed_data: Seed data to mutate
        """
        self.seed_data = seed_data
    
    def set_mutation_settings(self, mutation_count: int = None,
                             aggressive_prob: float = None) -> None:
        """
        Configure mutation settings.
        
        Args:
            mutation_count: Number of mutations to apply
            aggressive_prob: Probability of aggressive mutations (0.0-1.0)
        """
        if mutation_count is not None:
            self.mutation_count = max(1, mutation_count)
        
        if aggressive_prob is not None:
            self.aggressive_prob = max(0.0, min(1.0, aggressive_prob))
    
    def mutate(self, seed_data: Any = None) -> Any:
        """
        Mutate data according to the schema.
        
        Args:
            seed_data: Optional seed data to mutate (overrides the instance seed)
            
        Returns:
            Mutated data
        """
        data = seed_data if seed_data is not None else self.seed_data
        
        if data is None:
            # If no seed data provided, create a basic one
            from .structure_aware_generator import StructureAwareGenerator
            generator = StructureAwareGenerator(self.schema)
            data = generator.generate(valid=True)
        
        # Create a deep copy of the data to mutate
        if isinstance(data, dict):
            mutated_data = dict(data)
        elif isinstance(data, list):
            mutated_data = list(data)
        elif isinstance(data, str):
            mutated_data = data
        elif isinstance(data, bytes):
            mutated_data = bytes(data)
        else:
            mutated_data = data
        
        # Apply a random number of mutations
        mutation_count = random.randint(1, self.mutation_count)
        
        for _ in range(mutation_count):
            # Pick a random node in the data structure and mutate it
            mutated_data = self._mutate_node_recursive(self.schema.root_node, mutated_data)
        
        return mutated_data
    
    def _mutate_node_recursive(self, node: SchemaNode, data: Any,
                              path: List[str] = None) -> Any:
        """
        Recursively traverse and mutate the data structure.
        
        Args:
            node: Schema node for this data
            data: Data to mutate
            path: Current path in the data structure
            
        Returns:
            Mutated data
        """
        if path is None:
            path = []
        
        # Decide whether to mutate this node (more likely for shorter paths)
        mutate_prob = 1.0 / (len(path) + 1) if path else 0.8
        if random.random() < mutate_prob:
            # Mutate this node
            if node.schema_type == SchemaType.STRING and isinstance(data, str):
                return self._mutate_string(node, data)
            
            elif node.schema_type == SchemaType.INTEGER and isinstance(data, int):
                return self._mutate_integer(node, data)
            
            elif node.schema_type == SchemaType.NUMBER and isinstance(data, (int, float)):
                return self._mutate_number(node, data)
            
            elif node.schema_type == SchemaType.BOOLEAN and isinstance(data, bool):
                return self._mutate_boolean(node, data)
            
            elif node.schema_type == SchemaType.ARRAY and isinstance(data, list):
                if isinstance(node, ArrayNode):
                    return self._mutate_array(node, data)
                else:
                    # Mutate as generic array
                    return self._mutate_any(node, data)
            
            elif node.schema_type == SchemaType.OBJECT and isinstance(data, dict):
                if isinstance(node, ObjectNode):
                    return self._mutate_object(node, data)
                else:
                    # Mutate as generic object
                    return self._mutate_any(node, data)
            
            elif node.schema_type == SchemaType.NULL and data is None:
                return self._mutate_null(node, data)
            
            elif node.schema_type == SchemaType.TEXT and isinstance(data, str):
                return self._mutate_text(node, data)
            
            elif node.schema_type == SchemaType.BINARY and isinstance(data, bytes):
                return self._mutate_binary(node, data)
            
            elif node.schema_type == SchemaType.BYTES and isinstance(data, bytes):
                return self._mutate_bytes(node, data)
            
            else:
                # Generic mutation for incompatible types
                return self._mutate_any(node, data)
        
        # Don't mutate this node, but recurse into children
        if node.schema_type == SchemaType.OBJECT and isinstance(data, dict):
            # Deep copy the data
            mutated_data = dict(data)
            
            # Recursively mutate properties
            if isinstance(node, ObjectNode):
                for prop_name, prop_value in data.items():
                    if prop_name in node.properties:
                        # Recurse with schema
                        new_path = path + [prop_name]
                        mutated_data[prop_name] = self._mutate_node_recursive(
                            node.properties[prop_name], prop_value, new_path
                        )
                    else:
                        # Mutate without schema
                        new_path = path + [prop_name]
                        mutated_data[prop_name] = self._mutate_any(None, prop_value)
            else:
                # Generic object, mutate all properties without schema
                for prop_name, prop_value in data.items():
                    new_path = path + [prop_name]
                    mutated_data[prop_name] = self._mutate_any(None, prop_value)
            
            return mutated_data
            
        elif node.schema_type == SchemaType.ARRAY and isinstance(data, list):
            # Deep copy the data
            mutated_data = list(data)
            
            # Recursively mutate array items
            if isinstance(node, ArrayNode) and node.items:
                for i, item in enumerate(data):
                    # Skip some items to avoid excessive mutation
                    if random.random() < 0.7:
                        new_path = path + [str(i)]
                        mutated_data[i] = self._mutate_node_recursive(node.items, item, new_path)
            else:
                # Generic array, mutate all items without schema
                for i, item in enumerate(data):
                    # Skip some items
                    if random.random() < 0.7:
                        new_path = path + [str(i)]
                        mutated_data[i] = self._mutate_any(None, item)
            
            return mutated_data
        
        # For other types, no children to recurse into, return unchanged
        return data
    
    def _mutate_string(self, node: SchemaNode, data: str) -> str:
        """Mutate a string value."""
        strategies = [
            # Character mutation
            lambda: self._string_character_mutation(node, data),
            # Case mutation
            lambda: self._string_case_mutation(node, data),
            # Boundary mutation
            lambda: self._string_boundary_mutation(node, data),
            # Special string mutation
            lambda: self._string_special_mutation(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _string_character_mutation(self, node: SchemaNode, data: str) -> str:
        """Mutate individual characters in the string."""
        if not data:
            return "fuzz"
        
        chars = list(data)
        
        # Choose a mutation type
        mutation_type = random.choice([
            "change", "insert", "delete", "duplicate"
        ])
        
        if mutation_type == "change" and chars:
            # Change a random character
            index = random.randint(0, len(chars) - 1)
            chars[index] = random.choice(string.printable)
        
        elif mutation_type == "insert":
            # Insert a random character
            index = random.randint(0, len(chars))
            chars.insert(index, random.choice(string.printable))
        
        elif mutation_type == "delete" and len(chars) > 1:
            # Delete a random character
            index = random.randint(0, len(chars) - 1)
            chars.pop(index)
        
        elif mutation_type == "duplicate" and chars:
            # Duplicate a random character
            index = random.randint(0, len(chars) - 1)
            chars.insert(index, chars[index])
        
        return ''.join(chars)
    
    def _string_case_mutation(self, node: SchemaNode, data: str) -> str:
        """Mutate string case."""
        if not data:
            return "fuzz"
        
        case_mutation = random.choice([
            "upper", "lower", "title", "swap"
        ])
        
        if case_mutation == "upper":
            return data.upper()
        elif case_mutation == "lower":
            return data.lower()
        elif case_mutation == "title":
            return data.title()
        else:  # swap
            return ''.join(c.upper() if c.islower() else c.lower() for c in data)
    
    def _string_boundary_mutation(self, node: SchemaNode, data: str) -> str:
        """Mutate string for boundary testing."""
        boundary_mutation = random.choice([
            "empty", "very_long", "whitespace", "special"
        ])
        
        if boundary_mutation == "empty":
            return ""
        elif boundary_mutation == "very_long":
            # Create a very long string
            return data * random.randint(100, 1000)
        elif boundary_mutation == "whitespace":
            # Add or remove whitespace
            whitespace_type = random.choice(["prefix", "suffix", "both", "internal"])
            
            if whitespace_type == "prefix":
                return " " * random.randint(1, 10) + data
            elif whitespace_type == "suffix":
                return data + " " * random.randint(1, 10)
            elif whitespace_type == "both":
                return " " * random.randint(1, 5) + data + " " * random.randint(1, 5)
            else:  # internal
                chars = list(data)
                for _ in range(min(5, len(data))):
                    index = random.randint(0, len(chars))
                    chars.insert(index, " ")
                return ''.join(chars)
        else:  # special
            # Use special characters
            specials = ['\\', '\0', '\n', '\r', '\t', '\v', '\f', '\u200B']
            special_char = random.choice(specials)
            
            special_type = random.choice(["prefix", "suffix", "both", "internal"])
            
            if special_type == "prefix":
                return special_char + data
            elif special_type == "suffix":
                return data + special_char
            elif special_type == "both":
                return special_char + data + special_char
            else:  # internal
                chars = list(data)
                for _ in range(min(3, len(data))):
                    index = random.randint(0, len(chars))
                    chars.insert(index, special_char)
                return ''.join(chars)
    
    def _string_special_mutation(self, node: SchemaNode, data: str) -> str:
        """Inject special sequences into the string."""
        format_name = node.format if hasattr(node, "format") else None
        
        # Use format-specific mutations if applicable
        if format_name == "date":
            return random.choice([
                "0000-00-00", "9999-99-99", "2000-02-30", 
                datetime.datetime.now().strftime("%Y-%m-%d")
            ])
        elif format_name == "time":
            return random.choice([
                "00:00:00", "23:59:59", "24:00:00", "12:60:00", "12:00:60"
            ])
        elif format_name == "date-time":
            return random.choice([
                "0000-00-00T00:00:00Z", "2000-02-30T12:34:56",
                "2023-01-01T25:00:00Z", "2023-01-01T12:60:00Z"
            ])
        elif format_name == "email":
            return random.choice([
                "user@example.com", "a@a", "@invalid", "user@localhost",
                "very.long.email.address.that.exceeds.normal.limits@extremely.long.domain.name.that.should.cause.problems.in.some.implementations.com"
            ])
        elif format_name == "uri":
            return random.choice([
                "https://example.com", "http://localhost", "file:///etc/passwd",
                "https://user:password@example.com:8080/path/to/resource?query=value#fragment",
                "http://" + "a" * 1000 + ".com"
            ])
        elif format_name == "ipv4":
            return random.choice([
                "127.0.0.1", "0.0.0.0", "255.255.255.255", "999.999.999.999", "1.2.3"
            ])
        elif format_name == "uuid":
            return random.choice([
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "not-a-valid-uuid"
            ])
        
        # Generic special strings
        return random.choice([
            # SQL Injection
            "' OR 1=1; --",
            "'; DROP TABLE users; --",
            # XSS
            "<script>alert('XSS')</script>",
            # Format string
            "%s%s%s%n%n%n",
            # Command injection
            "$(id)",
            "`id`",
            "| id",
            # Path traversal
            "../../../etc/passwd",
            # Null bytes
            "test\0test",
            # Unicode
            "你好世界",
            "😀😊😎👍🏼🎉"
        ])
    
    def _mutate_integer(self, node: SchemaNode, data: int) -> Union[int, Any]:
        """Mutate an integer value."""
        strategies = [
            # Small change
            lambda: self._integer_small_change(node, data),
            # Boundary value
            lambda: self._integer_boundary_value(node, data),
            # Bit flip
            lambda: self._integer_bitflip(node, data),
            # Special value
            lambda: self._integer_special_value(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _integer_small_change(self, node: SchemaNode, data: int) -> int:
        """Make a small change to the integer."""
        # Adjust by a small amount
        change = random.randint(-10, 10)
        return data + change
    
    def _integer_boundary_value(self, node: SchemaNode, data: int) -> int:
        """Use a boundary value for the integer."""
        # Common boundary values
        boundaries = [
            0, 1, -1, 127, 128, 255, 256, 
            32767, 32768, 65535, 65536, 
            2147483647, 2147483648, 4294967295, 4294967296,
            9223372036854775807, 9223372036854775808
        ]
        
        # Include negative versions
        negative_boundaries = [-b for b in boundaries if b > 0]
        all_boundaries = boundaries + negative_boundaries
        
        return random.choice(all_boundaries)
    
    def _integer_bitflip(self, node: SchemaNode, data: int) -> int:
        """Flip a random bit in the integer."""
        # Choose a random bit position
        bit_position = random.randint(0, 31)  # Assume 32-bit int
        
        # Flip that bit
        return data ^ (1 << bit_position)
    
    def _integer_special_value(self, node: SchemaNode, data: int) -> int:
        """Use a special integer value."""
        return random.choice([
            # Common special values
            0, 1, -1, 
            # Powers of 2
            2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
            # Negative powers of 2
            -2, -4, -8, -16, -32, -64, -128, -256, -512, -1024, -2048, -4096, -8192, -16384, -32768, -65536,
            # Very large/small values
            2**31 - 1, -2**31, 2**32 - 1, 2**63 - 1, -2**63
        ])
    
    def _mutate_number(self, node: SchemaNode, data: float) -> Union[float, Any]:
        """Mutate a number (float) value."""
        strategies = [
            # Small change
            lambda: self._number_small_change(node, data),
            # Scale change
            lambda: self._number_scale_change(node, data),
            # Special value
            lambda: self._number_special_value(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _number_small_change(self, node: SchemaNode, data: float) -> float:
        """Make a small change to the float."""
        # Add a small random value
        change = random.uniform(-1.0, 1.0) * (abs(data) / 10 if data != 0 else 1.0)
        return data + change
    
    def _number_scale_change(self, node: SchemaNode, data: float) -> float:
        """Change the scale of the float."""
        # Multiply or divide by a factor
        factor = random.uniform(0.1, 10.0)
        operation = random.choice(["multiply", "divide"])
        
        if operation == "multiply":
            return data * factor
        else:
            # Avoid division by zero
            if data == 0:
                return 0.0
            return data / factor
    
    def _number_special_value(self, node: SchemaNode, data: float) -> float:
        """Use a special float value."""
        return random.choice([
            # Zero, one, and negative one
            0.0, 1.0, -1.0,
            # Special IEEE values
            float('inf'), float('-inf'), float('nan'),
            # Very small positive values
            1e-6, 1e-12, 1e-18, 1e-24, 1e-30,
            # Very large values
            1e6, 1e12, 1e18, 1e24, 1e30,
            # Numbers close to 1
            0.9999, 1.0001, 0.999999, 1.000001,
            # Common fractions
            0.5, 0.25, 0.125, 0.33333, 0.66667
        ])
    
    def _mutate_boolean(self, node: SchemaNode, data: bool) -> bool:
        """Mutate a boolean value."""
        # Simply invert the boolean value
        return not data
    
    def _mutate_array(self, node: ArrayNode, data: List) -> Union[List, Any]:
        """Mutate an array value."""
        if not data and random.random() < 0.5:
            # Empty array, sometimes generate a new one
            from .structure_aware_generator import StructureAwareGenerator
            generator = StructureAwareGenerator(Schema(node, "array"))
            return generator._generate_array(node, True)
        
        strategies = [
            # Item mutation
            lambda: self._array_item_mutation(node, data),
            # Structure mutation
            lambda: self._array_structure_mutation(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _array_item_mutation(self, node: ArrayNode, data: List) -> List:
        """Mutate a random item in the array."""
        if not data:
            return data
        
        # Make a copy of the array
        mutated_data = list(data)
        
        # Choose a random item to mutate
        index = random.randint(0, len(data) - 1)
        
        # Mutate the item
        if node.items:
            mutated_data[index] = self._mutate_node_recursive(node.items, data[index])
        else:
            mutated_data[index] = self._mutate_any(None, data[index])
        
        return mutated_data
    
    def _array_structure_mutation(self, node: ArrayNode, data: List) -> List:
        """Mutate the structure of the array."""
        # Make a copy
        mutated_data = list(data)
        
        # Choose a structure mutation type
        mutation_type = random.choice([
            "add", "remove", "duplicate", "swap", "reverse", "shuffle"
        ])
        
        if mutation_type == "add" and node.items:
            # Add a new item
            from .structure_aware_generator import StructureAwareGenerator
            generator = StructureAwareGenerator(Schema(node, "array"))
            new_item = generator._generate_node(node.items, True)
            
            # Insert at random position
            index = random.randint(0, len(mutated_data))
            mutated_data.insert(index, new_item)
        
        elif mutation_type == "remove" and mutated_data:
            # Remove a random item
            index = random.randint(0, len(mutated_data) - 1)
            mutated_data.pop(index)
        
        elif mutation_type == "duplicate" and mutated_data:
            # Duplicate a random item
            index = random.randint(0, len(mutated_data) - 1)
            mutated_data.append(mutated_data[index])
        
        elif mutation_type == "swap" and len(mutated_data) > 1:
            # Swap two random items
            i = random.randint(0, len(mutated_data) - 1)
            j = random.randint(0, len(mutated_data) - 1)
            while i == j:
                j = random.randint(0, len(mutated_data) - 1)
            
            mutated_data[i], mutated_data[j] = mutated_data[j], mutated_data[i]
        
        elif mutation_type == "reverse" and len(mutated_data) > 1:
            # Reverse the array
            mutated_data.reverse()
        
        elif mutation_type == "shuffle" and len(mutated_data) > 1:
            # Shuffle the array
            random.shuffle(mutated_data)
        
        return mutated_data
    
    def _mutate_object(self, node: ObjectNode, data: Dict) -> Union[Dict, Any]:
        """Mutate an object value."""
        if not data and random.random() < 0.5:
            # Empty object, sometimes generate a new one
            from .structure_aware_generator import StructureAwareGenerator
            generator = StructureAwareGenerator(Schema(node, "object"))
            return generator._generate_object(node, True)
        
        strategies = [
            # Property mutation
            lambda: self._object_property_mutation(node, data),
            # Structure mutation
            lambda: self._object_structure_mutation(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _object_property_mutation(self, node: ObjectNode, data: Dict) -> Dict:
        """Mutate a random property in the object."""
        if not data:
            return data
        
        # Make a copy of the object
        mutated_data = dict(data)
        
        # Choose a random property to mutate
        if data:
            prop_name = random.choice(list(data.keys()))
            
            # Mutate the property
            if prop_name in node.properties:
                mutated_data[prop_name] = self._mutate_node_recursive(
                    node.properties[prop_name], data[prop_name]
                )
            else:
                mutated_data[prop_name] = self._mutate_any(None, data[prop_name])
        
        return mutated_data
    
    def _object_structure_mutation(self, node: ObjectNode, data: Dict) -> Dict:
        """Mutate the structure of the object."""
        # Make a copy
        mutated_data = dict(data)
        
        # Choose a structure mutation type
        mutation_type = random.choice([
            "add", "remove", "rename", "duplicate"
        ])
        
        if mutation_type == "add" and node.properties:
            # Add a new property
            from .structure_aware_generator import StructureAwareGenerator
            generator = StructureAwareGenerator(Schema(node, "object"))
            
            # Choose a property from the schema that's not in the data
            available_props = [p for p in node.properties if p not in data]
            if available_props and random.random() < 0.7:
                # Use an existing schema property
                prop_name = random.choice(available_props)
                prop_node = node.properties[prop_name]
                mutated_data[prop_name] = generator._generate_node(prop_node, True)
            else:
                # Create a completely new property
                prop_name = f"added_property_{random.randint(1, 1000)}"
                mutated_data[prop_name] = generator._generate_node(SchemaNode(SchemaType.STRING), True)
        
        elif mutation_type == "remove" and mutated_data:
            # Remove a random property (but not required ones)
            non_required_props = [p for p in mutated_data if p not in node.required_props]
            if non_required_props:
                prop_name = random.choice(non_required_props)
                del mutated_data[prop_name]
        
        elif mutation_type == "rename" and mutated_data:
            # Rename a random property
            if mutated_data:
                old_name = random.choice(list(mutated_data.keys()))
                new_name = f"renamed_{old_name}_{random.randint(1, 1000)}"
                
                mutated_data[new_name] = mutated_data[old_name]
                del mutated_data[old_name]
        
        elif mutation_type == "duplicate" and mutated_data:
            # Duplicate a random property
            if mutated_data:
                prop_name = random.choice(list(mutated_data.keys()))
                new_name = f"copy_of_{prop_name}"
                
                mutated_data[new_name] = mutated_data[prop_name]
        
        return mutated_data
    
    def _mutate_null(self, node: SchemaNode, data: None) -> Optional[Any]:
        """Mutate a null value."""
        # Convert null to a non-null value
        return random.choice([
            "", 0, False, [], {}
        ])
    
    def _mutate_any(self, node: SchemaNode, data: Any) -> Any:
        """Mutate any type of value."""
        if data is None:
            return self._mutate_null(node, data)
        elif isinstance(data, str):
            return self._mutate_string(SchemaNode(SchemaType.STRING), data)
        elif isinstance(data, int):
            return self._mutate_integer(SchemaNode(SchemaType.INTEGER), data)
        elif isinstance(data, float):
            return self._mutate_number(SchemaNode(SchemaType.NUMBER), data)
        elif isinstance(data, bool):
            return self._mutate_boolean(SchemaNode(SchemaType.BOOLEAN), data)
        elif isinstance(data, list):
            return self._mutate_array(
                ArrayNode(items=SchemaNode(SchemaType.ANY)),
                data
            )
        elif isinstance(data, dict):
            # Create a simple object node for mutation
            obj_node = ObjectNode()
            for key in data:
                obj_node.properties[key] = SchemaNode(SchemaType.ANY)
            return self._mutate_object(obj_node, data)
        elif isinstance(data, bytes):
            return self._mutate_binary(SchemaNode(SchemaType.BINARY), data)
        else:
            # Unknown type, convert to string and mutate
            return self._mutate_string(SchemaNode(SchemaType.STRING), str(data))
    
    def _mutate_text(self, node: SchemaNode, data: str) -> str:
        """Mutate text content."""
        strategies = [
            # Line mutation
            lambda: self._text_line_mutation(node, data),
            # Paragraph mutation
            lambda: self._text_paragraph_mutation(node, data),
            # Inject mutation
            lambda: self._text_inject_mutation(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _text_line_mutation(self, node: SchemaNode, data: str) -> str:
        """Mutate a random line in the text."""
        if not data:
            return "Fuzz text content"
        
        # Split into lines
        lines = data.splitlines()
        if not lines:
            lines = [data]
        
        # Choose a random line to mutate
        if lines:
            index = random.randint(0, len(lines) - 1)
            
            # Mutate the line using string mutation
            lines[index] = self._mutate_string(SchemaNode(SchemaType.STRING), lines[index])
        
        # Rejoin the lines
        return '\n'.join(lines)
    
    def _text_paragraph_mutation(self, node: SchemaNode, data: str) -> str:
        """Mutate paragraph structure in the text."""
        if not data:
            return "Fuzz text content"
        
        # Split into paragraphs (separated by blank lines)
        paragraphs = re.split(r'\n\s*\n', data)
        if not paragraphs:
            paragraphs = [data]
        
        # Choose a mutation type
        mutation_type = random.choice([
            "add", "remove", "duplicate", "swap"
        ])
        
        if mutation_type == "add":
            # Add a new paragraph
            new_paragraph = ' '.join(
                self._random_word() for _ in range(random.randint(10, 30))
            )
            
            # Insert at random position
            index = random.randint(0, len(paragraphs))
            paragraphs.insert(index, new_paragraph)
        
        elif mutation_type == "remove" and len(paragraphs) > 1:
            # Remove a random paragraph
            index = random.randint(0, len(paragraphs) - 1)
            paragraphs.pop(index)
        
        elif mutation_type == "duplicate" and paragraphs:
            # Duplicate a random paragraph
            index = random.randint(0, len(paragraphs) - 1)
            paragraphs.append(paragraphs[index])
        
        elif mutation_type == "swap" and len(paragraphs) > 1:
            # Swap two random paragraphs
            i = random.randint(0, len(paragraphs) - 1)
            j = random.randint(0, len(paragraphs) - 1)
            while i == j:
                j = random.randint(0, len(paragraphs) - 1)
            
            paragraphs[i], paragraphs[j] = paragraphs[j], paragraphs[i]
        
        # Rejoin the paragraphs
        return '\n\n'.join(paragraphs)
    
    def _text_inject_mutation(self, node: SchemaNode, data: str) -> str:
        """Inject special sequences into the text."""
        if not data:
            return "Fuzz text content"
        
        # Choose an injection type
        injection_type = random.choice([
            "comment", "markdown", "xml", "control", "unicode"
        ])
        
        if injection_type == "comment":
            # Inject a comment
            comments = [
                "/* Comment */",
                "// Comment",
                "<!-- Comment -->",
                "# Comment",
                "-- Comment"
            ]
            inject = random.choice(comments)
        
        elif injection_type == "markdown":
            # Inject markdown syntax
            markdowns = [
                "# Heading",
                "## Subheading",
                "*italic*",
                "**bold**",
                "[link](http://example.com)",
                "```code```",
                "> Quote"
            ]
            inject = random.choice(markdowns)
        
        elif injection_type == "xml":
            # Inject XML-like syntax
            xmls = [
                "<tag>content</tag>",
                "<self-closing />",
                "<parent><child>nested</child></parent>",
                "<?xml version=\"1.0\"?>"
            ]
            inject = random.choice(xmls)
        
        elif injection_type == "control":
            # Inject control characters
            controls = [
                "\0", "\n", "\r", "\t", "\v", "\f", "\b", "\a"
            ]
            inject = random.choice(controls)
        
        else:  # unicode
            # Inject Unicode characters
            unicodes = [
                "你好",  # Chinese
                "こんにちは",  # Japanese
                "안녕하세요",  # Korean
                "Привет",  # Russian
                "مرحبا",  # Arabic
                "שלום",  # Hebrew
                "€£¥₹₽₩",  # Currency symbols
                "☺☻♥♦♣♠•◘○◙"  # Symbols
            ]
            inject = random.choice(unicodes)
        
        # Choose where to inject
        position = random.choice(["start", "end", "random"])
        
        if position == "start":
            return inject + data
        elif position == "end":
            return data + inject
        else:  # random
            # Insert at a random position
            index = random.randint(0, len(data))
            return data[:index] + inject + data[index:]
    
    def _mutate_binary(self, node: SchemaNode, data: bytes) -> bytes:
        """Mutate binary data."""
        strategies = [
            # Byte mutation
            lambda: self._binary_byte_mutation(node, data),
            # Block mutation
            lambda: self._binary_block_mutation(node, data),
            # Special mutation
            lambda: self._binary_special_mutation(node, data)
        ]
        
        return random.choice(strategies)()
    
    def _binary_byte_mutation(self, node: SchemaNode, data: bytes) -> bytes:
        """Mutate individual bytes."""
        if not data:
            return b"fuzz"
        
        # Convert to bytearray for mutation
        binary = bytearray(data)
        
        # Choose a mutation type
        mutation_type = random.choice([
            "change", "insert", "delete", "flip_bit"
        ])
        
        if mutation_type == "change" and binary:
            # Change random bytes
            count = random.randint(1, max(1, len(binary) // 10))
            for _ in range(count):
                index = random.randint(0, len(binary) - 1)
                binary[index] = random.randint(0, 255)
        
        elif mutation_type == "insert":
            # Insert random bytes
            count = random.randint(1, 10)
            index = random.randint(0, len(binary))
            for _ in range(count):
                binary.insert(index, random.randint(0, 255))
                index += 1
        
        elif mutation_type == "delete" and len(binary) > 1:
            # Delete random bytes
            count = min(random.randint(1, 10), len(binary) - 1)
            index = random.randint(0, len(binary) - count)
            for _ in range(count):
                binary.pop(index)
        
        elif mutation_type == "flip_bit" and binary:
            # Flip random bits
            count = random.randint(1, max(1, len(binary) // 5))
            for _ in range(count):
                index = random.randint(0, len(binary) - 1)
                bit_pos = random.randint(0, 7)
                binary[index] ^= (1 << bit_pos)
        
        return bytes(binary)
    
    def _binary_block_mutation(self, node: SchemaNode, data: bytes) -> bytes:
        """Mutate a block of bytes."""
        if not data:
            return b"fuzz"
        
        # Convert to bytearray for mutation
        binary = bytearray(data)
        
        # Choose a mutation type
        mutation_type = random.choice([
            "repeat", "zero", "ones", "random", "swap"
        ])
        
        if mutation_type == "repeat" and binary:
            # Repeat a block of bytes
            block_size = min(random.randint(1, 8), len(binary))
            start = random.randint(0, len(binary) - block_size)
            block = binary[start:start + block_size]
            
            # Repeat the block and insert it
            repeat_count = random.randint(2, 10)
            insert_pos = random.randint(0, len(binary))
            
            # Insert repeated block
            for _ in range(repeat_count):
                for i, b in enumerate(block):
                    if insert_pos + i < len(binary):
                        binary[insert_pos + i] = b
                    else:
                        binary.append(b)
        
        elif mutation_type == "zero" and binary:
            # Zero out a block of bytes
            block_size = min(random.randint(1, 16), len(binary))
            start = random.randint(0, len(binary) - block_size)
            
            for i in range(start, start + block_size):
                binary[i] = 0
        
        elif mutation_type == "ones" and binary:
            # Set a block of bytes to all ones
            block_size = min(random.randint(1, 16), len(binary))
            start = random.randint(0, len(binary) - block_size)
            
            for i in range(start, start + block_size):
                binary[i] = 0xFF
        
        elif mutation_type == "random" and binary:
            # Set a block of bytes to random values
            block_size = min(random.randint(1, 16), len(binary))
            start = random.randint(0, len(binary) - block_size)
            
            for i in range(start, start + block_size):
                binary[i] = random.randint(0, 255)
        
        elif mutation_type == "swap" and len(binary) > 1:
            # Swap two blocks of bytes
            block_size = min(random.randint(1, 8), len(binary) // 2)
            
            # Ensure blocks don't overlap
            start1 = random.randint(0, len(binary) - 2*block_size)
            start2 = start1 + block_size + random.randint(0, len(binary) - start1 - 2*block_size)
            
            # Swap the blocks
            for i in range(block_size):
                binary[start1 + i], binary[start2 + i] = binary[start2 + i], binary[start1 + i]
        
        return bytes(binary)
    
    def _binary_special_mutation(self, node: SchemaNode, data: bytes) -> bytes:
        """Use special byte sequences."""
        if not data:
            return b"fuzz"
        
        # Convert to bytearray for mutation
        binary = bytearray(data)
        
        # Choose a special sequence
        special_type = random.choice([
            "nulls", "pattern", "format_string", "common_binary"
        ])
        
        if special_type == "nulls":
            # Insert null bytes
            null_sequence = b"\x00" * random.randint(1, 10)
            
            # Insert at a random position
            index = random.randint(0, len(binary))
            binary[index:index] = null_sequence
        
        elif special_type == "pattern":
            # Insert a pattern sequence
            patterns = [
                bytes([i % 256 for i in range(20)]),  # Incrementing
                bytes([255 - (i % 256) for i in range(20)]),  # Decrementing
                b"\xAA" * 10,  # 10101010
                b"\x55" * 10,  # 01010101
                b"\xFF" * 10,  # 11111111
                b"\x00" * 10,  # 00000000
            ]
            pattern = random.choice(patterns)
            
            # Insert at a random position
            index = random.randint(0, len(binary))
            binary[index:index] = pattern
        
        elif special_type == "format_string":
            # Insert format string patterns
            format_strings = [
                b"%s%s%s%s%n%n%n%n",
                b"%x%x%x%x",
                b"%p%p%p%p",
                b"%d%d%d%d",
                b"%.1024d",
                b"%n%n%n%n"
            ]
            fmt_str = random.choice(format_strings)
            
            # Insert at a random position
            index = random.randint(0, len(binary))
            binary[index:index] = fmt_str
        
        else:  # common_binary
            # Insert common binary sequences
            common_sequences = [
                b"ELF",  # ELF header
                b"PE\x00\x00",  # PE header
                b"MZ",  # DOS header
                b"PK\x03\x04",  # ZIP signature
                b"\x89PNG",  # PNG signature
                b"GIF8",  # GIF signature
                b"\xFF\xD8\xFF",  # JPEG signature
                b"ID3",  # MP3 ID3 signature
                b"<script>alert(1)</script>",  # XSS
                b"#!/bin/sh"  # Shebang
            ]
            sequence = random.choice(common_sequences)
            
            # Insert at a random position
            index = random.randint(0, len(binary))
            binary[index:index] = sequence
        
        return bytes(binary)
    
    def _mutate_bytes(self, node: SchemaNode, data: bytes) -> bytes:
        """Mutate bytes data."""
        # Delegate to binary mutation
        return self._mutate_binary(node, data)
    
    def _random_word(self, min_length: int = 2, max_length: int = 10) -> str:
        """Generate a random word."""
        length = random.randint(min_length, max_length)
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    def generate_mutation_corpus(self, seed_data: Any, count: int = 10,
                               output_dir: Optional[str] = None) -> List:
        """
        Generate a corpus of mutated test data from seed data.
        
        Args:
            seed_data: Seed data to mutate
            count: Number of mutations to generate
            output_dir: Optional directory to write instances to files
            
        Returns:
            List of mutated instances or file paths
        """
        corpus = []
        
        # Set the seed data
        self.set_seed_data(seed_data)
        
        # Create output directory if specified
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for i in range(count):
            # Generate mutation
            instance = self.mutate()
            
            if output_dir:
                # Write to file
                ext = self._get_file_extension()
                file_path = os.path.join(output_dir, f"mutation_{i:04d}{ext}")
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