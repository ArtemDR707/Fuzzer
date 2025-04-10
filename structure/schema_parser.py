#!/usr/bin/env python3
"""
Schema Parser for Structure-Aware Fuzzing

This module provides schema parsing and representation for intelligent structure-aware fuzzing.
"""

import json
import enum
from typing import Any, Dict, List, Optional, Set, Union


class SchemaType(enum.Enum):
    """Types supported in schema definitions."""
    INTEGER = "integer"
    NUMBER = "number"
    STRING = "string"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    NULL = "null"
    ANY = "any"
    
    # Format-specific types
    TEXT = "text"
    BINARY = "binary"
    BYTES = "bytes"


class SchemaNode:
    """Base class for schema nodes."""
    
    def __init__(self, schema_type: SchemaType, description: Optional[str] = None,
                format: Optional[str] = None, pattern: Optional[str] = None,
                enum: Optional[List[Any]] = None, required: bool = True):
        """
        Initialize a schema node.
        
        Args:
            schema_type: Type of the node
            description: Optional description
            format: Optional format specifier
            pattern: Optional pattern (for strings)
            enum: Optional enumeration of allowed values
            required: Whether this node is required
        """
        self.schema_type = schema_type
        self.description = description
        self.format = format
        self.pattern = pattern
        self.enum = enum
        self.required = required
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the node to a dictionary."""
        result = {
            "type": self.schema_type.value
        }
        
        if self.description:
            result["description"] = self.description
        
        if self.format:
            result["format"] = self.format
        
        if self.pattern:
            result["pattern"] = self.pattern
        
        if self.enum:
            result["enum"] = self.enum
        
        if not self.required:
            result["required"] = False
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SchemaNode':
        """Create a node from a dictionary representation."""
        if not data:
            return cls(SchemaType.ANY)
        
        # Determine the type
        type_str = data.get("type", "any")
        try:
            schema_type = SchemaType(type_str)
        except ValueError:
            schema_type = SchemaType.ANY
        
        # Create specific node types based on schema_type
        if schema_type == SchemaType.OBJECT:
            return ObjectNode.from_dict(data)
        elif schema_type == SchemaType.ARRAY:
            return ArrayNode.from_dict(data)
        else:
            # Basic node types
            return cls(
                schema_type=schema_type,
                description=data.get("description"),
                format=data.get("format"),
                pattern=data.get("pattern"),
                enum=data.get("enum"),
                required=data.get("required", True)
            )


class ArrayNode(SchemaNode):
    """Schema node for arrays."""
    
    def __init__(self, items: Union[SchemaNode, Dict[str, Any]] = None,
                min_items: Optional[int] = None, max_items: Optional[int] = None,
                unique_items: bool = False, **kwargs):
        """
        Initialize an array node.
        
        Args:
            items: Schema for array items (can be a schema node or a dict)
            min_items: Minimum number of items
            max_items: Maximum number of items
            unique_items: Whether items must be unique
            **kwargs: Additional SchemaNode arguments
        """
        super().__init__(SchemaType.ARRAY, **kwargs)
        
        # If items is a dict, convert it to a SchemaNode
        if isinstance(items, dict):
            self.items = SchemaNode.from_dict(items)
        else:
            self.items = items or SchemaNode(SchemaType.ANY)
        
        self.min_items = min_items
        self.max_items = max_items
        self.unique_items = unique_items
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the array node to a dictionary."""
        result = super().to_dict()
        
        result["items"] = self.items.to_dict() if self.items else {}
        
        if self.min_items is not None:
            result["minItems"] = self.min_items
        
        if self.max_items is not None:
            result["maxItems"] = self.max_items
        
        if self.unique_items:
            result["uniqueItems"] = True
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ArrayNode':
        """Create an array node from a dictionary representation."""
        items_data = data.get("items", {})
        items = SchemaNode.from_dict(items_data) if items_data else None
        
        return cls(
            items=items,
            min_items=data.get("minItems"),
            max_items=data.get("maxItems"),
            unique_items=data.get("uniqueItems", False),
            description=data.get("description"),
            format=data.get("format"),
            required=data.get("required", True)
        )


class ObjectNode(SchemaNode):
    """Schema node for objects."""
    
    def __init__(self, properties: Dict[str, Dict[str, Any]] = None,
                required_props: List[str] = None, additional_properties: bool = True,
                min_properties: Optional[int] = None, max_properties: Optional[int] = None,
                **kwargs):
        """
        Initialize an object node.
        
        Args:
            properties: Dictionary of property names to schema nodes
            required_props: List of required property names
            additional_properties: Whether additional properties are allowed
            min_properties: Minimum number of properties
            max_properties: Maximum number of properties
            **kwargs: Additional SchemaNode arguments
        """
        super().__init__(SchemaType.OBJECT, **kwargs)
        
        # Convert property dicts to SchemaNodes
        self.properties = {}
        if properties:
            for name, prop_dict in properties.items():
                if isinstance(prop_dict, dict):
                    self.properties[name] = SchemaNode.from_dict(prop_dict)
                else:
                    self.properties[name] = prop_dict
        
        self.required_props = required_props or []
        self.additional_properties = additional_properties
        self.min_properties = min_properties
        self.max_properties = max_properties
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the object node to a dictionary."""
        result = super().to_dict()
        
        # Convert property SchemaNodes to dicts
        props_dict = {}
        for name, prop in self.properties.items():
            props_dict[name] = prop.to_dict()
        
        result["properties"] = props_dict
        
        if self.required_props:
            result["requiredProperties"] = self.required_props
        
        if not self.additional_properties:
            result["additionalProperties"] = False
        
        if self.min_properties is not None:
            result["minProperties"] = self.min_properties
        
        if self.max_properties is not None:
            result["maxProperties"] = self.max_properties
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ObjectNode':
        """Create an object node from a dictionary representation."""
        props_data = data.get("properties", {})
        properties = {}
        
        for name, prop_dict in props_data.items():
            properties[name] = SchemaNode.from_dict(prop_dict)
        
        return cls(
            properties=properties,
            required_props=data.get("requiredProperties") or data.get("required", []),
            additional_properties=data.get("additionalProperties", True),
            min_properties=data.get("minProperties"),
            max_properties=data.get("maxProperties"),
            description=data.get("description"),
            format=data.get("format"),
            required=data.get("required", True)
        )


class Schema:
    """Schema definition for a data format."""
    
    def __init__(self, root_node: SchemaNode, format_name: str,
                title: Optional[str] = None, description: Optional[str] = None):
        """
        Initialize a schema.
        
        Args:
            root_node: Root node of the schema
            format_name: Name of the format (json, xml, text, etc.)
            title: Optional title
            description: Optional description
        """
        self.root_node = root_node
        self.format_name = format_name
        self.title = title
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the schema to a dictionary."""
        result = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "format": self.format_name
        }
        
        if self.title:
            result["title"] = self.title
        
        if self.description:
            result["description"] = self.description
        
        # Add root node properties
        result.update(self.root_node.to_dict())
        
        return result
    
    def to_json(self) -> str:
        """Convert the schema to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Schema':
        """Create a schema from a dictionary representation."""
        # Get format name
        format_name = data.get("format", "json")
        
        # Create root node
        root_node = SchemaNode.from_dict(data)
        
        return cls(
            root_node=root_node,
            format_name=format_name,
            title=data.get("title"),
            description=data.get("description")
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Schema':
        """Create a schema from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


def json_basic_schema() -> Schema:
    """Create a basic JSON schema."""
    root = ObjectNode(
        properties={
            "id": SchemaNode(SchemaType.INTEGER, description="Identifier"),
            "name": SchemaNode(SchemaType.STRING, description="Name"),
            "data": ArrayNode(
                items=SchemaNode(SchemaType.ANY),
                description="Data array"
            )
        },
        required_props=["id"],
        description="Basic JSON object"
    )
    
    return Schema(
        root_node=root,
        format_name="json",
        title="Basic JSON Schema",
        description="A simple schema for JSON data"
    )


def xml_basic_schema() -> Schema:
    """Create a basic XML schema."""
    root = ObjectNode(
        properties={
            "root": ObjectNode(
                properties={
                    "element": ArrayNode(
                        items=SchemaNode(SchemaType.STRING),
                        description="XML elements"
                    ),
                    "attribute": SchemaNode(SchemaType.STRING, description="Attribute")
                },
                description="Root element"
            )
        },
        description="XML document"
    )
    
    return Schema(
        root_node=root,
        format_name="xml",
        title="Basic XML Schema",
        description="A simple schema for XML data"
    )


def text_basic_schema() -> Schema:
    """Create a basic text schema."""
    root = SchemaNode(
        schema_type=SchemaType.TEXT,
        description="Text content"
    )
    
    return Schema(
        root_node=root,
        format_name="text",
        title="Basic Text Schema",
        description="A simple schema for text data"
    )


def binary_basic_schema() -> Schema:
    """Create a basic binary schema."""
    root = SchemaNode(
        schema_type=SchemaType.BINARY,
        description="Binary content"
    )
    
    return Schema(
        root_node=root,
        format_name="binary",
        title="Basic Binary Schema",
        description="A simple schema for binary data"
    )