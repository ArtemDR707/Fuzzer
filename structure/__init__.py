"""
Structure-Aware Fuzzing Package

This package provides tools for schema-based, structure-aware fuzzing.
It includes schema parsing, format inference, and intelligent data generation
based on structural understanding of formats.
"""

# Import schema types for direct access
from .schema_parser import (
    Schema,
    SchemaNode,
    SchemaType,
    ObjectNode,
    ArrayNode
)

# Import core components
from .format_inferrer import FormatInferrer
from .structure_aware_generator import StructureAwareGenerator
from .structure_aware_mutator import StructureAwareMutator