"""
Grammar Package for Intelligent Fuzzing

This package contains grammar definitions for different input formats
used in fuzzing. Grammars are used to generate structured inputs that
are more likely to find bugs than random inputs.
"""

import os
import sys
import importlib.util
import importlib
from types import ModuleType
import logging

logger = logging.getLogger(__name__)

# Define available grammar types
GRAMMAR_TYPES = ['json', 'xml', 'command', 'binary']

# Storage for loaded grammar modules
_grammar_modules = {}

def load_grammar(grammar_type):
    """
    Load a grammar module by type.
    
    Args:
        grammar_type: Type of grammar to load (json, xml, command, binary)
        
    Returns:
        module: Loaded grammar module or None if not found
    """
    global _grammar_modules
    
    # Return cached module if available
    if grammar_type in _grammar_modules:
        return _grammar_modules[grammar_type]
    
    # Check if grammar type is valid
    if grammar_type not in GRAMMAR_TYPES:
        logger.error(f"Unknown grammar type: {grammar_type}")
        return None
    
    # Try to import the module
    try:
        module_name = f"grammars.{grammar_type}_grammar"
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            logger.error(f"Grammar module not found: {module_name}")
            return None
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Cache the module
        _grammar_modules[grammar_type] = module
        return module
        
    except Exception as e:
        logger.error(f"Error loading grammar module {grammar_type}: {e}")
        return None

def get_json_grammar():
    """Get the JSON grammar module."""
    module = load_grammar('json')
    if module is None:
        logger.error("JSON grammar module not available")
    return module

def get_xml_grammar():
    """Get the XML grammar module."""
    module = load_grammar('xml')
    if module is None:
        logger.error("XML grammar module not available")
    return module

def get_command_grammar():
    """Get the command-line grammar module."""
    module = load_grammar('command')
    if module is None:
        logger.error("Command grammar module not available")
    return module

def get_binary_grammar():
    """Get the binary grammar module."""
    module = load_grammar('binary')
    if module is None:
        logger.error("Binary grammar module not available")
    return module

def list_available_grammars():
    """
    List all available grammar modules.
    
    Returns:
        list: Names of available grammar modules
    """
    available = []
    for grammar_type in GRAMMAR_TYPES:
        module = load_grammar(grammar_type)
        if module is not None:
            available.append(grammar_type)
    
    return available