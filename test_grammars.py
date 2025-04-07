#!/usr/bin/env python3
"""
Test script for the grammar modules.

This script tests the grammar modules by generating sample inputs
and corpus files for each supported grammar type.
"""

import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("grammar_test")

# Import after logging is configured
from grammars import (
    generate_input, 
    generate_corpus, 
    get_available_grammars
)

# Create test directories
CORPUS_DIR = "./corpus"
os.makedirs(CORPUS_DIR, exist_ok=True)


def test_json_grammar():
    """Test the JSON grammar module."""
    logger.info("Testing JSON grammar")
    
    # Generate a single JSON input
    json_data = generate_input("json")
    logger.info(f"Generated JSON: {json_data[:100]}...")
    
    # Generate a JSON corpus
    corpus_dir = os.path.join(CORPUS_DIR, "json")
    corpus = generate_corpus("json", count=5, output_dir=corpus_dir)
    logger.info(f"Generated JSON corpus: {len(corpus)} items")


def test_xml_grammar():
    """Test the XML grammar module."""
    logger.info("Testing XML grammar")
    
    # Generate a single XML input
    xml_data = generate_input("xml")
    logger.info(f"Generated XML: {xml_data[:100]}...")
    
    # Generate an XML corpus
    corpus_dir = os.path.join(CORPUS_DIR, "xml")
    corpus = generate_corpus("xml", count=5, output_dir=corpus_dir)
    logger.info(f"Generated XML corpus: {len(corpus)} items")


def test_command_grammar():
    """Test the command-line grammar module."""
    logger.info("Testing command-line grammar")
    
    # Generate a single command input
    cmd_data = generate_input("command")
    logger.info(f"Generated command: {cmd_data}")
    
    # Generate a command corpus
    corpus_dir = os.path.join(CORPUS_DIR, "command")
    corpus = generate_corpus("command", count=5, output_dir=corpus_dir)
    logger.info(f"Generated command corpus: {len(corpus)} items")


def test_binary_grammar():
    """Test the binary grammar module."""
    logger.info("Testing binary grammar")
    
    # Test various binary formats
    binary_formats = ["raw", "elf", "pe", "zip", "png", "jpeg", "network", "protocol"]
    
    for fmt in binary_formats:
        logger.info(f"Testing binary format: {fmt}")
        
        # Generate a single binary input
        binary_data = generate_input("binary", format_type=fmt)
        logger.info(f"Generated {fmt} binary data: {len(binary_data)} bytes")
        
        # Also test direct format specification
        if fmt != "raw":
            binary_data2 = generate_input(fmt)
            logger.info(f"Direct {fmt} binary data: {len(binary_data2)} bytes")
        
        # Generate a binary corpus
        corpus_dir = os.path.join(CORPUS_DIR, "binary", fmt)
        corpus = generate_corpus("binary", format_type=fmt, count=3, output_dir=corpus_dir)
        logger.info(f"Generated {fmt} binary corpus: {len(corpus)} items")


def list_available_grammars():
    """List all available grammar types."""
    grammars = get_available_grammars()
    logger.info(f"Available grammars: {', '.join(grammars)}")
    
    # Check if modules work by generating a minimal example
    for grammar_type in grammars:
        try:
            data = generate_input(grammar_type)
            logger.info(f"Grammar '{grammar_type}' verified with a sample generation")
        except Exception as e:
            logger.error(f"Error verifying grammar '{grammar_type}': {e}")


def main():
    """Run the grammar tests."""
    logger.info("Starting grammar tests")
    
    list_available_grammars()
    
    test_json_grammar()
    test_xml_grammar()
    test_command_grammar()
    test_binary_grammar()
    
    logger.info("Grammar tests completed")
    

if __name__ == "__main__":
    main()