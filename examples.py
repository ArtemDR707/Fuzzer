#!/usr/bin/env python3
"""
Examples of using the intelligent fuzzing grammars.

This script demonstrates how to use the grammar modules
to generate various types of test inputs for fuzzing.
"""

import os
import logging
import binascii
import json
from grammars import generate_input, generate_corpus, get_available_grammars

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("examples")

# Directory for examples
EXAMPLES_DIR = "./examples"
os.makedirs(EXAMPLES_DIR, exist_ok=True)


def hex_dump(data, max_length=100):
    """Create a hex dump of binary data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hex_str = binascii.hexlify(data[:max_length]).decode('ascii')
    formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    
    if len(data) > max_length:
        formatted += " ..."
        
    return formatted


def json_example():
    """Example of generating JSON inputs."""
    logger.info("=== JSON Example ===")
    
    # Generate a simple JSON object
    json_data = generate_input("json")
    logger.info(f"Simple JSON: {json_data}")
    
    # Generate a larger JSON object
    json_data = generate_input("json", min_size=200, max_size=500)
    logger.info(f"Larger JSON: {json_data[:100]}...")
    
    # Generate JSON with higher probability of edge cases
    json_data = generate_input("json", edge_case_probability=0.8)
    logger.info(f"Edge case JSON: {json_data}")
    
    # Generate and save a JSON corpus
    corpus_dir = os.path.join(EXAMPLES_DIR, "json_corpus")
    corpus = generate_corpus("json", count=3, output_dir=corpus_dir)
    logger.info(f"Generated JSON corpus: {len(corpus)} files in {corpus_dir}")


def xml_example():
    """Example of generating XML inputs."""
    logger.info("=== XML Example ===")
    
    # Generate a simple XML document
    xml_data = generate_input("xml")
    logger.info(f"Simple XML:\n{xml_data}")
    
    # Generate XML with higher probability of edge cases
    xml_data = generate_input("xml", edge_case_probability=0.8)
    logger.info(f"Edge case XML: {xml_data[:100]}...")
    
    # Generate and save an XML corpus
    corpus_dir = os.path.join(EXAMPLES_DIR, "xml_corpus")
    corpus = generate_corpus("xml", count=3, output_dir=corpus_dir)
    logger.info(f"Generated XML corpus: {len(corpus)} files in {corpus_dir}")


def command_example():
    """Example of generating command-line inputs."""
    logger.info("=== Command-line Example ===")
    
    # Generate a simple command-line input
    cmd_data = generate_input("command")
    logger.info(f"Simple command: {cmd_data}")
    
    # Generate a command with edge cases
    cmd_data = generate_input("command", edge_case_probability=0.8)
    logger.info(f"Edge case command: {cmd_data}")
    
    # Generate and save a command corpus
    corpus_dir = os.path.join(EXAMPLES_DIR, "command_corpus")
    corpus = generate_corpus("command", count=3, output_dir=corpus_dir)
    logger.info(f"Generated command corpus: {len(corpus)} files in {corpus_dir}")


def binary_example():
    """Example of generating binary inputs."""
    logger.info("=== Binary Example ===")
    
    # Generate different binary formats
    formats = ["raw", "elf", "pe", "zip", "png", "jpeg", "network", "protocol"]
    
    for fmt in formats:
        logger.info(f"--- {fmt.upper()} Format ---")
        
        # Generate a simple binary input
        binary_data = generate_input("binary", format_type=fmt)
        logger.info(f"Binary {fmt} ({len(binary_data)} bytes): {hex_dump(binary_data)}")
        
        # Save an example to file
        example_path = os.path.join(EXAMPLES_DIR, f"example_{fmt}.bin")
        with open(example_path, "wb") as f:
            f.write(binary_data)
        logger.info(f"Saved example to {example_path}")
        
    # Generate a network packet with specific parameters
    packet = generate_input("binary", format_type="network", min_size=100, max_size=200)
    logger.info(f"Custom network packet ({len(packet)} bytes): {hex_dump(packet)}")
    
    # Generate a small corpus of PE files
    corpus_dir = os.path.join(EXAMPLES_DIR, "pe_corpus")
    corpus = generate_corpus("binary", format_type="pe", count=3, output_dir=corpus_dir)
    logger.info(f"Generated PE corpus: {len(corpus)} files in {corpus_dir}")


def main():
    """Run the examples."""
    logger.info("Starting examples")
    
    # List available grammar types
    grammars = get_available_grammars()
    logger.info(f"Available grammars: {', '.join(grammars)}")
    
    # Run examples
    json_example()
    xml_example()
    command_example()
    binary_example()
    
    logger.info("Examples completed")


if __name__ == "__main__":
    main()