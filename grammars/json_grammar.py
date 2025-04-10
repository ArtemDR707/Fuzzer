"""
JSON Grammar for Intelligent Fuzzing

This module provides a grammar for generating JSON data for fuzzing.
It includes both valid and invalid JSON formats to test parser robustness.
"""

import random
import string
import json

# Maximum recursion depth for nested structures
MAX_DEPTH = 5

def generate_string(min_length=0, max_length=100, with_special=True):
    """Generate a random string."""
    length = random.randint(min_length, max_length)
    
    if with_special and random.random() < 0.2:
        # Include some problematic characters
        chars = string.printable
    else:
        # Normal alphanumeric strings
        chars = string.ascii_letters + string.digits + ' '
    
    # Sometimes add Unicode characters
    if with_special and random.random() < 0.1:
        # Add some non-ASCII Unicode characters
        chars += ''.join(chr(i) for i in range(0x100, 0x10FF, 100))
    
    return ''.join(random.choice(chars) for _ in range(length))

def generate_number():
    """Generate a random number."""
    number_type = random.choice(['int', 'float', 'special'])
    
    if number_type == 'int':
        return random.randint(-1000000, 1000000)
    elif number_type == 'float':
        return random.uniform(-1000.0, 1000.0)
    else:
        # Special numbers
        return random.choice([
            0, 1, -1, 
            float('inf'), float('-inf'), float('nan'),  # These will cause JSON encoding errors
            1e+100, -1e+100
        ])

def generate_boolean():
    """Generate a random boolean."""
    return random.choice([True, False])

def generate_null():
    """Generate a null value."""
    return None

def generate_array(depth=0):
    """Generate a random array."""
    if depth >= MAX_DEPTH:
        # Prevent excessive recursion
        return []
    
    length = random.randint(0, 10)
    array = []
    
    for _ in range(length):
        array.append(generate_value(depth + 1))
    
    return array

def generate_object(depth=0):
    """Generate a random object."""
    if depth >= MAX_DEPTH:
        # Prevent excessive recursion
        return {}
    
    count = random.randint(0, 10)
    obj = {}
    
    for _ in range(count):
        key = generate_string(min_length=1, max_length=20, with_special=False)
        obj[key] = generate_value(depth + 1)
    
    return obj

def generate_value(depth=0):
    """Generate a random JSON value."""
    if depth >= MAX_DEPTH:
        # Prevent excessive recursion
        return generate_simple_value()
    
    value_type = random.choice(['string', 'number', 'boolean', 'null', 'array', 'object'])
    
    if value_type == 'string':
        return generate_string()
    elif value_type == 'number':
        return generate_number()
    elif value_type == 'boolean':
        return generate_boolean()
    elif value_type == 'null':
        return generate_null()
    elif value_type == 'array':
        return generate_array(depth + 1)
    else:  # object
        return generate_object(depth + 1)

def generate_simple_value():
    """Generate a simple JSON value (non-recursive)."""
    value_type = random.choice(['string', 'number', 'boolean', 'null'])
    
    if value_type == 'string':
        return generate_string()
    elif value_type == 'number':
        return generate_number()
    elif value_type == 'boolean':
        return generate_boolean()
    else:  # null
        return generate_null()

def generate(valid=True):
    """
    Generate JSON data.
    
    Args:
        valid: Whether to generate valid JSON (if False, may generate invalid JSON)
        
    Returns:
        str: Generated JSON string
    """
    # Generate a JSON value
    value = random.choice([
        generate_object(),
        generate_array()
    ])
    
    # Convert to string
    try:
        json_str = json.dumps(value)
        
        # If we want to generate invalid JSON, randomly corrupt it
        if not valid and random.random() < 0.8:
            json_str = corrupt_json(json_str)
        
        return json_str
    except (TypeError, OverflowError):
        # Handle special values that can't be encoded
        if valid:
            # For valid mode, just return a simple valid JSON
            return json.dumps({"valid": True})
        else:
            # For invalid mode, return the unencoded value as a string
            return str(value)

def corrupt_json(json_str):
    """Corrupt a JSON string to make it invalid."""
    if not json_str:
        return '{}'
    
    corruption_type = random.choice([
        'remove_quotes',
        'remove_comma',
        'add_comma',
        'remove_brace',
        'unmatched_quotes',
        'extra_data',
        'truncate'
    ])
    
    if corruption_type == 'remove_quotes':
        # Remove a quote character
        if '"' in json_str:
            pos = json_str.find('"')
            return json_str[:pos] + json_str[pos+1:]
    
    elif corruption_type == 'remove_comma':
        # Remove a comma
        if ',' in json_str:
            pos = json_str.find(',')
            return json_str[:pos] + json_str[pos+1:]
    
    elif corruption_type == 'add_comma':
        # Add an extra comma
        if len(json_str) > 2:
            pos = random.randint(1, len(json_str) - 2)
            return json_str[:pos] + ',' + json_str[pos:]
    
    elif corruption_type == 'remove_brace':
        # Remove a brace or bracket
        braces = []
        for i, c in enumerate(json_str):
            if c in '{[]}':
                braces.append(i)
        
        if braces:
            pos = random.choice(braces)
            return json_str[:pos] + json_str[pos+1:]
    
    elif corruption_type == 'unmatched_quotes':
        # Add an unmatched quote
        if len(json_str) > 2:
            pos = random.randint(1, len(json_str) - 2)
            return json_str[:pos] + '"' + json_str[pos:]
    
    elif corruption_type == 'extra_data':
        # Add extra data after JSON
        return json_str + generate_string(min_length=1, max_length=10)
    
    elif corruption_type == 'truncate':
        # Truncate the JSON
        if len(json_str) > 10:
            return json_str[:random.randint(1, len(json_str) - 5)]
    
    # If corruption failed, return the original string
    return json_str

def generate_corpus(count=10, output_dir=None):
    """
    Generate a corpus of JSON files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write files to
        
    Returns:
        list: List of generated JSON strings or file paths
    """
    import os
    
    corpus = []
    
    for i in range(count):
        # Mostly valid JSON, but some invalid
        valid = random.random() < 0.8
        json_str = generate(valid=valid)
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f"json_seed_{i:04d}.json")
            with open(file_path, 'w') as f:
                f.write(json_str)
            corpus.append(file_path)
        else:
            corpus.append(json_str)
    
    return corpus