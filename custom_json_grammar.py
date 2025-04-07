"""
Custom JSON Grammar for Testing Crash Conditions

This module defines a specific JSON grammar targeting known crash scenarios in the test application.
"""

import random
import string
import json

def generate_long_string(min_len=100, max_len=10000):
    """Generate a long string for buffer overflow testing."""
    length = random.randint(min_len, max_len)
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_crash_json():
    """Generate JSON specifically designed to try to crash the target."""
    # Choose a crash type to target
    crash_type = random.choice(['magic', 'buffer_overflow', 'division_by_zero', 'recursion_depth', 'combined'])
    
    json_obj = {}
    
    if crash_type == 'magic' or crash_type == 'combined':
        # 50% chance of including the exact magic string that causes a crash
        if random.random() < 0.5:
            json_obj['magic'] = 'crash_me_now'
        else:
            # Add some variation for fuzzing
            prefix = random.choice(['crash_', 'crashme_', 'crash_me_', ''])
            suffix = random.choice(['now', 'today', 'please', 'here', ''])
            json_obj['magic'] = f"{prefix}{suffix}"
    
    if crash_type == 'buffer_overflow' or crash_type == 'combined':
        # Create buffer with lengths around the 100-character threshold
        buffer_len = random.choice([90, 95, 99, 100, 101, 105, 110, 200, 500, 1000])
        json_obj['buffer'] = ''.join(random.choice(string.ascii_letters) for _ in range(buffer_len))
    
    if crash_type == 'division_by_zero' or crash_type == 'combined':
        # Create values around zero for division testing
        divisor_options = [0, 0.0, -0.0, 0.00001, -0.00001, 1, -1, 0.1, -0.1]
        json_obj['divisor'] = random.choice(divisor_options)
    
    if crash_type == 'recursion_depth' or crash_type == 'combined':
        # Test recursion with values around the threshold
        depth_options = [500, 999, 1000, 1001, 1500, 2000, 5000]
        json_obj['depth'] = random.choice(depth_options)
    
    return json.dumps(json_obj)

def generate(mutation_probability=0.2):
    """
    Generate JSON data that targets crash conditions.
    
    Args:
        mutation_probability: Probability of generating a mutated sample
        
    Returns:
        str: Generated JSON data
    """
    # Use the specialized crash-targeting generator most of the time
    if random.random() < 0.8:
        return generate_crash_json()
    
    # Sometimes generate standard JSON objects
    obj = {}
    
    # Add a few random fields
    for _ in range(random.randint(1, 5)):
        key = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(3, 10)))
        value_type = random.choice(['string', 'number', 'boolean', 'null', 'array'])
        
        if value_type == 'string':
            # Occasionally generate a very long string
            if random.random() < 0.2:
                obj[key] = generate_long_string()
            else:
                obj[key] = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(3, 20)))
        elif value_type == 'number':
            # Sometimes generate values close to zero for division testing
            if random.random() < 0.3:
                obj[key] = random.choice([0, 0.0, 0.00001, -0.00001])
            else:
                obj[key] = random.uniform(-1000, 1000)
        elif value_type == 'boolean':
            obj[key] = random.choice([True, False])
        elif value_type == 'null':
            obj[key] = None
        elif value_type == 'array':
            array_len = random.randint(0, 5)
            obj[key] = [random.randint(-100, 100) for _ in range(array_len)]
    
    # Occasionally add special crash-inducing keys
    if random.random() < 0.3:
        obj['magic'] = random.choice(['crash_me_now', 'crashme', 'crash'])
    
    if random.random() < 0.3:
        obj['buffer'] = generate_long_string()
    
    if random.random() < 0.3:
        obj['divisor'] = random.choice([0, 0.0, -0.0, 0.00001, -0.00001])
    
    if random.random() < 0.3:
        obj['depth'] = random.choice([500, 999, 1000, 1001, 1500, 2000])
    
    return json.dumps(obj)

def generate_corpus(count=10, output_dir=None):
    """
    Generate a corpus of JSON files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write the files to
        
    Returns:
        list: List of generated JSON strings or file paths
    """
    import os
    
    corpus = []
    
    for i in range(count):
        json_data = generate()
        corpus.append(json_data)
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f"json_crash_test_{i}.json")
            with open(file_path, 'w') as f:
                f.write(json_data)
    
    return corpus