"""
Generic Grammar for Intelligent Fuzzing

This module provides a grammar for generating generic inputs for fuzzing.
It includes various patterns that are commonly used to trigger software bugs.
"""

import os
import random
import string

def random_string(min_length=1, max_length=100):
    """Generate a random string."""
    length = random.randint(min_length, max_length)
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def generate_format_string():
    """Generate a format string that might cause bugs."""
    formats = ['%s', '%d', '%x', '%p', '%n', '%s%s%s%s%s']
    return random.choice(formats) * random.randint(1, 100)

def generate_buffer_overflow():
    """Generate a string that might cause buffer overflow."""
    return 'A' * random.randint(100, 10000)

def generate_integer_overflow():
    """Generate integer values that might cause overflow."""
    return str(random.choice([2**31-1, 2**31, 2**32-1, 2**32, 2**63-1, 2**63, 2**64-1, 2**64]))

def generate(valid=True):
    """
    Generate generic input data.
    
    Args:
        valid: Whether to generate valid input (if False, may generate malicious input)
        
    Returns:
        str: Generated input string
    """
    if valid or random.random() < 0.7:  # 70% chance of valid input even when valid=False
        return random_string(1, 100)
    else:
        # Generate potentially problematic input
        choices = [
            generate_format_string,
            generate_buffer_overflow,
            generate_integer_overflow,
            lambda: '../' * random.randint(1, 10) + 'etc/passwd',  # Path traversal
            lambda: '`cat /etc/passwd`',  # Command injection
            lambda: "'; DROP TABLE users; --",  # SQL injection
            lambda: '<script>alert(1)</script>',  # XSS
        ]
        return random.choice(choices)()

def generate_corpus(count=10, output_dir=None):
    """
    Generate a corpus of generic files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write files to
        
    Returns:
        list: List of generated strings or file paths
    """
    corpus = []
    for i in range(count):
        data = generate(valid=random.random() < 0.8)  # 80% valid inputs
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f"generic_seed_{i:04d}.txt")
            with open(file_path, 'w') as f:
                f.write(data)
            corpus.append(file_path)
        else:
            corpus.append(data)
    return corpus
