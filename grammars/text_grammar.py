#!/usr/bin/env python3
"""
Text Grammar for Intelligent Fuzzing

This module provides grammar and generation functions for text content fuzzing.
It includes various text patterns, control characters, and text manipulation techniques
that are likely to trigger issues in applications processing text data.
"""

import os
import random
import string
import re
import codecs
from datetime import datetime

# Patterns that might cause issues in text processing
CONTROL_CHARS = ''.join(chr(i) for i in range(32) if i not in (9, 10, 13))  # All control chars except tab, LF, CR
UNICODE_PROBLEMATIC = '\u200B\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069\uFEFF'  # Zero-width, direction controls, BOM
LONG_SEQUENCES = ['A' * n for n in (100, 1000, 10000, 100000)]
FORMAT_STRINGS = ['%s', '%d', '%x', '%n', '%p', '%.100000f', '{0}', '{0:d}', '{0!r}', '${0}']
REGEX_PATTERNS = ['(a+)+$', '\\1', '[\\w-]+', '(?:a|a?)+', '(?:.*)+', 'a{1,10000}']

# Common injection patterns
SQL_INJECTIONS = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users WHERE '1'='1"]
COMMAND_INJECTIONS = ["; ls -la", "|| cat /etc/passwd", "`id`", "$(id)", "&& echo pwned"]
PATH_TRAVERSALS = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\SAM"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"]

def generate_random_bytes(min_len=10, max_len=1000):
    """Generate random bytes that might be interpreted as text."""
    length = random.randint(min_len, max_len)
    return os.urandom(length)

def generate_random_unicode(min_len=5, max_len=100):
    """Generate random Unicode characters."""
    length = random.randint(min_len, max_len)
    # Generate from various Unicode ranges that might be problematic
    ranges = [
        (0x20, 0x7F),   # ASCII
        (0x80, 0xFF),   # Latin-1 Supplement
        (0x100, 0x17F), # Latin Extended-A
        (0x2500, 0x257F), # Box drawing characters
        (0x3000, 0x303F), # CJK Symbols and Punctuation
        (0x10000, 0x10FFF) # Linear B Syllabary
    ]
    
    result = []
    for _ in range(length):
        start, end = random.choice(ranges)
        char_code = random.randint(start, end)
        try:
            result.append(chr(char_code))
        except (ValueError, OverflowError):
            # Fall back to ASCII if we hit an invalid code point
            result.append(random.choice(string.printable))
    
    return ''.join(result)

def generate_format_string_attack():
    """Generate format string attacks."""
    formats = random.sample(FORMAT_STRINGS, random.randint(1, len(FORMAT_STRINGS)))
    return ' '.join(formats)

def generate_regex_catastrophe():
    """Generate strings that might cause regex catastrophic backtracking."""
    pattern = random.choice(REGEX_PATTERNS)
    # Generate a string that matches the pattern but might cause backtracking
    if 'a+' in pattern:
        return 'a' * random.randint(10, 1000)
    elif '\\w' in pattern:
        return ''.join(random.choice(string.ascii_letters + string.digits + '_') for _ in range(random.randint(10, 500)))
    else:
        return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(10, 500)))

def generate_long_lines():
    """Generate very long lines that might overflow buffers."""
    char = random.choice(string.printable)
    return char * random.randint(1000, 10000)

def generate_weird_whitespace():
    """Generate strings with weird whitespace patterns."""
    spaces = [' ', '\t', '\n', '\r', '\f', '\v', '\u00A0', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u3000']
    return ''.join(random.choice(spaces) for _ in range(random.randint(10, 100)))

def generate_text_with_nulls():
    """Generate text with embedded null characters."""
    text = ''.join(random.choice(string.printable) for _ in range(random.randint(10, 100)))
    # Insert null bytes at random positions
    positions = sorted(random.sample(range(len(text)), random.randint(1, min(10, len(text)))))
    result = list(text)
    for pos in positions:
        result.insert(pos, '\0')
    return ''.join(result)

def generate_encoding_tricks():
    """Generate text with various encoding tricks."""
    text = ''.join(random.choice(string.printable) for _ in range(random.randint(10, 50)))
    tricks = [
        # UTF-16 encoding
        codecs.encode(text, 'utf-16').decode('latin1'),
        # UTF-8 BOM + text
        '\ufeff' + text,
        # Bidirectional text
        'English ' + '\u202E' + 'txet esreveR' + '\u202C' + ' more English',
        # Zero-width characters inserted
        ''.join(c + random.choice(['\u200B', '']) for c in text)
    ]
    return random.choice(tricks)

def generate_control_char_sequence():
    """Generate a sequence with control characters."""
    normal_text = ''.join(random.choice(string.printable) for _ in range(random.randint(5, 20)))
    control_sequence = ''.join(random.choice(CONTROL_CHARS) for _ in range(random.randint(1, 10)))
    
    # Mix control characters into normal text at random positions
    positions = sorted(random.sample(range(len(normal_text) + 1), random.randint(1, min(5, len(normal_text) + 1))))
    result = list(normal_text)
    
    for i, pos in enumerate(positions):
        result.insert(pos + i, control_sequence[i % len(control_sequence)])
    
    return ''.join(result)

def generate_injection_attack():
    """Generate a string that looks like an injection attack."""
    attack_types = [SQL_INJECTIONS, COMMAND_INJECTIONS, PATH_TRAVERSALS, XSS_PAYLOADS]
    attack_type = random.choice(attack_types)
    return random.choice(attack_type)

def generate(valid=True):
    """
    Generate a random text string using one of the generation methods.
    
    Args:
        valid: If True, generate more likely valid text; if False, generate more problematic text
        
    Returns:
        str: Generated text string
    """
    if valid:
        # For valid text, prioritize less problematic generators
        generators = [
            lambda: generate_random_unicode(min_len=5, max_len=50),  # Shorter strings
            lambda: ''.join(random.choice(string.printable) for _ in range(random.randint(10, 100))),  # ASCII text
            lambda: '\n'.join(''.join(random.choice(string.ascii_letters + ' ') for _ in range(random.randint(5, 30))) 
                           for _ in range(random.randint(1, 5))),  # Simple paragraphs
            lambda: generate_weird_whitespace()  # Less likely to cause issues
        ]
    else:
        # For invalid text, use more problematic generators
        generators = [
            generate_format_string_attack,
            generate_regex_catastrophe,
            generate_long_lines,
            lambda: generate_random_unicode(min_len=100, max_len=1000),  # Longer unicode
            generate_text_with_nulls,
            generate_encoding_tricks,
            generate_control_char_sequence,
            generate_injection_attack
        ]
    
    return random.choice(generators)()

def generate_corpus(count=10, output_dir=None):
    """
    Generate a corpus of text files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write the files to
        
    Returns:
        list: List of generated text strings or file paths
    """
    result = []
    
    for i in range(count):
        # 80% chance of using our generators, 20% chance of using realistic text
        if random.random() < 0.8:
            generator = random.choice([
                generate_random_unicode,
                generate_format_string_attack,
                generate_regex_catastrophe,
                generate_long_lines,
                generate_weird_whitespace,
                generate_text_with_nulls,
                generate_encoding_tricks,
                generate_control_char_sequence,
                generate_injection_attack
            ])
            text = generator()
        else:
            # Generate more realistic text content
            paragraphs = random.randint(1, 5)
            text = []
            for _ in range(paragraphs):
                sentences = random.randint(1, 10)
                paragraph = []
                for _ in range(sentences):
                    words = random.randint(3, 15)
                    sentence = ' '.join(''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(2, 10))) 
                                    for _ in range(words))
                    sentence = sentence.capitalize() + random.choice(['.', '!', '?', '...'])
                    paragraph.append(sentence)
                text.append(' '.join(paragraph))
            text = '\n\n'.join(text)
        
        if output_dir:
            file_path = os.path.join(output_dir, f"text_seed_{i:04d}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(text)
            result.append(file_path)
        else:
            result.append(text)
    
    return result

if __name__ == "__main__":
    # Test the grammar by generating some samples
    for i in range(5):
        sample = generate()
        print(f"Sample {i+1}:\n{sample[:100]}...\n")
