"""
XML Grammar for Intelligent Fuzzing

This module provides a grammar for generating XML data for fuzzing.
It includes both valid and invalid XML formats to test parser robustness.
"""

import random
import string
import re
from xml.sax.saxutils import escape as xml_escape

# Maximum recursion depth for nested elements
MAX_DEPTH = 5
# Maximum number of attributes per element
MAX_ATTRIBUTES = 5
# Maximum number of child elements
MAX_CHILDREN = 10

def generate_tag_name(min_length=1, max_length=10):
    """Generate a random XML tag name."""
    length = random.randint(min_length, max_length)
    
    # First character must be letter or underscore
    first_char = random.choice(string.ascii_letters + '_')
    
    # Remaining characters can be letters, digits, underscores, hyphens, periods
    if length > 1:
        rest = ''.join(random.choice(string.ascii_letters + string.digits + '_-.') 
                      for _ in range(length - 1))
        return first_char + rest
    else:
        return first_char

def generate_attribute_name(min_length=1, max_length=10):
    """Generate a random XML attribute name."""
    return generate_tag_name(min_length, max_length)

def generate_text_content(min_length=0, max_length=50, with_special=True):
    """Generate random text content for XML elements."""
    length = random.randint(min_length, max_length)
    
    if length == 0:
        return ""
    
    if with_special and random.random() < 0.2:
        # Include some problematic characters that need escaping
        chars = string.printable
        text = ''.join(random.choice(chars) for _ in range(length))
        return xml_escape(text)
    else:
        # Normal alphanumeric strings
        chars = string.ascii_letters + string.digits + ' '
        return ''.join(random.choice(chars) for _ in range(length))

def generate_attribute_value(min_length=0, max_length=20, with_special=True):
    """Generate a random XML attribute value."""
    return generate_text_content(min_length, max_length, with_special)

def generate_element(depth=0, with_declaration=True):
    """
    Generate a random XML element with optional children.
    
    Args:
        depth: Current recursion depth
        with_declaration: Whether to include XML declaration
        
    Returns:
        str: Generated XML element
    """
    if depth >= MAX_DEPTH:
        # Prevent excessive recursion by returning a simple element
        tag = generate_tag_name()
        content = generate_text_content()
        return f"<{tag}>{content}</{tag}>"
    
    # Generate element name
    tag = generate_tag_name()
    
    # Generate attributes
    attributes = {}
    attr_count = random.randint(0, min(MAX_ATTRIBUTES, 3 if depth < 2 else 1))
    for _ in range(attr_count):
        attr_name = generate_attribute_name()
        attr_value = generate_attribute_value()
        attributes[attr_name] = attr_value
    
    # Format attributes string
    attrs_str = " ".join(f'{name}="{value}"' for name, value in attributes.items())
    if attrs_str:
        attrs_str = " " + attrs_str
    
    # Decide element type
    element_type = random.choice(['empty', 'text', 'nested'])
    
    if element_type == 'empty':
        # Empty element
        return f"<{tag}{attrs_str}/>"
    
    elif element_type == 'text':
        # Element with text content
        content = generate_text_content()
        return f"<{tag}{attrs_str}>{content}</{tag}>"
    
    else:  # nested
        # Element with child elements
        child_count = random.randint(0, min(MAX_CHILDREN, 5 if depth < 1 else 2))
        
        children = []
        for _ in range(child_count):
            children.append(generate_element(depth + 1, False))
        
        content = "\n" + "\n".join(children) + "\n"
        return f"<{tag}{attrs_str}>{content}</{tag}>"

def generate(valid=True):
    """
    Generate XML data.
    
    Args:
        valid: Whether to generate valid XML (if False, may generate invalid XML)
        
    Returns:
        str: Generated XML string
    """
    # Generate XML declaration
    declaration = '<?xml version="1.0" encoding="UTF-8"?>'
    
    # Generate root element
    root = generate_element(0, False)
    
    # Combine declaration and root
    xml_data = declaration + "\n" + root
    
    # If we want to generate invalid XML, randomly corrupt it
    if not valid and random.random() < 0.8:
        xml_data = corrupt_xml(xml_data)
    
    return xml_data

def corrupt_xml(xml_data):
    """Corrupt an XML string to make it invalid."""
    if not xml_data:
        return '<?xml version="1.0"?><root/>'
    
    corruption_type = random.choice([
        'remove_bracket',
        'unmatched_tag',
        'invalid_attribute',
        'unclosed_tag',
        'extra_bracket',
        'unclosed_attribute',
        'invalid_character',
        'duplicate_attribute',
        'nested_error'
    ])
    
    if corruption_type == 'remove_bracket':
        # Remove a bracket character
        brackets = []
        for i, c in enumerate(xml_data):
            if c in '<>/':
                brackets.append(i)
        
        if brackets:
            pos = random.choice(brackets)
            return xml_data[:pos] + xml_data[pos+1:]
    
    elif corruption_type == 'unmatched_tag':
        # Create an unmatched tag
        tags = re.findall(r'<(\w+)[^>]*>', xml_data)
        if tags:
            tag = random.choice(tags)
            if f"</{tag}>" in xml_data:
                return xml_data.replace(f"</{tag}>", f"</{tag}X>", 1)
    
    elif corruption_type == 'invalid_attribute':
        # Insert an invalid attribute
        if "<" in xml_data and ">" in xml_data:
            pos = xml_data.find(">", xml_data.find("<"))
            if pos > 0 and xml_data[pos-1] != '/':
                invalid_attr = f' {generate_attribute_name()}='
                return xml_data[:pos] + invalid_attr + xml_data[pos:]
    
    elif corruption_type == 'unclosed_tag':
        # Remove a closing tag
        closing_tags = list(re.finditer(r'</\w+>', xml_data))
        if closing_tags:
            match = random.choice(closing_tags)
            return xml_data[:match.start()] + xml_data[match.end():]
    
    elif corruption_type == 'extra_bracket':
        # Add an extra bracket
        pos = random.randint(0, len(xml_data) - 1)
        bracket = random.choice(['<', '>', '/'])
        return xml_data[:pos] + bracket + xml_data[pos:]
    
    elif corruption_type == 'unclosed_attribute':
        # Make an attribute unclosed
        attr_quotes = list(re.finditer(r'=("[^"]*"|\'[^\']*\')', xml_data))
        if attr_quotes:
            match = random.choice(attr_quotes)
            quote_end = match.end()
            return xml_data[:quote_end-1] + xml_data[quote_end:]
    
    elif corruption_type == 'invalid_character':
        # Insert an invalid XML character
        pos = random.randint(0, len(xml_data) - 1)
        invalid_char = chr(random.choice([0x00, 0x1F]))  # Control characters are invalid in XML
        return xml_data[:pos] + invalid_char + xml_data[pos:]
    
    elif corruption_type == 'duplicate_attribute':
        # Add a duplicate attribute
        tags_with_attrs = list(re.finditer(r'<\w+\s+([^>]+)>', xml_data))
        if tags_with_attrs:
            match = random.choice(tags_with_attrs)
            attrs_text = match.group(1)
            attr_matches = list(re.finditer(r'(\w+)=', attrs_text))
            if attr_matches:
                attr_match = random.choice(attr_matches)
                attr_name = attr_match.group(1)
                tag_end = match.end()
                tag_start = match.start()
                
                # Find position to insert duplicate
                pos = xml_data.rfind(">", tag_start, tag_end)
                if pos > 0:
                    duplicate = f' {attr_name}="duplicate"'
                    return xml_data[:pos] + duplicate + xml_data[pos:]
    
    elif corruption_type == 'nested_error':
        # Create improperly nested tags
        tags = re.findall(r'<(\w+)[^>]*>', xml_data)
        if len(tags) >= 2:
            tag1, tag2 = random.sample(tags, 2)
            if f"</{tag1}>" in xml_data and f"</{tag2}>" in xml_data:
                # Find positions
                open1 = xml_data.find(f"<{tag1}")
                close1 = xml_data.find(f"</{tag1}>", open1)
                open2 = xml_data.find(f"<{tag2}")
                close2 = xml_data.find(f"</{tag2}>", open2)
                
                # Check if we can create overlapping tags
                if open1 < open2 < close1 < close2:
                    # Swap closing tags
                    part1 = xml_data[:close1]
                    part2 = xml_data[close1:close2].replace(f"</{tag1}>", f"</{tag2}>")
                    part3 = xml_data[close2:].replace(f"</{tag2}>", f"</{tag1}>", 1)
                    return part1 + part2 + part3
    
    # If corruption failed, return the original string
    return xml_data

def generate_corpus(count=10, output_dir=None):
    """
    Generate a corpus of XML files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write files to
        
    Returns:
        list: List of generated XML strings or file paths
    """
    import os
    
    corpus = []
    
    for i in range(count):
        # Mostly valid XML, but some invalid
        valid = random.random() < 0.8
        xml_str = generate(valid=valid)
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f"xml_seed_{i:04d}.xml")
            with open(file_path, 'w') as f:
                f.write(xml_str)
            corpus.append(file_path)
        else:
            corpus.append(xml_str)
    
    return corpus