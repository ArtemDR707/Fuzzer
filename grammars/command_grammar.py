"""
Command Grammar for Intelligent Fuzzing

This module provides a grammar for generating command-line arguments
for fuzzing command-line applications.
"""

import random
import string
import os
import re

def generate_option_name(long_form=False):
    """Generate a random option name."""
    if long_form:
        # Long option (--option)
        length = random.randint(3, 15)
        name = ''.join(random.choice(string.ascii_lowercase + string.digits + '-') for _ in range(length))
        return f"--{name}"
    else:
        # Short option (-o)
        return f"-{random.choice(string.ascii_lowercase)}"

def generate_option_value(option_type=None):
    """Generate a random option value."""
    if option_type is None:
        option_type = random.choice(['string', 'number', 'file', 'path', 'boolean'])
    
    if option_type == 'string':
        length = random.randint(1, 30)
        return ''.join(random.choice(string.ascii_letters + string.digits + '_-.') for _ in range(length))
    
    elif option_type == 'number':
        if random.random() < 0.8:
            # Integer
            return str(random.randint(-1000000, 1000000))
        else:
            # Float
            return str(random.uniform(-1000.0, 1000.0))
    
    elif option_type == 'file':
        # Generate a random filename
        extensions = ['.txt', '.json', '.xml', '.csv', '.dat', '.bin', '.cfg']
        name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(3, 10)))
        return name + random.choice(extensions)
    
    elif option_type == 'path':
        # Generate a random path
        depth = random.randint(1, 3)
        parts = []
        for _ in range(depth):
            part = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(3, 8)))
            parts.append(part)
        return os.path.join(*parts)
    
    elif option_type == 'boolean':
        # Boolean options often don't need values, just return empty string
        return ""

def generate_option(program_type=None):
    """Generate a random command-line option."""
    # Decide if it's a long or short option
    long_form = random.random() < 0.7
    
    # Generate option name
    option = generate_option_name(long_form)
    
    # For some program types, use more realistic options
    if program_type == 'compression':
        option = random.choice(['-c', '-d', '-k', '-f', '-v', '--keep', '--force', '--verbose'])
    elif program_type == 'text_processing':
        option = random.choice(['-n', '-E', '-i', '-v', '-w', '-x', '--line-number', '--regexp', '--ignore-case'])
    elif program_type == 'file_utility':
        option = random.choice(['-r', '-f', '-a', '-m', '-t', '--recursive', '--force', '--all', '--type'])
    
    # Decide if option takes a value
    if random.random() < 0.7:
        # Option with value
        option_type = random.choice(['string', 'number', 'file', 'path'])
        value = generate_option_value(option_type)
        
        # Format option and value
        if random.random() < 0.5 and long_form:
            # --option=value format
            return f"{option}={value}"
        else:
            # --option value format
            return f"{option} {value}"
    else:
        # Flag option (no value)
        return option

def generate_command_line(program=None, num_options=None, program_type=None):
    """
    Generate a random command-line.
    
    Args:
        program: Optional program name (if None, a random one is generated)
        num_options: Number of options to generate (if None, random 0-10)
        program_type: Type of program to simulate (affects option generation)
        
    Returns:
        str: Generated command line
    """
    if program is None:
        # Generate a random program name
        program = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(2, 10)))
    
    if num_options is None:
        num_options = random.randint(0, 10)
    
    # Generate options
    options = []
    for _ in range(num_options):
        options.append(generate_option(program_type))
    
    # Sometimes add positional arguments
    if random.random() < 0.7:
        num_args = random.randint(1, 3)
        for _ in range(num_args):
            arg_type = random.choice(['file', 'string', 'path'])
            options.append(generate_option_value(arg_type))
    
    # Combine program and options
    command = program + " " + " ".join(options)
    
    return command

def extract_options_from_help(help_text):
    """
    Extract command-line options from help text.
    
    Args:
        help_text: Help text output from a program
        
    Returns:
        list: List of extracted options
    """
    options = []
    
    # Look for option patterns in the help text
    # Common patterns: -h, --help, -v, --verbose, etc.
    short_opt_pattern = r'-([a-zA-Z0-9])\b'
    long_opt_pattern = r'--([a-zA-Z0-9][-a-zA-Z0-9]*)'
    
    # Extract short options
    short_opts = re.findall(short_opt_pattern, help_text)
    for opt in short_opts:
        options.append(f"-{opt}")
    
    # Extract long options
    long_opts = re.findall(long_opt_pattern, help_text)
    for opt in long_opts:
        options.append(f"--{opt}")
    
    return options

def generate_command_from_help(program, help_text, use_real_options=True):
    """
    Generate a command line based on help text.
    
    Args:
        program: Program name
        help_text: Help text from the program
        use_real_options: Whether to use options extracted from help text
        
    Returns:
        str: Generated command line
    """
    # Extract options from help text
    if use_real_options:
        extracted_options = extract_options_from_help(help_text)
        
        # Generate a command line with extracted options
        if extracted_options:
            # Choose a random subset of options
            num_options = random.randint(1, min(5, len(extracted_options)))
            selected_options = random.sample(extracted_options, num_options)
            
            # Add values to some options
            command_parts = [program]
            for option in selected_options:
                if random.random() < 0.5 and option.startswith("--"):
                    # Add a value to this option
                    option_type = random.choice(['string', 'number', 'file', 'path'])
                    value = generate_option_value(option_type)
                    if random.random() < 0.5:
                        # --option=value format
                        command_parts.append(f"{option}={value}")
                    else:
                        # --option value format
                        command_parts.append(option)
                        command_parts.append(value)
                else:
                    # Just add the option as is
                    command_parts.append(option)
            
            # Add positional arguments if needed
            if random.random() < 0.5:
                num_args = random.randint(1, 2)
                for _ in range(num_args):
                    arg_type = random.choice(['file', 'string'])
                    command_parts.append(generate_option_value(arg_type))
            
            return " ".join(command_parts)
    
    # Fallback to random generation
    return generate_command_line(program)

def generate(valid=True):
    """
    Generate a command-line string.
    
    Args:
        valid: Whether to generate valid command-line (if False, may generate invalid)
        
    Returns:
        str: Generated command-line string
    """
    # Choose a common program type
    program_type = random.choice([
        'compression',
        'text_processing',
        'file_utility',
        'network',
        None  # Generic
    ])
    
    # Choose a program based on type
    if program_type == 'compression':
        program = random.choice(['gzip', 'tar', 'zip', 'bzip2', 'xz'])
    elif program_type == 'text_processing':
        program = random.choice(['grep', 'sed', 'awk', 'cut', 'tr'])
    elif program_type == 'file_utility':
        program = random.choice(['ls', 'cp', 'mv', 'rm', 'find'])
    elif program_type == 'network':
        program = random.choice(['curl', 'wget', 'ssh', 'telnet', 'nc'])
    else:
        # Generate random program name
        program = ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(2, 10)))
    
    # Generate valid command-line
    command = generate_command_line(program, program_type=program_type)
    
    # For invalid commands, corrupt the command line
    if not valid and random.random() < 0.8:
        command = corrupt_command(command)
    
    return command

def corrupt_command(command):
    """Corrupt a command-line to make it potentially invalid."""
    corruption_type = random.choice([
        'remove_dash',
        'add_dash',
        'duplicate_option',
        'remove_value',
        'add_garbage',
        'add_unicode'
    ])
    
    if corruption_type == 'remove_dash':
        # Remove a dash from an option
        if '-' in command:
            parts = command.split()
            for i, part in enumerate(parts):
                if part.startswith('-') and len(part) > 1:
                    # Remove one dash
                    parts[i] = part[1:]
                    break
            return ' '.join(parts)
    
    elif corruption_type == 'add_dash':
        # Add an extra dash to a non-option
        parts = command.split()
        for i, part in enumerate(parts):
            if not part.startswith('-') and i > 0:
                # Add a dash
                parts[i] = '-' + part
                break
        return ' '.join(parts)
    
    elif corruption_type == 'duplicate_option':
        # Duplicate an option
        parts = command.split()
        for part in parts:
            if part.startswith('-'):
                # Duplicate this option
                return command + ' ' + part
    
    elif corruption_type == 'remove_value':
        # Remove a value after an option
        parts = command.split()
        for i, part in enumerate(parts):
            if part.startswith('-') and i < len(parts) - 1 and not parts[i+1].startswith('-'):
                # Remove the value
                return ' '.join(parts[:i+1] + parts[i+2:])
    
    elif corruption_type == 'add_garbage':
        # Add some garbage characters
        garbage = ''.join(random.choice(string.punctuation) for _ in range(random.randint(1, 5)))
        pos = random.randint(0, len(command) - 1)
        return command[:pos] + garbage + command[pos:]
    
    elif corruption_type == 'add_unicode':
        # Add some Unicode characters
        unicode_chars = ''.join(chr(random.randint(0x100, 0x10FF)) for _ in range(random.randint(1, 3)))
        pos = random.randint(0, len(command) - 1)
        return command[:pos] + unicode_chars + command[pos:]
    
    # If corruption failed, return the original command
    return command

def generate_corpus(count=10, output_dir=None):
    """
    Generate a corpus of command-line files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write files to
        
    Returns:
        list: List of generated command-line strings or file paths
    """
    import os
    
    corpus = []
    
    for i in range(count):
        # Mostly valid commands, but some invalid
        valid = random.random() < 0.8
        command = generate(valid=valid)
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f"cmd_seed_{i:04d}.txt")
            with open(file_path, 'w') as f:
                f.write(command)
            corpus.append(file_path)
        else:
            corpus.append(command)
    
    return corpus