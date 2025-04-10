"""
Binary Grammar for Intelligent Fuzzing

This module provides a grammar for generating binary data for fuzzing.
It includes tools for creating various binary formats including
network protocols, file formats, and other structured binary data.
"""

import random
import struct
import binascii
import io
import zlib
import os

# Common binary formats and signatures
FORMAT_SIGNATURES = {
    'elf': b'\x7fELF',
    'pe': b'MZ',
    'jpeg': b'\xff\xd8\xff',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF8',
    'zip': b'PK\x03\x04',
    'pdf': b'%PDF-1.',
    'gzip': b'\x1f\x8b\x08',
    'bmp': b'BM',
    'mp3': b'ID3'
}

# Maximum size for generated binary data
MAX_SIZE = 1024 * 1024  # 1 MB

def random_bytes(min_length=0, max_length=1024):
    """Generate random bytes."""
    length = random.randint(min_length, max_length)
    return bytes(random.randint(0, 255) for _ in range(length))

def random_int32():
    """Generate a random 32-bit integer."""
    return random.randint(-2147483648, 2147483647)

def random_uint32():
    """Generate a random 32-bit unsigned integer."""
    return random.randint(0, 4294967295)

def random_int16():
    """Generate a random 16-bit integer."""
    return random.randint(-32768, 32767)

def random_uint16():
    """Generate a random 16-bit unsigned integer."""
    return random.randint(0, 65535)

def random_int8():
    """Generate a random 8-bit integer."""
    return random.randint(-128, 127)

def random_uint8():
    """Generate a random 8-bit unsigned integer."""
    return random.randint(0, 255)

def pack_int32(value=None):
    """Pack a 32-bit integer."""
    if value is None:
        value = random_int32()
    return struct.pack('<i', value)

def pack_uint32(value=None):
    """Pack a 32-bit unsigned integer."""
    if value is None:
        value = random_uint32()
    return struct.pack('<I', value)

def pack_int16(value=None):
    """Pack a 16-bit integer."""
    if value is None:
        value = random_int16()
    return struct.pack('<h', value)

def pack_uint16(value=None):
    """Pack a 16-bit unsigned integer."""
    if value is None:
        value = random_uint16()
    return struct.pack('<H', value)

def pack_int8(value=None):
    """Pack an 8-bit integer."""
    if value is None:
        value = random_int8()
    return struct.pack('<b', value)

def pack_uint8(value=None):
    """Pack an 8-bit unsigned integer."""
    if value is None:
        value = random_uint8()
    return struct.pack('<B', value)

def pack_float(value=None):
    """Pack a 32-bit float."""
    if value is None:
        value = random.uniform(-1000000.0, 1000000.0)
    return struct.pack('<f', value)

def pack_double(value=None):
    """Pack a 64-bit float."""
    if value is None:
        value = random.uniform(-1000000.0, 1000000.0)
    return struct.pack('<d', value)

def generate_string(min_length=0, max_length=100, null_terminated=True):
    """Generate a binary string."""
    length = random.randint(min_length, max_length)
    chars = []
    for _ in range(length):
        chars.append(random.randint(32, 126))  # ASCII printable characters
    
    if null_terminated:
        chars.append(0)  # Null terminator
    
    return bytes(chars)

def generate_structured_binary(num_fields=None, with_header=True):
    """
    Generate structured binary data with multiple fields.
    
    Args:
        num_fields: Number of fields to generate (if None, random 3-20)
        with_header: Whether to include a header with signature and size
        
    Returns:
        bytes: Generated binary data
    """
    if num_fields is None:
        num_fields = random.randint(3, 20)
    
    data = bytearray()
    
    # Add header if requested
    if with_header:
        # Signature (4 bytes)
        signature = random_bytes(4, 4)
        data.extend(signature)
        
        # Version (2 bytes)
        version = pack_uint16(random.randint(1, 100))
        data.extend(version)
        
        # Flags (4 bytes)
        flags = pack_uint32()
        data.extend(flags)
        
        # Reserve space for total size (4 bytes, will be filled later)
        size_pos = len(data)
        data.extend(b'\x00\x00\x00\x00')
        
        # Number of fields (4 bytes)
        data.extend(pack_uint32(num_fields))
    
    # Generate fields
    for i in range(num_fields):
        field_type = random.choice([
            'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32',
            'float', 'double', 'string', 'bytes'
        ])
        
        # Add field type identifier (1 byte)
        field_type_id = {'int8': 1, 'uint8': 2, 'int16': 3, 'uint16': 4,
                        'int32': 5, 'uint32': 6, 'float': 7, 'double': 8,
                        'string': 9, 'bytes': 10}[field_type]
        data.extend(pack_uint8(field_type_id))
        
        # Add field data
        if field_type == 'int8':
            data.extend(pack_int8())
        elif field_type == 'uint8':
            data.extend(pack_uint8())
        elif field_type == 'int16':
            data.extend(pack_int16())
        elif field_type == 'uint16':
            data.extend(pack_uint16())
        elif field_type == 'int32':
            data.extend(pack_int32())
        elif field_type == 'uint32':
            data.extend(pack_uint32())
        elif field_type == 'float':
            data.extend(pack_float())
        elif field_type == 'double':
            data.extend(pack_double())
        elif field_type == 'string':
            string_data = generate_string()
            # Add string length (4 bytes)
            data.extend(pack_uint32(len(string_data)))
            # Add string data
            data.extend(string_data)
        elif field_type == 'bytes':
            bytes_data = random_bytes(0, 100)
            # Add bytes length (4 bytes)
            data.extend(pack_uint32(len(bytes_data)))
            # Add bytes data
            data.extend(bytes_data)
    
    # Update total size if header was included
    if with_header:
        total_size = len(data)
        # Replace size placeholder
        data[size_pos:size_pos+4] = struct.pack('<I', total_size)
    
    return bytes(data)

def generate_network_packet(protocol=None):
    """
    Generate a network protocol packet.
    
    Args:
        protocol: Protocol to generate (if None, random)
        
    Returns:
        bytes: Generated packet data
    """
    # Choose protocol if not specified
    if protocol is None:
        protocol = random.choice(['tcp', 'udp', 'icmp', 'http', 'dns'])
    
    if protocol == 'tcp':
        return generate_tcp_packet()
    elif protocol == 'udp':
        return generate_udp_packet()
    elif protocol == 'icmp':
        return generate_icmp_packet()
    elif protocol == 'http':
        return generate_http_packet()
    elif protocol == 'dns':
        return generate_dns_packet()
    else:
        # Default to TCP
        return generate_tcp_packet()

def generate_tcp_packet():
    """Generate a TCP packet."""
    packet = bytearray()
    
    # Source port (2 bytes)
    packet.extend(pack_uint16(random.randint(1024, 65535)))
    
    # Destination port (2 bytes)
    packet.extend(pack_uint16(random.randint(1, 65535)))
    
    # Sequence number (4 bytes)
    packet.extend(pack_uint32())
    
    # Acknowledgment number (4 bytes)
    packet.extend(pack_uint32())
    
    # Data offset, reserved, flags (2 bytes)
    flags = random.randint(0, 0x3F)  # 6 bits of flags
    header_len = 5 << 4  # 5 32-bit words (20 bytes)
    packet.extend(struct.pack('!H', header_len | flags))
    
    # Window size (2 bytes)
    packet.extend(pack_uint16(random.randint(1000, 65535)))
    
    # Checksum (2 bytes)
    packet.extend(pack_uint16())
    
    # Urgent pointer (2 bytes)
    packet.extend(pack_uint16())
    
    # TCP payload
    payload_size = random.randint(0, 1024)
    packet.extend(random_bytes(payload_size, payload_size))
    
    return bytes(packet)

def generate_udp_packet():
    """Generate a UDP packet."""
    packet = bytearray()
    
    # Source port (2 bytes)
    packet.extend(pack_uint16(random.randint(1024, 65535)))
    
    # Destination port (2 bytes)
    packet.extend(pack_uint16(random.randint(1, 65535)))
    
    # Length (2 bytes, will be filled later)
    length_pos = len(packet)
    packet.extend(b'\x00\x00')
    
    # Checksum (2 bytes)
    packet.extend(pack_uint16())
    
    # UDP payload
    payload_size = random.randint(0, 1024)
    payload = random_bytes(payload_size, payload_size)
    packet.extend(payload)
    
    # Update length
    packet_length = len(packet)
    packet[length_pos:length_pos+2] = struct.pack('!H', packet_length)
    
    return bytes(packet)

def generate_icmp_packet():
    """Generate an ICMP packet."""
    packet = bytearray()
    
    # Type (1 byte)
    packet.extend(pack_uint8(random.randint(0, 255)))
    
    # Code (1 byte)
    packet.extend(pack_uint8(random.randint(0, 255)))
    
    # Checksum (2 bytes)
    packet.extend(pack_uint16())
    
    # Rest of header (4 bytes)
    packet.extend(pack_uint32())
    
    # ICMP payload
    payload_size = random.randint(0, 1024)
    packet.extend(random_bytes(payload_size, payload_size))
    
    return bytes(packet)

def generate_http_packet():
    """Generate an HTTP packet (as binary data)."""
    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
    method = random.choice(http_methods)
    
    paths = ['/index.html', '/api/data', '/users', '/login', '/images/logo.png']
    path = random.choice(paths)
    
    versions = ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0']
    version = random.choice(versions)
    
    # Generate request line
    request_line = f"{method} {path} {version}\r\n"
    
    # Generate headers
    headers = []
    headers.append(f"Host: example.com:{random.randint(1, 65535)}")
    headers.append(f"User-Agent: FuzzClient/{random.randint(1, 100)}.{random.randint(0, 99)}")
    headers.append(f"Content-Length: {random.randint(0, 1024)}")
    headers.append(f"Connection: {'keep-alive' if random.random() < 0.7 else 'close'}")
    
    # Add random headers
    for _ in range(random.randint(0, 5)):
        header_name = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ-') for _ in range(random.randint(5, 15)))
        header_value = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789 ') for _ in range(random.randint(5, 50)))
        headers.append(f"{header_name}: {header_value}")
    
    # Format headers
    headers_str = '\r\n'.join(headers) + '\r\n\r\n'
    
    # Generate body (for POST/PUT)
    body = ''
    if method in ['POST', 'PUT']:
        body_length = random.randint(10, 1024)
        body = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789 ') for _ in range(body_length))
    
    packet = request_line + headers_str + body
    return packet.encode('utf-8', errors='ignore')

def generate_dns_packet():
    """Generate a DNS packet."""
    packet = bytearray()
    
    # Transaction ID (2 bytes)
    packet.extend(pack_uint16())
    
    # Flags (2 bytes)
    flags = random.randint(0, 0xFFFF)
    packet.extend(pack_uint16(flags))
    
    # Number of questions (2 bytes)
    num_questions = random.randint(1, 5)
    packet.extend(pack_uint16(num_questions))
    
    # Number of answers (2 bytes)
    packet.extend(pack_uint16(random.randint(0, 10)))
    
    # Number of authority records (2 bytes)
    packet.extend(pack_uint16(random.randint(0, 5)))
    
    # Number of additional records (2 bytes)
    packet.extend(pack_uint16(random.randint(0, 5)))
    
    # Questions
    for _ in range(num_questions):
        # Domain name (variable length)
        domain_parts = random.randint(1, 5)
        for _ in range(domain_parts):
            part_length = random.randint(1, 10)
            packet.extend(pack_uint8(part_length))
            for _ in range(part_length):
                packet.extend(pack_uint8(random.randint(97, 122)))  # a-z
        
        # Terminating zero
        packet.extend(b'\x00')
        
        # Query type (2 bytes)
        packet.extend(pack_uint16(random.randint(1, 16)))
        
        # Query class (2 bytes)
        packet.extend(pack_uint16(1))  # IN (Internet)
    
    return bytes(packet)

def generate_file_format(format_type=None):
    """
    Generate a specific file format.
    
    Args:
        format_type: Type of file to generate (if None, random)
        
    Returns:
        bytes: Generated file data
    """
    # Choose format if not specified
    if format_type is None:
        format_type = random.choice(list(FORMAT_SIGNATURES.keys()))
    
    # Basic generator for placeholder formats
    def basic_format(signature, min_size=100, max_size=1024):
        data_size = random.randint(min_size, max_size)
        data = bytearray(signature)
        data.extend(random_bytes(data_size - len(signature), data_size - len(signature)))
        return bytes(data)
    
    if format_type == 'elf':
        return generate_elf_header()
    elif format_type == 'pe':
        return generate_pe_header()
    elif format_type == 'zip':
        return generate_zip_file()
    elif format_type in FORMAT_SIGNATURES:
        return basic_format(FORMAT_SIGNATURES[format_type])
    else:
        # Default to structured binary
        return generate_structured_binary()

def generate_elf_header():
    """
    Generate a basic ELF header.
    
    This generates just enough of an ELF file to be recognized as an ELF file.
    It's not a valid executable.
    """
    elf = bytearray()
    
    # ELF magic (4 bytes)
    elf.extend(FORMAT_SIGNATURES['elf'])
    
    # Class (1 byte): 1 = 32-bit, 2 = 64-bit
    elf.extend(pack_uint8(random.randint(1, 2)))
    
    # Data encoding (1 byte): 1 = little endian, 2 = big endian
    elf.extend(pack_uint8(random.randint(1, 2)))
    
    # ELF version (1 byte)
    elf.extend(pack_uint8(1))
    
    # OS ABI (1 byte)
    elf.extend(pack_uint8(random.randint(0, 12)))
    
    # ABI version (1 byte)
    elf.extend(pack_uint8(0))
    
    # Padding (7 bytes)
    elf.extend(b'\x00' * 7)
    
    # Object file type (2 bytes)
    elf.extend(pack_uint16(random.randint(1, 4)))
    
    # Machine architecture (2 bytes)
    elf.extend(pack_uint16(random.randint(0, 100)))
    
    # Object file version (4 bytes)
    elf.extend(pack_uint32(1))
    
    # Entry point (4 or 8 bytes)
    elf.extend(pack_uint32())
    
    # Add some random data to make it look like a real ELF file
    elf.extend(random_bytes(100, 500))
    
    return bytes(elf)

def generate_pe_header():
    """
    Generate a basic PE header.
    
    This generates just enough of a PE file to be recognized as a PE file.
    It's not a valid executable.
    """
    pe = bytearray()
    
    # DOS header
    pe.extend(FORMAT_SIGNATURES['pe'])  # MZ signature
    
    # Add DOS stub (random data)
    pe.extend(random_bytes(58, 58))
    
    # PE header offset at offset 0x3C (4 bytes)
    pe_offset = 0x80  # Arbitrary offset
    pe[0x3C:0x40] = struct.pack('<I', pe_offset)
    
    # Fill gap with random data
    pe.extend(random_bytes(pe_offset - len(pe), pe_offset - len(pe)))
    
    # PE signature "PE\0\0" (4 bytes)
    pe.extend(b'PE\0\0')
    
    # Machine (2 bytes)
    pe.extend(pack_uint16(random.randint(0, 0xFFFF)))
    
    # Number of sections (2 bytes)
    pe.extend(pack_uint16(random.randint(1, 10)))
    
    # Time date stamp (4 bytes)
    pe.extend(pack_uint32())
    
    # Add some random data to make it look like a real PE file
    pe.extend(random_bytes(100, 500))
    
    return bytes(pe)

def generate_zip_file():
    """
    Generate a basic ZIP file with random content.
    
    This generates a valid ZIP file with random files inside.
    """
    output = io.BytesIO()
    
    # Local file header signature (4 bytes)
    output.write(FORMAT_SIGNATURES['zip'])
    
    # Version needed to extract (2 bytes)
    output.write(pack_uint16(20))
    
    # General purpose bit flag (2 bytes)
    output.write(pack_uint16(0))
    
    # Compression method (2 bytes)
    output.write(pack_uint16(8))  # DEFLATE
    
    # Last mod file time (2 bytes)
    output.write(pack_uint16(random.randint(0, 0xFFFF)))
    
    # Last mod file date (2 bytes)
    output.write(pack_uint16(random.randint(0, 0xFFFF)))
    
    # CRC-32 (4 bytes)
    crc = random.randint(0, 0xFFFFFFFF)
    output.write(struct.pack('<I', crc))
    
    # Compressed size (4 bytes) - will be updated later
    compressed_size_pos = output.tell()
    output.write(b'\x00\x00\x00\x00')
    
    # Uncompressed size (4 bytes) - will be updated later
    uncompressed_size_pos = output.tell()
    output.write(b'\x00\x00\x00\x00')
    
    # File name length (2 bytes)
    filename = f"file{random.randint(1, 999)}.dat"
    output.write(struct.pack('<H', len(filename)))
    
    # Extra field length (2 bytes)
    output.write(pack_uint16(0))
    
    # File name (variable size)
    output.write(filename.encode('utf-8'))
    
    # File data - generate random data and compress it
    uncompressed_data = random_bytes(100, 1000)
    uncompressed_size = len(uncompressed_data)
    
    # Compress data
    compressed_data = zlib.compress(uncompressed_data)
    compressed_size = len(compressed_data)
    
    # Write compressed data
    output.write(compressed_data)
    
    # Go back and update sizes
    current_pos = output.tell()
    output.seek(compressed_size_pos)
    output.write(struct.pack('<I', compressed_size))
    output.seek(uncompressed_size_pos)
    output.write(struct.pack('<I', uncompressed_size))
    output.seek(current_pos)
    
    # Central directory header
    output.write(b'PK\x01\x02')  # Central directory signature
    
    # Version made by (2 bytes)
    output.write(pack_uint16(20))
    
    # Version needed to extract (2 bytes)
    output.write(pack_uint16(20))
    
    # General purpose bit flag (2 bytes)
    output.write(pack_uint16(0))
    
    # Compression method (2 bytes)
    output.write(pack_uint16(8))  # DEFLATE
    
    # Last mod file time (2 bytes)
    output.write(pack_uint16(random.randint(0, 0xFFFF)))
    
    # Last mod file date (2 bytes)
    output.write(pack_uint16(random.randint(0, 0xFFFF)))
    
    # CRC-32 (4 bytes)
    output.write(struct.pack('<I', crc))
    
    # Compressed size (4 bytes)
    output.write(struct.pack('<I', compressed_size))
    
    # Uncompressed size (4 bytes)
    output.write(struct.pack('<I', uncompressed_size))
    
    # File name length (2 bytes)
    output.write(struct.pack('<H', len(filename)))
    
    # Extra field length (2 bytes)
    output.write(pack_uint16(0))
    
    # File comment length (2 bytes)
    output.write(pack_uint16(0))
    
    # Disk number start (2 bytes)
    output.write(pack_uint16(0))
    
    # Internal file attributes (2 bytes)
    output.write(pack_uint16(0))
    
    # External file attributes (4 bytes)
    output.write(pack_uint32(0))
    
    # Relative offset of local header (4 bytes)
    output.write(pack_uint32(0))
    
    # File name (variable size)
    output.write(filename.encode('utf-8'))
    
    # End of central directory record
    output.write(b'PK\x05\x06')  # End of central directory signature
    
    # Number of this disk (2 bytes)
    output.write(pack_uint16(0))
    
    # Number of the disk with the start of the central directory (2 bytes)
    output.write(pack_uint16(0))
    
    # Total number of entries in the central directory on this disk (2 bytes)
    output.write(pack_uint16(1))
    
    # Total number of entries in the central directory (2 bytes)
    output.write(pack_uint16(1))
    
    # Size of the central directory (4 bytes)
    central_dir_size = current_pos
    output.write(struct.pack('<I', central_dir_size))
    
    # Offset of start of central directory with respect to the starting disk number (4 bytes)
    output.write(pack_uint32(0))
    
    # .ZIP file comment length (2 bytes)
    output.write(pack_uint16(0))
    
    return output.getvalue()

def mutate_binary(data, mutation_rate=0.05):
    """
    Mutate binary data by randomly changing some bytes.
    
    Args:
        data: Binary data to mutate
        mutation_rate: Probability of mutating each byte
        
    Returns:
        bytes: Mutated binary data
    """
    data = bytearray(data)
    for i in range(len(data)):
        if random.random() < mutation_rate:
            # Choose mutation type
            mutation_type = random.choice(['bit_flip', 'byte_replace', 'byte_swap'])
            
            if mutation_type == 'bit_flip':
                # Flip a random bit
                bit = random.randint(0, 7)
                data[i] ^= (1 << bit)
            
            elif mutation_type == 'byte_replace':
                # Replace with random byte
                data[i] = random.randint(0, 255)
            
            elif mutation_type == 'byte_swap' and i < len(data) - 1:
                # Swap with adjacent byte
                data[i], data[i+1] = data[i+1], data[i]
    
    return bytes(data)

def generate(valid=True, format_type=None):
    """
    Generate binary data.
    
    Args:
        valid: Whether to generate valid binary (if False, may generate invalid)
        format_type: Type of format to generate (if None, random)
        
    Returns:
        bytes: Generated binary data
    """
    # Choose format type if not specified
    if format_type is None:
        formats = ['structured', 'network', 'file']
        format_type = random.choice(formats)
    
    # Generate data based on format type
    if format_type == 'structured':
        data = generate_structured_binary()
    elif format_type == 'network':
        data = generate_network_packet()
    elif format_type == 'file':
        data = generate_file_format()
    else:
        # Default to structured binary
        data = generate_structured_binary()
    
    # If not valid, mutate the data
    if not valid:
        data = mutate_binary(data, mutation_rate=random.uniform(0.05, 0.2))
    
    return data

def generate_corpus(count=10, output_dir=None, format_type=None):
    """
    Generate a corpus of binary files for fuzzing.
    
    Args:
        count: Number of files to generate
        output_dir: Directory to write files to
        format_type: Type of format to generate (if None, random)
        
    Returns:
        list: List of generated binary data or file paths
    """
    corpus = []
    
    for i in range(count):
        # Mostly valid binary, but some invalid
        valid = random.random() < 0.8
        data = generate(valid=valid, format_type=format_type)
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, f"binary_seed_{i:04d}.bin")
            with open(file_path, 'wb') as f:
                f.write(data)
            corpus.append(file_path)
        else:
            corpus.append(data)
    
    return corpus
