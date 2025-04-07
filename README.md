# IntelFuzz - Intelligent Fuzzing Tool

IntelFuzz is an advanced fuzzing tool designed for testing executable files with smart grammar-based input generation, comprehensive crash detection, and detailed analysis capabilities. It specializes in structure-aware fuzzing with support for various input formats, including JSON, XML, command-line arguments, and binary data.

## Key Features

- **Smart Grammar-Based Input Generation**: Uses formal grammars to generate structurally valid inputs
- **Multi-Format Support**: Handles JSON, XML, command-line, and binary formats
- **Automatic Format Detection**: Automatically identifies appropriate grammar for target files
- **Process Monitoring**: Tracks resource usage, file access patterns, and network activity
- **Comprehensive Crash Analysis**: Categorizes and analyzes crashes with detailed reports
- **QEMU Instrumentation**: Enables fuzzing closed-source binaries with coverage information
- **Source Code Analysis**: Identifies potential vulnerabilities and extract input formats
- **Terminal-Based Interface**: Designed for command-line operation with detailed logging

## Installation

### Requirements

- Python 3.10 or higher
- Dependencies: gramfuzz, python-magic, psutil, matplotlib, tqdm

### Setup

```bash
# Install dependencies
pip install gramfuzz python-magic psutil matplotlib tqdm
```

For QEMU instrumentation capabilities (optional):

```bash
# Install AFL++ with QEMU support
apt-get install build-essential libtool-bin python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

## Usage

### Basic Usage

Fuzz a binary with automatic format detection:

```bash
python fuzzer_cli.py fuzz /path/to/binary --iterations 1000 --timeout 30
```

Fuzz with a specific grammar:

```bash
python fuzzer_cli.py fuzz /path/to/binary --grammar json --iterations 1000
```

Generate a corpus of test files:

```bash
python fuzzer_cli.py generate-corpus --format json --output corpus/json --count 50
```

Analyze source code for potential vulnerabilities:

```bash
python fuzzer_cli.py analyze-source /path/to/source/code
```

Analyze a crash:

```bash
python fuzzer_cli.py analyze-crash /path/to/binary /path/to/crash_file
```

Fuzz using QEMU instrumentation (requires AFL++):

```bash
python fuzzer_cli.py qemu-fuzz /path/to/binary --timeout 3600
```

Detect format of files:

```bash
python fuzzer_cli.py detect-format /path/to/file_or_directory --recursive
```

### Advanced Options

- `--output-dir`: Specify output directory for results
- `--seed-corpus`: Use an existing corpus as seed
- `--memory-monitor`: Enable detailed memory monitoring
- `--memory-limit`: Set memory limit for AFL++ (for QEMU fuzzing)

## Directory Structure

```
.
├── fuzzer_cli.py          # Main command-line interface
├── grammars/              # Grammar definitions for input generation
│   ├── __init__.py        # Grammar loading mechanism
│   ├── json_grammar.py    # JSON grammar
│   ├── xml_grammar.py     # XML grammar
│   ├── command_grammar.py # Command-line grammar
│   └── binary_grammar.py  # Binary format grammar
├── utils/                 # Utility modules
│   ├── format_detector.py # Input format detection
│   ├── source_analyzer.py # Source code analysis
│   ├── behavior_monitor.py # Process behavior monitoring
│   ├── qemu_instrumentation.py # QEMU-based fuzzing
│   ├── logger.py          # Advanced logging
│   └── common.py          # Common utilities
├── results/               # Fuzzing results (created by the tool)
├── corpus/                # Test corpus (created by the tool)
└── logs/                  # Log files (created by the tool)
```

## Example Workflow

1. Analyze source code to understand input formats and potential vulnerabilities:
   ```bash
   python fuzzer_cli.py analyze-source /path/to/source
   ```

2. Generate a test corpus based on detected formats:
   ```bash
   python fuzzer_cli.py generate-corpus --format json --output corpus/json
   ```

3. Run fuzzing with the generated corpus:
   ```bash
   python fuzzer_cli.py fuzz /path/to/binary --seed-corpus corpus/json
   ```

4. Analyze any crashes found:
   ```bash
   python fuzzer_cli.py analyze-crash /path/to/binary /path/to/results/crashes/crash_00001.input
   ```

## Supported Binary Formats

- Executables: ELF, PE
- Archives: ZIP, GZIP
- Documents: PDF
- Images: JPEG, PNG, BMP, GIF
- Audio: MP3
- Network: TCP, UDP, ICMP, HTTP, DNS

## Advanced Features

### QEMU Instrumentation

The QEMU instrumentation feature allows fuzzing closed-source binaries with coverage information. This is particularly useful for finding bugs in applications where source code is not available.

```bash
python fuzzer_cli.py qemu-fuzz /path/to/binary --timeout 7200 --memory-limit 2048
```

### Source Code Analysis

The source code analyzer can identify input handling functions, data structures, and potential vulnerabilities in the source code. Supported languages include C, C++, Python, JavaScript, Java, Go, and Rust.

```bash
python fuzzer_cli.py analyze-source /path/to/source --output analysis_results.json
```

### Crash Analysis

The crash analyzer provides detailed information about crashes, including crash type, crash location, and potential vulnerability. It can also reproduce crashes to verify they are genuine.

```bash
python fuzzer_cli.py analyze-crash /path/to/binary /path/to/crash_file --timeout 30
```

## Credits

This tool was developed by [Your Organization] for advanced fuzzing research.

## License

This project is licensed under the MIT License - see the LICENSE file for details.