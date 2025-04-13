Fuzzer - 
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
- Dependencies: gramfuzz, python-magic, psutil, matplotlib, tqdm and AFL++ with QUME

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


## Supported Binary Formats

- Executables: ELF, PE
- Archives: ZIP, GZIP
- Documents: PDF
- Images: JPEG, PNG, BMP, GIF
- Audio: MP3
- Network: TCP, UDP, ICMP, HTTP, DNS

## Advanced Features

python3 fuzzer_cli.py fuzz /path/to/target_binary
Полный фаззинг с использованием всех методов:
python3 fuzzer_cli.py full-fuzz /path/to/target_binary_or_directory --generate-corpus
Структурно-ориентированный фаззинг:
python3 fuzzer_cli.py structure-fuzz /path/to/target_binary --format json
QEMU-фаззинг для закрытых бинарных файлов:
python3 fuzzer_cli.py qemu-fuzz /path/to/binary
