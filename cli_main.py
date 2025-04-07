#!/usr/bin/env python3
"""
Intelligent Fuzzing Tool - CLI Frontend

This script provides a simple command-line frontend to the intelligent fuzzing tool.
It's designed to be used directly rather than through the web interface.
"""

import sys
from fuzzer_cli import main as cli_main

if __name__ == "__main__":
    sys.exit(cli_main())