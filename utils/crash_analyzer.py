"""
Crash Analyzer for Intelligent Fuzzing

This module provides functionality to analyze program crashes during fuzzing,
categorize their severity, and generate crash reports.
"""

import os
import re
import logging
import time
import hashlib
import subprocess
import platform
import signal
import json
from datetime import datetime

logger = logging.getLogger("fuzzer.crash_analyzer")

class CrashAnalyzer:
    """Class for analyzing program crashes during fuzzing."""
    
    # Crash types and their severity
    CRASH_TYPES = {
        "SEGFAULT": 8,             # Segmentation fault
        "SIGABRT": 7,              # Abort signal
        "SIGSEGV": 8,              # Segmentation violation
        "SIGILL": 9,               # Illegal instruction
        "SIGFPE": 7,               # Floating point exception
        "SIGBUS": 8,               # Bus error
        "STACK_OVERFLOW": 6,       # Stack overflow
        "HEAP_CORRUPTION": 9,      # Heap corruption
        "MEMORY_LEAK": 4,          # Memory leak
        "NULL_DEREFERENCE": 7,     # Null pointer dereference
        "DIVIDE_BY_ZERO": 6,       # Division by zero
        "BUFFER_OVERFLOW": 9,      # Buffer overflow
        "FORMAT_STRING": 10,       # Format string vulnerability
        "USE_AFTER_FREE": 9,       # Use after free
        "DOUBLE_FREE": 8,          # Double free
        "TIMEOUT": 3,              # Program timeout
        "ASSERTION_FAILURE": 5,    # Assertion failure
        "UNDEFINED_BEHAVIOR": 7,   # Undefined behavior
        "UNKNOWN": 5               # Unknown crash type
    }
    
    def __init__(self, report_dir="crash_reports"):
        """
        Initialize the crash analyzer.
        
        Args:
            report_dir: Directory to store crash reports
        """
        self.report_dir = report_dir
        
        # Create report directory if it doesn't exist
        os.makedirs(report_dir, exist_ok=True)
        
        # Keep track of seen crash signatures
        self.seen_crashes = set()
    
    def analyze_crash(self, executable_path, input_file, output_log, exit_code):
        """
        Analyze a program crash and generate a crash report.
        
        Args:
            executable_path: Path to the crashed executable
            input_file: Path to the input file that caused the crash
            output_log: Path to the program output log
            exit_code: Program exit code
            
        Returns:
            dict: Information about the crash
        """
        # Start with basic crash info
        crash_info = {
            "executable": os.path.basename(executable_path),
            "timestamp": datetime.now().isoformat(),
            "exit_code": exit_code,
            "crash_type": "UNKNOWN",
            "crash_signature": "",
            "severity": self.CRASH_TYPES["UNKNOWN"],
            "report_path": "",
            "details": {}
        }
        
        # Read program output for analysis
        output_content = ""
        try:
            with open(output_log, 'r') as f:
                output_content = f.read()
        except Exception as e:
            logger.warning(f"Could not read output log: {e}")
        
        # Analyze the crash type from output and exit code
        crash_type, details = self._detect_crash_type(output_content, exit_code)
        crash_info["crash_type"] = crash_type
        crash_info["severity"] = self.CRASH_TYPES.get(crash_type, self.CRASH_TYPES["UNKNOWN"])
        crash_info["details"] = details
        
        # Create a unique crash signature
        crash_info["crash_signature"] = self._generate_crash_signature(
            executable_path, crash_type, details, input_file
        )
        
        # Generate crash report
        crash_info["report_path"] = self._generate_crash_report(
            executable_path, input_file, crash_info, output_content
        )
        
        # Check if this is a new crash
        crash_info["is_new"] = crash_info["crash_signature"] not in self.seen_crashes
        
        # Add to seen crashes
        self.seen_crashes.add(crash_info["crash_signature"])
        
        return crash_info
    
    def _detect_crash_type(self, output_content, exit_code):
        """
        Detect the type of crash from program output and exit code.
        
        Args:
            output_content: Program output content
            exit_code: Program exit code
            
        Returns:
            tuple: (crash_type, details)
        """
        details = {}
        output_lower = output_content.lower()
        
        # Check for timeout
        if output_content.strip() == "TIMEOUT: Execution exceeded maximum allowed time":
            return "TIMEOUT", {"reason": "Execution exceeded maximum allowed time"}
        
        # Check for common crash signatures in output
        if "segmentation fault" in output_lower or "segfault" in output_lower:
            return "SEGFAULT", self._extract_segfault_details(output_content)
        
        if "abort" in output_lower:
            return "SIGABRT", {"reason": "Program called abort()"}
        
        if "illegal instruction" in output_lower:
            return "SIGILL", {"reason": "Illegal instruction executed"}
        
        if "floating point exception" in output_lower:
            return "SIGFPE", {"reason": "Floating point exception"}
        
        if "bus error" in output_lower:
            return "SIGBUS", {"reason": "Bus error (misaligned memory access)"}
        
        # Check for memory-related issues
        if "stack overflow" in output_lower:
            return "STACK_OVERFLOW", {"reason": "Stack overflow detected"}
        
        if "heap corruption" in output_lower or "corrupted heap" in output_lower:
            return "HEAP_CORRUPTION", {"reason": "Heap corruption detected"}
        
        if "memory leak" in output_lower:
            return "MEMORY_LEAK", self._extract_memory_leak_details(output_content)
        
        if "null pointer" in output_lower or "null dereference" in output_lower:
            return "NULL_DEREFERENCE", {"reason": "Null pointer dereference"}
        
        if "divide by zero" in output_lower or "division by zero" in output_lower:
            return "DIVIDE_BY_ZERO", {"reason": "Division by zero"}
        
        # Check for security-related issues
        if "buffer overflow" in output_lower:
            return "BUFFER_OVERFLOW", {"reason": "Buffer overflow detected"}
        
        if "format string" in output_lower:
            return "FORMAT_STRING", {"reason": "Format string vulnerability"}
        
        if "use after free" in output_lower:
            return "USE_AFTER_FREE", {"reason": "Use after free detected"}
        
        if "double free" in output_lower or "corrupted double-linked list" in output_lower:
            return "DOUBLE_FREE", {"reason": "Double free detected"}
        
        # Check for assertion failures
        if "assertion failed" in output_lower or "assert failed" in output_lower:
            return "ASSERTION_FAILURE", self._extract_assertion_details(output_content)
        
        # Try to infer from exit code
        if exit_code < 0:
            # Negative exit codes are usually signals
            signal_num = abs(exit_code)
            if signal_num == signal.SIGSEGV:
                return "SIGSEGV", {"reason": "Segmentation violation (from exit code)"}
            elif signal_num == signal.SIGABRT:
                return "SIGABRT", {"reason": "Abort signal (from exit code)"}
            elif signal_num == signal.SIGILL:
                return "SIGILL", {"reason": "Illegal instruction (from exit code)"}
            elif signal_num == signal.SIGFPE:
                return "SIGFPE", {"reason": "Floating point exception (from exit code)"}
            elif signal_num == signal.SIGBUS:
                return "SIGBUS", {"reason": "Bus error (from exit code)"}
        
        # If we can't determine the type, return UNKNOWN
        return "UNKNOWN", {"exit_code": exit_code, "output_sample": output_content[:200]}
    
    def _extract_segfault_details(self, output_content):
        """Extract details from a segfault crash output."""
        details = {"reason": "Segmentation fault"}
        
        # Try to extract fault address
        address_match = re.search(r'at address (?:0x)?([0-9a-fA-F]+)', output_content)
        if address_match:
            details["address"] = f"0x{address_match.group(1)}"
        
        # Try to extract instruction pointer
        ip_match = re.search(r'ip:? (?:0x)?([0-9a-fA-F]+)', output_content)
        if ip_match:
            details["instruction_pointer"] = f"0x{ip_match.group(1)}"
        
        # Try to extract stack/registers if available
        if "rax" in output_content or "eax" in output_content:
            # Extract register info
            reg_matches = re.findall(r'([er][abcd]x|[er]?[sbi]p|r\d+)\s+(?:0x)?([0-9a-fA-F]+)', output_content)
            if reg_matches:
                details["registers"] = {reg: f"0x{val}" for reg, val in reg_matches}
        
        return details
    
    def _extract_memory_leak_details(self, output_content):
        """Extract details from a memory leak output."""
        details = {"reason": "Memory leak detected"}
        
        # Try to extract leaked bytes
        bytes_match = re.search(r'(\d+) bytes? leaked', output_content)
        if bytes_match:
            details["leaked_bytes"] = int(bytes_match.group(1))
        
        # Try to extract leak locations if available
        locations = []
        loc_matches = re.findall(r'at ([^:]+):(\d+)', output_content)
        if loc_matches:
            for file, line in loc_matches:
                locations.append({"file": file, "line": int(line)})
        
        if locations:
            details["locations"] = locations
        
        return details
    
    def _extract_assertion_details(self, output_content):
        """Extract details from an assertion failure output."""
        details = {"reason": "Assertion failed"}
        
        # Try to extract assertion expression
        expr_match = re.search(r'assertion ["\'](.+)["\'] failed', output_content)
        if expr_match:
            details["expression"] = expr_match.group(1)
        
        # Try to extract file and line
        file_line_match = re.search(r'at ([^:]+):(\d+)', output_content)
        if file_line_match:
            details["file"] = file_line_match.group(1)
            details["line"] = int(file_line_match.group(2))
        
        return details
    
    def _generate_crash_signature(self, executable_path, crash_type, details, input_file):
        """
        Generate a unique signature for a crash.
        
        Args:
            executable_path: Path to the crashed executable
            crash_type: Type of crash
            details: Crash details
            input_file: Path to the input file
            
        Returns:
            str: Crash signature hash
        """
        # Create a string to hash for the signature
        signature_elements = [
            os.path.basename(executable_path),
            crash_type
        ]
        
        # Add key details to the signature
        if "address" in details:
            signature_elements.append(f"addr:{details['address']}")
        
        if "instruction_pointer" in details:
            signature_elements.append(f"ip:{details['instruction_pointer']}")
            
        if "expression" in details:
            signature_elements.append(f"expr:{details['expression']}")
        
        # Combine elements and hash
        signature_str = ":".join(signature_elements)
        signature_hash = hashlib.md5(signature_str.encode()).hexdigest()
        
        return signature_hash
    
    def _generate_crash_report(self, executable_path, input_file, crash_info, output_content):
        """
        Generate a crash report and save it to a file.
        
        Args:
            executable_path: Path to the crashed executable
            input_file: Path to the input file
            crash_info: Crash information
            output_content: Program output content
            
        Returns:
            str: Path to the crash report
        """
        # Create a report directory with timestamp and executable name
        exec_name = os.path.basename(executable_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        crash_id = crash_info["crash_signature"][:8]
        
        report_dir = os.path.join(self.report_dir, f"{timestamp}_{exec_name}_{crash_id}")
        os.makedirs(report_dir, exist_ok=True)
        
        # Create the crash report content
        report = {
            "crash_info": crash_info,
            "executable": {
                "name": exec_name,
                "path": executable_path,
                "size": os.path.getsize(executable_path) if os.path.exists(executable_path) else 0,
                "modified": datetime.fromtimestamp(os.path.getmtime(executable_path) if os.path.exists(executable_path) else 0).isoformat(),
                "system": platform.system(),
                "platform": platform.platform()
            },
            "input": {
                "path": input_file,
                "size": os.path.getsize(input_file) if os.path.exists(input_file) else 0
            },
            "output": output_content[:4096]  # Limit output size
        }
        
        # Save the report as JSON
        report_path = os.path.join(report_dir, "report.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save the input file that caused the crash
        try:
            with open(input_file, 'rb') as src, open(os.path.join(report_dir, "input"), 'wb') as dst:
                dst.write(src.read())
        except Exception as e:
            logger.warning(f"Could not save input file: {e}")
        
        # Save the output log
        output_path = os.path.join(report_dir, "output.log")
        with open(output_path, 'w') as f:
            f.write(output_content)
        
        return report_path
    
    def get_recent_crashes(self, limit=10):
        """
        Get information about recent crashes.
        
        Args:
            limit: Maximum number of crashes to return
            
        Returns:
            list: Recent crash information
        """
        crashes = []
        
        try:
            # Get list of crash report directories
            report_dirs = [os.path.join(self.report_dir, d) for d in os.listdir(self.report_dir) 
                            if os.path.isdir(os.path.join(self.report_dir, d))]
            
            # Sort by timestamp (directory name starts with timestamp)
            report_dirs.sort(reverse=True)
            
            # Load crash reports
            for report_dir in report_dirs[:limit]:
                report_path = os.path.join(report_dir, "report.json")
                if os.path.exists(report_path):
                    try:
                        with open(report_path, 'r') as f:
                            report = json.load(f)
                            crashes.append(report["crash_info"])
                    except Exception as e:
                        logger.warning(f"Could not load crash report {report_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error getting recent crashes: {e}")
        
        return crashes
    
    def categorize_crashes(self):
        """
        Categorize crashes by type and severity.
        
        Returns:
            dict: Crash categories and counts
        """
        categories = {
            "by_type": {},
            "by_severity": {
                "critical": 0,  # 9-10
                "high": 0,      # 7-8
                "medium": 0,    # 5-6
                "low": 0        # 1-4
            },
            "by_executable": {},
            "total": 0
        }
        
        try:
            # Process all crash reports
            for root, dirs, files in os.walk(self.report_dir):
                for file in files:
                    if file == "report.json":
                        report_path = os.path.join(root, file)
                        try:
                            with open(report_path, 'r') as f:
                                report = json.load(f)
                                crash_info = report["crash_info"]
                                
                                # Count by type
                                crash_type = crash_info["crash_type"]
                                if crash_type not in categories["by_type"]:
                                    categories["by_type"][crash_type] = 0
                                categories["by_type"][crash_type] += 1
                                
                                # Count by severity
                                severity = crash_info["severity"]
                                if severity >= 9:
                                    categories["by_severity"]["critical"] += 1
                                elif severity >= 7:
                                    categories["by_severity"]["high"] += 1
                                elif severity >= 5:
                                    categories["by_severity"]["medium"] += 1
                                else:
                                    categories["by_severity"]["low"] += 1
                                
                                # Count by executable
                                executable = crash_info["executable"]
                                if executable not in categories["by_executable"]:
                                    categories["by_executable"][executable] = 0
                                categories["by_executable"][executable] += 1
                                
                                # Increment total
                                categories["total"] += 1
                        
                        except Exception as e:
                            logger.warning(f"Could not process crash report {report_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error categorizing crashes: {e}")
        
        return categories