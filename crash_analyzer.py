#!/usr/bin/env python3
"""
Crash Analyzer for Intelligent Fuzzing

This script analyzes crash reports from the intelligent fuzzing tool,
groups them by type, and provides detailed information about each crash.
"""

import os
import json
import sys
import argparse
import subprocess
import logging
import time
from collections import defaultdict
try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None
from datetime import datetime
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("crash_analyzer")

def setup_directories(output_dir=None):
    """Set up necessary directories.
    
    Args:
        output_dir: Optional output directory override. If None, uses default location.
        
    Returns:
        Path to the analysis directory
    """
    if output_dir:
        # Use the specified output directory
        analysis_dir = output_dir
    else:
        # Use default location
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        analysis_dir = os.path.join(os.getcwd(), "crash_analysis", f"analysis_{timestamp}")
        
    os.makedirs(analysis_dir, exist_ok=True)
    
    # Create subdirectories for different types of outputs
    reports_dir = os.path.join(analysis_dir, "reports")
    visuals_dir = os.path.join(analysis_dir, "visualizations")
    data_dir = os.path.join(analysis_dir, "data")
    
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(visuals_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    
    logger.info(f"Analysis will be saved to: {analysis_dir}")
    
    return {
        'analysis_dir': analysis_dir,
        'reports_dir': reports_dir,
        'visuals_dir': visuals_dir,
        'data_dir': data_dir
    }

def find_crash_files(input_dir):
    """Find all crash files in the given directory."""
    crash_files = []
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.startswith("crash_") and file.endswith(".json"):
                crash_files.append(os.path.join(root, file))
    return crash_files

def execute_target_with_crash(target, crash_file):
    """Execute the target with the given crash file and capture output."""
    try:
        process = subprocess.Popen(
            [target, crash_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=5)
        return process.returncode, stdout, stderr
    except Exception as e:
        logger.error(f"Error executing target with crash file: {e}")
        return -1, "", str(e)

def extract_crash_reason(stderr, stdout=""):
    """Extract the crash reason from stderr and stdout with detailed diagnostics."""
    stderr = stderr.lower()
    stdout = stdout.lower()
    
    # First check for explicit error messages
    for line in stderr.split('\n'):
        if "error:" in line.lower():
            return line.strip()
        elif "exception" in line.lower():
            return line.strip()
    
    # Create a detailed classification of crash reason
    if "segmentation fault" in stderr:
        if "null pointer" in stderr or "null pointer" in stdout:
            return "Null Pointer Dereference"
        elif "stack overflow" in stderr or "stack overflow" in stdout:
            return "Stack Overflow"
        elif "heap corruption" in stderr or "heap corruption" in stdout:
            return "Heap Corruption"
        elif "buffer overflow" in stderr or "buffer overflow" in stdout:
            return "Buffer Overflow"
        elif "invalid memory" in stderr or "invalid memory" in stdout:
            return "Invalid Memory Access"
        else:
            return "Segmentation Fault"
            
    elif "bus error" in stderr:
        if "alignment" in stderr:
            return "Memory Alignment Error"
        else:
            return "Bus Error (Hardware Exception)"
            
    elif "illegal instruction" in stderr:
        return "Illegal Instruction"
        
    elif "floating point" in stderr:
        if "division by zero" in stderr or "divide by zero" in stderr:
            return "Division by Zero"
        else:
            return "Floating Point Exception"
            
    elif "abort" in stderr or "aborted" in stderr:
        if "assertion" in stderr:
            return "Assertion Failure"
        elif "double free" in stderr:
            return "Double Free"
        elif "memory corruption" in stderr:
            return "Memory Corruption"
        else:
            return "Program Aborted"
            
    elif "stack smashing" in stderr:
        return "Stack Smashing Detected"
        
    elif "memory exhausted" in stderr or "out of memory" in stderr:
        return "Out of Memory"
        
    elif "timeout" in stderr:
        return "Execution Timeout"
        
    elif "buffer overflow" in stderr or "buffer overflow" in stdout:
        return "Buffer Overflow"
        
    elif "divide by zero" in stderr or "division by zero" in stderr:
        return "Division by Zero"
        
    elif "use after free" in stderr:
        return "Use After Free"
        
    elif "heap buffer overflow" in stderr:
        return "Heap Buffer Overflow"
        
    elif "stack buffer overflow" in stderr:
        return "Stack Buffer Overflow"
        
    elif "memory leak" in stderr:
        return "Memory Leak"
        
    elif "uninitialized" in stderr and ("value" in stderr or "memory" in stderr):
        return "Uninitialized Memory Access"
        
    elif "heap" in stderr and "overflow" in stderr:
        return "Heap Overflow"
        
    elif "integer overflow" in stderr:
        return "Integer Overflow"
        
    # Examine error messages for possible JSON parsing issues
    elif any(x in stderr or x in stdout for x in ["json", "parsing", "syntax error", "unexpected token"]):
        if "unexpected character" in stderr or "unexpected token" in stderr:
            return "JSON Syntax Error - Unexpected Character"
        elif "end of file" in stderr:
            return "JSON Syntax Error - Unexpected End of File"
        elif "maximum nesting" in stderr:
            return "JSON Parsing Error - Maximum Nesting Exceeded"
        else:
            return "JSON Parsing Error"
    
    # XML parsing errors
    elif any(x in stderr or x in stdout for x in ["xml", "parsing", "malformed"]):
        if "unexpected" in stderr:
            return "XML Syntax Error - Unexpected Element"
        elif "not well-formed" in stderr:
            return "XML Syntax Error - Not Well-formed"
        else:
            return "XML Parsing Error"
    
    # Command-line errors
    elif any(x in stderr for x in ["command", "argument", "option", "flag", "parameter"]):
        if "unknown" in stderr:
            return "Command-line Error - Unknown Option"
        elif "missing" in stderr:
            return "Command-line Error - Missing Argument"
        elif "invalid" in stderr:
            return "Command-line Error - Invalid Argument"
        else:
            return "Command-line Error"
    
    # File I/O errors
    elif any(x in stderr for x in ["file", "open", "read", "write", "permission", "access"]):
        if "not found" in stderr or "no such file" in stderr:
            return "File Not Found Error"
        elif "permission" in stderr:
            return "File Permission Error"
        elif "i/o error" in stderr:
            return "I/O Error"
        else:
            return "File Access Error"
        
    else:
        return "Unknown Error"

def analyze_json_content(crash_file):
    """Analyze the content of a JSON crash file with enhanced pattern detection."""
    try:
        with open(crash_file, 'r') as f:
            content = f.read()
            try:
                data = json.loads(content)
                
                result = {
                    "file_size": len(content),
                    "object_keys": list(data.keys()) if isinstance(data, dict) else [],
                    "data_type": type(data).__name__,
                    "trigger_features": [],
                    "complexity_metrics": {}
                }
                
                # Check for known crash trigger features
                if isinstance(data, dict):
                    # Known magic values
                    if "magic" in data and data["magic"] == "crash_me_now":
                        result["trigger_features"].append("magic_value")
                    
                    # Various buffer overflow patterns    
                    if "buffer" in data and isinstance(data["buffer"], str) and len(data["buffer"]) > 100:
                        result["trigger_features"].append("buffer_overflow")
                    
                    # Look for very long strings
                    for k, v in data.items():
                        if isinstance(v, str) and len(v) > 1000:
                            result["trigger_features"].append("large_string")
                            break
                            
                    # Division by zero patterns
                    if "divisor" in data and isinstance(data["divisor"], (int, float)) and data["divisor"] == 0:
                        result["trigger_features"].append("division_by_zero")
                    
                    # Deep recursion or nesting
                    if "depth" in data and isinstance(data["depth"], int) and data["depth"] > 1000:
                        result["trigger_features"].append("recursion_depth")
                    
                    # Integer overflows
                    for k, v in data.items():
                        if isinstance(v, int) and (v > 2**31-1 or v < -2**31):
                            result["trigger_features"].append("integer_overflow")
                            break
                            
                    # Format string vulnerabilities
                    for k, v in data.items():
                        if isinstance(v, str) and "%" in v and any(c in v for c in "diouxXeEfFgGcrs"):
                            result["trigger_features"].append("format_string")
                            break
                    
                    # Command injection patterns
                    for k, v in data.items():
                        if isinstance(v, str) and any(cmd in v for cmd in [";", "|", "`", "$(",  "&&", "||"]):
                            result["trigger_features"].append("command_injection")
                            break
                    
                    # SQL injection patterns
                    for k, v in data.items():
                        if isinstance(v, str) and any(sql in v.lower() for sql in ["select ", "insert ", "update ", "delete ", "drop ", "union ", "from "]):
                            result["trigger_features"].append("sql_injection")
                            break
                
                # Compute complexity metrics
                if isinstance(data, dict):
                    result["complexity_metrics"]["depth"] = _get_max_nesting_depth(data)
                    result["complexity_metrics"]["total_nodes"] = _count_total_nodes(data)
                    result["complexity_metrics"]["max_string_length"] = _get_max_string_length(data)
                    result["complexity_metrics"]["total_size"] = len(content)
                
                # Detect if this data is specifically crafted to trigger crashes
                crafted_score = 0
                for feature in result["trigger_features"]:
                    crafted_score += 1
                
                if isinstance(data, dict) and len(data) < 5 and any(len(str(v)) > 100 for v in data.values()):
                    crafted_score += 1
                
                if crafted_score >= 2:
                    result["potentially_malicious"] = True
                
                return result
            
            except json.JSONDecodeError:
                # Handle invalid JSON
                # Try to determine what's wrong with it
                result = {
                    "file_size": len(content),
                    "error": "Invalid JSON",
                    "trigger_features": []
                }
                
                if content.count('{') != content.count('}'):
                    result["trigger_features"].append("unbalanced_braces")
                if content.count('[') != content.count(']'):
                    result["trigger_features"].append("unbalanced_brackets")
                if '\\' in content:
                    result["trigger_features"].append("escape_sequences")
                if len(content) > 1000:
                    result["trigger_features"].append("large_input")
                    
                return result
    except Exception as e:
        logger.error(f"Error analyzing JSON content: {e}")
        return {"error": str(e), "file_size": os.path.getsize(crash_file) if os.path.exists(crash_file) else 0}

def _get_max_nesting_depth(obj, current_depth=0):
    """Helper function to get maximum nesting depth of JSON object."""
    if isinstance(obj, dict):
        if not obj:
            return current_depth
        return max([_get_max_nesting_depth(v, current_depth + 1) for v in obj.values()])
    elif isinstance(obj, list):
        if not obj:
            return current_depth
        return max([_get_max_nesting_depth(v, current_depth + 1) for v in obj])
    else:
        return current_depth

def _count_total_nodes(obj):
    """Helper function to count total number of nodes in JSON object."""
    if isinstance(obj, dict):
        return 1 + sum(_count_total_nodes(v) for v in obj.values())
    elif isinstance(obj, list):
        return 1 + sum(_count_total_nodes(v) for v in obj)
    else:
        return 1

def _get_max_string_length(obj):
    """Helper function to get maximum string length in JSON object."""
    if isinstance(obj, dict):
        return max([_get_max_string_length(v) for v in obj.values()], default=0)
    elif isinstance(obj, list):
        return max([_get_max_string_length(v) for v in obj], default=0)
    elif isinstance(obj, str):
        return len(obj)
    else:
        return 0

def generate_crash_hash(crash_file, crash_reason):
    """Generate a unique hash for the crash based on content and reason."""
    try:
        with open(crash_file, 'r') as f:
            content = f.read()
            # Combine content and reason, then hash
            combined = content + crash_reason
            return hashlib.md5(combined.encode()).hexdigest()[:10]
    except Exception as e:
        logger.error(f"Error generating crash hash: {e}")
        return "unknown_hash"

def analyze_crashes(target, crash_files):
    """Analyze crashes and group them by type."""
    crash_groups = defaultdict(list)
    unique_crashes = set()
    crash_data = []
    
    for crash_file in crash_files:
        # Execute target with crash file
        exit_code, stdout, stderr = execute_target_with_crash(target, crash_file)
        
        # Extract crash reason with detailed diagnostics
        crash_reason = extract_crash_reason(stderr, stdout)
        
        # Generate crash hash
        crash_hash = generate_crash_hash(crash_file, crash_reason)
        
        # Check if this is a unique crash
        if crash_hash not in unique_crashes:
            unique_crashes.add(crash_hash)
        
        # Analyze JSON content
        content_analysis = analyze_json_content(crash_file)
        
        # Group by crash reason
        crash_groups[crash_reason].append(crash_file)
        
        # Collect data for report with more detailed information
        crash_data.append({
            "file": crash_file,
            "reason": crash_reason,
            "hash": crash_hash,
            "content_analysis": content_analysis,
            "exit_code": exit_code,
            "stdout": stdout[:1000],  # Include truncated stdout to help with diagnosis
            "stderr": stderr[:1000],  # Include truncated stderr to help with diagnosis
            "crash_severity": "High" if any(x in crash_reason.lower() for x in 
                                         ['overflow', 'null pointer', 'memory corruption']) else "Medium",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return crash_groups, crash_data, len(unique_crashes)

def generate_report(crash_groups, crash_data, unique_crash_count, analysis_dirs):
    """Generate a detailed report of crash analysis."""
    report_file = os.path.join(analysis_dirs['reports_dir'], f"crash_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    with open(report_file, 'w') as f:
        f.write("==================================================\n")
        f.write("           INTELLIGENT FUZZING CRASH REPORT       \n")
        f.write("==================================================\n\n")
        
        f.write(f"Total crashes analyzed: {len(crash_data)}\n")
        f.write(f"Unique crashes identified: {unique_crash_count}\n\n")
        
        f.write("CRASH GROUPS BY REASON:\n")
        f.write("=======================\n\n")
        
        for reason, files in crash_groups.items():
            f.write(f"Reason: {reason}\n")
            f.write(f"Count: {len(files)}\n")
            f.write("Example files:\n")
            for i, file in enumerate(files[:5]):  # Show at most 5 examples
                f.write(f"  - {file}\n")
            if len(files) > 5:
                f.write(f"  - ... and {len(files) - 5} more\n")
            f.write("\n")
        
        f.write("\nDETAILED CRASH ANALYSIS:\n")
        f.write("========================\n\n")
        
        for crash in crash_data[:20]:  # Show at most 20 detailed entries
            f.write(f"File: {crash['file']}\n")
            f.write(f"Reason: {crash['reason']}\n")
            f.write(f"Hash: {crash['hash']}\n")
            f.write("Content Analysis:\n")
            for key, value in crash['content_analysis'].items():
                f.write(f"  - {key}: {value}\n")
            f.write("\n")
    
    logger.info(f"Report generated: {report_file}")
    return report_file

def generate_visualizations(crash_groups, crash_data, analysis_dirs):
    """Generate visualizations for crash analysis."""
    try:
        visuals_dir = analysis_dirs['visuals_dir']
        
        # Crash types pie chart
        plt.figure(figsize=(10, 6))
        reasons = [reason for reason in crash_groups.keys()]
        counts = [len(files) for files in crash_groups.values()]
        
        plt.pie(counts, labels=reasons, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        plt.title('Crash Types Distribution')
        
        chart_file = os.path.join(visuals_dir, "crash_types_distribution.png")
        plt.savefig(chart_file)
        plt.close()
        
        # Trigger features bar chart
        all_features = []
        for crash in crash_data:
            if 'content_analysis' in crash and 'trigger_features' in crash['content_analysis']:
                all_features.extend(crash['content_analysis']['trigger_features'])
        
        feature_counts = defaultdict(int)
        for feature in all_features:
            feature_counts[feature] += 1
        
        plt.figure(figsize=(10, 6))
        plt.bar(feature_counts.keys(), feature_counts.values())
        plt.title('Crash Trigger Features')
        plt.xlabel('Feature')
        plt.ylabel('Count')
        
        features_chart_file = os.path.join(visuals_dir, "crash_trigger_features.png")
        plt.savefig(features_chart_file)
        plt.close()
        
        # Save a JSON summary of the visualization data
        summary_data = {
            'crash_types': {reason: len(files) for reason, files in crash_groups.items()},
            'trigger_features': dict(feature_counts),
            'total_crashes': len(crash_data),
            'unique_crash_count': sum(1 for crash in crash_data if any(
                feature in crash.get('content_analysis', {}).get('trigger_features', [])
                for feature in ['magic_value', 'buffer_overflow', 'division_by_zero']
            ))
        }
        
        with open(os.path.join(analysis_dirs['data_dir'], 'visualization_data.json'), 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        logger.info(f"Visualizations generated: {chart_file}, {features_chart_file}")
        return [chart_file, features_chart_file]
    
    except Exception as e:
        logger.error(f"Error generating visualizations: {e}")
        return []

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Crash Analyzer for Intelligent Fuzzing")
    parser.add_argument("target", help="Target executable that produced the crashes")
    parser.add_argument("crashes_dir", help="Directory containing crash files")
    parser.add_argument("--output-dir", help="Directory to save analysis results (defaults to timestamped directory under crash_analysis)")
    parser.add_argument("--format", choices=["text", "json", "both"], default="both", 
                      help="Output format for reports (text, json, or both)")
    parser.add_argument("--visualize", action="store_true", default=True,
                      help="Generate visualization charts of crash data")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target) or not os.access(args.target, os.X_OK):
        logger.error(f"Target {args.target} does not exist or is not executable")
        return 1
    
    if not os.path.isdir(args.crashes_dir):
        logger.error(f"Crashes directory {args.crashes_dir} does not exist or is not a directory")
        return 1
    
    # Set up directories
    analysis_dirs = setup_directories(args.output_dir)
    
    # Find crash files
    crash_files = find_crash_files(args.crashes_dir)
    logger.info(f"Found {len(crash_files)} crash files")
    
    if not crash_files:
        logger.info("No crash files found")
        return 0
    
    # Analyze crashes
    logger.info("Analyzing crashes...")
    crash_groups, crash_data, unique_crash_count = analyze_crashes(args.target, crash_files)
    
    # Generate report
    report_file = generate_report(crash_groups, crash_data, unique_crash_count, analysis_dirs)
    logger.info(f"Report generated: {report_file}")
    
    # Save JSON data 
    json_data = {
        'crash_summary': {
            'total_crashes': len(crash_data),
            'unique_crashes': unique_crash_count,
            'crash_groups': {reason: len(files) for reason, files in crash_groups.items()}
        },
        'crash_details': crash_data,
        'timestamp': datetime.now().isoformat(),
        'target': args.target,
        'crashes_dir': args.crashes_dir
    }
    
    json_file = os.path.join(analysis_dirs['data_dir'], 'crash_analysis.json')
    with open(json_file, 'w') as f:
        json.dump(json_data, f, indent=2)
    logger.info(f"JSON data saved to: {json_file}")
    
    # Generate visualizations if requested
    if args.visualize:
        try:
            import matplotlib
            visualization_files = generate_visualizations(crash_groups, crash_data, analysis_dirs)
            logger.info(f"Generated {len(visualization_files)} visualization files")
        except ImportError:
            logger.warning("Matplotlib not available, skipping visualizations")
    
    logger.info(f"Crash analysis complete. Results saved to: {analysis_dirs['analysis_dir']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())