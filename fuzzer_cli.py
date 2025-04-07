#!/usr/bin/env python3
"""
Intelligent Fuzzing CLI Tool

This script provides a command-line interface for the intelligent fuzzing tool.
It allows users to fuzz executables, analyze source code, and manage fuzzing campaigns.
"""

import os
import sys
import argparse
import logging
import time
import json
import glob
import random
import shutil
import hashlib
import subprocess
from pathlib import Path

try:
    import magic
except ImportError:
    print("Warning: python-magic not installed, falling back to basic file detection")
    magic = None

# Add current directory to path for module imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import utility modules
from utils.logger import setup_logger
from utils.format_detector import FormatDetector, InputFormat
from utils.source_analyzer import SourceAnalyzer
from utils.behavior_monitor import BehaviorMonitor
from utils.qemu_instrumentation import QEMUInstrumentation

# Import grammar modules
try:
    from grammars import generic_grammar, json_grammar, xml_grammar, command_grammar, binary_grammar, text_grammar
except ImportError as e:
    print(f"Warning: Could not import all grammars: {e}")
    # Continue execution, specific grammars will be checked later

# Try to import structure-aware fuzzing components
try:
    from structure_aware_fuzzing import StructureAwareFuzzer
except ImportError as e:
    print(f"Warning: Could not import structure-aware fuzzing components: {e}")
    # Continue execution, specific imports will be checked when needed

# Set up logger
logger = setup_logger(name='fuzzer_cli', level=logging.INFO, verbose=True)

def setup_argparse():
    """Set up command-line argument parsing."""
    parser = argparse.ArgumentParser(
        description='Intelligent Fuzzing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz a binary with automatic format detection
  python fuzzer_cli.py fuzz /path/to/binary --iterations 1000 --timeout 30
  
  # Fuzz with a specific grammar
  python fuzzer_cli.py fuzz /path/to/binary --grammar json --iterations 1000
  
  # Analyze source code for potential vulnerabilities
  python fuzzer_cli.py analyze-source /path/to/source
  
  # Generate test corpus based on detected input format
  python fuzzer_cli.py generate-corpus --format json --output corpus/json
  
  # Analyze a crash
  python fuzzer_cli.py analyze-crash /path/to/binary /path/to/crash_file
  """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Fuzz command
    fuzz_parser = subparsers.add_parser('fuzz', help='Fuzz a binary')
    fuzz_parser.add_argument('target', help='Path to target binary or directory of binaries')
    fuzz_parser.add_argument('--grammar', choices=['json', 'xml', 'command', 'binary', 'generic'], 
                            help='Grammar to use for input generation')
    fuzz_parser.add_argument('--iterations', type=int, default=100, 
                            help='Number of fuzzing iterations')
    fuzz_parser.add_argument('--timeout', type=int, default=10, 
                            help='Timeout for each execution in seconds')
    fuzz_parser.add_argument('--output-dir', help='Directory to save results (defaults to session results directory)')
    fuzz_parser.add_argument('--seed-corpus', help='Directory containing seed files')
    fuzz_parser.add_argument('--afl', action='store_true', help='Use AFL++ for fuzzing')
    fuzz_parser.add_argument('--memory-monitor', action='store_true', 
                            help='Monitor memory usage during fuzzing')
    
    # Analyze source command
    analyze_parser = subparsers.add_parser('analyze-source', help='Analyze source code')
    analyze_parser.add_argument('source_dir', help='Directory containing source code')
    analyze_parser.add_argument('--output', help='Output file for analysis results (defaults to a file in session results directory)')
    analyze_parser.add_argument('--no-recursive', action='store_true', 
                                help='Do not recursively analyze subdirectories')
    
    # Generate corpus command
    corpus_parser = subparsers.add_parser('generate-corpus', help='Generate test corpus')
    corpus_parser.add_argument('--format', choices=['json', 'xml', 'command', 'binary', 'generic'], 
                                required=True, help='Format of corpus to generate')
    corpus_parser.add_argument('--count', type=int, default=20, 
                                help='Number of corpus files to generate')
    corpus_parser.add_argument('--output', help='Output directory for corpus (defaults to session corpus directory)')
    
    # Analyze crash command
    crash_parser = subparsers.add_parser('analyze-crash', help='Analyze a crash')
    crash_parser.add_argument('binary', help='Path to binary')
    crash_parser.add_argument('crash_file', help='Path to crash file')
    crash_parser.add_argument('--output', help='Output file for crash analysis (defaults to a file in session results directory)')
    crash_parser.add_argument('--timeout', type=int, default=30, 
                                help='Timeout for crash analysis in seconds')
    
    # Detect format command
    format_parser = subparsers.add_parser('detect-format', help='Detect format of files')
    format_parser.add_argument('target', help='File or directory to analyze')
    format_parser.add_argument('--recursive', action='store_true', 
                                help='Recursively analyze files in directory')
    format_parser.add_argument('--output-dir', help='Directory to save results (defaults to session results directory)')
    
    # QEMU fuzzing command
    qemu_parser = subparsers.add_parser('qemu-fuzz', help='Fuzz using QEMU instrumentation')
    qemu_parser.add_argument('binary', help='Path to binary to fuzz')
    qemu_parser.add_argument('--timeout', type=int, default=3600, 
                            help='Timeout for fuzzing in seconds')
    qemu_parser.add_argument('--output-dir', help='Directory to save results (defaults to session results directory)')
    qemu_parser.add_argument('--seed-corpus', help='Directory containing seed files')
    qemu_parser.add_argument('--memory-limit', type=int, help='Memory limit for AFL++ in MB')
    
    # Full fuzzing pipeline command
    full_fuzz_parser = subparsers.add_parser('full-fuzz', help='Run complete fuzzing pipeline with all available methods')
    full_fuzz_parser.add_argument('target', help='Path to target binary or directory of binaries')
    full_fuzz_parser.add_argument('--output-dir', help='Directory to save all results (defaults to session results directory)')
    full_fuzz_parser.add_argument('--timeout', type=int, default=3600, 
                                help='Total timeout for the entire fuzzing process in seconds')
    full_fuzz_parser.add_argument('--afl-cores', type=int, default=2, 
                                help='Number of cores to use for AFL++ fuzzing')
    full_fuzz_parser.add_argument('--seed-corpus', help='Optional initial seed corpus directory')
    full_fuzz_parser.add_argument('--generate-corpus', action='store_true', 
                                help='Auto-generate seed corpus before fuzzing')
    full_fuzz_parser.add_argument('--skip-grammar', action='store_true',
                                help='Skip grammar-based fuzzing')
    full_fuzz_parser.add_argument('--skip-afl', action='store_true',
                                help='Skip AFL++ fuzzing')
    full_fuzz_parser.add_argument('--skip-qemu', action='store_true',
                                help='Skip QEMU fuzzing for closed binaries')
    
    # Structure-aware fuzzing command
    structure_parser = subparsers.add_parser('structure-fuzz', help='Run structure-aware fuzzing with schema inference')
    structure_parser.add_argument('target', help='Path to target binary or file')
    structure_parser.add_argument('--format', choices=['json', 'xml', 'text', 'binary', 'auto'], 
                                default='auto', help='Format type (default: auto-detect)')
    structure_parser.add_argument('--schema', help='Path to schema file (optional)')
    structure_parser.add_argument('--iterations', type=int, default=100, 
                                help='Number of iterations (default: 100)')
    structure_parser.add_argument('--timeout', type=int, default=5, 
                                help='Timeout for each test case in seconds (default: 5)')
    structure_parser.add_argument('--output-dir', help='Output directory for results')
    structure_parser.add_argument('--seed-corpus', help='Directory containing seed files')
    structure_parser.add_argument('--corpus-size', type=int, default=20, 
                                help='Initial corpus size (default: 20)')
    structure_parser.add_argument('--mutation-count', type=int, default=5, 
                                help='Mutations per seed (default: 5)')
    structure_parser.add_argument('--valid-ratio', type=float, default=0.8, 
                                help='Ratio of valid to invalid test cases (default: 0.8)')
    
    return parser

def find_executable_files(directory):
    """Find fuzzable files in a directory recursively."""
    files_to_fuzz = []
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            
            # Skip directories and make sure file exists and is readable
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                try:
                    # Try to determine if it's a binary or text file
                    if magic:
                        mime = magic.Magic(mime=True)
                        file_type = mime.from_file(file_path)
                    else:
                        # Fallback to using extension if python-magic is not available
                        file_type = 'application/octet-stream'  # Default type
                    
                    # Include specific MIME types that are known to be fuzzable
                    fuzzable = False
                    
                    # Executables and shared libraries
                    if ('application/x-executable' in file_type or 
                        'application/x-elf' in file_type or 
                        'application/x-mach-binary' in file_type or
                        'application/x-sharedlib' in file_type or
                        'application/x-dosexec' in file_type):  # PE files
                        fuzzable = True
                        
                    # Scripts
                    elif ('text/x-python' in file_type or
                          'text/x-script' in file_type or
                          'text/x-shellscript' in file_type or
                          'text/x-perl' in file_type or
                          'text/x-ruby' in file_type):
                        fuzzable = True
                        
                    # Data formats
                    elif ('application/json' in file_type or
                          'application/xml' in file_type or
                          'text/xml' in file_type or
                          'application/x-sqlite' in file_type or
                          'application/sql' in file_type or
                          'application/zip' in file_type or
                          'application/x-tar' in file_type or
                          'application/x-gzip' in file_type or
                          'application/pdf' in file_type or
                          'application/octet-stream' in file_type):
                        fuzzable = True
                        
                    # Text formats
                    elif ('text/' in file_type and 
                          'text/html' not in file_type and 
                          'text/css' not in file_type):
                        # Most plain text formats (excluding html/css)
                        fuzzable = True
                    
                    # Check by extension as fallback
                    if not fuzzable:
                        _, ext = os.path.splitext(file_path)
                        ext = ext.lower()
                        if ext in ['.json', '.xml', '.sql', '.db', '.sqlite', 
                                  '.exe', '.dll', '.so', '.dylib', '.bin',
                                  '.py', '.sh', '.pl', '.rb', '.js',
                                  '.zip', '.tar', '.gz', '.pdf', '.conf']:
                            fuzzable = True
                    
                    if fuzzable:
                        logger.info(f"Found fuzzable file: {file_path} ({file_type})")
                        files_to_fuzz.append(file_path)
                    else:
                        logger.debug(f"Skipping non-fuzzable file: {file_path} ({file_type})")
                        
                except ImportError:
                    # If magic library is not available, use extension-based detection only
                    _, ext = os.path.splitext(file_path)
                    ext = ext.lower()
                    if ext in ['.json', '.xml', '.sql', '.db', '.sqlite', 
                              '.exe', '.dll', '.so', '.dylib', '.bin',
                              '.py', '.sh', '.pl', '.rb', '.js',
                              '.zip', '.tar', '.gz', '.pdf', '.conf']:
                        logger.info(f"Found fuzzable file (by extension): {file_path}")
                        files_to_fuzz.append(file_path)
                    
    return files_to_fuzz

def import_grammar(grammar_type):
    """Import the specified grammar type."""
    try:
        print(f"Attempting to import grammar for format: {grammar_type}")
        if grammar_type == 'json':
            import grammars.json_grammar
            return grammars.json_grammar
        elif grammar_type == 'xml':
            import grammars.xml_grammar
            return grammars.xml_grammar
        elif grammar_type == 'command':
            import grammars.command_grammar
            return grammars.command_grammar
        elif grammar_type == 'binary':
            import grammars.binary_grammar
            return grammars.binary_grammar
        elif grammar_type == 'text':
            import grammars.text_grammar
            return grammars.text_grammar
        elif grammar_type == 'generic':
            import grammars.generic_grammar
            return grammars.generic_grammar
        else:
            logger.error(f"Unknown grammar type: {grammar_type}")
            return None
    except ImportError as e:
        logger.error(f"Failed to load grammar for format: {grammar_type}, error: {e}")
        # Fall back to JSON grammar if available
        try:
            import grammars.json_grammar
            logger.info(f"Falling back to JSON grammar for {grammar_type}")
            return grammars.json_grammar
        except ImportError:
            logger.error("Failed to load JSON grammar as fallback")
            return None

def command_fuzz(args):
    """Run fuzzing command."""
    target_path = args.target
    
    # Check if target is a directory
    if os.path.isdir(target_path):
        logger.info(f"Target is a directory: {target_path}")
        # Find all files in the directory
        files_to_fuzz = find_executable_files(target_path)
        
        if not files_to_fuzz:
            logger.error(f"No fuzzable files found in {target_path}")
            return 1
            
        logger.info(f"Found {len(files_to_fuzz)} files to fuzz")
        
        # Use the session's consolidated results directory
        consolidated_dir = os.path.join(args.output_dir, "consolidated")
        os.makedirs(consolidated_dir, exist_ok=True)
        
        # Track results for each file
        consolidated_results = {
            'target_directory': target_path,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'files_fuzzed': [],
            'total_crashes': 0,
            'total_execution_time': 0,
            'crash_types': {}
        }
        
        start_time = time.time()
        
        for file_path in files_to_fuzz:
            logger.info(f"Fuzzing file: {file_path}")
            result_file = fuzz_single_target(file_path, args)
            
            # If fuzzing was successful and result file exists
            if result_file and os.path.exists(result_file):
                try:
                    with open(result_file, 'r') as f:
                        result_data = json.load(f)
                    
                    # Add file results to consolidated results
                    file_result = {
                        'file_path': file_path,
                        'crash_count': result_data.get('crash_count', 0),
                        'execution_time': result_data.get('execution_time', 0),
                        'result_file': result_file
                    }
                    
                    consolidated_results['files_fuzzed'].append(file_result)
                    consolidated_results['total_crashes'] += result_data.get('crash_count', 0)
                    consolidated_results['total_execution_time'] += result_data.get('execution_time', 0)
                    
                    # Aggregate crash types
                    for crash_type, count in result_data.get('crash_types', {}).items():
                        if crash_type in consolidated_results['crash_types']:
                            consolidated_results['crash_types'][crash_type] += count
                        else:
                            consolidated_results['crash_types'][crash_type] = count
                            
                except Exception as e:
                    logger.error(f"Error processing result file {result_file}: {e}")
        
        # Calculate total elapsed time
        total_elapsed = time.time() - start_time
        consolidated_results['wall_clock_time'] = total_elapsed
        
        # Save consolidated report
        consolidated_file = os.path.join(consolidated_dir, 'consolidated_report.json')
        with open(consolidated_file, 'w') as f:
            json.dump(consolidated_results, f, indent=2)
        
        # Create a readable text summary
        summary_text = f"""
=================================================================
CONSOLIDATED FUZZING SUMMARY REPORT
=================================================================
Target Directory:        {target_path}
Files Fuzzed:            {len(consolidated_results['files_fuzzed'])}
Total Crashes:           {consolidated_results['total_crashes']}
Total Process Time:      {consolidated_results['total_execution_time']:.2f} seconds
Wall Clock Time:         {total_elapsed:.2f} seconds
Date/Time:               {time.strftime("%Y-%m-%d %H:%M:%S")}

CRASH TYPES:
"""
        if consolidated_results['crash_types']:
            for crash_type, count in consolidated_results['crash_types'].items():
                summary_text += f"  {crash_type}: {count}\n"
        else:
            summary_text += "  No crashes found\n"
        
        summary_text += "\nFILES FUZZED:\n"
        for file_result in consolidated_results['files_fuzzed']:
            summary_text += f"  {file_result['file_path']}: {file_result['crash_count']} crashes\n"
        
        summary_text += """
=================================================================
"""
        
        # Save text summary
        text_summary_file = os.path.join(consolidated_dir, 'consolidated_report.txt')
        with open(text_summary_file, 'w') as f:
            f.write(summary_text)
        
        logger.info(f"Consolidated JSON report saved to: {consolidated_file}")
        logger.info(f"Consolidated text summary saved to: {text_summary_file}")
            
        return 0
    else:
        # Target is a single file
        return fuzz_single_target(target_path, args)

def fuzz_single_target(target_path, args):
    """Fuzz a single target executable."""
    logger.info(f"Starting fuzzing on target: {target_path}")
    
    if not os.path.exists(target_path):
        logger.error(f"Target not found: {target_path}")
        return 1
    
    # Setup output directory - if not specified, use the session's results directory
    output_dir = args.output_dir
    
    # Create a target-specific subdirectory
    target_basename = os.path.basename(target_path)
    target_output_dir = os.path.join(output_dir, f"fuzz_{target_basename}")
    os.makedirs(target_output_dir, exist_ok=True)
    output_dir = target_output_dir
    
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Results will be saved to: {output_dir}")
    
    if args.afl:
        # Use AFL++ with QEMU instrumentation
        return qemu_fuzzing(target_path, output_dir, args.seed_corpus, 
                            args.timeout, memory_limit=None)
    
    # Detect input format if not specified
    input_format = None
    if args.grammar:
        input_format = args.grammar
    else:
        logger.info("No grammar specified, attempting to detect format...")
        detector = FormatDetector()
        detected_format = detector.detect_format(target_path)
        input_format = detector.suggest_grammar(detected_format)
        logger.info(f"Detected format: {input_format}")
    
    # Load appropriate grammar using direct import
    try:
        if input_format == 'json':
            import grammars.json_grammar as grammar_module
        elif input_format == 'xml':
            import grammars.xml_grammar as grammar_module
        elif input_format == 'command':
            import grammars.command_grammar as grammar_module
        elif input_format == 'binary':
            import grammars.binary_grammar as grammar_module
        elif input_format == 'text':
            import grammars.text_grammar as grammar_module
        elif input_format == 'generic':
            import grammars.generic_grammar as grammar_module
        else:
            logger.error(f"Unknown grammar type: {input_format}")
            return 1
        
        logger.info(f"Successfully loaded {input_format} grammar")
    except ImportError as e:
        logger.error(f"Failed to load grammar for format: {input_format}, error: {e}")
        return 1
    
    # Setup monitoring
    behavior_monitor = BehaviorMonitor(output_dir=os.path.join(output_dir, 'behavior'))
    
    # Run fuzzing
    crash_count = 0
    crashes = []
    start_time = time.time()
    
    logger.info(f"Starting fuzzing with {args.iterations} iterations, "
               f"timeout {args.timeout}s per execution")
    
    for i in range(args.iterations):
        if i % 10 == 0:
            elapsed = time.time() - start_time
            logger.info(f"Progress: {i}/{args.iterations} iterations "
                       f"({i/args.iterations*100:.1f}%), "
                       f"found {crash_count} crashes, "
                       f"elapsed time: {elapsed:.1f}s")
        
        # Generate input
        valid = i % 5 != 0  # 80% valid inputs, 20% invalid
        input_data = grammar_module.generate(valid=valid)
        
        # Create temporary input file
        input_file = os.path.join(output_dir, f"input_{i:05d}")
        with open(input_file, 'w') as f:
            f.write(input_data)
        
        # Run target with input and monitor
        run_id, return_code, stdout, stderr, execution_time, anomalies = (
            behavior_monitor.monitor_process_with_input(
                target_path, input_file=input_file, timeout=args.timeout
            )
        )
        
        # Check for crash
        crashed = return_code != 0
        if crashed:
            crash_count += 1
            logger.warning(f"Crash detected in iteration {i}, return code: {return_code}")
            
            # Save crash info
            crash_dir = os.path.join(output_dir, 'crashes')
            os.makedirs(crash_dir, exist_ok=True)
            
            crash_info = {
                'iteration': i,
                'return_code': return_code,
                'execution_time': execution_time,
                'stdout': stdout,
                'stderr': stderr,
                'anomalies': anomalies,
                'input_data': input_data,
                'input_file': input_file,
                'run_id': run_id
            }
            
            # Detect crash type
            crash_type = 'Unknown'
            if stderr:
                if 'segmentation fault' in stderr.lower():
                    crash_type = 'Segmentation Fault'
                elif 'bus error' in stderr.lower():
                    crash_type = 'Bus Error'
                elif 'illegal instruction' in stderr.lower():
                    crash_type = 'Illegal Instruction'
                elif 'floating point exception' in stderr.lower():
                    crash_type = 'Floating Point Exception'
                elif 'aborted' in stderr.lower():
                    crash_type = 'Aborted'
            
            crash_info['crash_type'] = crash_type
            crashes.append(crash_info)
            
            crash_file = os.path.join(crash_dir, f"crash_{i:05d}.json")
            with open(crash_file, 'w') as f:
                json.dump(crash_info, f, indent=2)
            
            # Copy crash input
            crash_input = os.path.join(crash_dir, f"crash_{i:05d}.input")
            with open(crash_input, 'w') as f:
                f.write(input_data)
    
    # Print final stats
    elapsed = time.time() - start_time
    logger.info(f"Fuzzing completed: {args.iterations} iterations, "
               f"found {crash_count} crashes, "
               f"elapsed time: {elapsed:.1f}s")
    
    # Generate summary report
    summary_report = {
        'target': target_path,
        'iterations': args.iterations,
        'timeout': args.timeout,
        'grammar': input_format,
        'crash_count': crash_count,
        'execution_time': elapsed,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'crashes': crashes
    }
    
    # Create categorized crash types list
    crash_types = {}
    for crash in crashes:
        crash_type = crash.get('crash_type', 'Unknown')
        if crash_type in crash_types:
            crash_types[crash_type] += 1
        else:
            crash_types[crash_type] = 1
    
    summary_report['crash_types'] = crash_types
    
    # Save summary report
    summary_file = os.path.join(output_dir, 'summary_report.json')
    with open(summary_file, 'w') as f:
        json.dump(summary_report, f, indent=2)
    
    # Create a readable text summary
    summary_text = f"""
=================================================================
FUZZING SUMMARY REPORT
=================================================================
Target:                  {target_path}
Grammar:                 {input_format}
Iterations:              {args.iterations}
Execution time:          {elapsed:.2f} seconds
Crashes found:           {crash_count}
Date/Time:               {time.strftime("%Y-%m-%d %H:%M:%S")}

CRASH TYPES:
"""
    if crash_types:
        for crash_type, count in crash_types.items():
            summary_text += f"  {crash_type}: {count}\n"
    else:
        summary_text += "  No crashes found\n"
    
    summary_text += """
=================================================================
"""
    
    # Save text summary
    text_summary_file = os.path.join(output_dir, 'summary_report.txt')
    with open(text_summary_file, 'w') as f:
        f.write(summary_text)
    
    logger.info(f"Summary report saved to: {summary_file}")
    logger.info(f"Text summary saved to: {text_summary_file}")
    
    # Return the summary file path for consolidated reporting
    return summary_file

def qemu_fuzzing(binary, output_dir, seed_corpus=None, timeout=3600, memory_limit=None):
    """Run fuzzing using QEMU instrumentation.
    
    This function runs AFL++ in QEMU mode on the given binary executable,
    which allows instrumentation of closed-source binaries for coverage-guided fuzzing.
    
    Args:
        binary: Path to the binary executable to fuzz
        output_dir: Directory to save fuzzing results
        seed_corpus: Optional directory containing seed files
        timeout: Maximum runtime in seconds (default: 1 hour)
        memory_limit: Memory limit for AFL++ in MB (None means no limit)
        
    Returns:
        int: 0 on success, 1 on error
    """
    logger.info(f"Starting QEMU fuzzing on target: {binary}")
    
    # Verify the binary exists and is executable
    if not os.path.exists(binary):
        logger.error(f"Binary {binary} does not exist")
        return 1
    
    if not os.access(binary, os.X_OK):
        logger.error(f"Binary {binary} is not executable")
        return 1
    
    # Create subdirectories
    input_dir = os.path.join(output_dir, "input")
    os.makedirs(input_dir, exist_ok=True)
    
    afl_output_dir = os.path.join(output_dir, "afl_output")
    os.makedirs(afl_output_dir, exist_ok=True)
    
    minimized_dir = os.path.join(output_dir, "minimized_corpus")
    os.makedirs(minimized_dir, exist_ok=True)
    
    crash_analysis_dir = os.path.join(output_dir, "crash_analysis")
    os.makedirs(crash_analysis_dir, exist_ok=True)
    
    # If seed corpus is provided, copy it to input directory
    if seed_corpus and os.path.isdir(seed_corpus):
        seed_count = 0
        for file in os.listdir(seed_corpus):
            source_file = os.path.join(seed_corpus, file)
            if os.path.isfile(source_file):
                dest_file = os.path.join(input_dir, f"seed_{seed_count:04d}")
                shutil.copy2(source_file, dest_file)
                seed_count += 1
        logger.info(f"Copied {seed_count} seed files to {input_dir}")
    
    # Create default seeds if no seed corpus provided or it's empty
    if not os.listdir(input_dir):
        logger.info("Creating default seed files...")
        with open(os.path.join(input_dir, "seed_default"), "w") as f:
            f.write("fuzzing_input")
        with open(os.path.join(input_dir, "seed_small"), "w") as f:
            f.write("A" * 10)
        with open(os.path.join(input_dir, "seed_medium"), "w") as f:
            f.write("A" * 100)
        with open(os.path.join(input_dir, "seed_large"), "w") as f:
            f.write("A" * 1000)
        
        # Add some structured data
        with open(os.path.join(input_dir, "seed_json"), "w") as f:
            f.write('{"key1":"value1","key2":42,"key3":true}')
        with open(os.path.join(input_dir, "seed_xml"), "w") as f:
            f.write('<root><item>value</item><item>value2</item></root>')
            
        logger.info(f"Created {len(os.listdir(input_dir))} default seed files")
    
    # Set up environment variables for AFL
    afl_env = os.environ.copy()
    afl_env["AFL_SKIP_CPUFREQ"] = "1"  # Skip CPU frequency check
    afl_env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"  # Skip crash symbolizer
    afl_env["AFL_SKIP_BIN_CHECK"] = "1"  # Skip binary check for non-PIE binaries
    
    # Build AFL command
    afl_cmd = [
        "afl-fuzz",
        "-Q",                    # QEMU mode
        "-i", input_dir,
        "-o", afl_output_dir,
        "-t", str(min(10000, timeout // 2)),  # Per-execution timeout
    ]
    
    # Set memory limit
    if memory_limit is not None:
        afl_cmd.extend(["-m", str(memory_limit)])
    else:
        afl_cmd.extend(["-m", "none"])  # No memory limit
    
    # Add target and input placeholder
    afl_cmd.extend(["--", binary, "@@"])
    
    # Start timer
    start_time = time.time()
    
    # Run AFL
    logger.info(f"Running AFL command: {' '.join(afl_cmd)}")
    result = {
        "status": "failed",
        "start_time": start_time,
        "command": ' '.join(afl_cmd),
        "crashes": [],
        "stats": {}
    }
    
    try:
        # Start AFL process
        process = subprocess.Popen(
            afl_cmd,
            env=afl_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Monitor the process
        while process.poll() is None:
            # Check the elapsed time
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                logger.info(f"Reached timeout of {timeout} seconds, stopping AFL")
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
            
            # Check for crashes every minute
            time.sleep(60)
            crashes_dir = os.path.join(afl_output_dir, "crashes")
            if os.path.exists(crashes_dir):
                crash_count = len([f for f in os.listdir(crashes_dir) 
                                 if os.path.isfile(os.path.join(crashes_dir, f)) and f != "README.txt"])
                logger.info(f"AFL running for {elapsed:.0f} seconds, found {crash_count} crashes")
        
        # Process finished or was terminated
        end_time = time.time()
        elapsed = end_time - start_time
        logger.info(f"AFL completed after {elapsed:.1f} seconds")
        
        # Parse AFL stats
        stats_file = os.path.join(afl_output_dir, "fuzzer_stats")
        if os.path.exists(stats_file):
            try:
                stats = {}
                with open(stats_file, "r") as f:
                    for line in f:
                        if ":" in line:
                            key, value = line.strip().split(":", 1)
                            stats[key.strip()] = value.strip()
                result["stats"] = stats
                logger.info(f"Parsed AFL stats: {len(stats)} entries")
            except Exception as e:
                logger.error(f"Error parsing AFL stats: {e}")
        
        # Collect crashes
        crashes_dir = os.path.join(afl_output_dir, "crashes")
        if os.path.exists(crashes_dir):
            crash_files = []
            for file in os.listdir(crashes_dir):
                if file != "README.txt" and os.path.isfile(os.path.join(crashes_dir, file)):
                    crash_files.append(file)
            
            # Copy crashes to the crash directory
            crash_dir = os.path.join(output_dir, "crashes")
            os.makedirs(crash_dir, exist_ok=True)
            
            for file in crash_files:
                source_file = os.path.join(crashes_dir, file)
                dest_file = os.path.join(crash_dir, file)
                shutil.copy2(source_file, dest_file)
            
            result["crashes"] = crash_files
            logger.info(f"Collected {len(crash_files)} crashes")
            
            # Analyze some crashes if we found any
            if crash_files:
                # Create a detailed crash report
                report_file = os.path.join(output_dir, "crash_report.txt")
                with open(report_file, "w") as f:
                    f.write("=== QEMU Fuzzing Crash Report ===\n\n")
                    f.write(f"Target: {binary}\n")
                    f.write(f"Crashes Found: {len(crash_files)}\n")
                    f.write(f"Fuzzing Duration: {elapsed:.1f} seconds\n\n")
                    
                    # List all crashes
                    f.write("Crash Files:\n")
                    for i, file in enumerate(sorted(crash_files)[:20]):  # Limit to 20 crash files
                        file_path = os.path.join(crashes_dir, file)
                        file_size = os.path.getsize(file_path)
                        f.write(f"{i+1}. {file} ({file_size} bytes)\n")
                    
                    if len(crash_files) > 20:
                        f.write(f"... and {len(crash_files) - 20} more\n")
                    
                    f.write("\n=== End of Report ===\n")
                
                logger.info(f"Crash report written to {report_file}")
                
                # Try to create a minimized corpus
                try:
                    queue_dir = os.path.join(afl_output_dir, "queue")
                    if os.path.exists(queue_dir) and os.listdir(queue_dir):
                        logger.info("Minimizing corpus with afl-cmin...")
                        cmin_cmd = [
                            "afl-cmin",
                            "-Q",  # QEMU mode
                            "-i", queue_dir,
                            "-o", minimized_dir,
                            "--", binary, "@@"
                        ]
                        
                        cmin_result = subprocess.run(
                            cmin_cmd,
                            env=afl_env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=300,  # 5-minute timeout
                        )
                        
                        if cmin_result.returncode == 0:
                            minimized_count = len(os.listdir(minimized_dir))
                            queue_count = len([f for f in os.listdir(queue_dir) 
                                            if os.path.isfile(os.path.join(queue_dir, f)) and f != "README.txt"])
                            logger.info(f"Minimized corpus from {queue_count} to {minimized_count} files")
                            
                            result["minimized_corpus_size"] = minimized_count
                            result["original_corpus_size"] = queue_count
                        else:
                            logger.error(f"Corpus minimization failed: {cmin_result.stderr}")
                except Exception as e:
                    logger.error(f"Error during corpus minimization: {e}")
        
        result["status"] = "completed"
        result["end_time"] = end_time
        result["elapsed"] = elapsed
        
        # Save result as JSON
        with open(os.path.join(output_dir, "qemu_fuzzing_result.json"), "w") as f:
            json.dump(result, f, indent=2)
        
        logger.info("QEMU fuzzing completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error during QEMU fuzzing: {e}")
        result["error"] = str(e)
        
        # Save error result
        with open(os.path.join(output_dir, "qemu_fuzzing_result.json"), "w") as f:
            json.dump(result, f, indent=2)
        
        return 1
    
    # This code is unreachable - it was part of the previous implementation
    # and is left over after the refactoring. Removing it to avoid confusion.

def command_analyze_source(args):
    """Run source code analysis command."""
    logger.info(f"Starting source code analysis on: {args.source_dir}")
    
    if not os.path.isdir(args.source_dir):
        logger.error(f"Source directory not found: {args.source_dir}")
        return 1
    
    # Initialize source analyzer
    analyzer = SourceAnalyzer()
    
    # Run analysis
    results = analyzer.analyze_directory(args.source_dir, recursive=not args.no_recursive)
    
    # Print summary
    logger.info(f"Analysis completed: {len(results['files_analyzed'])} files analyzed")
    logger.info(f"Found {len(results['input_functions'])} input functions")
    logger.info(f"Found {len(results['vulnerabilities'])} potential vulnerabilities")
    
    # Print vulnerabilities
    if results['vulnerabilities']:
        logger.info("\nPotential vulnerabilities found:")
        for i, vuln in enumerate(results['vulnerabilities']):
            logger.info(f"{i+1}. {vuln['type']} in {vuln['file']}:{vuln['line']}")
            logger.info(f"   Description: {vuln['description']}")
            logger.info(f"   Code: {vuln['code']}")
    
    # Save results
    if args.output:
        output_file = args.output
    else:
        output_file = os.path.join(args.output_dir, "source_analysis.json")
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Results saved to: {output_file}")
    return 0

def command_generate_corpus(args):
    """Run corpus generation command."""
    logger.info(f"Generating {args.count} {args.format} corpus files in {args.output}")
    
    os.makedirs(args.output, exist_ok=True)
    
    # Load appropriate grammar
    try:
        # Direct import approach for each grammar type
        if args.format == 'json':
            import grammars.json_grammar as grammar_module
        elif args.format == 'xml':
            import grammars.xml_grammar as grammar_module
        elif args.format == 'command':
            import grammars.command_grammar as grammar_module
        elif args.format == 'binary':
            import grammars.binary_grammar as grammar_module
        elif args.format == 'generic':
            import grammars.generic_grammar as grammar_module
        else:
            logger.error(f"Unknown grammar type: {args.format}")
            return 1
        
        logger.info(f"Successfully loaded {args.format} grammar")
    except ImportError as e:
        logger.error(f"Failed to load grammar for format: {args.format}, error: {e}")
        return 1
    
    # Generate corpus
    try:
        corpus_files = grammar_module.generate_corpus(count=args.count, output_dir=args.output)
        logger.info(f"Generated {len(corpus_files)} corpus files")
        return 0
    except Exception as e:
        logger.error(f"Failed to generate corpus: {e}")
        return 1

def command_analyze_crash(args):
    """Run crash analysis command."""
    logger.info(f"Analyzing crash in {args.binary} from {args.crash_file}")
    
    if not os.path.exists(args.binary):
        logger.error(f"Binary not found: {args.binary}")
        return 1
    
    if not os.path.exists(args.crash_file):
        logger.error(f"Crash file not found: {args.crash_file}")
        return 1
    
    # Run binary with crash input
    try:
        import subprocess
        cmd = [args.binary]
        
        with open(args.crash_file, 'rb') as f:
            crash_data = f.read()
        
        process = subprocess.run(cmd, input=crash_data, capture_output=True, timeout=args.timeout)
        
        # Analysis output
        analysis = {
            'binary': args.binary,
            'crash_file': args.crash_file,
            'return_code': process.returncode,
            'stdout': process.stdout.decode('utf-8', errors='ignore'),
            'stderr': process.stderr.decode('utf-8', errors='ignore'),
            'crash_data_size': len(crash_data),
            'analyzed_at': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Detect crash reason with detailed analysis
        stderr = analysis['stderr'].lower()
        stdout = analysis['stdout'].lower()
        
        # Create a detailed crash type classification
        if 'segmentation fault' in stderr:
            if 'null pointer' in stderr or 'null pointer' in stdout:
                analysis['crash_type'] = 'Null Pointer Dereference'
            elif 'stack overflow' in stderr or 'stack overflow' in stdout:
                analysis['crash_type'] = 'Stack Overflow'
            elif 'heap corruption' in stderr or 'heap corruption' in stdout:
                analysis['crash_type'] = 'Heap Corruption'
            elif 'buffer overflow' in stderr or 'buffer overflow' in stdout:
                analysis['crash_type'] = 'Buffer Overflow'
            elif 'invalid memory' in stderr or 'invalid memory' in stdout:
                analysis['crash_type'] = 'Invalid Memory Access'
            else:
                analysis['crash_type'] = 'Segmentation Fault'
                
        elif 'bus error' in stderr:
            if 'alignment' in stderr:
                analysis['crash_type'] = 'Memory Alignment Error'
            else:
                analysis['crash_type'] = 'Bus Error (Hardware Exception)'
                
        elif 'illegal instruction' in stderr:
            analysis['crash_type'] = 'Illegal Instruction'
            
        elif 'floating point' in stderr:
            if 'division by zero' in stderr or 'divide by zero' in stderr:
                analysis['crash_type'] = 'Division by Zero'
            else:
                analysis['crash_type'] = 'Floating Point Exception'
                
        elif 'abort' in stderr or 'aborted' in stderr:
            if 'assertion' in stderr:
                analysis['crash_type'] = 'Assertion Failure'
            elif 'double free' in stderr:
                analysis['crash_type'] = 'Double Free'
            elif 'memory corruption' in stderr:
                analysis['crash_type'] = 'Memory Corruption'
            else:
                analysis['crash_type'] = 'Program Aborted'
                
        elif 'stack smashing' in stderr:
            analysis['crash_type'] = 'Stack Smashing Detected'
            
        elif 'memory exhausted' in stderr or 'out of memory' in stderr:
            analysis['crash_type'] = 'Out of Memory'
            
        elif 'timeout' in stderr or analysis.get('timeout', False):
            analysis['crash_type'] = 'Execution Timeout'
            
        elif 'buffer overflow' in stderr or 'buffer overflow' in stdout:
            analysis['crash_type'] = 'Buffer Overflow'
            
        elif 'divide by zero' in stderr or 'division by zero' in stderr:
            analysis['crash_type'] = 'Division by Zero'
            
        elif analysis['return_code'] != 0:
            # If we have a non-zero return code but no specific error message, classify by return code
            signal_code = analysis['return_code'] & 0x7F  # Extract signal from return code
            if signal_code > 0:
                signal_names = {
                    1: 'SIGHUP - Hangup',
                    2: 'SIGINT - Interrupt',
                    3: 'SIGQUIT - Quit',
                    4: 'SIGILL - Illegal Instruction',
                    5: 'SIGTRAP - Trap',
                    6: 'SIGABRT - Aborted',
                    7: 'SIGBUS - Bus Error',
                    8: 'SIGFPE - Floating Point Exception',
                    9: 'SIGKILL - Killed',
                    10: 'SIGUSR1 - User Signal 1',
                    11: 'SIGSEGV - Segmentation Fault',
                    12: 'SIGUSR2 - User Signal 2',
                    13: 'SIGPIPE - Broken Pipe',
                    14: 'SIGALRM - Alarm',
                    15: 'SIGTERM - Terminated',
                }
                analysis['crash_type'] = f'Signal: {signal_names.get(signal_code, f"Unknown Signal {signal_code}")}'
            else:
                analysis['crash_type'] = f'Exit Code: {analysis["return_code"]}'
        else:
            # Complete fallback for when we have no clue
            analysis['crash_type'] = 'Unknown Error'
            
        # Add a crash fingerprint to help identify unique crashes
        crash_data_hash = hashlib.md5(open(args.crash_file, 'rb').read()[:1024]).hexdigest()[:8]
        stderr_hash = hashlib.md5(stderr.encode()).hexdigest()[:8]
        analysis['crash_fingerprint'] = f"{crash_data_hash}_{stderr_hash}"
        analysis['crash_severity'] = 'High' if any(x in analysis['crash_type'].lower() for x in ['overflow', 'null pointer', 'memory corruption']) else 'Medium'
        
        # Print analysis
        logger.info(f"Crash type: {analysis['crash_type']}")
        logger.info(f"Return code: {analysis['return_code']}")
        if analysis['stderr']:
            logger.info(f"Error output: {analysis['stderr'][:200]}...")
        
        # Save results
        if args.output:
            output_file = args.output
        else:
            crash_file_name = os.path.basename(args.crash_file)
            # Use the results directory from session dirs if output_dir not explicitly set
            output_dir = getattr(args, 'output_dir', None)
            if not output_dir:
                output_dir = os.path.join("sessions", f"session_{time.strftime('%Y%m%d-%H%M%S')}", "results")
                os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"crash_analysis_{crash_file_name}.json")
            
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        logger.info(f"Analysis saved to: {output_file}")
        return 0
        
    except subprocess.TimeoutExpired:
        logger.error(f"Analysis timed out after {args.timeout} seconds")
        return 1
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1

def command_detect_format(args):
    """Run format detection command."""
    target = args.target
    logger.info(f"Detecting format of: {target}")
    
    # Initialize format detector
    detector = FormatDetector()
    
    if os.path.isdir(target):
        # Analyze all files in directory
        targets = []
        if args.recursive:
            for root, _, files in os.walk(target):
                for filename in files:
                    targets.append(os.path.join(root, filename))
        else:
            targets = [os.path.join(target, f) for f in os.listdir(target) 
                       if os.path.isfile(os.path.join(target, f))]
        
        logger.info(f"Analyzing {len(targets)} files in directory")
        
        results = {}
        for file_path in targets:
            try:
                format_type = detector.detect_format(file_path)
                results[file_path] = format_type.name
            except Exception as e:
                results[file_path] = f"Error: {e}"
        
        # Print results
        for file_path, format_type in results.items():
            logger.info(f"{file_path}: {format_type}")
        
        # Count formats
        format_counts = {}
        for _, format_type in results.items():
            if format_type in format_counts:
                format_counts[format_type] += 1
            else:
                format_counts[format_type] = 1
        
        logger.info("\nFormat distribution:")
        for format_type, count in format_counts.items():
            logger.info(f"{format_type}: {count} files")
        
    else:
        # Analyze single file
        try:
            format_type = detector.detect_format(target)
            logger.info(f"Detected format: {format_type.name}")
            
            # Get suggested grammar
            grammar = detector.suggest_grammar(format_type)
            logger.info(f"Suggested grammar for fuzzing: {grammar}")
            
            # Get more file info
            import os
            file_size = os.path.getsize(target)
            
            logger.info(f"File size: {file_size} bytes")
            logger.info(f"Is executable: {os.access(target, os.X_OK)}")
            
        except Exception as e:
            logger.error(f"Failed to detect format: {e}")
            return 1
    
    return 0

def generate_intelligent_corpus(target, output_dir, format_type=None, min_files=10, max_files=50):
    """
    Generate an intelligent corpus optimized for the target based on format detection.
    
    Args:
        target: Path to the target binary
        output_dir: Directory to save the generated corpus
        format_type: Optional format type override, if not provided will be auto-detected
        min_files: Minimum number of corpus files to generate
        max_files: Maximum number of corpus files to generate
        
    Returns:
        Path to the corpus directory
    """
    logger.info(f"Generating intelligent corpus for {target}")
    os.makedirs(output_dir, exist_ok=True)
    
    # Detect format if not provided
    if not format_type:
        detector = FormatDetector()
        detected_format = detector.detect_format(target)
        format_type = detector.suggest_grammar(detected_format)
        logger.info(f"Auto-detected format: {format_type}")
    
    # Find appropriate grammar module
    try:
        grammar_module = import_grammar(format_type)
        if not grammar_module:
            logger.warning(f"Could not load {format_type} grammar, falling back to generic")
            grammar_module = import_grammar('generic')
            if not grammar_module:
                raise ImportError("Failed to load any grammar module")
    except ImportError as e:
        logger.error(f"Error loading grammar: {e}")
        # Create basic fallback corpus
        fallback_path = os.path.join(output_dir, "fallback.txt")
        with open(fallback_path, "w") as f:
            f.write("test\n")
        logger.warning("Created basic fallback corpus")
        return output_dir
    
    # Generate corpus files
    try:
        # Dynamic population size based on format complexity
        format_complexity = {
            'json': 0.8,  # Complex structure, many edge cases
            'xml': 0.9,   # Very complex structure, many edge cases
            'command': 0.5,  # Medium complexity
            'binary': 0.7,  # Binary formats can be complex
            'generic': 0.4  # Generic is simpler
        }
        
        complexity_factor = format_complexity.get(format_type, 0.5)
        target_files = min(max_files, max(min_files, int(min_files + (max_files - min_files) * complexity_factor)))
        
        logger.info(f"Generating {target_files} {format_type} corpus files")
        
        # Generate the corpus
        if hasattr(grammar_module, 'generate_corpus'):
            corpus_files = grammar_module.generate_corpus(count=target_files, output_dir=output_dir)
            logger.info(f"Generated {len(corpus_files)} corpus files")
        else:
            # Fall back to manual generation if generate_corpus not available
            logger.info("Grammar module doesn't have generate_corpus method, using manual generation")
            corpus_files = []
            for i in range(target_files):
                if hasattr(grammar_module, 'generate'):
                    data = grammar_module.generate()
                else:
                    # Ultimate fallback
                    data = f"test_input_{i}\n"
                
                file_path = os.path.join(output_dir, f"corpus_{i:04d}")
                # Проверяем тип данных и используем соответствующий режим
                if isinstance(data, bytes):
                    with open(file_path, "wb") as f:
                        f.write(data)
                else:
                    with open(file_path, "w") as f:
                        f.write(str(data))
                corpus_files.append(file_path)
            
            logger.info(f"Manually generated {len(corpus_files)} corpus files")
        
        # Add boundary cases and special values
        add_boundary_cases(output_dir, format_type)
        
        return output_dir
        
    except Exception as e:
        logger.error(f"Error generating corpus: {e}", exc_info=True)
        # Create basic fallback corpus
        fallback_path = os.path.join(output_dir, "fallback.txt")
        with open(fallback_path, "w") as f:
            f.write("test\n")
        logger.warning("Created basic fallback corpus after error")
        return output_dir

def add_boundary_cases(corpus_dir, format_type):
    """Add boundary cases to a corpus directory based on format type."""
    logger.info(f"Adding boundary cases for {format_type} format")
    
    if format_type == 'json':
        cases = [
            ('empty_object.json', '{}'),
            ('empty_array.json', '[]'),
            ('deep_nesting.json', '{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}'),
            ('large_array.json', '[' + ','.join(['1'] * 1000) + ']'),
            ('special_chars.json', '{"special\\u0000chars":"\\"\\n\\r\\t\\f\\b"}'),
            ('unicode.json', '{"unicode":"\\u1234\\u5678\\u90AB\\uCDEF"}'),
            ('max_integer.json', '{"max_int":9007199254740991}'),
            ('min_integer.json', '{"min_int":-9007199254740991}'),
            ('large_number.json', '{"large_num":1e308}'),
            ('small_number.json', '{"small_num":1e-308}')
        ]
    elif format_type == 'xml':
        cases = [
            ('empty.xml', '<?xml version="1.0"?><root/>'),
            ('deep_nesting.xml', '<?xml version="1.0"?><a><b><c><d><e><f><g><h><i><j>test</j></i></h></g></f></e></d></c></b></a>'),
            ('large_element.xml', '<?xml version="1.0"?><root>' + '<item></item>' * 1000 + '</root>'),
            ('special_chars.xml', '<?xml version="1.0"?><root><![CDATA[Special chars: & < > " \' \\ / \b \f \n \r \t]]></root>'),
            ('namespaces.xml', '<?xml version="1.0"?><root xmlns:ns1="http://example.com/ns1" xmlns:ns2="http://example.com/ns2"><ns1:elem>Test</ns1:elem><ns2:elem>Test</ns2:elem></root>')
        ]
    elif format_type == 'binary':
        cases = [
            ('all_zeros.bin', b'\x00' * 1024),
            ('all_ones.bin', b'\xFF' * 1024),
            ('alternating.bin', b'\x00\xFF' * 512),
            ('incrementing.bin', bytes(range(256)) * 4),
            ('random_binary.bin', os.urandom(1024))
        ]
        # Binary files need special handling
        for name, content in cases:
            path = os.path.join(corpus_dir, name)
            with open(path, 'wb') as f:
                f.write(content)
        return
    elif format_type == 'text':
        cases = [
            ('empty.txt', ''),
            ('long_input.txt', 'A' * 10000),
            ('special_chars.txt', '!@#$%^&*()_+-=[]{}|;:\'",.<>/?\\~`'),
            ('control_chars.txt', '\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0B\x0C\r\x0E\x0F'),
            ('unicode.txt', 'ñáéíóúäëïöüÑÁÉÍÓÚÄËÏÖÜ'),
            ('format_string.txt', '%s %d %x %n %.1000f ${PATH} $HOME'),
            ('regex_bomb.txt', 'a' * 1000 + '!' + 'a' * 1000),
            ('sql_injection.txt', '\' OR \'1\'=\'1\'; DROP TABLE users; --'),
            ('html_injection.txt', '<script>alert(1)</script><img src=x onerror=alert(1)>'),
            ('path_traversal.txt', '../../../etc/passwd\n..\\..\\..\\windows\\system32\\cmd.exe'),
            ('text_with_nulls.txt', 'Hello\x00World\x00Test\x00with\x00null\x00bytes'),
            ('very_long_line.txt', ''.join(chr((i % 94) + 32) for i in range(50000)))
        ]
    else:  # Default/generic/command formats
        cases = [
            ('empty.txt', ''),
            ('long_input.txt', 'A' * 10000),
            ('special_chars.txt', '!@#$%^&*()_+-=[]{}|;:\'",.<>/?\\~`'),
            ('control_chars.txt', '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'),
            ('unicode.txt', 'ñáéíóúäëïöüÑÁÉÍÓÚÄËÏÖÜ')
        ]
    
    # Write text-based cases
    for name, content in cases:
        path = os.path.join(corpus_dir, name)
        with open(path, 'w') as f:
            f.write(content)

def command_full_fuzz(args):
    """Run the full fuzzing pipeline with all available methods."""
    start_time = time.time()
    target_path = args.target
    
    # Set up output directory if not specified
    output_dir = args.output_dir
    full_fuzz_dir = os.path.join(output_dir, "full_fuzz_results")
    os.makedirs(full_fuzz_dir, exist_ok=True)
    
    # Set up directories for each fuzzing method
    grammar_dir = os.path.join(full_fuzz_dir, "grammar_fuzzing")
    afl_dir = os.path.join(full_fuzz_dir, "afl_fuzzing")
    qemu_dir = os.path.join(full_fuzz_dir, "qemu_fuzzing")
    corpus_dir = os.path.join(full_fuzz_dir, "corpus")
    consolidated_dir = os.path.join(full_fuzz_dir, "consolidated")
    
    os.makedirs(grammar_dir, exist_ok=True)
    os.makedirs(afl_dir, exist_ok=True)
    os.makedirs(qemu_dir, exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)
    os.makedirs(consolidated_dir, exist_ok=True)
    
    # Use provided seed corpus or generate one
    seed_corpus = args.seed_corpus
    if not seed_corpus or args.generate_corpus:
        logger.info("Generating intelligent seed corpus...")
        seed_corpus = generate_intelligent_corpus(target_path, corpus_dir)
        logger.info(f"Generated seed corpus at: {seed_corpus}")
    
    # Find all binary files if target is a directory
    total_binary_files = 0
    fuzzed_binary_files = 0
    binary_files_list = []
    
    if os.path.isdir(target_path):
        logger.info("Target is a directory, scanning for binary files...")
        for root, _, files in os.walk(target_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                    # Check if it's a binary file
                    try:
                        if magic:
                            mime = magic.Magic(mime=True)
                            file_type = mime.from_file(file_path)
                            is_binary = not file_type.startswith('text/')
                        else:
                            # Fallback method - check for null bytes
                            with open(file_path, 'rb') as f:
                                content = f.read(4096)  # Read first 4KB
                                is_binary = b'\x00' in content
                                
                        if is_binary:
                            total_binary_files += 1
                            binary_files_list.append(file_path)
                    except Exception as e:
                        logger.warning(f"Error checking file {file_path}: {e}")
        logger.info(f"Found {total_binary_files} binary files in the target directory")
    else:
        # Single target file
        total_binary_files = 1
        binary_files_list = [target_path]
    
    # Track results for various methods
    results = {
        'target': target_path,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'methods_used': [],
        'total_crashes': 0,
        'total_execution_time': 0,
        'crash_types': {},
        'crashes_by_method': {},
        'binary_files': {
            'total_found': total_binary_files,
            'fuzzed': 0,
            'coverage_percentage': 0,
            'files_list': binary_files_list
        }
    }
    
    # Calculate timeout per method based on total timeout
    # Reserve 10% for overhead and consolidation
    method_count = 3  # Grammar, AFL, QEMU
    if args.skip_grammar:
        method_count -= 1
    if args.skip_afl:
        method_count -= 1
    if args.skip_qemu:
        method_count -= 1
    
    if method_count == 0:
        logger.error("All fuzzing methods are skipped! Please enable at least one method.")
        return 1
    
    method_timeout = int(args.timeout * 0.9 / method_count)
    
    # 1. Run grammar-based fuzzing if not skipped
    if not args.skip_grammar:
        logger.info("=== STARTING GRAMMAR-BASED FUZZING ===")
        grammar_args = argparse.Namespace(
            target=target_path,
            iterations=1000,  # Reasonable default for quick results
            timeout=5,        # Per execution timeout
            grammar=None,     # Auto-detect
            output_dir=grammar_dir,
            afl=False
        )
        
        method_start = time.time()
        grammar_result = fuzz_single_target(target_path, grammar_args)
        method_elapsed = time.time() - method_start
        
        results['methods_used'].append('grammar')
        results['crashes_by_method']['grammar'] = {
            'result_file': grammar_result if isinstance(grammar_result, str) else None,
            'execution_time': method_elapsed
        }
        
        if isinstance(grammar_result, str) and os.path.exists(grammar_result):
            try:
                with open(grammar_result, 'r') as f:
                    grammar_data = json.load(f)
                
                # Add grammar results to consolidated results
                crash_count = grammar_data.get('crash_count', 0)
                results['total_crashes'] += crash_count
                results['total_execution_time'] += grammar_data.get('execution_time', 0)
                
                # Aggregate crash types
                for crash_type, count in grammar_data.get('crash_types', {}).items():
                    if crash_type in results['crash_types']:
                        results['crash_types'][crash_type] += count
                    else:
                        results['crash_types'][crash_type] = count
                        
                logger.info(f"Grammar-based fuzzing found {crash_count} crashes in {method_elapsed:.2f} seconds")
            except Exception as e:
                logger.error(f"Error processing grammar result file: {e}")
    
    # 2. Run AFL++ fuzzing if not skipped
    if not args.skip_afl:
        logger.info("=== STARTING AFL++ FUZZING ===")
        afl_timeout = min(method_timeout, 3600)  # Cap at 1 hour
        
        afl_args = argparse.Namespace(
            binary=target_path if os.path.isfile(target_path) else None,
            timeout=afl_timeout,
            output_dir=afl_dir,
            seed_corpus=seed_corpus,
            memory_limit=None
        )
        
        # For directory targets, just use the first executable file
        if os.path.isdir(target_path):
            files_to_fuzz = find_executable_files(target_path)
            if files_to_fuzz:
                afl_args.binary = files_to_fuzz[0]
                logger.info(f"Using {afl_args.binary} as representative binary for AFL++ fuzzing")
            else:
                logger.warning("No suitable binaries found for AFL++ fuzzing in directory")
                afl_args.binary = None
        
        method_start = time.time()
        afl_result = 1  # Default to error
        
        if afl_args.binary:
            afl_result = qemu_fuzzing(afl_args.binary, afl_dir, afl_args.seed_corpus, 
                                    afl_args.timeout, afl_args.memory_limit)
            
            # Check for AFL output directory with crashes
            crashes_dir = os.path.join(afl_dir, "afl_output", "default", "crashes")
            if os.path.exists(crashes_dir):
                crash_files = [f for f in os.listdir(crashes_dir) if f != 'README.txt']
                crash_count = len(crash_files)
                
                results['methods_used'].append('afl')
                results['total_crashes'] += crash_count
                
                # Add an "AFL" crash type
                crash_type = "AFL-detected crash"
                if crash_type in results['crash_types']:
                    results['crash_types'][crash_type] += crash_count
                else:
                    results['crash_types'][crash_type] = crash_count
                
                logger.info(f"AFL++ fuzzing found {crash_count} crashes")
                
                # Run crash analyzer on AFL crashes if available
                try:
                    from crash_analyzer import analyze_crashes, extract_crash_reason
                    
                    logger.info("Analyzing AFL crash files...")
                    crash_paths = [os.path.join(crashes_dir, f) for f in crash_files]
                    
                    # Only analyze a sample if there are many crashes
                    if len(crash_paths) > 20:
                        logger.info(f"Sampling 20 crashes out of {len(crash_paths)} for detailed analysis")
                        import random
                        crash_paths = random.sample(crash_paths, 20)
                    
                    for crash_file in crash_paths:
                        # Execute target with crash input
                        try:
                            cmd = [afl_args.binary]
                            with open(crash_file, 'rb') as f:
                                crash_input = f.read()
                            
                            process = subprocess.Popen(
                                cmd, 
                                stdin=subprocess.PIPE, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE
                            )
                            
                            try:
                                stdout, stderr = process.communicate(input=crash_input, timeout=10)
                                exit_code = process.returncode
                                
                                if exit_code != 0:
                                    crash_reason = extract_crash_reason(stderr.decode('utf-8', errors='ignore'), 
                                                                      stdout.decode('utf-8', errors='ignore'))
                                    
                                    if crash_reason != "Unknown":
                                        crash_type = crash_reason
                                        if crash_type in results['crash_types']:
                                            results['crash_types'][crash_type] += 1
                                        else:
                                            results['crash_types'][crash_type] = 1
                            except subprocess.TimeoutExpired:
                                process.kill()
                        except Exception as e:
                            logger.error(f"Error analyzing crash file {crash_file}: {e}")
                except ImportError:
                    logger.warning("crash_analyzer module not available for detailed AFL crash analysis")
            else:
                logger.warning(f"No AFL crashes directory found at {crashes_dir}")
        else:
            logger.warning("Skipping AFL++ fuzzing due to no suitable binary target")
        
        method_elapsed = time.time() - method_start
        results['crashes_by_method']['afl'] = {
            'result_code': afl_result,
            'execution_time': method_elapsed
        }
        results['total_execution_time'] += method_elapsed
    
    # 3. Run QEMU fuzzing if not skipped and if the target includes closed-source binaries
    if not args.skip_qemu and os.path.isfile(target_path) and os.access(target_path, os.X_OK):
        logger.info("=== STARTING QEMU FUZZING ===")
        qemu_timeout = min(method_timeout, 3600)  # Cap at 1 hour
        
        qemu_args = argparse.Namespace(
            binary=target_path,
            timeout=qemu_timeout,
            output_dir=qemu_dir,
            seed_corpus=seed_corpus,
            memory_limit=None
        )
        
        method_start = time.time()
        qemu_result = command_qemu_fuzz(qemu_args)
        method_elapsed = time.time() - method_start
        
        results['methods_used'].append('qemu')
        results['crashes_by_method']['qemu'] = {
            'result_code': qemu_result,
            'execution_time': method_elapsed
        }
        results['total_execution_time'] += method_elapsed
    
    # Generate consolidated report
    total_elapsed = time.time() - start_time
    results['wall_clock_time'] = total_elapsed
    
    # Save consolidated report
    consolidated_file = os.path.join(consolidated_dir, 'full_fuzz_report.json')
    with open(consolidated_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Create a readable text summary
    # Update binary statistics if we have info
    fuzzed_binary_files = 0
    # Count unique binaries that were fuzzed across all methods
    fuzzed_binary_set = set()
    
    # Mark binaries as fuzzed based on test results 
    for method in results['methods_used']:
        method_results = results['crashes_by_method'].get(method, {})
        if 'binaries_tested' in method_results:
            for binary in method_results['binaries_tested']:
                fuzzed_binary_set.add(binary)
    
    # For the single target case, always count it as fuzzed if we had methods
    if os.path.isfile(target_path) and os.access(target_path, os.X_OK) and results['methods_used']:
        fuzzed_binary_set.add(target_path)
    
    # Update the count 
    fuzzed_binary_files = len(fuzzed_binary_set)
    results['binary_files']['fuzzed'] = fuzzed_binary_files
    
    # Calculate coverage percentage
    coverage_percentage = 0
    if results['binary_files']['total_found'] > 0:
        coverage_percentage = (fuzzed_binary_files / results['binary_files']['total_found']) * 100
    results['binary_files']['coverage_percentage'] = coverage_percentage
    
    summary_text = f"""
=================================================================
FULL FUZZING PIPELINE SUMMARY REPORT
=================================================================
Target:                  {target_path}
Methods Used:            {', '.join(results['methods_used'])}
Total Crashes:           {results['total_crashes']}
Total Process Time:      {results['total_execution_time']:.2f} seconds
Wall Clock Time:         {total_elapsed:.2f} seconds
Date/Time:               {time.strftime("%Y-%m-%d %H:%M:%S")}

BINARY COVERAGE:
  Total Binary Files:    {results['binary_files']['total_found']}
  Fuzzed Binary Files:   {fuzzed_binary_files}
  Coverage Percentage:   {coverage_percentage:.2f}%

CRASH TYPES:
"""
    if results['crash_types']:
        for crash_type, count in results['crash_types'].items():
            summary_text += f"  {crash_type}: {count}\n"
    else:
        summary_text += "  No crashes found\n"
    
    summary_text += "\nMETHOD RESULTS:\n"
    for method in results['methods_used']:
        method_results = results['crashes_by_method'].get(method, {})
        summary_text += f"  {method}: {method_results.get('execution_time', 0):.2f} seconds\n"
    
    summary_text += """
=================================================================
"""
    
    # Save text summary
    text_summary_file = os.path.join(consolidated_dir, 'full_fuzz_report.txt')
    with open(text_summary_file, 'w') as f:
        f.write(summary_text)
    
    logger.info(f"Full fuzzing completed in {total_elapsed:.2f} seconds")
    logger.info(f"JSON report saved to: {consolidated_file}")
    logger.info(f"Text summary saved to: {text_summary_file}")
    
    return 0

def command_qemu_fuzz(args):
    """Run QEMU fuzzing command."""
    if not os.path.exists(args.binary):
        logger.error(f"Binary not found: {args.binary}")
        return 1
    
    # Use the session's output directory or the specified one
    output_dir = args.output_dir
    
    # Create a dedicated qemu directory under the output directory
    qemu_output_dir = os.path.join(output_dir, "qemu_fuzz")
    os.makedirs(qemu_output_dir, exist_ok=True)
    
    return qemu_fuzzing(args.binary, qemu_output_dir, args.seed_corpus, 
                        args.timeout, args.memory_limit)

def setup_session_dir():
    """Set up a session directory for all output files for this run."""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    session_dir = os.path.join("sessions", f"session_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)
    
    # Create subdirectories
    logs_dir = os.path.join(session_dir, "logs")
    results_dir = os.path.join(session_dir, "results")
    corpus_dir = os.path.join(session_dir, "corpus")
    crashes_dir = os.path.join(session_dir, "crashes")
    
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)
    os.makedirs(crashes_dir, exist_ok=True)
    
    return {
        'session_dir': session_dir,
        'logs_dir': logs_dir,
        'results_dir': results_dir,
        'corpus_dir': corpus_dir,
        'crashes_dir': crashes_dir,
        'timestamp': timestamp
    }

def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
        
    # Set up session directory for this run
    session_dirs = setup_session_dir()
    
    # Set up logging to both console and file
    log_filename = os.path.join(session_dirs['logs_dir'], "fuzzer_cli.log")
    
    # Configure file logger
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(file_handler)
    
    # Log session start
    logger.info(f"=== Starting new fuzzing session ({session_dirs['timestamp']}) ===")
    logger.info(f"Session directory: {session_dirs['session_dir']}")
    logger.info(f"Running command: {args.command}")
    
    # If output directory was not specified, use the session results directory
    if hasattr(args, 'output_dir') and not args.output_dir:
        args.output_dir = session_dirs['results_dir']
        logger.info(f"Setting output directory to session results: {args.output_dir}")
    
    # If seed corpus directory was not specified but we need one, use the session corpus directory
    if hasattr(args, 'seed_corpus') and not args.seed_corpus and 'corpus' in args.command:
        args.seed_corpus = session_dirs['corpus_dir']
        logger.info(f"Setting corpus directory to session corpus: {args.seed_corpus}")
    
    # Run appropriate command
    try:
        if args.command == 'fuzz':
            return command_fuzz(args)
        elif args.command == 'analyze-source':
            return command_analyze_source(args)
        elif args.command == 'generate-corpus':
            return command_generate_corpus(args)
        elif args.command == 'analyze-crash':
            return command_analyze_crash(args)
        elif args.command == 'detect-format':
            return command_detect_format(args)
        elif args.command == 'qemu-fuzz':
            return command_qemu_fuzz(args)
        elif args.command == 'full-fuzz':
            return command_full_fuzz(args)
        elif args.command == 'structure-fuzz':
            return command_structure_fuzz(args)
        else:
            logger.error(f"Unknown command: {args.command}")
            return 1
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error running command: {e}", exc_info=True)
        # Save exception traceback to a dedicated error log
        error_log = os.path.join(session_dirs['logs_dir'], "error.log")
        with open(error_log, 'w') as f:
            import traceback
            traceback.print_exc(file=f)
        logger.error(f"Full error details saved to: {error_log}")
        return 1
    finally:
        logger.info(f"=== Session completed. All outputs in: {session_dirs['session_dir']} ===")
        
        # Create a simple report summary file for the session
        summary_path = os.path.join(session_dirs['session_dir'], "session_summary.txt")
        with open(summary_path, 'w') as f:
            f.write(f"Fuzzing Session: {session_dirs['timestamp']}\n")
            f.write(f"Command: {args.command} {' '.join(str(a) for a in vars(args).values() if isinstance(a, (str, int)) and not a == args.command)}\n")
            f.write(f"Session Directory: {session_dirs['session_dir']}\n")
            f.write(f"Logs Directory: {session_dirs['logs_dir']}\n")
            f.write(f"Results Directory: {session_dirs['results_dir']}\n")
            if hasattr(args, 'seed_corpus') and args.seed_corpus:
                f.write(f"Corpus Directory: {args.seed_corpus}\n")

def command_structure_fuzz(args):
    """Run structure-aware fuzzing with schema inference."""
    target_path = args.target
    output_dir = args.output_dir or f"structure_fuzzing_results_{int(time.time())}"
    seed_corpus = args.seed_corpus
    format_type = args.format
    schema_path = args.schema
    iterations = args.iterations
    timeout = args.timeout
    corpus_size = args.corpus_size
    mutation_count = args.mutation_count
    valid_ratio = args.valid_ratio
    
    # Check if target exists
    if not os.path.exists(target_path):
        logger.error(f"Target not found: {target_path}")
        return 1
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Log configuration
    logger.info("=== Starting Structure-Aware Fuzzing ===")
    logger.info(f"Target:                  {target_path}")
    logger.info(f"Format type:             {format_type or 'Auto-detect'}")
    logger.info(f"Schema path:             {schema_path or 'Auto-infer'}")
    logger.info(f"Iterations:              {iterations}")
    logger.info(f"Timeout:                 {timeout} seconds")
    logger.info(f"Corpus size:             {corpus_size}")
    logger.info(f"Mutation count:          {mutation_count}")
    logger.info(f"Valid ratio:             {valid_ratio}")
    logger.info(f"Output directory:        {output_dir}")
    logger.info(f"Seed corpus:             {seed_corpus or 'None'}")
    
    # Verify structure-aware fuzzing components are available
    try:
        from structure_aware_fuzzing import StructureAwareFuzzer
    except ImportError as e:
        logger.error(f"Structure-aware fuzzing components not available: {e}")
        logger.error("Please ensure the structure/ package is properly installed")
        return 1
    
    # Setup and run the structure-aware fuzzer
    try:
        # Create fuzzer instance
        fuzzer = StructureAwareFuzzer(
            target_path=target_path,
            output_dir=output_dir,
            seed_corpus=seed_corpus
        )
        
        # If format is 'auto', set to None for auto-detection
        if format_type == 'auto':
            format_type = None
            
        # Setup fuzzer with format and schema
        fuzzer.setup_for_fuzzing(format_type=format_type, schema_path=schema_path)
        
        # Run fuzzing
        stats = fuzzer.fuzz(
            iterations=iterations,
            timeout=timeout,
            corpus_size=corpus_size,
            mutation_count=mutation_count,
            valid_ratio=valid_ratio
        )
        
        # Log results
        logger.info("=== Structure-Aware Fuzzing Completed ===")
        logger.info(f"Test cases generated:       {stats['test_cases_generated']}")
        logger.info(f"Test cases executed:        {stats['test_cases_executed']}")
        logger.info(f"Crashes found:              {stats['crashes_found']}")
        logger.info(f"Execution time:             {stats['execution_time']:.2f} seconds")
        
        # Print crash types if any crashes were found
        if stats['crashes_found'] > 0:
            # Count crash types
            crash_types = {}
            for crash in stats['crashes']:
                crash_type = crash.get('crash_type', 'Unknown')
                if crash_type in crash_types:
                    crash_types[crash_type] += 1
                else:
                    crash_types[crash_type] = 1
            
            logger.info("Crash types:")
            for crash_type, count in crash_types.items():
                logger.info(f"  {crash_type}: {count}")
        
        # Return success
        return 0
    
    except Exception as e:
        logger.error(f"Error during structure-aware fuzzing: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())