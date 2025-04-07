#!/usr/bin/env python3
"""
Custom Fuzzer for Testing JSON Parsing

This script uses a specialized JSON grammar to fuzz test the target application.
It focuses on generating inputs that are likely to trigger specific crash conditions.
"""

import os
import sys
import time
import random
import subprocess
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor

# Import the custom grammar
import custom_json_grammar

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("custom_fuzzer")

def setup_output_directories():
    """Set up output directories for results."""
    results_dir = os.path.join(os.getcwd(), "custom_fuzzing_results")
    crashes_dir = os.path.join(results_dir, "crashes")
    seeds_dir = os.path.join(results_dir, "seeds")
    
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(crashes_dir, exist_ok=True)
    os.makedirs(seeds_dir, exist_ok=True)
    
    return results_dir, crashes_dir, seeds_dir

def run_test_case(target, test_input, timeout=5):
    """
    Run a single test case against the target.
    
    Args:
        target: Path to the target executable
        test_input: JSON string to test
        timeout: Timeout in seconds
        
    Returns:
        tuple: (exit_code, stdout, stderr, execution_time)
    """
    start_time = time.time()
    
    # Create a temporary input file
    input_file = f"temp_input_{int(time.time())}_{random.randint(1000, 9999)}.json"
    with open(input_file, 'w') as f:
        f.write(test_input)
    
    try:
        # Run the target with the input file
        process = subprocess.Popen(
            [target, input_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            exit_code = process.returncode
            execution_time = time.time() - start_time
            
            return exit_code, stdout, stderr, execution_time, input_file
            
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.warning(f"Test case timed out after {timeout} seconds")
            return -1, stdout, stderr, timeout, input_file
    
    except Exception as e:
        logger.error(f"Error executing test case: {e}")
        return -2, "", str(e), time.time() - start_time, input_file

def fuzz_target(target, iterations=100, timeout=5, parallel=4):
    """
    Fuzz the target using the custom JSON grammar.
    
    Args:
        target: Path to the target executable
        iterations: Number of test cases to run
        timeout: Timeout for each test case
        parallel: Number of parallel test cases to run
        
    Returns:
        dict: Fuzzing results statistics
    """
    results_dir, crashes_dir, seeds_dir = setup_output_directories()
    
    stats = {
        'iterations': 0,
        'crashes': 0,
        'timeouts': 0,
        'successful': 0,
        'crash_types': {},
        'total_time': 0
    }
    
    logger.info(f"Starting fuzzing of {target} with {iterations} iterations")
    start_time = time.time()
    
    # Generate a few seed files
    logger.info("Generating seed files...")
    custom_json_grammar.generate_corpus(count=10, output_dir=seeds_dir)
    
    # Function to run in parallel
    def run_iteration(_):
        test_input = custom_json_grammar.generate()
        exit_code, stdout, stderr, execution_time, input_file = run_test_case(target, test_input, timeout)
        
        if exit_code != 0:
            # This is a crash or error
            crash_type = "timeout" if exit_code == -1 else "crash"
            
            # Extract error message if available
            error_msg = "Unknown error"
            for line in stderr.split('\n'):
                if "Error:" in line:
                    error_msg = line.strip()
                    break
            
            # Save the crash input
            crash_file = os.path.join(crashes_dir, f"crash_{int(time.time())}_{random.randint(1000, 9999)}.json")
            os.rename(input_file, crash_file)
            
            logger.info(f"Found {crash_type}: {error_msg} (saved to {crash_file})")
            
            return {
                'result': crash_type,
                'error': error_msg,
                'execution_time': execution_time,
                'file': crash_file
            }
        else:
            # Clean up input file if no crash
            try:
                os.unlink(input_file)
            except:
                pass
            
            return {
                'result': 'success',
                'execution_time': execution_time
            }
    
    # Run test cases in parallel
    with ThreadPoolExecutor(max_workers=parallel) as executor:
        futures = [executor.submit(run_iteration, i) for i in range(iterations)]
        
        for i, future in enumerate(futures, 1):
            try:
                result = future.result()
                stats['iterations'] += 1
                
                if result['result'] == 'crash':
                    stats['crashes'] += 1
                    
                    # Track crash types
                    error = result.get('error', 'Unknown error')
                    if error not in stats['crash_types']:
                        stats['crash_types'][error] = 0
                    stats['crash_types'][error] += 1
                    
                elif result['result'] == 'timeout':
                    stats['timeouts'] += 1
                else:
                    stats['successful'] += 1
                
                # Print progress every 10%
                if i % max(1, iterations // 10) == 0:
                    logger.info(f"Progress: {i}/{iterations} ({i/iterations*100:.1f}%) - "
                                f"Crashes: {stats['crashes']}, Timeouts: {stats['timeouts']}")
                
            except Exception as e:
                logger.error(f"Error processing result: {e}")
    
    stats['total_time'] = time.time() - start_time
    
    # Print summary
    logger.info(f"Fuzzing completed in {stats['total_time']:.2f} seconds")
    logger.info(f"Total iterations: {stats['iterations']}")
    logger.info(f"Crashes: {stats['crashes']}")
    logger.info(f"Timeouts: {stats['timeouts']}")
    logger.info(f"Successful: {stats['successful']}")
    
    if stats['crash_types']:
        logger.info("Crash types:")
        for error, count in stats['crash_types'].items():
            logger.info(f"  - {error}: {count}")
    
    return stats

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Custom JSON Fuzzer")
    parser.add_argument("target", help="Target executable to fuzz")
    parser.add_argument("-i", "--iterations", type=int, default=100, 
                        help="Number of test cases to run")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                        help="Timeout for each test case in seconds")
    parser.add_argument("-p", "--parallel", type=int, default=4,
                        help="Number of parallel test cases to run")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target) or not os.access(args.target, os.X_OK):
        logger.error(f"Target {args.target} does not exist or is not executable")
        return 1
    
    fuzz_target(args.target, args.iterations, args.timeout, args.parallel)
    return 0

if __name__ == "__main__":
    sys.exit(main())