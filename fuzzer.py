"""
Intelligent Fuzzing Tool for Executable Files

This tool performs smart fuzzing on executable files using grammar-based input
generation, parallel execution, and comprehensive crash detection.

Features:
- Smart grammar-based input generation
- File input fuzzing with boundary testing
- Parallel execution for multiple files
- Crash detection and reporting
- Comprehensive logging
- Behavior monitoring
- OSS-Fuzz integration
"""

import os
import sys
import time
import logging
import argparse
import json
import shutil
import threading
import subprocess
import random
import string
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fuzzer.log')
    ]
)
logger = logging.getLogger(__name__)

class IntelligentFuzzer:
    """Main class for the intelligent fuzzing tool."""
    
    def __init__(self, args=None):
        """Initialize the fuzzer with the given arguments."""
        self.args = self._parse_default_args() if args is None else args
        
        # Initialize statistics
        self.stats = {
            'status': 'idle',
            'executions': 0,
            'crashes': 0,
            'timeouts': 0,
            'total_runtime': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Initialize crash and activity logs
        self.crashes = []
        self.activities = []
        
        # Signal handler for graceful termination
        self.running = False
        
        # Create necessary directories
        self.work_dir = os.path.abspath(os.path.dirname(__file__))
        self.results_dir = os.path.join(self.work_dir, 'results')
        self.corpus_dir = os.path.join(self.work_dir, 'corpus')
        
        for directory in [self.results_dir, self.corpus_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Add first activity
        self.add_activity("Initialized Intelligent Fuzzer", "info")
    
    def setup_logging(self):
        """Set up the logging configuration."""
        self.logger = logging.getLogger('fuzzer.main')
        self.logger.setLevel(logging.INFO)
    
    def find_executable_files(self, directory):
        """Find executable files in the given directory."""
        executable_files = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if os.access(file_path, os.X_OK) and not self._is_binary_file(file_path):
                    executable_files.append(file_path)
        
        return executable_files
    
    def _is_binary_file(self, file_path):
        """Check if a file is a binary executable."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read(1024)  # Try to read as text
            return False  # If successful, it's a text file
        except UnicodeDecodeError:
            return True  # If it fails, it's likely a binary
    
    def generate_fuzz_data(self, executable_path):
        """Generate intelligent fuzz data for the given executable."""
        # Try to infer the input format
        try:
            from utils.format_detector import FormatDetector, InputFormat
            detector = FormatDetector()
            format_type, confidence, _ = detector.detect_format(executable_path)
            
            if format_type == InputFormat.JSON:
                # Use JSON grammar
                from grammars import get_json_grammar
                grammar = get_json_grammar()
                fuzz_data = grammar.generate()
                self.add_activity(f"Generated JSON input for {os.path.basename(executable_path)}", "info")
                return fuzz_data.encode('utf-8')
                
            elif format_type == InputFormat.XML:
                # Use XML grammar
                from grammars import get_xml_grammar
                grammar = get_xml_grammar()
                fuzz_data = grammar.generate()
                self.add_activity(f"Generated XML input for {os.path.basename(executable_path)}", "info")
                return fuzz_data.encode('utf-8')
                
            elif format_type == InputFormat.COMMAND:
                # Use command grammar
                from grammars import get_command_grammar
                grammar = get_command_grammar()
                fuzz_data = grammar.generate()
                self.add_activity(f"Generated command-line input for {os.path.basename(executable_path)}", "info")
                return fuzz_data.encode('utf-8')
        except ImportError:
            # Fallback if format detector or grammar is not available
            pass
        
        # Try to use OSS-Fuzz resources if enabled
        if self.args.use_oss_fuzz:
            oss_fuzz_data = self.get_oss_fuzz_input(executable_path)
            if oss_fuzz_data:
                self.add_activity(f"Using OSS-Fuzz input for {os.path.basename(executable_path)}", "info")
                return oss_fuzz_data
        
        # Fallback to random data generation
        input_length = random.randint(10, 1000)
        input_mode = random.choice(['binary', 'text', 'mixed'])
        
        if input_mode == 'binary':
            fuzz_data = bytes(random.randint(0, 255) for _ in range(input_length))
        elif input_mode == 'text':
            fuzz_data = self.random_string(input_length).encode('utf-8')
        else:  # mixed
            fuzz_data = bytearray()
            for _ in range(input_length):
                if random.random() < 0.7:  # 70% ASCII
                    fuzz_data.append(random.randint(32, 126))
                else:  # 30% binary
                    fuzz_data.append(random.randint(0, 255))
            fuzz_data = bytes(fuzz_data)
        
        # Apply mutations to make the data more interesting
        fuzz_data = self.mutate_binary_data(fuzz_data)
        
        return fuzz_data
    
    def mutate_binary_data(self, data):
        """Apply random mutations to binary data."""
        data = bytearray(data)
        data_len = len(data)
        
        if data_len == 0:
            return bytes(data)
        
        # Apply a random number of mutations
        num_mutations = random.randint(1, max(1, data_len // 10))
        
        for _ in range(num_mutations):
            mutation_type = random.choice(['bit_flip', 'byte_flip', 'interesting_byte', 'interesting_integer', 'repeated_bytes'])
            
            if mutation_type == 'bit_flip':
                # Flip a random bit
                byte_idx = random.randint(0, data_len - 1)
                bit_idx = random.randint(0, 7)
                data[byte_idx] ^= (1 << bit_idx)
                
            elif mutation_type == 'byte_flip':
                # Flip a random byte
                byte_idx = random.randint(0, data_len - 1)
                data[byte_idx] = 255 - data[byte_idx]
                
            elif mutation_type == 'interesting_byte':
                # Replace with an interesting byte value
                byte_idx = random.randint(0, data_len - 1)
                interesting_bytes = [0, 1, 0x7F, 0x80, 0xFF, 0xFE]
                data[byte_idx] = random.choice(interesting_bytes)
                
            elif mutation_type == 'interesting_integer':
                # Replace with an interesting integer value
                if data_len >= 4:
                    byte_idx = random.randint(0, data_len - 4)
                    interesting_ints = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE]
                    integer = random.choice(interesting_ints)
                    
                    # Replace 4 bytes with the chosen integer
                    data[byte_idx:byte_idx+4] = integer.to_bytes(4, byteorder=random.choice(['little', 'big']), signed=False)
                    
            elif mutation_type == 'repeated_bytes':
                # Replace with repeated bytes
                if data_len >= 4:
                    byte_idx = random.randint(0, data_len - 4)
                    repeat_byte = random.randint(0, 255)
                    data[byte_idx:byte_idx+4] = bytes([repeat_byte] * 4)
        
        return bytes(data)
    
    def random_string(self, length):
        """Generate a random string of the given length."""
        characters = string.ascii_letters + string.digits + string.punctuation + ' ' * 10  # More spaces for readability
        return ''.join(random.choice(characters) for _ in range(length))
    
    def check_oss_fuzz_resources(self, executable_path):
        """Check if OSS-Fuzz resources are available for the executable."""
        # This is a simplified implementation
        executable_name = os.path.basename(executable_path)
        
        # Check if there's a matching directory in OSS-Fuzz corpus
        oss_fuzz_dir = os.path.join('/tmp', 'oss-fuzz-corpus', executable_name)
        if os.path.exists(oss_fuzz_dir):
            return True
            
        # Try to download OSS-Fuzz corpus
        try:
            os.makedirs(os.path.dirname(oss_fuzz_dir), exist_ok=True)
            # In a real implementation, we would download the corpus here
            return os.path.exists(oss_fuzz_dir)
        except Exception as e:
            self.logger.warning(f"Error checking OSS-Fuzz resources: {e}")
            return False
    
    def get_oss_fuzz_input(self, executable_path):
        """Get input data from OSS-Fuzz resources."""
        # This is a simplified implementation
        return None  # In a real implementation, we would return the input data
    
    def fuzz_executable(self, executable_path):
        """Fuzz a single executable."""
        if not os.path.exists(executable_path) or not os.access(executable_path, os.X_OK):
            self.logger.error(f"File {executable_path} is not executable or does not exist")
            return
        
        self.add_activity(f"Started fuzzing {os.path.basename(executable_path)}", "info")
        
        # Generate input data
        fuzz_data = self.generate_fuzz_data(executable_path)
        
        # Create a temporary input file
        input_file = os.path.join(self.results_dir, f"input_{int(time.time())}_{random.randint(1000, 9999)}.bin")
        with open(input_file, 'wb') as f:
            f.write(fuzz_data)
        
        self.logger.info(f"Created input file: {input_file}")
        
        # Execute the program with the input
        result = self._execute_with_input(executable_path, input_file, self.args.timeout)
        
        # Handle the result
        if result.get('returncode', 0) != 0 and result.get('status') != 'timeout':
            self._handle_crash(executable_path, input_file, result, 'generated')
            self.stats['crashes'] += 1
            self.add_activity(f"Crash detected in {os.path.basename(executable_path)}", "error")
        elif result.get('status') == 'timeout':
            self.stats['timeouts'] += 1
            self.add_activity(f"Timeout detected in {os.path.basename(executable_path)}", "warning")
        else:
            # Cleanup input file if no crash
            os.unlink(input_file)
        
        self.stats['executions'] += 1
        
        return result
    
    def _execute_with_input(self, executable_path, input_file, timeout):
        """Execute the program with the given input."""
        self.logger.info(f"Executing {executable_path} with input {input_file}")
        
        # Check if we can use behavior monitor
        try:
            from utils.behavior_monitor import monitor_process_with_input
            
            # Read the input data
            with open(input_file, 'rb') as f:
                input_data = f.read()
            
            # Monitor the process behavior
            result = monitor_process_with_input(executable_path, input_data, timeout)
            
            return result
        except ImportError:
            self.logger.warning("Behavior monitor not available, using basic execution")
        
        # Fallback to basic execution
        start_time = time.time()
        
        try:
            # Execute the program with the input file as stdin
            with open(input_file, 'rb') as f:
                process = subprocess.Popen(
                    [executable_path],
                    stdin=f,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=os.environ.copy()
                )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                returncode = process.returncode
                status = 'crashed' if returncode != 0 else 'normal'
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                returncode = -1
                status = 'timeout'
        
        except Exception as e:
            self.logger.error(f"Error executing {executable_path}: {e}")
            return {
                'status': 'error',
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'runtime': time.time() - start_time
            }
        
        return {
            'status': status,
            'returncode': returncode,
            'stdout': stdout.decode('utf-8', errors='replace'),
            'stderr': stderr.decode('utf-8', errors='replace'),
            'runtime': time.time() - start_time
        }
    
    def _handle_crash(self, executable_path, input_file, result, input_type):
        """Handle a detected crash."""
        # Create a crash directory with timestamp
        crash_time = int(time.time())
        crash_dir = os.path.join(self.results_dir, f"crash_{crash_time}_{os.path.basename(executable_path)}")
        os.makedirs(crash_dir, exist_ok=True)
        
        # Copy the input file
        input_copy = os.path.join(crash_dir, "input.bin")
        shutil.copy(input_file, input_copy)
        
        # Save the crash report
        report_path = os.path.join(crash_dir, "report.json")
        with open(report_path, 'w') as f:
            report = {
                'executable': executable_path,
                'timestamp': crash_time,
                'exit_code': result.get('returncode', -1),
                'status': result.get('status', 'unknown'),
                'runtime': result.get('runtime', 0),
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'input_type': input_type,
                'input_file': input_copy
            }
            json.dump(report, f, indent=2)
        
        # Add to crashes list
        self.crashes.append({
            'executable': os.path.basename(executable_path),
            'timestamp': crash_time,
            'exit_code': result.get('returncode', -1),
            'status': result.get('status', 'unknown'),
            'report_path': report_path,
            'input_type': input_type
        })
        
        self.logger.info(f"Crash detected in {executable_path}, report saved to {crash_dir}")
        
        return crash_dir
    
    def run_parallel_fuzzing(self, executable_files):
        """Run fuzzing in parallel for multiple executables."""
        max_workers = min(multiprocessing.cpu_count(), self.args.parallel)
        self.logger.info(f"Running fuzzing with {max_workers} workers")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.fuzz_executable, exec_file): exec_file for exec_file in executable_files}
            
            for future in as_completed(futures):
                exec_file = futures[future]
                try:
                    result = future.result()
                    if result and result.get('status') == 'crashed':
                        self.logger.info(f"Found crash in {exec_file}")
                except Exception as e:
                    self.logger.error(f"Error fuzzing {exec_file}: {e}")
    
    def run(self):
        """Run the main fuzzing loop."""
        self.stats['status'] = 'running'
        self.stats['start_time'] = time.time()
        self.running = True
        
        target = self.args.target
        
        # Check if target is a file or directory
        if os.path.isfile(target):
            executable_files = [target]
        elif os.path.isdir(target):
            executable_files = self.find_executable_files(target)
        else:
            self.logger.error(f"Target {target} is not a valid file or directory")
            return False
        
        self.logger.info(f"Found {len(executable_files)} executable files")
        
        # Run the fuzzing loop
        iteration = 0
        while self.running and (self.args.iterations == 0 or iteration < self.args.iterations):
            self.run_parallel_fuzzing(executable_files)
            iteration += 1
            
            # Check max runtime
            if self.args.max_runtime > 0 and (time.time() - self.stats['start_time']) > self.args.max_runtime:
                self.logger.info(f"Reached maximum runtime of {self.args.max_runtime} seconds")
                break
        
        self.stats['status'] = 'completed'
        self.stats['end_time'] = time.time()
        self.stats['total_runtime'] = self.stats['end_time'] - self.stats['start_time']
        self.running = False
        
        self.add_activity("Fuzzing completed", "success")
        self.logger.info(f"Fuzzing completed: {self.stats['executions']} executions, {self.stats['crashes']} crashes, {self.stats['timeouts']} timeouts")
        
        return self.stats['crashes'] > 0
    
    def start(self, target=None, options=None):
        """Start fuzzing the specified target."""
        if options:
            # Update arguments with the provided options
            for key, value in options.items():
                if hasattr(self.args, key):
                    setattr(self.args, key, value)
        
        if target:
            self.args.target = target
        
        if not self.args.target:
            self.logger.error("No target specified")
            return False
        
        try:
            # Run the fuzzing
            return self.run()
        except Exception as e:
            self.logger.error(f"Error during fuzzing: {e}")
            self.stats['status'] = 'error'
            self.running = False
            return False
    
    def stop(self):
        """Stop the fuzzing process."""
        self.running = False
        self.stats['status'] = 'stopped'
        self.add_activity("Fuzzing stopped", "info")
        return True
    
    def print_stats(self):
        """Print fuzzing statistics."""
        runtime = 0
        if self.stats['start_time']:
            if self.stats['end_time']:
                runtime = self.stats['end_time'] - self.stats['start_time']
            else:
                runtime = time.time() - self.stats['start_time']
        
        print(f"\nFuzzing Statistics:")
        print(f"Status:     {self.stats['status']}")
        print(f"Executions: {self.stats['executions']}")
        print(f"Crashes:    {self.stats['crashes']}")
        print(f"Timeouts:   {self.stats['timeouts']}")
        print(f"Runtime:    {runtime:.2f} seconds")
        
        if self.crashes:
            print("\nCrashes:")
            for crash in self.crashes[:10]:  # Show only the first 10 crashes
                print(f"  {crash['executable']} (Exit code: {crash['exit_code']})")
    
    def get_stats(self):
        """Get current statistics."""
        # Update total runtime if running
        if self.stats['status'] == 'running' and self.stats['start_time']:
            self.stats['total_runtime'] = time.time() - self.stats['start_time']
        
        return self.stats
    
    def get_recent_crashes(self, limit=10):
        """Get the most recent crashes."""
        return self.crashes[:limit]
    
    def get_recent_activities(self, limit=20):
        """Get the most recent activities."""
        return self.activities[:limit]
    
    def get_oss_fuzz_projects(self):
        """Get available OSS-Fuzz projects."""
        # This is a placeholder implementation
        return []
    
    def add_activity(self, message, activity_type):
        """Add an activity to the recent activities log."""
        activity = {
            'timestamp': time.time(),
            'message': message,
            'type': activity_type
        }
        self.activities.insert(0, activity)
        self.logger.info(f"Activity ({activity_type}): {message}")
        return activity
    
    def signal_handler(self, signum, frame):
        """Handle termination signals gracefully."""
        self.logger.info(f"Received signal {signum}, stopping fuzzing")
        self.stop()
    
    def _parse_default_args(self):
        """Parse default arguments."""
        parser = argparse.ArgumentParser(description='Intelligent Fuzzing Tool')
        parser.add_argument('target', nargs='?', default=None, help='Target file or directory to fuzz')
        parser.add_argument('--iterations', '-i', type=int, default=0, help='Number of fuzzing iterations (0 for unlimited)')
        parser.add_argument('--timeout', '-t', type=int, default=10, help='Timeout for each execution in seconds')
        parser.add_argument('--parallel', '-p', type=int, default=multiprocessing.cpu_count(), help='Number of parallel fuzzing processes')
        parser.add_argument('--max-runtime', '-r', type=int, default=0, help='Maximum runtime in seconds (0 for unlimited)')
        parser.add_argument('--use-oss-fuzz', action='store_true', help='Use OSS-Fuzz resources if available')
        parser.add_argument('--output', '-o', default=None, help='Output directory for results')
        parser.add_argument('--input-type', choices=['auto', 'json', 'xml', 'binary', 'text'], default='auto', help='Input type for fuzzing')
        
        # Parse with empty list to get default values
        return parser.parse_args([])


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Intelligent Fuzzing Tool')
    parser.add_argument('target', nargs='?', help='Target file or directory to fuzz')
    parser.add_argument('--iterations', '-i', type=int, default=100, help='Number of fuzzing iterations')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Timeout for each execution in seconds')
    parser.add_argument('--parallel', '-p', type=int, default=multiprocessing.cpu_count(), help='Number of parallel fuzzing processes')
    parser.add_argument('--max-runtime', '-r', type=int, default=0, help='Maximum runtime in seconds (0 for unlimited)')
    parser.add_argument('--use-oss-fuzz', action='store_true', help='Use OSS-Fuzz resources if available')
    parser.add_argument('--output', '-o', default=None, help='Output directory for results')
    parser.add_argument('--input-type', choices=['auto', 'json', 'xml', 'binary', 'text'], default='auto', help='Input type for fuzzing')
    
    return parser.parse_args()


def main():
    """Main entry point for the fuzzer."""
    args = parse_arguments()
    
    if not args.target:
        print("Please specify a target file or directory to fuzz")
        sys.exit(1)
    
    fuzzer = IntelligentFuzzer(args)
    
    # Set up signal handlers for graceful termination
    import signal
    signal.signal(signal.SIGINT, fuzzer.signal_handler)
    signal.signal(signal.SIGTERM, fuzzer.signal_handler)
    
    # Start fuzzing
    fuzzer.start()
    
    # Print statistics
    fuzzer.print_stats()


if __name__ == "__main__":
    main()