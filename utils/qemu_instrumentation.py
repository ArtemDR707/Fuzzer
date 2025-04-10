"""
QEMU Instrumentation for Intelligent Fuzzing

This module provides functionality to instrument binaries using QEMU
for coverage-guided fuzzing without source code access.
"""

import os
import subprocess
import logging
import time
import json
import shutil
import glob
import re
from pathlib import Path

class QEMUInstrumentation:
    """Handles QEMU-based instrumentation for binary fuzzing."""
    
    def __init__(self, output_dir=None, seed_corpus_dir=None):
        """
        Initialize QEMU instrumentation.
        
        Args:
            output_dir: Directory for fuzzing output
            seed_corpus_dir: Directory containing seed corpus
        """
        self.logger = logging.getLogger(__name__)
        
        # Set directories
        self.output_dir = output_dir if output_dir else os.path.join(os.getcwd(), 'qemu_output')
        self.seed_corpus_dir = seed_corpus_dir if seed_corpus_dir else os.path.join(os.getcwd(), 'seed_corpus')
        
        # Create directories if they don't exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.seed_corpus_dir, exist_ok=True)
        
        # Internal state
        self.current_run = None
        self.stats = {}
    
    def prepare_seed_corpus(self, min_files=10):
        """
        Prepare seed corpus for fuzzing.
        
        If insufficient seed files exist, generate some basic ones.
        
        Args:
            min_files: Minimum number of files to have in corpus
            
        Returns:
            str: Path to seed corpus directory
        """
        # Count existing seed files
        seed_files = glob.glob(os.path.join(self.seed_corpus_dir, '*'))
        
        # Generate basic seeds if needed
        if len(seed_files) < min_files:
            self.logger.info(f"Generating basic seed files (found {len(seed_files)}, need {min_files})")
            
            # Generate simple text files with various content
            for i in range(len(seed_files), min_files):
                seed_file = os.path.join(self.seed_corpus_dir, f"seed_{i:04d}")
                
                # Simple patterns for different seed types
                if i % 5 == 0:
                    # Binary pattern
                    with open(seed_file, 'wb') as f:
                        f.write(bytes([i % 256 for i in range(64)]))
                elif i % 5 == 1:
                    # ASCII text
                    with open(seed_file, 'w') as f:
                        f.write(f"seed_{i} " * 10)
                elif i % 5 == 2:
                    # JSON pattern
                    with open(seed_file, 'w') as f:
                        f.write(f'{{ "id": {i}, "value": "test_{i}" }}')
                elif i % 5 == 3:
                    # Command-line pattern
                    with open(seed_file, 'w') as f:
                        f.write(f"--option1 value_{i} --option2 {i*10}")
                else:
                    # XML pattern
                    with open(seed_file, 'w') as f:
                        f.write(f'<root><item id="{i}">test_{i}</item></root>')
        
        return self.seed_corpus_dir
    
    def run_afl_qemu(self, binary_path, timeout=3600, memory_limit=None):
        """
        Run AFL++ in QEMU mode for coverage-guided fuzzing.
        
        Args:
            binary_path: Path to the target binary
            timeout: Timeout in seconds (default: 1 hour)
            memory_limit: Memory limit for AFL (default: none)
            
        Returns:
            tuple: (success, output_dir, stats)
        """
        if not os.path.exists(binary_path):
            self.logger.error(f"Binary {binary_path} not found")
            return False, None, {}
        
        # Create unique output directory for this run
        timestamp = int(time.time())
        binary_name = os.path.basename(binary_path)
        run_dir = os.path.join(self.output_dir, f"{binary_name}_{timestamp}")
        os.makedirs(run_dir, exist_ok=True)
        
        # Ensure seed corpus is prepared
        self.prepare_seed_corpus()
        
        # Check if afl-fuzz is available
        try:
            subprocess.run(["afl-fuzz", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except FileNotFoundError:
            self.logger.error("afl-fuzz not found. Install AFL++ with QEMU support.")
            return False, run_dir, {"error": "afl-fuzz not found"}
        
        # Build AFL command
        afl_cmd = [
            "afl-fuzz",
            "-Q",  # QEMU mode
            "-i", self.seed_corpus_dir,
            "-o", run_dir,
        ]
        
        # Add optional parameters
        if memory_limit:
            afl_cmd.extend(["-m", str(memory_limit)])
        else:
            afl_cmd.extend(["-m", "none"])  # No memory limit
        
        # Add target command
        afl_cmd.extend(["--", binary_path, "@@"])
        
        # Start AFL process
        self.logger.info(f"Starting AFL++ QEMU fuzzing: {' '.join(afl_cmd)}")
        
        try:
            # Run AFL with timeout
            process = subprocess.Popen(
                afl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor for a few seconds to ensure it starts correctly
            start_time = time.time()
            while time.time() - start_time < 10:  # 10 second startup check
                if process.poll() is not None:
                    # Process exited too quickly - this is an error
                    stdout, stderr = process.communicate()
                    self.logger.error(f"AFL exited too quickly. stderr: {stderr}")
                    return False, run_dir, {"error": stderr}
                
                # Check if fuzzer_stats file exists (indicates successful start)
                if os.path.exists(os.path.join(run_dir, "fuzzer_stats")):
                    break
                
                time.sleep(0.5)
            
            # Save command for reference
            with open(os.path.join(run_dir, "command.txt"), 'w') as f:
                f.write(' '.join(afl_cmd))
            
            # Set the current run directory
            self.current_run = run_dir
            
            # Run for the specified timeout
            self.logger.info(f"AFL++ running in {run_dir}, will timeout after {timeout} seconds")
            
            # Wait for the specified timeout
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # This is expected - we want to terminate after the timeout
                self.logger.info(f"AFL++ fuzzing timeout reached ({timeout} seconds)")
                process.terminate()
                try:
                    process.wait(timeout=5)  # Wait a bit for graceful termination
                except subprocess.TimeoutExpired:
                    process.kill()  # Force kill if necessary
            
            # Parse final stats
            stats = self._parse_fuzzer_stats(run_dir)
            self.stats = stats
            
            return True, run_dir, stats
        
        except Exception as e:
            self.logger.error(f"Error running AFL++: {e}")
            return False, run_dir, {"error": str(e)}
    
    def _parse_fuzzer_stats(self, run_dir):
        """
        Parse AFL++ fuzzer_stats file.
        
        Args:
            run_dir: AFL++ run directory
            
        Returns:
            dict: Parsed stats
        """
        stats_file = os.path.join(run_dir, "fuzzer_stats")
        if not os.path.exists(stats_file):
            return {}
        
        stats = {}
        try:
            with open(stats_file, 'r') as f:
                for line in f:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Try to convert numerical values
                        try:
                            if "." in value:
                                value = float(value)
                            else:
                                value = int(value)
                        except ValueError:
                            pass
                        
                        stats[key] = value
            
            # Calculate derived metrics
            if "execs_per_sec" in stats and "execs_done" in stats:
                stats["estimated_runtime_hours"] = stats["execs_done"] / stats["execs_per_sec"] / 3600
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error parsing fuzzer_stats: {e}")
            return {}
    
    def collect_crashes(self, run_dir=None, output_dir=None):
        """
        Collect crashes found during fuzzing.
        
        Args:
            run_dir: AFL++ run directory (if None, use the most recent run)
            output_dir: Directory to copy crashes to
            
        Returns:
            list: Paths to crash files
        """
        # Use the current run dir if none specified
        if run_dir is None:
            run_dir = self.current_run
        
        if run_dir is None:
            self.logger.error("No run directory specified and no current run")
            return []
        
        # Find crashes directory
        crashes_dir = os.path.join(run_dir, "crashes")
        if not os.path.exists(crashes_dir):
            self.logger.warning(f"No crashes directory found in {run_dir}")
            return []
        
        # List crash files
        crash_files = [f for f in glob.glob(os.path.join(crashes_dir, "id:*")) 
                        if not f.endswith('README.txt')]
        
        if not crash_files:
            self.logger.info(f"No crashes found in {crashes_dir}")
            return []
        
        self.logger.info(f"Found {len(crash_files)} crashes in {crashes_dir}")
        
        # Copy crashes to output directory if specified
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
            for crash_file in crash_files:
                crash_name = os.path.basename(crash_file)
                dest_path = os.path.join(output_dir, crash_name)
                shutil.copy2(crash_file, dest_path)
                
            self.logger.info(f"Copied {len(crash_files)} crashes to {output_dir}")
        
        return crash_files
    
    def reproduce_crash(self, binary_path, crash_file, timeout=10):
        """
        Attempt to reproduce a crash.
        
        Args:
            binary_path: Path to the target binary
            crash_file: Path to the crash file
            timeout: Timeout in seconds
            
        Returns:
            tuple: (crashed, return_code, stdout, stderr)
        """
        if not os.path.exists(binary_path):
            self.logger.error(f"Binary {binary_path} not found")
            return False, None, "", "Binary not found"
        
        if not os.path.exists(crash_file):
            self.logger.error(f"Crash file {crash_file} not found")
            return False, None, "", "Crash file not found"
        
        # Run the binary with the crash input
        try:
            self.logger.info(f"Reproducing crash with {crash_file}")
            
            process = subprocess.Popen(
                [binary_path, crash_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
                
                # Check if crash reproduced
                crashed = return_code < 0 or return_code > 128
                
                if crashed:
                    self.logger.info(f"Crash reproduced with return code {return_code}")
                else:
                    self.logger.warning(f"Crash did not reproduce (return code: {return_code})")
                
                return crashed, return_code, stdout, stderr
                
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.logger.warning(f"Timeout while reproducing crash")
                return True, -1, stdout, stderr
                
        except Exception as e:
            self.logger.error(f"Error reproducing crash: {e}")
            return False, None, "", str(e)
    
    def get_coverage_report(self, run_dir=None):
        """
        Get coverage information from the fuzzing run.
        
        Args:
            run_dir: AFL++ run directory (if None, use the most recent run)
            
        Returns:
            dict: Coverage statistics
        """
        # Use the current run dir if none specified
        if run_dir is None:
            run_dir = self.current_run
        
        if run_dir is None:
            self.logger.error("No run directory specified and no current run")
            return {}
        
        # Check if plot_data exists
        plot_file = os.path.join(run_dir, "plot_data")
        if not os.path.exists(plot_file):
            self.logger.warning(f"No plot_data file found in {run_dir}")
            return {}
        
        # Parse plot_data for coverage information
        coverage = {
            "edges_total": 0,
            "edges_covered": 0,
            "coverage_percent": 0,
            "coverage_over_time": []
        }
        
        try:
            with open(plot_file, 'r') as f:
                lines = f.readlines()
                
                for line in lines:
                    if not line.strip() or line.startswith("#"):
                        continue
                    
                    parts = line.strip().split(", ")
                    if len(parts) < 6:
                        continue
                    
                    # Extract coverage data
                    # Format: unix_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec
                    try:
                        unix_time = int(parts[0])
                        paths_total = int(parts[3])
                        unique_crashes = int(parts[7])
                        
                        coverage["coverage_over_time"].append({
                            "timestamp": unix_time,
                            "paths": paths_total,
                            "crashes": unique_crashes
                        })
                    except (ValueError, IndexError):
                        continue
            
            # Extract the latest data
            if coverage["coverage_over_time"]:
                latest = coverage["coverage_over_time"][-1]
                coverage["edges_covered"] = latest["paths"]
                
                # Try to get total edges from fuzzer_stats
                stats = self._parse_fuzzer_stats(run_dir)
                if "bitmap_size" in stats:
                    coverage["edges_total"] = stats["bitmap_size"]
                    
                    # Calculate percentage
                    if coverage["edges_total"] > 0:
                        coverage["coverage_percent"] = (coverage["edges_covered"] / coverage["edges_total"]) * 100
        
        except Exception as e:
            self.logger.error(f"Error parsing coverage data: {e}")
        
        return coverage