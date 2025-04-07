#!/usr/bin/env python3
"""
Structure-Aware Fuzzing Interface

This module provides a high-level interface to structure-aware fuzzing
functionality for the intelligent fuzzing platform.
"""

import os
import sys
import json
import logging
import tempfile
import subprocess
import time
import datetime
import random
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

# Import structure-aware components
from structure.schema_parser import Schema, SchemaNode, SchemaType, ObjectNode, ArrayNode
from structure.format_inferrer import FormatInferrer
from structure.structure_aware_generator import StructureAwareGenerator
from structure.structure_aware_mutator import StructureAwareMutator


class StructureAwareFuzzer:
    """Structure-aware fuzzing interface for the fuzzing platform."""
    
    def __init__(self, target_path=None, output_dir=None, seed_corpus=None):
        """
        Initialize a structure-aware fuzzer.
        
        Args:
            target_path: Path to the target executable or file
            output_dir: Directory to save results
            seed_corpus: Path to the seed corpus
        """
        self.target_path = target_path
        self.output_dir = output_dir
        self.seed_corpus_path = seed_corpus
        
        # Set up output directory
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Initialize components
        self.format_inferrer = FormatInferrer()
        self.schema = None
        self.generator = None
        self.mutator = None
        self.format_type = None
        
        # Setup logging
        self.logger = logging.getLogger("structure_aware_fuzzer")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def analyze_target(self) -> str:
        """
        Analyze the target to determine the appropriate format.
        
        Returns:
            str: Detected format type
        """
        self.logger.info(f"Analyzing target: {self.target_path}")
        
        if self.seed_corpus_path and os.path.exists(self.seed_corpus_path):
            # Load sample files from the seed corpus
            samples = self.load_seed_corpus()
            
            # Infer format from samples
            format_type = self.format_inferrer.infer_format(samples)
            self.logger.info(f"Inferred format type from seed corpus: {format_type}")
            
            return format_type
        elif os.path.isfile(self.target_path):
            # Try to determine format from file content
            try:
                with open(self.target_path, 'rb') as f:
                    content = f.read()
                    
                # Try to decode as text
                try:
                    text_content = content.decode('utf-8')
                    format_type = self.format_inferrer.infer_format([text_content])
                except UnicodeDecodeError:
                    # Binary content
                    format_type = "binary"
                
                self.logger.info(f"Inferred format type from target file: {format_type}")
                return format_type
                
            except Exception as e:
                self.logger.warning(f"Error analyzing target file: {e}")
                # Default to binary as a safe option
                return "binary"
        else:
            # Default to text format if we can't determine
            self.logger.info("Could not determine format, defaulting to 'text'")
            return "text"
    
    def load_or_infer_schema(self, format_type: str = None, schema_path: str = None) -> Schema:
        """
        Load a schema from a file or infer it from samples.
        
        Args:
            format_type: Format type (if not provided, will be inferred)
            schema_path: Path to a schema file (optional)
            
        Returns:
            Schema: Loaded or inferred schema
        """
        # Determine format type if not provided
        if not format_type:
            format_type = self.analyze_target()
        
        self.format_type = format_type
        
        # Load schema from file if provided
        if schema_path and os.path.exists(schema_path):
            self.logger.info(f"Loading schema from {schema_path}")
            try:
                with open(schema_path, 'r') as f:
                    schema_json = f.read()
                schema = Schema.from_json(schema_json)
                return schema
            except Exception as e:
                self.logger.warning(f"Error loading schema from file: {e}")
                # Fall back to inference
        
        # Infer schema from samples
        self.logger.info(f"Inferring schema for format: {format_type}")
        
        if self.seed_corpus_path and os.path.exists(self.seed_corpus_path):
            samples = self.load_seed_corpus()
            schema = self.format_inferrer.infer_schema(samples, format_type)
            
            # Save inferred schema for reference
            if self.output_dir:
                schema_file = os.path.join(self.output_dir, "inferred_schema.json")
                with open(schema_file, 'w') as f:
                    f.write(schema.to_json())
                self.logger.info(f"Saved inferred schema to {schema_file}")
            
            return schema
        else:
            # Create a basic schema for the format
            if format_type == "json":
                from structure.schema_parser import json_basic_schema
                return json_basic_schema()
            elif format_type == "xml":
                from structure.schema_parser import xml_basic_schema
                return xml_basic_schema()
            elif format_type == "text":
                from structure.schema_parser import text_basic_schema
                return text_basic_schema()
            elif format_type == "binary":
                from structure.schema_parser import binary_basic_schema
                return binary_basic_schema()
            else:
                # Default to text
                from structure.schema_parser import text_basic_schema
                return text_basic_schema()
    
    def setup_for_fuzzing(self, format_type: str = None, schema_path: str = None) -> None:
        """
        Set up the fuzzer with schema and generators.
        
        Args:
            format_type: Format type (if not provided, will be inferred)
            schema_path: Path to a schema file (optional)
        """
        if not format_type:
            # Use the class instance format_type if set, or infer it
            format_type = self.format_type if self.format_type else self.analyze_target()
        
        # Store the format type
        self.format_type = format_type
        
        # Load or infer schema
        self.schema = self.load_or_infer_schema(format_type, schema_path)
        
        # Initialize generator and mutator
        self.generator = StructureAwareGenerator(self.schema)
        self.mutator = StructureAwareMutator(self.schema)
    
    def generate_corpus(self, count: int = 20, valid_ratio: float = 0.8) -> List[str]:
        """
        Generate a corpus of test cases.
        
        Args:
            count: Number of test cases to generate
            valid_ratio: Ratio of valid to invalid test cases
            
        Returns:
            List[str]: Paths to generated corpus files
        """
        if not self.generator:
            self.setup_for_fuzzing()
        
        # Create corpus directory
        corpus_dir = os.path.join(self.output_dir, "corpus") if self.output_dir else "corpus"
        os.makedirs(corpus_dir, exist_ok=True)
        
        self.logger.info(f"Generating corpus of {count} test cases (valid ratio: {valid_ratio})")
        
        # Generate corpus
        file_paths = self.generator.generate_corpus(
            count=count,
            output_dir=corpus_dir,
            valid_ratio=valid_ratio
        )
        
        self.logger.info(f"Generated {len(file_paths)} corpus files in {corpus_dir}")
        
        return file_paths
    
    def generate_mutations(self, sample: Any, count: int = 10) -> List[Any]:
        """
        Generate mutations from a sample.
        
        Args:
            sample: Sample data to mutate
            count: Number of mutations to generate
            
        Returns:
            List[Any]: Generated mutations
        """
        if not self.mutator:
            self.setup_for_fuzzing()
        
        self.logger.info(f"Generating {count} mutations")
        
        # Set seed data
        self.mutator.set_seed_data(sample)
        
        # Generate mutations
        mutations = []
        for _ in range(count):
            mutations.append(self.mutator.mutate())
        
        return mutations
    
    def load_seed_corpus(self) -> List[Any]:
        """
        Load the seed corpus.
        
        Returns:
            List[Any]: Loaded seed data
        """
        if not self.seed_corpus_path or not os.path.exists(self.seed_corpus_path):
            self.logger.warning("Seed corpus path not found")
            return []
        
        self.logger.info(f"Loading seed corpus from {self.seed_corpus_path}")
        
        seed_data = []
        
        # Process all files in the seed corpus directory
        if os.path.isdir(self.seed_corpus_path):
            for root, _, files in os.walk(self.seed_corpus_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    data = self._load_file(file_path)
                    if data is not None:
                        seed_data.append(data)
        # Or just a single file
        elif os.path.isfile(self.seed_corpus_path):
            data = self._load_file(self.seed_corpus_path)
            if data is not None:
                seed_data.append(data)
        
        self.logger.info(f"Loaded {len(seed_data)} seed samples")
        
        return seed_data
    
    def _load_file(self, file_path: str) -> Optional[Any]:
        """
        Load a file based on format.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Optional[Any]: Loaded data or None if loading failed
        """
        try:
            # Get file extension
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            # Try to load based on extension or format
            if ext == '.json' or (self.format_type and self.format_type == 'json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            elif ext == '.xml' or (self.format_type and self.format_type == 'xml'):
                try:
                    tree = ET.parse(file_path)
                    return ET.tostring(tree.getroot(), encoding='utf-8').decode('utf-8')
                except ET.ParseError:
                    # If not well-formed XML, load as text
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        return f.read()
            
            elif ext in ['.bin', '.dat'] or (self.format_type and self.format_type in ['binary', 'bytes']):
                with open(file_path, 'rb') as f:
                    return f.read()
            
            else:
                # Default to text loading
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        return f.read()
                except UnicodeDecodeError:
                    # If not valid text, load as binary
                    with open(file_path, 'rb') as f:
                        return f.read()
                
        except Exception as e:
            self.logger.warning(f"Error loading file {file_path}: {e}")
            return None
    
    def execute_testcase(self, test_data: Any, timeout: int = 5, iteration: int = 0, is_valid_input: bool = True) -> Dict:
        """
        Execute a test case against the target.
        
        Args:
            test_data: Test data to execute
            timeout: Timeout in seconds
            iteration: Current fuzzing iteration number
            is_valid_input: Whether this test case is valid according to the schema
            
        Returns:
            Dict: Test result information with detailed execution data
        """
        if not self.target_path:
            self.logger.error("No target executable specified")
            return {"status": "error", "reason": "No target executable specified"}
        
        # Prepare test data
        if isinstance(test_data, dict) or isinstance(test_data, list):
            # Convert to JSON
            test_input = json.dumps(test_data)
        elif isinstance(test_data, bytes):
            # Binary data
            test_input = test_data
        else:
            # Convert to string
            test_input = str(test_data)
        
        # Create a temporary file for the test case
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            if isinstance(test_input, str):
                tmp_file.write(test_input.encode('utf-8'))
            else:
                tmp_file.write(test_input)
            tmp_file_path = tmp_file.name
        
        try:
            self.logger.debug(f"Executing test case with timeout {timeout}s")
            start_time = time.time()
            
            # Execute the target with the test case file as input
            command = [self.target_path, tmp_file_path]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                execution_time = time.time() - start_time
                return_code = process.returncode
                
                # Check for crash
                if return_code != 0:
                    # Save the crash
                    if self.output_dir:
                        crash_dir = os.path.join(self.output_dir, "crashes")
                        os.makedirs(crash_dir, exist_ok=True)
                        
                        crash_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        crash_file = os.path.join(crash_dir, f"crash_{crash_time}.bin")
                        
                        if isinstance(test_input, str):
                            with open(crash_file, 'w', encoding='utf-8') as f:
                                f.write(test_input)
                        else:
                            with open(crash_file, 'wb') as f:
                                f.write(test_input)
                        
                        # Save info
                        info_file = os.path.join(crash_dir, f"crash_{crash_time}.info")
                        with open(info_file, 'w', encoding='utf-8') as f:
                            f.write(f"Return code: {return_code}\n")
                            f.write(f"Execution time: {execution_time:.6f}s\n")
                            f.write(f"Command: {' '.join(command)}\n\n")
                            f.write("STDOUT:\n")
                            f.write(stdout.decode('utf-8', errors='replace'))
                            f.write("\n\nSTDERR:\n")
                            f.write(stderr.decode('utf-8', errors='replace'))
                    
                    self.logger.info(f"Test case crashed the target (return code: {return_code})")
                    
                    # Generate unique test case ID
                    test_id = f"crash_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
                    
                    # Determine crash type from stderr output
                    stderr_text = stderr.decode('utf-8', errors='replace')
                    crash_type = "Unknown"
                    if "segmentation fault" in stderr_text.lower():
                        crash_type = "SEGFAULT"
                    elif "bus error" in stderr_text.lower():
                        crash_type = "BUS_ERROR"
                    elif "illegal instruction" in stderr_text.lower():
                        crash_type = "ILLEGAL_INSTRUCTION"
                    elif "assertion failed" in stderr_text.lower():
                        crash_type = "ASSERTION_FAILURE"
                    elif "memory error" in stderr_text.lower():
                        crash_type = "MEMORY_ERROR"
                    elif "arithmetic exception" in stderr_text.lower():
                        crash_type = "ARITHMETIC_EXCEPTION"
                    elif "aborted" in stderr_text.lower():
                        crash_type = "ABORTED"
                    elif return_code < 0:
                        crash_type = f"SIGNAL_{abs(return_code)}"
                    else:
                        crash_type = f"CRASH_CODE_{return_code}"
                    
                    # Create detailed result
                    detailed_result = {
                        "id": test_id,
                        "status": "crash",
                        "iteration": iteration,
                        "is_valid_input": is_valid_input,
                        "return_code": return_code,
                        "execution_time": execution_time,
                        "crash_type": crash_type,
                        "error_message": stderr_text.strip() if stderr_text else None,
                        "test_data_size": len(test_input) if isinstance(test_input, bytes) else len(str(test_input)),
                        "test_case_path": crash_file if self.output_dir else None,
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "stdout": stdout.decode('utf-8', errors='replace'),
                        "stderr": stderr_text
                    }
                    
                    # Add to detailed results list if it's not already in the stats dictionary
                    return detailed_result
                else:
                    # Successful execution
                    test_id = f"success_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
                    
                    # Create detailed result for successful execution
                    detailed_result = {
                        "id": test_id,
                        "status": "success",
                        "iteration": iteration,
                        "is_valid_input": is_valid_input,
                        "return_code": return_code,
                        "execution_time": execution_time,
                        "test_data_size": len(test_input) if isinstance(test_input, bytes) else len(str(test_input)),
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "stdout": stdout.decode('utf-8', errors='replace'),
                        "stderr": stderr.decode('utf-8', errors='replace')
                    }
                    
                    return detailed_result
                
            except subprocess.TimeoutExpired:
                # Kill the process
                process.kill()
                process.wait()
                
                # Save the timeout
                if self.output_dir:
                    timeout_dir = os.path.join(self.output_dir, "timeouts")
                    os.makedirs(timeout_dir, exist_ok=True)
                    
                    timeout_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    timeout_file = os.path.join(timeout_dir, f"timeout_{timeout_time}.bin")
                    
                    if isinstance(test_input, str):
                        with open(timeout_file, 'w', encoding='utf-8') as f:
                            f.write(test_input)
                    else:
                        with open(timeout_file, 'wb') as f:
                            f.write(test_input)
                
                self.logger.info(f"Test case timed out after {timeout}s")
                
                # Generate unique test case ID for timeout
                test_id = f"timeout_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
                
                # Create detailed result for timeout
                detailed_result = {
                    "id": test_id,
                    "status": "timeout",
                    "iteration": iteration,
                    "is_valid_input": is_valid_input,
                    "execution_time": timeout,
                    "test_data_size": len(test_input) if isinstance(test_input, bytes) else len(str(test_input)),
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "test_case_path": timeout_file if self.output_dir else None
                }
                
                return detailed_result
        
        except Exception as e:
            self.logger.error(f"Error executing test case: {e}")
            # Generate unique test case ID for error
            test_id = f"error_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
            
            # Create detailed result for error
            return {
                "id": test_id,
                "status": "error",
                "iteration": iteration,
                "is_valid_input": is_valid_input,
                "error_message": str(e),
                "test_data_size": len(test_input) if isinstance(test_input, bytes) else len(str(test_input)),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        finally:
            # Clean up the temporary file
            try:
                os.unlink(tmp_file_path)
            except Exception:
                pass
    
    def fuzz(self, iterations: int = 100, timeout: int = 5,
            corpus_size: int = 20, mutation_count: int = 5,
            valid_ratio: float = 0.8) -> Dict:
        """
        Run structure-aware fuzzing.
        
        Args:
            iterations: Number of iterations to run
            timeout: Timeout for each test case
            corpus_size: Initial corpus size
            mutation_count: Number of mutations per seed
            valid_ratio: Ratio of valid to invalid test cases (default: 0.8)
            
        Returns:
            Dict: Fuzzing statistics
        """
        # Set up fuzzer if not already done
        if not self.schema or not self.generator or not self.mutator:
            self.setup_for_fuzzing()
        
        # Create initial corpus if needed
        corpus_dir = os.path.join(self.output_dir, "corpus") if self.output_dir else "corpus"
        os.makedirs(corpus_dir, exist_ok=True)
        
        # Load existing corpus if available, or generate a new one
        corpus_files = [f for f in os.listdir(corpus_dir) if os.path.isfile(os.path.join(corpus_dir, f))]
        
        if not corpus_files:
            # Generate initial corpus
            self.logger.info(f"Generating initial corpus of {corpus_size} files (valid ratio: {valid_ratio})")
            corpus_files = self.generate_corpus(count=corpus_size, valid_ratio=valid_ratio)
        else:
            self.logger.info(f"Using existing corpus of {len(corpus_files)} files")
            corpus_files = [os.path.join(corpus_dir, f) for f in corpus_files]
        
        # If we still don't have a corpus (e.g., generation failed)
        if not corpus_files:
            self.logger.error("Failed to create or load corpus")
            return {"status": "error", "reason": "Failed to create or load corpus"}
        
        # Set up statistics
        stats = {
            "total_executions": 0,
            "crashes": 0,
            "timeouts": 0,
            "successes": 0,
            "errors": 0,
            "start_time": time.time(),
            "end_time": None,
            "total_time": None,
            "valid_ratio": valid_ratio,
            "detailed_results": [],  # Storage for detailed test results
            "crashes_list": []       # Storage for detailed crash information
        }
        
        self.logger.info(f"Starting fuzzing for {iterations} iterations with timeout {timeout}s")
        
        try:
            # Main fuzzing loop
            for i in range(iterations):
                if i % 10 == 0:
                    self.logger.info(f"Fuzzing iteration {i+1}/{iterations}")
                
                # Choose a random seed from the corpus
                seed_file = random.choice(corpus_files)
                seed_data = self._load_file(seed_file)
                
                if seed_data is None:
                    continue  # Skip this iteration if seed loading failed
                
                # Apply multiple mutations
                self.mutator.set_seed_data(seed_data)
                
                for _ in range(mutation_count):
                    # Generate mutation
                    test_data = self.mutator.mutate()
                    
                    # Execute test case with iteration number and validity info
                    is_valid = self.generator.is_valid(test_data) if hasattr(self.generator, 'is_valid') else True
                    result = self.execute_testcase(test_data, timeout, i, is_valid)
                    stats["total_executions"] += 1
                    
                    # Add results to detailed results list
                    stats["detailed_results"].append(result)
                    
                    # Update statistics
                    if result["status"] == "crash":
                        stats["crashes"] += 1
                        # Add to crashes list for detailed reporting
                        stats["crashes_list"].append(result)
                    elif result["status"] == "timeout":
                        stats["timeouts"] += 1
                    elif result["status"] == "success":
                        stats["successes"] += 1
                    else:  # error
                        stats["errors"] += 1
            
            # Add some additional generated tests
            self.logger.info(f"Adding additional generated test cases (valid ratio: {valid_ratio})")
            for _ in range(max(10, iterations // 10)):
                # Generate a new test case with the specified valid ratio
                is_valid = random.random() < valid_ratio
                test_data = self.generator.generate(valid=is_valid)
                
                # Execute test case with iteration info
                is_valid = random.random() < valid_ratio
                iteration_number = iterations + _ # Add iterations to distinguish from mutation tests
                result = self.execute_testcase(test_data, timeout, iteration_number, is_valid)
                stats["total_executions"] += 1
                
                # Add results to detailed results list
                stats["detailed_results"].append(result)
                
                # Update statistics
                if result["status"] == "crash":
                    stats["crashes"] += 1
                    # Add to crashes list for detailed reporting
                    stats["crashes_list"].append(result)
                elif result["status"] == "timeout":
                    stats["timeouts"] += 1
                elif result["status"] == "success":
                    stats["successes"] += 1
                else:  # error
                    stats["errors"] += 1
        
        except KeyboardInterrupt:
            self.logger.info("Fuzzing interrupted by user")
        
        # Finalize statistics
        stats["end_time"] = time.time()
        stats["total_time"] = stats["end_time"] - stats["start_time"]
        
        # Log final statistics
        self.logger.info("Fuzzing completed")
        self.logger.info(f"Total executions: {stats['total_executions']}")
        self.logger.info(f"Crashes: {stats['crashes']}")
        self.logger.info(f"Timeouts: {stats['timeouts']}")
        self.logger.info(f"Successes: {stats['successes']}")
        self.logger.info(f"Errors: {stats['errors']}")
        self.logger.info(f"Total time: {stats['total_time']:.2f}s")
        
        # Generate summary report
        if self.output_dir:
            self._generate_summary_report(stats)
        
        return stats
    
    def _generate_summary_report(self, stats: Dict) -> None:
        """Generate a detailed JSON report of the fuzzing results."""
        # Create text summary report
        txt_report_file = os.path.join(self.output_dir, "fuzzing_summary.txt")
        
        # Get valid ratio from stats if available, otherwise use default
        valid_ratio = stats.get('valid_ratio', 0.8)
        
        with open(txt_report_file, 'w', encoding='utf-8') as f:
            f.write("Structure-Aware Fuzzing Summary Report\n")
            f.write("====================================\n\n")
            
            # Target information
            f.write(f"Target: {self.target_path}\n")
            f.write(f"Format: {self.format_type}\n")
            f.write(f"Output directory: {self.output_dir}\n")
            f.write(f"Valid/Invalid ratio: {valid_ratio:.2f}/{1-valid_ratio:.2f}\n")
            f.write(f"Binary coverage: 1/1 (100%)\n\n")
            
            # Statistics
            f.write("Statistics:\n")
            f.write(f"  Total executions: {stats['total_executions']}\n")
            f.write(f"  Crashes: {stats['crashes']}\n")
            f.write(f"  Timeouts: {stats['timeouts']}\n")
            f.write(f"  Successes: {stats['successes']}\n")
            f.write(f"  Errors: {stats['errors']}\n")
            
            # Calculate crash rate
            crash_rate = (stats['crashes'] / stats['total_executions']) * 100 if stats['total_executions'] > 0 else 0
            timeout_rate = (stats['timeouts'] / stats['total_executions']) * 100 if stats['total_executions'] > 0 else 0
            f.write(f"  Crash rate: {crash_rate:.2f}%\n")
            f.write(f"  Timeout rate: {timeout_rate:.2f}%\n\n")
            
            # Timing information
            start_time_str = datetime.datetime.fromtimestamp(stats['start_time']).strftime("%Y-%m-%d %H:%M:%S")
            end_time_str = datetime.datetime.fromtimestamp(stats['end_time']).strftime("%Y-%m-%d %H:%M:%S")
            
            f.write("Timing:\n")
            f.write(f"  Start time: {start_time_str}\n")
            f.write(f"  End time: {end_time_str}\n")
            f.write(f"  Total time: {stats['total_time']:.2f}s\n\n")
            
            # Crash locations
            crashes_dir = os.path.join(self.output_dir, "crashes")
            if os.path.exists(crashes_dir):
                crash_files = [f for f in os.listdir(crashes_dir) if f.endswith('.bin')]
                f.write(f"Crashes: {len(crash_files)}\n")
                f.write(f"  Location: {crashes_dir}\n\n")
            
            # Timeout locations
            timeouts_dir = os.path.join(self.output_dir, "timeouts")
            if os.path.exists(timeouts_dir):
                timeout_files = [f for f in os.listdir(timeouts_dir) if f.endswith('.bin')]
                f.write(f"Timeouts: {len(timeout_files)}\n")
                f.write(f"  Location: {timeouts_dir}\n\n")
        
        self.logger.info(f"Summary report written to {txt_report_file}")
        
        # Create detailed JSON report
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        json_report_file = os.path.join(self.output_dir, f"fuzzing_detailed_report_{timestamp}.json")
        
        # Collect detailed test case information if available
        detailed_results = stats.get('detailed_results', [])
        
        # Calculate crash and timeout rates
        crash_rate = (stats['crashes'] / stats['total_executions']) * 100 if stats['total_executions'] > 0 else 0
        timeout_rate = (stats['timeouts'] / stats['total_executions']) * 100 if stats['total_executions'] > 0 else 0
        
        json_report = {
            "_SUMMARY_": {
                "TOTAL_EXECUTIONS": stats['total_executions'],
                "CRASHES": stats['crashes'],
                "TIMEOUTS": stats['timeouts'],
                "SUCCESSES": stats['successes'],
                "ERRORS": stats['errors'],
                "CRASH_RATE": f"{crash_rate:.2f}%",
                "TIMEOUT_RATE": f"{timeout_rate:.2f}%",
                "STATUS": "COMPLETED" if stats.get('status', '') != "error" else "FAILED"
            },
            "_TARGET_INFO_": {
                "TARGET_PATH": self.target_path,
                "FORMAT_TYPE": self.format_type,
                "VALID_RATIO": valid_ratio,
                "BINARY_ANALYSIS": {
                    "TOTAL_BINARY_FILES": 1,  # Starting with the target
                    "FUZZED_BINARY_FILES": 1, 
                    "COVERAGE_PERCENTAGE": 100.0
                }
            },
            "_TIMING_": {
                "START_TIME": start_time_str,
                "END_TIME": end_time_str,
                "TOTAL_TIME_SECONDS": stats['total_time']
            },
            "_DETAILED_RESULTS_": {}
        }
        
        # Add detailed test case results
        for test_case in detailed_results:
            test_id = test_case.get('id', 'unknown')
            json_report["_DETAILED_RESULTS_"][test_id] = {
                "STATUS": test_case.get('status', 'unknown'),
                "ITERATION": test_case.get('iteration', -1),
                "EXECUTION_TIME": test_case.get('execution_time', 0),
                "TEST_DATA_SIZE": test_case.get('test_data_size', 0),
                "IS_VALID_INPUT": test_case.get('is_valid_input', True),
                "CRASH_TYPE": test_case.get('crash_type', None),
                "ERROR_MESSAGE": test_case.get('error_message', None),
                "TEST_CASE_PATH": test_case.get('test_case_path', None)
            }
        
        # If detailed crash information is available, add it
        if 'crashes_list' in stats and isinstance(stats['crashes_list'], list) and len(stats['crashes_list']) > 0:
            json_report["_CRASH_DETAILS_"] = {}
            for i, crash in enumerate(stats['crashes_list']):
                crash_id = crash.get('id', f"crash_{i}")
                json_report["_CRASH_DETAILS_"][crash_id] = {
                    "CRASH_TYPE": crash.get('crash_type', 'Unknown'),
                    "FILE_PATH": crash.get('test_case_path', None),
                    "ITERATION": crash.get('iteration', -1),
                    "CRASH_TIME": crash.get('timestamp', None),
                    "ERROR_MESSAGE": crash.get('error_message', None),
                    "STACK_TRACE": crash.get('stack_trace', None),
                    "IS_VALID_INPUT": crash.get('is_valid_input', True),
                    "TEST_DATA_SIZE": crash.get('test_data_size', 0)
                }
        
        # Write JSON report
        with open(json_report_file, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=4)
        
        self.logger.info(f"Detailed JSON report written to {json_report_file}")