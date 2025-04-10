"""
Behavior Monitor for Intelligent Fuzzing

This module monitors the behavior of processes during fuzzing,
including resource usage, file access, and network activity.
"""

import os
import time
import logging
import signal
import subprocess
import tempfile
import json
import csv
from datetime import datetime
from collections import defaultdict
import psutil

# Get logger
logger = logging.getLogger(__name__)

class BehaviorMonitor:
    """
    Monitors and analyzes process behavior during fuzzing.
    
    This class tracks resource usage, file access patterns, and network
    activity of target processes to identify potential vulnerabilities
    and behavior anomalies.
    """
    
    def __init__(self, output_dir=None, sampling_interval=0.1):
        """
        Initialize the behavior monitor.
        
        Args:
            output_dir: Directory to store monitoring results
            sampling_interval: Time between samples in seconds
        """
        self.output_dir = output_dir if output_dir else os.path.join(os.getcwd(), 'behavior_logs')
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.sampling_interval = sampling_interval
        self.monitored_processes = {}
        self.monitoring_active = False
        self.current_run_id = None
        
        # Behavioral metrics
        self.metrics = defaultdict(list)
        self.anomalies = []
        self.behavior_summary = {}
        
        # Map of process PIDs to their behavior logs
        self.process_logs = {}
        
        logger.debug(f"Behavior monitor initialized with output_dir={self.output_dir}, "
                    f"sampling_interval={sampling_interval}")
    
    def _generate_run_id(self):
        """Generate a unique ID for a monitoring run."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"run_{timestamp}"
    
    def start_monitoring(self, process=None, pid=None, run_id=None):
        """
        Start monitoring a process.
        
        Args:
            process: A running process object (e.g., from subprocess.Popen)
            pid: Process ID to monitor (alternative to process)
            run_id: Optional run identifier
            
        Returns:
            str: Run ID for the monitoring session
        """
        if self.monitoring_active:
            logger.warning("Monitoring already active, stopping current session first")
            self.stop_monitoring()
        
        # Generate run ID if not provided
        if run_id is None:
            run_id = self._generate_run_id()
        
        self.current_run_id = run_id
        
        # Create output directory for this run
        run_dir = os.path.join(self.output_dir, run_id)
        os.makedirs(run_dir, exist_ok=True)
        
        # Determine PID to monitor
        target_pid = None
        if process is not None:
            try:
                target_pid = process.pid
            except AttributeError:
                logger.error("Invalid process object, no PID available")
                return run_id
        elif pid is not None:
            target_pid = pid
        else:
            logger.error("No process or PID provided for monitoring")
            return run_id
        
        # Verify PID exists
        try:
            if not psutil.pid_exists(target_pid):
                logger.error(f"PID {target_pid} does not exist")
                return run_id
            
            # Get process object
            p = psutil.Process(target_pid)
            
            # Check if process is running
            if not p.is_running():
                logger.error(f"Process {target_pid} is not running")
                return run_id
            
            # Store process info
            self.monitored_processes[target_pid] = {
                'process': p,
                'run_id': run_id,
                'start_time': time.time(),
                'cmd_line': p.cmdline(),
                'metrics': {
                    'cpu': [],
                    'memory': [],
                    'io': [],
                    'files': set(),
                    'network': set()
                }
            }
            
            # Set up log file
            log_file = os.path.join(run_dir, f"proc_{target_pid}.json")
            self.process_logs[target_pid] = {
                'file': log_file,
                'data': {
                    'pid': target_pid,
                    'cmd_line': p.cmdline(),
                    'start_time': datetime.now().isoformat(),
                    'samples': []
                }
            }
            
            logger.info(f"Started monitoring process {target_pid} ({' '.join(p.cmdline())})")
            self.monitoring_active = True
            
            # Start monitoring thread
            import threading
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop, 
                args=(target_pid,),
                daemon=True
            )
            self.monitor_thread.start()
            
            return run_id
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.error(f"Error accessing process {target_pid}: {e}")
            return run_id
    
    def _monitoring_loop(self, pid):
        """
        Main monitoring loop for collecting process metrics.
        
        Args:
            pid: Process ID to monitor
        """
        logger.debug(f"Monitoring loop started for PID {pid}")
        
        while self.monitoring_active and pid in self.monitored_processes:
            try:
                # Get process object
                p = self.monitored_processes[pid]['process']
                
                # Check if process is still running
                if not p.is_running():
                    logger.info(f"Process {pid} is no longer running, stopping monitoring")
                    self.monitoring_active = False
                    break
                
                # Collect metrics
                try:
                    # CPU usage (percent)
                    cpu = p.cpu_percent(interval=0)
                    
                    # Memory usage
                    memory = p.memory_info()
                    mem_usage = {
                        'rss': memory.rss,
                        'vms': memory.vms,
                        'percent': p.memory_percent()
                    }
                    
                    # I/O counters
                    try:
                        io = p.io_counters()
                        io_usage = {
                            'read_count': io.read_count,
                            'write_count': io.write_count,
                            'read_bytes': io.read_bytes,
                            'write_bytes': io.write_bytes
                        }
                    except (psutil.AccessDenied, AttributeError):
                        io_usage = {}
                    
                    # Thread count
                    try:
                        thread_count = len(p.threads())
                    except psutil.AccessDenied:
                        thread_count = 0
                    
                    # Open files
                    try:
                        open_files = p.open_files()
                        files = [f.path for f in open_files]
                        self.monitored_processes[pid]['metrics']['files'].update(files)
                    except psutil.AccessDenied:
                        files = []
                    
                    # Network connections
                    try:
                        connections = p.connections()
                        network = []
                        for conn in connections:
                            if conn.laddr and conn.raddr:
                                network.append(f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}")
                        self.monitored_processes[pid]['metrics']['network'].update(network)
                    except psutil.AccessDenied:
                        network = []
                    
                    # Record sample
                    sample = {
                        'timestamp': time.time(),
                        'cpu': cpu,
                        'memory': mem_usage,
                        'io': io_usage,
                        'thread_count': thread_count,
                        'files': files,
                        'network': network
                    }
                    
                    # Store metrics
                    self.monitored_processes[pid]['metrics']['cpu'].append(cpu)
                    self.monitored_processes[pid]['metrics']['memory'].append(mem_usage['rss'])
                    
                    if io_usage:
                        self.monitored_processes[pid]['metrics']['io'].append(
                            (io_usage['read_bytes'], io_usage['write_bytes'])
                        )
                    
                    # Store sample in process logs
                    if pid in self.process_logs:
                        self.process_logs[pid]['data']['samples'].append(sample)
                    
                    # Check for anomalies
                    self._check_anomalies(pid, sample)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    logger.warning(f"Lost access to process {pid}, stopping monitoring")
                    self.monitoring_active = False
                    break
                
            except Exception as e:
                logger.error(f"Error in monitoring loop for PID {pid}: {e}")
            
            # Sleep until next sample
            time.sleep(self.sampling_interval)
        
        # Monitoring ended, save results
        self._save_monitoring_results(pid)
    
    def _check_anomalies(self, pid, sample):
        """
        Check for anomalous behavior in the process.
        
        Args:
            pid: Process ID
            sample: Current metric sample
        """
        # Check for CPU spikes
        if len(self.monitored_processes[pid]['metrics']['cpu']) > 5:
            recent_cpu = self.monitored_processes[pid]['metrics']['cpu'][-5:]
            avg_cpu = sum(recent_cpu) / len(recent_cpu)
            
            if sample['cpu'] > avg_cpu * 3 and sample['cpu'] > 90:
                anomaly = {
                    'type': 'cpu_spike',
                    'pid': pid,
                    'timestamp': sample['timestamp'],
                    'value': sample['cpu'],
                    'avg': avg_cpu
                }
                self.anomalies.append(anomaly)
                logger.warning(f"CPU spike detected in PID {pid}: {sample['cpu']}% (avg: {avg_cpu:.1f}%)")
        
        # Check for memory leaks
        if len(self.monitored_processes[pid]['metrics']['memory']) > 10:
            recent_memory = self.monitored_processes[pid]['metrics']['memory'][-10:]
            
            # Calculate if memory is steadily increasing
            is_increasing = True
            for i in range(1, len(recent_memory)):
                if recent_memory[i] <= recent_memory[i-1]:
                    is_increasing = False
                    break
            
            if is_increasing and recent_memory[-1] > recent_memory[0] * 1.5:
                anomaly = {
                    'type': 'memory_leak',
                    'pid': pid,
                    'timestamp': sample['timestamp'],
                    'start_value': recent_memory[0],
                    'current_value': recent_memory[-1]
                }
                self.anomalies.append(anomaly)
                logger.warning(f"Potential memory leak detected in PID {pid}: "
                              f"{recent_memory[0]} -> {recent_memory[-1]} bytes")
    
    def _save_monitoring_results(self, pid):
        """
        Save monitoring results for a process.
        
        Args:
            pid: Process ID
        """
        if pid not in self.monitored_processes:
            return
        
        # Get process info
        p_info = self.monitored_processes[pid]
        
        # Add end time
        p_info['end_time'] = time.time()
        p_info['duration'] = p_info['end_time'] - p_info['start_time']
        
        # Calculate summary statistics
        if p_info['metrics']['cpu']:
            cpu_avg = sum(p_info['metrics']['cpu']) / len(p_info['metrics']['cpu'])
            cpu_max = max(p_info['metrics']['cpu'])
        else:
            cpu_avg = cpu_max = 0
        
        if p_info['metrics']['memory']:
            mem_avg = sum(p_info['metrics']['memory']) / len(p_info['metrics']['memory'])
            mem_max = max(p_info['metrics']['memory'])
            mem_growth = p_info['metrics']['memory'][-1] - p_info['metrics']['memory'][0] if len(p_info['metrics']['memory']) > 1 else 0
        else:
            mem_avg = mem_max = mem_growth = 0
        
        # Create summary
        summary = {
            'pid': pid,
            'cmd_line': p_info['cmd_line'],
            'run_id': p_info['run_id'],
            'start_time': datetime.fromtimestamp(p_info['start_time']).isoformat(),
            'end_time': datetime.fromtimestamp(p_info['end_time']).isoformat(),
            'duration': p_info['duration'],
            'cpu_avg': cpu_avg,
            'cpu_max': cpu_max,
            'memory_avg': mem_avg,
            'memory_max': mem_max,
            'memory_growth': mem_growth,
            'files_accessed': list(p_info['metrics']['files']),
            'network_connections': list(p_info['metrics']['network']),
            'anomalies': [a for a in self.anomalies if a['pid'] == pid]
        }
        
        # Save summary to file
        run_dir = os.path.join(self.output_dir, p_info['run_id'])
        summary_file = os.path.join(run_dir, f"proc_{pid}_summary.json")
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Save full process logs
        if pid in self.process_logs:
            log_file = self.process_logs[pid]['file']
            log_data = self.process_logs[pid]['data']
            
            # Add summary to log data
            log_data['summary'] = summary
            
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
        
        logger.info(f"Saved monitoring results for PID {pid} to {run_dir}")
        
        # Store summary
        self.behavior_summary[pid] = summary
    
    def stop_monitoring(self, pid=None):
        """
        Stop monitoring processes.
        
        Args:
            pid: Specific process ID to stop monitoring (if None, stop all)
        """
        if pid is not None:
            if pid in self.monitored_processes:
                logger.info(f"Stopping monitoring for PID {pid}")
                # Process will be removed in monitoring loop
                del self.monitored_processes[pid]
                
                if not self.monitored_processes:
                    self.monitoring_active = False
        else:
            logger.info("Stopping all process monitoring")
            self.monitored_processes.clear()
            self.monitoring_active = False
        
        # Wait for monitoring thread to finish
        if hasattr(self, 'monitor_thread') and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
    
    def get_anomalies(self, pid=None):
        """
        Get detected anomalies.
        
        Args:
            pid: Specific process ID to get anomalies for (if None, get all)
            
        Returns:
            list: List of detected anomalies
        """
        if pid is not None:
            return [a for a in self.anomalies if a['pid'] == pid]
        return self.anomalies
    
    def get_summary(self, pid=None):
        """
        Get behavior summary.
        
        Args:
            pid: Specific process ID to get summary for (if None, get all)
            
        Returns:
            dict: Behavior summary
        """
        if pid is not None and pid in self.behavior_summary:
            return self.behavior_summary[pid]
        return self.behavior_summary
    
    def plot_metrics(self, pid, output_file=None):
        """
        Generate plots of process metrics.
        
        Args:
            pid: Process ID to plot metrics for
            output_file: Path to save the plot
            
        Returns:
            str: Path to saved plot or None if plotting failed
        """
        try:
            import matplotlib.pyplot as plt
            
            if pid not in self.monitored_processes:
                logger.error(f"No monitoring data for PID {pid}")
                return None
            
            p_info = self.monitored_processes[pid]
            
            # Get metrics
            timestamps = []
            cpu_values = []
            memory_values = []
            
            if pid in self.process_logs:
                samples = self.process_logs[pid]['data']['samples']
                for sample in samples:
                    timestamps.append(sample['timestamp'] - p_info['start_time'])
                    cpu_values.append(sample['cpu'])
                    memory_values.append(sample['memory']['rss'] / (1024**2))  # Convert to MB
            
            if not timestamps:
                logger.error(f"No samples collected for PID {pid}")
                return None
            
            # Create plot
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
            
            # CPU plot
            ax1.plot(timestamps, cpu_values, 'b-')
            ax1.set_ylabel('CPU Usage (%)')
            ax1.set_title(f"Process Metrics for PID {pid}")
            ax1.grid(True)
            
            # Memory plot
            ax2.plot(timestamps, memory_values, 'r-')
            ax2.set_xlabel('Time (seconds)')
            ax2.set_ylabel('Memory Usage (MB)')
            ax2.grid(True)
            
            # Tight layout
            plt.tight_layout()
            
            # Save or show plot
            if output_file:
                plt.savefig(output_file)
                logger.info(f"Saved metrics plot to {output_file}")
                return output_file
            else:
                # Generate default output file
                run_dir = os.path.join(self.output_dir, p_info['run_id'])
                default_output = os.path.join(run_dir, f"proc_{pid}_metrics.png")
                plt.savefig(default_output)
                logger.info(f"Saved metrics plot to {default_output}")
                return default_output
                
        except ImportError:
            logger.error("Matplotlib not available, plotting skipped")
            return None
        except Exception as e:
            logger.error(f"Error plotting metrics: {e}")
            return None
    
    def monitor_process_with_input(self, command, input_data=None, input_file=None, timeout=30):
        """
        Run a process with given input and monitor its behavior.
        
        Args:
            command: Command to run (list or string)
            input_data: Input data to provide to the process
            input_file: Input file path to provide to the process
            timeout: Maximum execution time in seconds
            
        Returns:
            tuple: (run_id, return_code, stdout, stderr, execution_time, anomalies)
        """
        # Prepare command
        if isinstance(command, str):
            command = command.split()
        
        logger.info(f"Running command: {' '.join(command)}")
        
        # Set up process
        try:
            # Create temporary file for input if needed
            temp_input = None
            if input_data is not None and input_file is None:
                temp_input = tempfile.NamedTemporaryFile(delete=False)
                if isinstance(input_data, str):
                    temp_input.write(input_data.encode('utf-8'))
                else:
                    temp_input.write(input_data)
                temp_input.close()
                input_file = temp_input.name
            
            # Update command if input file is provided
            cmd = list(command)
            if input_file is not None:
                # Assume the last argument is a placeholder for the input file
                if '@@' in cmd:
                    cmd[cmd.index('@@')] = input_file
                else:
                    cmd.append(input_file)
            
            # Start process
            start_time = time.time()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Start monitoring
            run_id = self.start_monitoring(process=process)
            
            # Wait for process to finish or timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                # Process timed out
                logger.warning(f"Process timed out after {timeout} seconds")
                process.kill()
                stdout, stderr = process.communicate()
                return_code = -1
            
            # Calculate execution time
            execution_time = time.time() - start_time
            
            # Stop monitoring
            self.stop_monitoring(process.pid)
            
            # Get anomalies
            anomalies = self.get_anomalies(process.pid)
            
            # Clean up temporary file
            if temp_input:
                os.unlink(temp_input.name)
            
            return (run_id, return_code, stdout, stderr, execution_time, anomalies)
            
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return (None, -1, "", str(e), 0, [])
    
    def analyze_crash(self, command, crash_file, timeout=30):
        """
        Analyze a crash by running the command with a crash file input.
        
        Args:
            command: Command to run (list or string)
            crash_file: Path to the crash file
            timeout: Maximum execution time in seconds
            
        Returns:
            dict: Crash analysis results
        """
        if not os.path.exists(crash_file):
            logger.error(f"Crash file not found: {crash_file}")
            return {"error": "Crash file not found"}
        
        # Run and monitor process with crash file
        run_id, return_code, stdout, stderr, execution_time, anomalies = self.monitor_process_with_input(
            command, input_file=crash_file, timeout=timeout
        )
        
        # Determine if process crashed
        crashed = return_code != 0
        
        # Extract crash reason from stderr
        crash_reason = "Unknown"
        crash_type = "Unknown"
        
        if crashed:
            # Look for common crash signatures in stderr
            if "Segmentation fault" in stderr:
                crash_reason = "Segmentation fault"
                crash_type = "SIGSEGV"
            elif "Bus error" in stderr:
                crash_reason = "Bus error"
                crash_type = "SIGBUS"
            elif "Floating point exception" in stderr:
                crash_reason = "Floating point exception"
                crash_type = "SIGFPE"
            elif "Aborted" in stderr:
                crash_reason = "Aborted"
                crash_type = "SIGABRT"
            elif "Stack smashing detected" in stderr:
                crash_reason = "Stack smashing detected"
                crash_type = "Stack Overflow"
            elif "heap corruption" in stderr or "heap overflow" in stderr:
                crash_reason = "Heap corruption"
                crash_type = "Heap Overflow"
            elif "double free" in stderr:
                crash_reason = "Double free"
                crash_type = "Double Free"
            elif "Invalid free" in stderr:
                crash_reason = "Invalid free"
                crash_type = "Invalid Free"
            elif "division by zero" in stderr:
                crash_reason = "Division by zero"
                crash_type = "SIGFPE"
            else:
                # Generic crash
                crash_reason = f"Process crashed with exit code {return_code}"
        
        # Get behavior summary
        behavior = self.get_summary(process.pid) if 'process' in locals() else {}
        
        # Create analysis report
        analysis = {
            "command": command if isinstance(command, str) else " ".join(command),
            "crash_file": crash_file,
            "crashed": crashed,
            "exit_code": return_code,
            "execution_time": execution_time,
            "crash_reason": crash_reason,
            "crash_type": crash_type,
            "stdout": stdout,
            "stderr": stderr,
            "anomalies": anomalies,
            "behavior": behavior,
            "run_id": run_id
        }
        
        return analysis