"""
Intelligent Fuzzing Tool - Web Interface

This is the main entry point for the web interface of the intelligent fuzzing tool.
It provides a dashboard for monitoring the fuzzing process and results.
"""

import os
import sys
import logging
import argparse
import json
import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
import threading
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import fuzzer module - adjust import based on your renamed file
try:
    from fuzzer import IntelligentFuzzer
except ImportError:
    class IntelligentFuzzer:
        """Fallback implementation for testing"""
        def __init__(self, args=None):
            self._stats = {
                'status': 'idle',
                'executions': 0,
                'crashes': 0,
                'timeouts': 0,
                'total_runtime': 0
            }
            self._recent_crashes = []
            self._recent_activities = []
            self._running = False
            
        def start(self, target=None, options=None):
            """Start fuzzing the specified target."""
            self._running = True
            self._stats['status'] = 'running'
            self.add_activity(f"Started fuzzing {target}", "info")
            return True
            
        def stop(self):
            """Stop the fuzzing process."""
            self._running = False
            self._stats['status'] = 'idle'
            self.add_activity("Stopped fuzzing", "info")
            return True
            
        def get_stats(self):
            """Get current statistics."""
            return self._stats
            
        def get_recent_crashes(self, limit=10):
            """Get the most recent crashes."""
            return self._recent_crashes[:limit]
            
        def get_recent_activities(self, limit=20):
            """Get the most recent activities."""
            return self._recent_activities[:limit]
            
        def add_activity(self, message, activity_type="info"):
            """Add an activity to the recent activities log."""
            activity = {
                'timestamp': time.time(),
                'message': message,
                'type': activity_type
            }
            self._recent_activities.insert(0, activity)
            return activity

# Import utility modules if available
try:
    from utils.behavior_monitor import BehaviorMonitor
except ImportError:
    print("Warning: behavior_monitor module not available")
    
# These modules are not required for basic functionality
try:
    from utils.qemu_instrumentation import QEMUInstrumentation
except ImportError:
    print("Warning: qemu_instrumentation module not available")

try:
    from utils.format_detector import FormatDetector, InputFormat
except ImportError:
    print("Warning: format_detector module not available")
    
try:
    from utils.source_analyzer import SourceAnalyzer
except ImportError:
    print("Warning: source_analyzer module not available")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fuzzer_web.log'))
    ]
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__, 
            static_folder=os.path.join('web_interface', 'static'),
            template_folder=os.path.join('web_interface', 'templates'))

# Initialize the fuzzer
fuzzer = None
active_fuzz_task = None

# Define directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
CORPUS_DIR = os.path.join(BASE_DIR, 'corpus')
SOURCE_DIR = os.path.join(BASE_DIR, 'source')

# Create necessary directories
for directory in [UPLOADS_DIR, RESULTS_DIR, CORPUS_DIR, SOURCE_DIR]:
    os.makedirs(directory, exist_ok=True)

# Flask routes
@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Render the fuzzing dashboard."""
    return render_template('dashboard.html')

@app.route('/crash_reports')
def crash_reports():
    """View crash reports."""
    # Find all crash reports in the analysis directory
    reports = []
    analysis_dir = os.path.join(BASE_DIR, 'crash_analysis')
    if os.path.exists(analysis_dir):
        for root, _, files in os.walk(analysis_dir):
            for file in files:
                if file.startswith('crash_report_') and file.endswith('.txt'):
                    report_path = os.path.join(root, file)
                    report_date = file.replace('crash_report_', '').replace('.txt', '')
                    reports.append({
                        'path': report_path,
                        'name': file,
                        'date': report_date
                    })
    
    # Sort reports by date (newest first)
    reports.sort(key=lambda x: x['date'], reverse=True)
    
    # Find all visualization files
    visualizations = []
    if os.path.exists(analysis_dir):
        for root, _, files in os.walk(analysis_dir):
            for file in files:
                if file.endswith('.png'):
                    vis_path = os.path.join(root, file)
                    visualizations.append({
                        'path': vis_path,
                        'name': file
                    })
    
    return render_template('crash_reports.html', reports=reports, visualizations=visualizations)

@app.route('/view_report/<report_name>')
def view_report(report_name):
    """View a specific crash report."""
    report_path = os.path.join(BASE_DIR, 'crash_analysis', report_name)
    if not os.path.isfile(report_path):
        return "Report not found", 404
    
    with open(report_path, 'r') as f:
        report_content = f.read()
    
    return render_template('view_report.html', report_name=report_name, report_content=report_content)

@app.route('/api/status')
def get_status():
    """Get the current fuzzing status."""
    global fuzzer
    
    if fuzzer is None:
        return jsonify({
            'status': 'idle',
            'message': 'Fuzzer not initialized'
        })
    
    stats = fuzzer.get_stats()
    return jsonify({
        'status': stats.get('status', 'unknown'),
        'executions': stats.get('executions', 0),
        'crashes': stats.get('crashes', 0),
        'timeouts': stats.get('timeouts', 0),
        'runtime': stats.get('total_runtime', 0),
        'message': f"Fuzzer running: {stats.get('executions', 0)} executions, {stats.get('crashes', 0)} crashes"
    })

@app.route('/api/recent_crashes')
def get_recent_crashes():
    """Get recent crash information."""
    global fuzzer
    
    if fuzzer is None:
        return jsonify([])
    
    crashes = fuzzer.get_recent_crashes(limit=20)
    return jsonify(crashes)

@app.route('/api/activities')
def get_activities():
    """Get recent fuzzing activities."""
    global fuzzer
    
    if fuzzer is None:
        return jsonify([])
    
    activities = fuzzer.get_recent_activities(limit=50)
    return jsonify(activities)

@app.route('/api/start_fuzzing', methods=['POST'])
def start_fuzzing():
    """Start the fuzzing process."""
    global fuzzer, active_fuzz_task
    
    # Parse request data
    data = request.json
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({
            'success': False,
            'message': 'No target specified'
        })
    
    # Initialize fuzzer if not already done
    if fuzzer is None:
        try:
            fuzzer = IntelligentFuzzer()
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Failed to initialize fuzzer: {str(e)}'
            })
    
    # Check if fuzzing is already active
    if active_fuzz_task and active_fuzz_task.is_alive():
        return jsonify({
            'success': False,
            'message': 'Fuzzing already in progress'
        })
    
    # Prepare fuzzing options
    fuzz_options = {
        'target': target,
        'iterations': int(options.get('iterations', 100)),
        'timeout': int(options.get('timeout', 10)),
        'parallel': int(options.get('parallel', 4)),
        'input_type': options.get('input_type', 'auto'),
        'max_runtime': int(options.get('max_runtime', 0)),
        'use_oss_fuzz': options.get('use_oss_fuzz', False),
    }
    
    # Start fuzzing in a separate thread
    def run_fuzzing():
        try:
            fuzzer.start(target=fuzz_options['target'], options=fuzz_options)
        except Exception as e:
            logger.error(f"Error during fuzzing: {e}")
    
    active_fuzz_task = threading.Thread(target=run_fuzzing)
    active_fuzz_task.daemon = True
    active_fuzz_task.start()
    
    return jsonify({
        'success': True,
        'message': f'Started fuzzing {target}'
    })

@app.route('/api/stop_fuzzing', methods=['POST'])
def stop_fuzzing():
    """Stop the fuzzing process."""
    global fuzzer
    
    if fuzzer is None:
        return jsonify({
            'success': False,
            'message': 'Fuzzer not initialized'
        })
    
    try:
        fuzzer.stop()
        return jsonify({
            'success': True,
            'message': 'Fuzzing stopped'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to stop fuzzing: {str(e)}'
        })

@app.route('/api/analyze_binary', methods=['POST'])
def analyze_binary():
    """Analyze a binary file for fuzzing."""
    binary_path = request.json.get('path')
    
    if not binary_path or not os.path.exists(binary_path):
        return jsonify({
            'success': False,
            'message': 'Invalid binary path'
        })
    
    try:
        # Use the format detector to analyze the binary
        detector = FormatDetector()
        format_type, confidence, details = detector.detect_format(binary_path)
        
        # Get fuzzing strategy suggestions
        strategy = detector.suggest_fuzzing_strategy(binary_path)
        
        return jsonify({
            'success': True,
            'binary': os.path.basename(binary_path),
            'format': format_type.name,
            'confidence': confidence,
            'details': details,
            'strategy': strategy
        })
    except Exception as e:
        logger.error(f"Error analyzing binary {binary_path}: {e}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing binary: {str(e)}'
        })

@app.route('/api/qemu_fuzz', methods=['POST'])
def qemu_fuzz():
    """Start QEMU-based fuzzing for a binary."""
    data = request.json
    binary_path = data.get('path')
    timeout = int(data.get('timeout', 300))
    
    if not binary_path or not os.path.exists(binary_path):
        return jsonify({
            'success': False,
            'message': 'Invalid binary path'
        })
    
    try:
        # Initialize QEMU instrumentation
        qemu = QEMUInstrumentation()
        
        # Prepare seed corpus
        qemu.prepare_seed_corpus()
        
        # Run AFL++ in QEMU mode
        success, output_dir, stats = qemu.run_afl_qemu(
            binary_path=binary_path,
            timeout=timeout
        )
        
        if not success:
            return jsonify({
                'success': False,
                'message': 'QEMU fuzzing failed'
            })
        
        # Collect crashes
        crash_dir = os.path.join(RESULTS_DIR, f"qemu_crashes_{int(time.time())}")
        crashes = qemu.collect_crashes(output_dir, crash_dir)
        
        return jsonify({
            'success': True,
            'binary': os.path.basename(binary_path),
            'stats': stats,
            'crashes': len(crashes),
            'output_dir': output_dir,
            'crash_dir': crash_dir if crashes else None
        })
    except Exception as e:
        logger.error(f"Error during QEMU fuzzing of {binary_path}: {e}")
        return jsonify({
            'success': False,
            'message': f'Error during QEMU fuzzing: {str(e)}'
        })

@app.route('/api/analyze_source', methods=['POST'])
def analyze_source():
    """Analyze source code for fuzzing insights."""
    data = request.json
    source_dir = data.get('dir')
    
    if not source_dir or not os.path.isdir(source_dir):
        return jsonify({
            'success': False,
            'message': 'Invalid source directory'
        })
    
    try:
        # Initialize source analyzer
        analyzer = SourceAnalyzer(source_dir)
        
        # Detect languages
        languages = analyzer.detect_languages()
        
        # Find main source files
        main_files = analyzer.find_main_source_files()
        
        # Extract format information from main files
        formats = {}
        arg_info = {}
        
        for file in main_files[:5]:  # Limit to first 5 main files
            formats[os.path.basename(file)] = analyzer.extract_data_formats(file)
            arg_info[os.path.basename(file)] = analyzer.extract_command_line_args(file)
        
        return jsonify({
            'success': True,
            'languages': languages,
            'main_files': [os.path.basename(f) for f in main_files],
            'formats': formats,
            'arg_info': arg_info
        })
    except Exception as e:
        logger.error(f"Error analyzing source in {source_dir}: {e}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing source: {str(e)}'
        })

@app.route('/api/generate_seeds', methods=['POST'])
def generate_seeds():
    """Generate seed inputs based on source code analysis."""
    data = request.json
    source_dir = data.get('dir')
    binary_name = data.get('binary')
    
    if not source_dir or not os.path.isdir(source_dir):
        return jsonify({
            'success': False,
            'message': 'Invalid source directory'
        })
    
    try:
        # Initialize source analyzer
        analyzer = SourceAnalyzer(source_dir)
        
        # Generate source-based seeds
        output_dir = os.path.join(CORPUS_DIR, f"{binary_name or 'source'}_seeds_{int(time.time())}")
        seed_count, seed_dir = analyzer.generate_source_based_seeds(binary_name, output_dir)
        
        return jsonify({
            'success': True,
            'seed_count': seed_count,
            'seed_dir': seed_dir,
            'message': f'Generated {seed_count} seed inputs'
        })
    except Exception as e:
        logger.error(f"Error generating seeds from {source_dir}: {e}")
        return jsonify({
            'success': False,
            'message': f'Error generating seeds: {str(e)}'
        })

@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload a file for fuzzing."""
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'message': 'No file part'
        })
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({
            'success': False,
            'message': 'No selected file'
        })
    
    file_path = os.path.join(UPLOADS_DIR, file.filename)
    file.save(file_path)
    
    # Make the file executable
    os.chmod(file_path, 0o755)
    
    return jsonify({
        'success': True,
        'message': 'File uploaded successfully',
        'path': file_path
    })

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory(app.static_folder, path)

@app.route('/crash_report/<path:path>')
def serve_crash_report(path):
    """Serve crash report files."""
    dir_path = os.path.dirname(path)
    file_name = os.path.basename(path)
    return send_from_directory(os.path.join(RESULTS_DIR, dir_path), file_name)

@app.route('/visualization/<vis_name>')
def view_visualization(vis_name):
    """View a specific visualization."""
    vis_path = os.path.join(BASE_DIR, 'crash_analysis', vis_name)
    if not os.path.isfile(vis_path):
        return "Visualization not found", 404
    
    return send_from_directory(os.path.join(BASE_DIR, 'crash_analysis'), vis_name)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Intelligent Fuzzing Tool Web Interface')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    return parser.parse_args()

def main():
    """Main entry point for the web interface."""
    args = parse_arguments()
    
    # Check environment for port and host settings
    port = int(os.environ.get('PORT', args.port))
    host = os.environ.get('HOST', args.host)
    
    # Start the Flask application with Gunicorn
    app.run(host=host, port=port, debug=args.debug)

if __name__ == '__main__':
    main()