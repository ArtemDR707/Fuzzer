#!/usr/bin/env python3
"""
Crash Report Viewer

This script provides a simple web interface to view crash reports and visualizations.
"""

import os
import sys
import logging
from flask import Flask, render_template, send_from_directory, abort, request, redirect, url_for

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("crash_report_viewer")

app = Flask(__name__, template_folder='.')

def list_crash_reports():
    """List all available crash reports."""
    reports = []
    for root, _, files in os.walk('./crash_analysis'):
        for file in files:
            if file.startswith('crash_report_') and file.endswith('.txt'):
                reports.append({
                    'path': os.path.join(root, file),
                    'name': file,
                    'date': file.replace('crash_report_', '').replace('.txt', '')
                })
    
    # Sort by date (newest first)
    reports.sort(key=lambda x: x['date'], reverse=True)
    return reports

def list_visualizations():
    """List all available visualizations."""
    visualizations = []
    for root, _, files in os.walk('./crash_analysis'):
        for file in files:
            if file.endswith('.png'):
                visualizations.append({
                    'path': os.path.join(root, file),
                    'name': file
                })
    return visualizations

def create_templates():
    """Create the HTML templates if they don't exist."""
    os.makedirs('./templates', exist_ok=True)
    
    # Create index.html
    if not os.path.exists('./templates/index.html'):
        with open('./templates/index.html', 'w') as f:
            f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intelligent Fuzzing Dashboard</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1>Intelligent Fuzzing Dashboard</h1>
                <p class="lead">View crash reports and visualizations from the intelligent fuzzing tool.</p>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h2>Crash Reports</h2>
                    </div>
                    <div class="card-body">
                        {% if reports %}
                            <ul class="list-group">
                                {% for report in reports %}
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        <a href="{{ url_for('view_report', report_name=report.name) }}">{{ report.name }}</a>
                                        <span class="badge bg-primary rounded-pill">{{ report.date }}</span>
                                    </li>
                                {% endfor %}
                            </ul>
                        {% else %}
                            <p>No crash reports found.</p>
                        {% endif %}
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h2>Visualizations</h2>
                    </div>
                    <div class="card-body">
                        {% if visualizations %}
                            <div class="row">
                                {% for vis in visualizations %}
                                    <div class="col-md-6 mb-3">
                                        <div class="card">
                                            <div class="card-header">
                                                <h5>{{ vis.name }}</h5>
                                            </div>
                                            <div class="card-body">
                                                <a href="{{ url_for('view_visualization', vis_name=vis.name) }}">
                                                    <img src="{{ url_for('view_visualization', vis_name=vis.name) }}" 
                                                         class="img-fluid" alt="{{ vis.name }}">
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                {% endfor %}
                            </div>
                        {% else %}
                            <p>No visualizations found.</p>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
''')
    
    # Create report.html
    if not os.path.exists('./templates/report.html'):
        with open('./templates/report.html', 'w') as f:
            f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crash Report - {{ report_name }}</title>
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1>Crash Report - {{ report_name }}</h1>
                <a href="{{ url_for('index') }}" class="btn btn-primary">Back to Dashboard</a>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2>Report Content</h2>
                    </div>
                    <div class="card-body">
                        <pre>{{ report_content }}</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
''')

@app.route('/')
def index():
    """Render the dashboard."""
    create_templates()
    reports = list_crash_reports()
    visualizations = list_visualizations()
    return render_template('templates/index.html', reports=reports, visualizations=visualizations)

@app.route('/report/<report_name>')
def view_report(report_name):
    """View a specific crash report."""
    create_templates()
    report_path = os.path.join('./crash_analysis', report_name)
    if not os.path.isfile(report_path):
        abort(404)
    
    with open(report_path, 'r') as f:
        report_content = f.read()
    
    return render_template('templates/report.html', report_name=report_name, report_content=report_content)

@app.route('/visualization/<vis_name>')
def view_visualization(vis_name):
    """View a specific visualization."""
    vis_path = os.path.join('./crash_analysis', vis_name)
    if not os.path.isfile(vis_path):
        abort(404)
    
    return send_from_directory('./crash_analysis', vis_name)

def main():
    """Main entry point."""
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    main()