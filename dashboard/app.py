#!/usr/bin/env python3
"""
Cloud Security Posture Dashboard - Flask Application

This is the main web application that displays security findings.

HOW FLASK WORKS:
----------------
1. Flask is a "micro web framework" - it handles HTTP requests/responses
2. We define "routes" (URLs) that map to Python functions
3. Each function returns HTML (usually via templates)
4. Templates are HTML files with placeholders for dynamic data

EXAMPLE:
    @app.route('/hello')      # When user visits /hello
    def hello():
        return "Hello World"  # Show this text

For more complex pages, we use templates:
    @app.route('/dashboard')
    def dashboard():
        data = get_findings()
        return render_template('dashboard.html', findings=data)
"""

import json
import os
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify

# =============================================================================
# FLASK APP INITIALIZATION
# =============================================================================

# Create the Flask application
# __name__ tells Flask where to find templates and static files
app = Flask(__name__)

# Find the project root directory (one level up from dashboard/)
PROJECT_ROOT = Path(__file__).parent.parent.absolute()

# Where our aggregated findings are stored
FINDINGS_DIR = PROJECT_ROOT / "scan-results" / "aggregated"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def load_latest_findings():
    """
    Load the most recent aggregated findings JSON file.

    Returns a list of finding dictionaries, or an empty list if no files found.
    """
    if not FINDINGS_DIR.exists():
        print(f"Findings directory not found: {FINDINGS_DIR}")
        return []

    # Find all aggregated findings files
    finding_files = list(FINDINGS_DIR.glob("aggregated_findings_*.json"))

    if not finding_files:
        print("No aggregated findings files found")
        return []

    # Get the most recent file (by creation time)
    latest_file = max(finding_files, key=os.path.getctime)
    print(f"Loading findings from: {latest_file}")

    with open(latest_file, 'r') as f:
        return json.load(f)


def load_latest_summary():
    """
    Load the most recent summary JSON file.

    Returns a dictionary with summary statistics.
    """
    if not FINDINGS_DIR.exists():
        return {}

    summary_files = list(FINDINGS_DIR.glob("findings_summary_*.json"))

    if not summary_files:
        return {}

    latest_file = max(summary_files, key=os.path.getctime)

    with open(latest_file, 'r') as f:
        return json.load(f)


def get_severity_color(severity):
    """
    Return a color code for each severity level.

    Used in the dashboard to color-code findings.
    """
    colors = {
        'Critical': '#dc3545',  # Red
        'High': '#fd7e14',      # Orange
        'Medium': '#ffc107',    # Yellow
        'Low': '#28a745',       # Green
        'Informational': '#17a2b8'  # Blue
    }
    return colors.get(severity, '#6c757d')  # Gray default


# =============================================================================
# ROUTES (URL Endpoints)
# =============================================================================

@app.route('/')
def index():
    """
    Main dashboard page.

    This is what users see when they visit http://localhost:5000/

    We load the findings and summary, then pass them to the template.
    The template uses this data to render charts and statistics.
    """
    findings = load_latest_findings()
    summary = load_latest_summary()

    # Calculate some additional stats for the dashboard
    stats = {
        'total': len(findings),
        'critical': sum(1 for f in findings if f.get('severity') == 'Critical'),
        'high': sum(1 for f in findings if f.get('severity') == 'High'),
        'medium': sum(1 for f in findings if f.get('severity') == 'Medium'),
        'low': sum(1 for f in findings if f.get('severity') == 'Low'),
    }

    # Get severity data for the chart
    severity_data = summary.get('by_severity', {})

    return render_template(
        'index.html',
        findings=findings,
        summary=summary,
        stats=stats,
        severity_data=severity_data,
        get_severity_color=get_severity_color
    )


@app.route('/findings')
def findings_list():
    """
    Detailed findings page.

    Shows all findings in a searchable, sortable table.
    """
    findings = load_latest_findings()

    return render_template(
        'findings.html',
        findings=findings,
        get_severity_color=get_severity_color
    )


@app.route('/api/findings')
def api_findings():
    """
    API endpoint that returns findings as JSON.

    This is useful for:
    1. JavaScript on the frontend to fetch data dynamically
    2. External tools that want to consume our data
    3. Testing and debugging

    Example: curl http://localhost:5000/api/findings
    """
    findings = load_latest_findings()
    return jsonify(findings)


@app.route('/api/summary')
def api_summary():
    """
    API endpoint that returns the summary as JSON.
    """
    summary = load_latest_summary()
    return jsonify(summary)


# =============================================================================
# RUN THE APPLICATION
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Cloud Security Posture Dashboard")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Findings directory: {FINDINGS_DIR}")
    print()
    print("Starting Flask server...")
    print("Open http://localhost:51000 in your browser")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    # Run the Flask development server
    # debug=True enables:
    #   - Auto-reload when code changes
    #   - Detailed error pages
    # host='0.0.0.0' allows access from other machines (not just localhost)
    # port=51000 uses a custom port (default is 5000)
    app.run(debug=True, host='0.0.0.0', port=51000)
