"""
Web Service for Enterprise Reporting System
A simple web interface for managing and visualizing reports
"""

from flask import Flask, render_template, jsonify, request
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
import glob

app = Flask(__name__)

# Configuration
REPORTS_DIR = Path(os.getenv('REPORTS_DATA', Path.home() / 'reports' / 'data'))
CONFIG_FILE = Path(os.getenv('REPORTS_CONFIG', Path.home() / '.reports' / 'config.json'))

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/v1/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/v1/reports')
def get_reports():
    """Get list of reports"""
    report_type = request.args.get('type', 'all')
    limit = int(request.args.get('limit', 20))
    
    pattern = f"{report_type}*" if report_type != 'all' else "*"
    report_files = glob.glob(str(REPORTS_DIR / f"{pattern}_info_*.json"))
    
    reports = []
    for file_path in sorted(report_files, key=os.path.getmtime, reverse=True)[:limit]:
        try:
            with open(file_path, 'r') as f:
                report_data = json.load(f)
            
            reports.append({
                'id': os.path.basename(file_path),
                'type': report_data.get('type', 'unknown'),
                'hostname': report_data.get('hostname', 'unknown'),
                'timestamp': report_data.get('timestamp', ''),
                'size_bytes': os.path.getsize(file_path)
            })
        except (json.JSONDecodeError, KeyError):
            continue
    
    return jsonify({
        'data': reports,
        'pagination': {
            'limit': limit,
            'total': len(reports)
        }
    })

@app.route('/api/v1/systems')
def get_systems():
    """Get list of monitored systems"""
    # For demo purposes, return mock data
    # In a real implementation, this would come from collected reports
    systems = [
        {
            'hostname': 'server1.example.com',
            'status': 'active',
            'last_report': (datetime.now() - timedelta(minutes=5)).isoformat(),
            'type': 'physical',
            'os': 'Ubuntu 20.04',
            'cpu_count': 8,
            'memory_gb': 32
        },
        {
            'hostname': 'server2.example.com',
            'status': 'active',
            'last_report': (datetime.now() - timedelta(minutes=3)).isoformat(),
            'type': 'virtual',
            'os': 'CentOS 7',
            'cpu_count': 4,
            'memory_gb': 16
        }
    ]
    
    return jsonify({'data': systems})

@app.route('/api/v1/status')
def get_status():
    """Get system status"""
    return jsonify({
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'stats': {
            'reports_collected': 150,
            'systems_monitored': 10,
            'api_requests_today': 245,
            'active_alerts': 0
        }
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = Path('templates')
    templates_dir.mkdir(exist_ok=True)
    
    # Create a basic dashboard template
    dashboard_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Reporting System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #2c3e50; color: white; padding: 1rem; border-radius: 5px; margin-bottom: 20px; }
        .card { background-color: white; padding: 1.5rem; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background-color: #3498db; color: white; padding: 1rem; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enterprise Reporting System Dashboard</h1>
            <p>Comprehensive monitoring and reporting solution</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="systems-count">0</div>
                <div class="stat-label">Systems Monitored</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="reports-count">0</div>
                <div class="stat-label">Reports Collected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="alerts-count">0</div>
                <div class="stat-label">Active Alerts</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Recent Reports</h2>
            <div id="reports-list">Loading...</div>
        </div>
    </div>

    <script>
        // Load system stats
        fetch('/api/v1/status')
            .then(response => response.json())
            .then(data => {
                document.getElementById('systems-count').textContent = data.data.stats.systems_monitored;
                document.getElementById('reports-count').textContent = data.data.stats.reports_collected;
                document.getElementById('alerts-count').textContent = data.data.stats.active_alerts;
            });
        
        // Load recent reports
        fetch('/api/v1/reports?limit=10')
            .then(response => response.json())
            .then(data => {
                const reportsList = document.getElementById('reports-list');
                reportsList.innerHTML = '';
                
                data.data.forEach(report => {
                    const reportDiv = document.createElement('div');
                    reportDiv.className = 'report-item';
                    reportDiv.innerHTML = `
                        <strong>${report.hostname}</strong> 
                        <span>(${report.type})</span> 
                        <small>${new Date(report.timestamp).toLocaleString()}</small>
                    `;
                    reportsList.appendChild(reportDiv);
                });
            });
    </script>
</body>
</html>
    """
    
    with open(templates_dir / 'dashboard.html', 'w') as f:
        f.write(dashboard_template)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=8081, debug=True)