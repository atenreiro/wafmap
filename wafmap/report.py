# wafmap/report.py
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>wafmap Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2em; }}
        h1 {{ color: #2c3e50; }}
        .result {{ background: #f8f9fa; padding: 1em; border-radius: 5px; margin-bottom: 1em; }}
        .success {{ color: #27ae60; }}
        .error {{ color: #e74c3c; }}
        .warning {{ color: #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
        th, td {{ padding: 0.75em; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        pre {{ background: #f5f5f5; padding: 1em; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>wafmap Report</h1>
    <p>Generated at: {timestamp}</p>
    
    <div class="result">
        <h2>Scan Results</h2>
        {content}
    </div>
</body>
</html>
"""

def generate_html_report(data: Dict[str, Any], output_path: str) -> None:
    """Generate a professional HTML report"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate report content based on command type
    if 'ja4' in data:
        content = _generate_ja4_html(data)
    elif 'detected' in data:
        content = _generate_discover_html(data)
    elif 'results' in data:
        content = _generate_test_html(data)
    else:
        content = "<pre>" + json.dumps(data, indent=2) + "</pre>"
    
    html = HTML_TEMPLATE.format(timestamp=timestamp, content=content)
    Path(output_path).write_text(html)

def _generate_ja4_html(data: Dict[str, Any]) -> str:
    """Generate HTML for JA4 results"""
    html = f"""
    <h3>JA4 Fingerprinting Results</h3>
    <p><strong>Target:</strong> {data['target']}</p>
    <table>
        <tr><th>Client JA4</th><td>{data['ja4']['client']}</td></tr>
        <tr><th>Server JA4</th><td>{data['ja4']['server']}</td></tr>
    </table>
    """
    
    if data.get('debug'):
        html += "<h4>Debug Information</h4>"
        html += f"<p>Resolved IP: {data['debug'].get('dns_resolution', 'N/A')}</p>"
        html += f"<p>Packets Captured: {data['debug'].get('packets_captured', 0)}</p>"
        
        if 'client_hello' in data['debug']:
            html += "<h5>Client Hello</h5>"
            html += f"<p>Cipher Suites: {len(data['debug']['client_hello']['cipher_suites'])} offered</p>"
    
    return html

def _generate_discover_html(data: Dict[str, Any]) -> str:
    """Generate HTML for discover results"""
    vendors = data['detected'] or ["None detected"]
    html = f"""
    <h3>WAF/CDN Discovery Results</h3>
    <p><strong>Target:</strong> {data['target']}</p>
    <p class="{'success' if vendors else 'warning'}">
        <strong>Detected:</strong> {', '.join(vendors)}
    </p>
    """
    
    if data.get('debug') and data['debug'].get('headers'):
        html += "<h4>Headers</h4>"
        html += "<table><tr><th>Header</th><th>Value</th></tr>"
        for h, v in data['debug']['headers'].items():
            html += f"<tr><td>{h}</td><td>{v}</td></tr>"
        html += "</table>"
    
    return html

def _generate_test_html(data: Dict[str, Any]) -> str:
    """Generate HTML for test results"""
    html = f"""
    <h3>Signature Test Results</h3>
    <p><strong>Target:</strong> {data['target']}</p>
    <table>
        <tr>
            <th>Category</th>
            <th>ID</th>
            <th>Payload</th>
            <th>Status</th>
            <th>HTTP Code</th>
        </tr>
    """
    
    for row in data['results']:
        status_class = ""
        if "BLOCKED" in row[3]:
            status_class = "error"
        elif "PASSED" in row[3]:
            status_class = "success"
        
        html += f"""
        <tr>
            <td>{row[0]}</td>
            <td>{row[1]}</td>
            <td><code>{row[2]}</code></td>
            <td class="{status_class}">{row[3]}</td>
            <td>{row[4] if len(row) > 4 else 'N/A'}</td>
        </tr>
        """
    
    html += "</table>"
    return html

def generate_json_report(data: Dict[str, Any], output_path: str) -> None:
    """Generate JSON report"""
    Path(output_path).write_text(json.dumps(data, indent=2))