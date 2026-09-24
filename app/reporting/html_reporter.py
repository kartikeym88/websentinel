import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
import html

def format_datetime_ist(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        ist_offset = timezone(timedelta(hours=5, minutes=30))
        ist_time = value.astimezone(ist_offset)
        return ist_time.strftime('%Y-%m-%d %H:%M:%S IST')
    return value

class HTMLReporter:
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def _escape(self, text: str) -> str:
        if not text:
            return ""
        return html.escape(str(text))

    def generate(self, scan_stats: Dict[str, Any], findings: list) -> str:
        scan_id = scan_stats["scan"]["scan_id"]
        report_path = os.path.join(self.report_dir, f"report_{scan_id}.html")
        
        scan = scan_stats["scan"]
        stats = scan_stats
        
        findings_html = ""
        for f in findings:
            findings_html += f"""
            <div class="finding card">
                <h3>{self._escape(f['title'])} <span class="badge {self._escape(f['severity']).lower()}">{self._escape(f['severity'])}</span></h3>
                <table class="details-table">
                    <tr><th>Category</th><td>{self._escape(f['category'])}</td></tr>
                    <tr><th>URL</th><td>{self._escape(f['url'])}</td></tr>
                    <tr><th>Method</th><td>{self._escape(f['method'])}</td></tr>
                    <tr><th>Parameter</th><td>{self._escape(f.get('parameter', 'N/A'))}</td></tr>
                    <tr><th>Confidence</th><td>{self._escape(f['confidence'])}</td></tr>
                    <tr><th>Scanner</th><td>{self._escape(f['scanner_source'])}</td></tr>
                </table>
                <div class="section">
                    <h4>Description</h4>
                    <p>{self._escape(f['description'])}</p>
                </div>
                <div class="section">
                    <h4>Evidence</h4>
                    <pre>{self._escape(f['evidence'])}</pre>
                </div>
                <div class="section">
                    <h4>Remediation</h4>
                    <p>{self._escape(f['remediation'])}</p>
                </div>
            </div>
            """
            
        severity_html = ""
        for sev, count in stats.get("severity_counts", {}).items():
            severity_html += f"<li><strong>{self._escape(sev)}:</strong> {count}</li>"
            
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report - {self._escape(scan['target'])}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; color: #333; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                .header {{ border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
                .card {{ border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; color: white; }}
                .informational {{ background-color: #3498db; }}
                .low {{ background-color: #f1c40f; }}
                .medium {{ background-color: #e67e22; }}
                .high {{ background-color: #e74c3c; }}
                .critical {{ background-color: #c0392b; }}
                .details-table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
                .details-table th, .details-table td {{ text-align: left; padding: 8px; border-bottom: 1px solid #eee; }}
                .details-table th {{ width: 150px; color: #666; }}
                pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; border: 1px solid #eee; }}
                .section {{ margin-top: 15px; }}
                .summary-stats {{ display: flex; gap: 20px; }}
                .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; flex: 1; text-align: center; border: 1px solid #eee; }}
                .stat-box .num {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Web Application Security Assessment</h1>
                <p><strong>Target:</strong> {self._escape(scan['target'])}</p>
                <p><strong>Scan ID:</strong> {self._escape(scan['scan_id'])}</p>
                <p><strong>Date:</strong> {self._escape(format_datetime_ist(scan.get('completed_at', scan['started_at'])))}</p>
                <p><strong>Status:</strong> {self._escape(scan['status'])}</p>
            </div>
            
            <div class="card">
                <h2>Executive Summary</h2>
                <div class="summary-stats">
                    <div class="stat-box">
                        <div class="num">{stats.get('total_findings', 0)}</div>
                        <div>Total Findings</div>
                    </div>
                    <div class="stat-box">
                        <div class="num">{scan.get('pages_discovered', 0)}</div>
                        <div>Pages Scanned</div>
                    </div>
                </div>
                <h3>Severity Summary</h3>
                <ul>
                    {severity_html}
                </ul>
            </div>
            
            <h2>Detailed Findings</h2>
            {findings_html if findings else "<p>No findings reported.</p>"}
            
        </body>
        </html>
        """
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        return report_path
