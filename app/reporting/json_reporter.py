import json
import os
from datetime import datetime
from typing import Dict, Any

class JSONReporter:
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def generate(self, scan_stats: Dict[str, Any], findings: list) -> str:
        scan_id = scan_stats["scan"]["scan_id"]
        report_path = os.path.join(self.report_dir, f"report_{scan_id}.json")
        
        # Ensure datetimes are serialized
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
            
        report_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "scan_id": scan_id,
                "target": scan_stats["scan"]["target"],
                "status": scan_stats["scan"]["status"],
                "started_at": scan_stats["scan"]["started_at"].isoformat() if isinstance(scan_stats["scan"]["started_at"], datetime) else scan_stats["scan"]["started_at"],
                "completed_at": scan_stats["scan"]["completed_at"].isoformat() if isinstance(scan_stats["scan"]["completed_at"], datetime) else scan_stats["scan"]["completed_at"]
            },
            "statistics": {
                "pages_discovered": scan_stats["scan"]["pages_discovered"],
                "requests_made": scan_stats["scan"]["requests_made"],
                "total_findings": scan_stats["total_findings"],
                "severity_counts": scan_stats["severity_counts"]
            },
            "findings": findings
        }
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, default=default_serializer)
            
        return report_path
