import argparse
from app.core.logger import setup_logger
from app.http.client import HTTPClient
from requests.exceptions import RequestException

logger = setup_logger("cli")

def run_analyze(target: str):
    logger.info("Direct analyze command is deprecated. Routing to scan command.")
    run_scan(target)

def run_scan(target: str):
    from app.core.scan_manager import ScanManager
    from app.database.session import get_engine, get_session_factory
    from app.database.repository import Repository
    
    logger.info("Scan started")
    try:
        manager = ScanManager()
        scan_id = manager.run_scan(target)
        
        # Display results directly from the repository
        engine = get_engine()
        session_factory = get_session_factory(engine)
        with session_factory() as db_session:
            repo = Repository(db_session)
            
            stats = repo.get_scan_statistics(scan_id)
            findings = repo.get_scan_findings(scan_id)
            
            print(f"\n=== Results for Scan {scan_id} ===")
            print(f"Target: {stats['scan']['target']}")
            print(f"Status: {stats['scan']['status']}")
            print(f"Started: {stats['scan']['started_at']}")
            print(f"Pages Discovered: {stats['scan']['pages_discovered']}")
            print(f"Total Findings: {stats['total_findings']}")
            print("\nFindings Summary:")
            
            counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "CRITICAL": 0}
            for k, v in stats['severity_counts'].items():
                if k in counts:
                    counts[k] = v
                    
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
                if sev == "INFORMATIONAL":
                    print(f"INFO: {counts[sev]}")
                else:
                    print(f"{sev}: {counts[sev]}")
            
            print("\nFindings Detail:")
            for f in findings:
                sev_display = "INFO" if f['severity'] == "INFORMATIONAL" else f['severity']
                print(f"[{sev_display}] {f['title']} (Category: {f['category']})")
                print(f"URL: {f['url']}")
                print(f"Sources: {f['scanner_source']}\n")
            print("================================================\n")
            
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\nUnexpected error occurred: {e}\n")
    finally:
        logger.info("Scan execution finished")

def run_history(limit: int):
    from app.database.session import get_session_factory, get_engine
    from app.database.repository import Repository
    
    try:
        engine = get_engine()
        session_factory = get_session_factory(engine)
        
        with session_factory() as db_session:
            repo = Repository(db_session)
            repo.init_db(engine)
            
            scans = repo.list_scans(limit=limit)
            
            print(f"\n=== Scan History (Last {limit}) ===")
            for scan in scans:
                print(f"ID: {scan['scan_id']} | Target: {scan['target']} | Status: {scan['status']} | Findings: {scan['findings_count']} | Date: {scan['started_at']}")
            print("===================================\n")
            
    except Exception as e:
        print(f"\nError retrieving history: {e}\n")

def run_results(scan_id: str):
    from app.database.session import get_session_factory, get_engine
    from app.database.repository import Repository
    
    try:
        engine = get_engine()
        session_factory = get_session_factory(engine)
        
        with session_factory() as db_session:
            repo = Repository(db_session)
            repo.init_db(engine)
            
            scan = repo.get_scan(scan_id)
            if not scan:
                print(f"\nError: Scan ID {scan_id} not found.\n")
                return
                
            stats = repo.get_scan_statistics(scan_id)
            findings = repo.get_scan_findings(scan_id)
            
            print(f"\n=== Results for Scan {scan_id} ===")
            print(f"Target: {scan['target']}")
            print(f"Status: {scan['status']}")
            print(f"Started: {scan['started_at']}")
            print(f"Total Findings: {stats['total_findings']}")
            print("\nFindings Detail:")
            
            for f in findings:
                sev_display = "INFO" if f['severity'] == "INFORMATIONAL" else f['severity']
                print(f"[{sev_display}] {f['title']} (Category: {f['category']})")
                print(f"URL: {f['url']}")
            print("================================================\n")
            
    except Exception as e:
        print(f"\nError retrieving results: {e}\n")

def run_report(scan_id: str, format: str):
    from app.database.session import get_session_factory, get_engine
    from app.database.repository import Repository
    from app.reporting.json_reporter import JSONReporter
    from app.reporting.html_reporter import HTMLReporter
    
    try:
        engine = get_engine()
        session_factory = get_session_factory(engine)
        
        with session_factory() as db_session:
            repo = Repository(db_session)
            repo.init_db(engine)
            
            scan = repo.get_scan(scan_id)
            if not scan:
                print(f"\nError: Scan ID {scan_id} not found.\n")
                return
                
            stats = repo.get_scan_statistics(scan_id)
            findings = repo.get_scan_findings(scan_id)
            
            if format.lower() == "json":
                reporter = JSONReporter()
                path = reporter.generate(stats, findings)
            elif format.lower() == "html":
                reporter = HTMLReporter()
                path = reporter.generate(stats, findings)
            else:
                print(f"Unknown format {format}")
                return
                
            print(f"Report generated at: {path}")
            
    except Exception as e:
        print(f"\nError generating report: {e}\n")

def run_web(port: int):
    from app.web import create_app
    app = create_app()
    app.run(host="0.0.0.0", port=port, debug=True)

def main():
    parser = argparse.ArgumentParser(description="Web Application Security Assessment Platform")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    scan_parser = subparsers.add_parser("scan", help="Verify connectivity to target")
    scan_parser.add_argument("--target", required=True, help="Target URL (e.g., http://localhost:3000)")
    
    analyze_parser = subparsers.add_parser("analyze", help="Perform passive security analysis on target")
    analyze_parser.add_argument("--target", required=True, help="Target URL to analyze")
    
    history_parser = subparsers.add_parser("history", help="View recent scan history")
    history_parser.add_argument("--limit", type=int, default=10, help="Number of recent scans to view")
    
    results_parser = subparsers.add_parser("results", help="View findings for a specific scan")
    results_parser.add_argument("--id", required=True, help="Scan ID to retrieve")
    
    report_parser = subparsers.add_parser("report", help="Generate a report for a specific scan")
    report_parser.add_argument("--scan-id", required=True, help="Scan ID to generate report for")
    report_parser.add_argument("--format", required=True, choices=["json", "html"], help="Report format")
    
    web_parser = subparsers.add_parser("web", help="Start the web dashboard")
    web_parser.add_argument("--port", type=int, default=5000, help="Port to run the dashboard on")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        run_scan(args.target)
    elif args.command == "analyze":
        run_analyze(args.target)
    elif args.command == "history":
        run_history(args.limit)
    elif args.command == "results":
        run_results(args.id)
    elif args.command == "report":
        run_report(args.scan_id, args.format)
    elif args.command == "web":
        run_web(args.port)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
