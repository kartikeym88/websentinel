import subprocess
import sys

def test_cli_help():
    result = subprocess.run([sys.executable, "scanner.py", "--help"], capture_output=True, text=True, cwd="d:/AI JOURNEY/Project-1_ai/web-security-platform")
    assert "usage:" in result.stdout
    assert "scan" in result.stdout

def test_cli_scan_forbidden_domain():
    result = subprocess.run([sys.executable, "scanner.py", "scan", "--target", "http://example.com"], capture_output=True, text=True, cwd="d:/AI JOURNEY/Project-1_ai/web-security-platform")
    assert "Domain not in allowed list" in result.stderr
