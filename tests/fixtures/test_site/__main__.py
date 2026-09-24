import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

from tests.fixtures.test_site.app import run_server

if __name__ == '__main__':
    print("Starting test fixture on http://127.0.0.1:5000")
    run_server(port=5000)
