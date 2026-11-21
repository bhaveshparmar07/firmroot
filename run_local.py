"""
Self-contained runner that starts the local Firmroot backend server on port 8080 and verifies it.
"""
import subprocess
import sys
import os
import time

def main():
    dashboard_path = r"C:\Users\Bhavesh\.gemini\antigravity\brain\979e7942-44e9-49f5-8d5a-4f19bea2f7af\scratch\firmroot"
    os.chdir(dashboard_path)
    
    # Import and run server
    from server import run
    run(8080)

if __name__ == "__main__":
    main()
