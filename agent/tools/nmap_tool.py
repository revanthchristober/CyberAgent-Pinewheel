import subprocess
from langchain_core.tools import tool
from ..state import Task

@tool
def run_nmap(target: str, ports: str = "1-1000") -> str:
    """Run nmap scan and return open ports"""
    try:
        result = subprocess.run(
            ["nmap", "-p", ports, target],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"ERROR: {e.stderr}"