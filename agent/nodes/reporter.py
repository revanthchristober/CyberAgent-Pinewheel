from datetime import datetime
from ..state import CyberState

# agent/nodes/reporter.py
def generate_report(state: CyberState) -> CyberState:
    report = f"""
    Scan Report for {state['input']}:
    - Open Ports: {state['results'].get('0', 'N/A')}
    - Scope Violations: {state['violations']}
    """
    state["report"] = report
    return state