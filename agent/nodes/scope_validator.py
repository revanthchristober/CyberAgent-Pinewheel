from ipaddress import ip_network, ip_address
from langgraph.errors import NodeInterrupt
from ..state import CyberState, Task

def validate_scope(state: CyberState) -> CyberState:
    target = state["current_task"].target
    if not any(
        (domain.startswith(".") and target.endswith(domain)) or (target == domain)
        for domain in state["scope"].get("domains", [])
    ) and not any(
        ip_address(target) in ip_network(ip_range)
        for ip_range in state["scope"].get("ips", [])
    ):
        state["violations"].append(f"Scope violation: {target}")
        raise NodeInterrupt(f"Blocked out-of-scope target: {target}")
    return state