# agent/nodes/tool_executor.py
import subprocess
from langgraph.errors import NodeInterrupt
from ..state import CyberState, Task

def run_tool(state: CyberState) -> CyberState:
    task = state["current_task"]
    try:
        result = subprocess.run(
            task.command.split(),
            capture_output=True,
            text=True,
            timeout=300
        )
        state["results"][task.id] = result.stdout
        task.status = "completed"
        state["logs"].append(f"✅ {task.command} completed")
    except subprocess.CalledProcessError as e:
        task.status = "failed"
        state["logs"].append(f"❌ {task.command} failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        task.status = "retry"
        state["logs"].append(f"⏳ {task.command} timed out")
        state["tasks"].insert(0, task)  # Retry first
    return state