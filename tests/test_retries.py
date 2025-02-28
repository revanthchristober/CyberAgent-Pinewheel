import pytest
from agent.state import CyberState, Task
from agent.nodes.tool_executor import run_tool
from unittest.mock import patch, MagicMock
from langgraph.errors import NodeInterrupt
from datetime import datetime

@pytest.fixture
def mock_state():
    return CyberState(
        tasks=[Task(id="1", command="nmap google.com", target="google.com", retries=3)],
        current_task=Task(id="1", command="nmap google.com", target="google.com", retries=3),
        logs=[],
        scope={"domains": ["google.com"]},
        results={}
    )

@patch("subprocess.run")
def test_retry_on_failure(mock_run, mock_state):
    # Simulate tool failure
    mock_run.side_effect = subprocess.TimeoutExpired("nmap", 300)
    
    # First execution (should decrement retries)
    state = run_tool(mock_state)
    assert state["current_task"].retries == 2
    assert state["current_task"].status == "retry"
    
    # Second execution (retry with updated parameters)
    state["current_task"].parameters = {"ports": "1-100"}  # Simulate parameter adjustment
    state = run_tool(state)
    assert state["current_task"].retries == 1
    assert state["current_task"].status == "retry"

@patch("subprocess.run")
def test_max_retries_exceeded(mock_run, mock_state):
    mock_run.side_effect = subprocess.TimeoutExpired("nmap", 300)
    
    # Exhaust retries
    state = run_tool(mock_state)  # 3 → 2
    state = run_tool(state)      # 2 → 1
    state = run_tool(state)      # 1 → 0
    
    assert state["current_task"].status == "failed"
    assert len(state["logs"]) == 3  # 3 retry attempts logged

@patch("subprocess.run")
def test_retry_success_after_adjustment(mock_run, mock_state):
    # First failure
    mock_run.side_effect = [subprocess.TimeoutExpired("nmap", 300), MagicMock(stdout="Success")]
    mock_run.return_value.stdout = "Success"
    
    # First attempt (failure)
    state = run_tool(mock_state)
    assert state["current_task"].retries == 2
    
    # Retry with adjusted parameters
    state["current_task"].parameters = {"ports": "80,443"}
    state = run_tool(state)
    
    assert state["current_task"].status == "completed"
    assert "Success" in state["results"]["1"]

def test_scope_violation_retry_skipped(mock_state):
    # Simulate out-of-scope target
    mock_state["current_task"].target = "evil.com"
    
    with pytest.raises(NodeInterrupt):
        run_tool(mock_state)
    
    # Ensure no retries for scope violations
    assert mock_state["current_task"].status == "skipped"
    assert mock_state["violations"] == ["Scope violation: evil.com"]