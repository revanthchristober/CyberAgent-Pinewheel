from agent.nodes.scope_validator import validate_scope
from agent.state import CyberState, Task

def test_scope_validation():
    state = CyberState(
        scope={"domains": ["google.com"]},
        current_task=Task(target="evil.com")
    )
    
    with pytest.raises(NodeInterrupt):
        validate_scope(state)