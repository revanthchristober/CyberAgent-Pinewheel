# agent/state.py
from typing import Annotated, List, Dict, Any
from langgraph.graph.message import add_messages
from pydantic import BaseModel
from datetime import datetime
from typing_extensions import TypedDict

class Task(BaseModel):
    id: str
    command: str
    target: str
    status: str = "pending"
    retries: int = 3
    parameters: Dict[str, Any] = {}

class CyberState(TypedDict):
    messages: Annotated[list, add_messages]  # For chat messages
    input: str
    tasks: list # Annotated[List[Task], add_messages]
    current_task: Task
    logs: List[Dict[str, Any]]
    scope: Dict[str, List[str]]
    results: Dict[str, Any]
    violations: List[str]