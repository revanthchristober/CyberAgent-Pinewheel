from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from typing import List
from ..tools.utils import is_ip  # ✅ Added import
from langchain_core.messages import AIMessage
from ..state import CyberState, Task
import os

class Plan(BaseModel):
    steps: List[str] = Field(description="List of executable security commands (e.g., nmap, gobuster)")

prompt = ChatPromptTemplate.from_messages([
    ("system", "Break down security tasks into executable commands using **pre-installed tools** (nmap, gobuster, ffuf, sqlmap). Do NOT include installation steps. Output JSON with 'steps' array."),
    ("user", "{input}")
])

llm = ChatGroq(
    model_name="llama-3.3-70b-versatile",
    groq_api_key='<YOUR_GROQ_API_KEY>',
    temperature=0.3
).with_structured_output(Plan)

planner_chain = prompt | llm

def plan_task(state: CyberState) -> CyberState:
    plan = planner_chain.invoke({"input": state["input"]})
    # Add planning steps as a message
    state["messages"].append(
        AIMessage(content=f"Planning: {plan.steps}")
    )
    # Update tasks as a regular list
    state["tasks"] = [
        Task(id=str(i), command=step, target=extract_target(step))
        for i, step in enumerate(plan.steps)
    ]
    state["current_task"] = state["tasks"][0] if state["tasks"] else None
    return state

def extract_target(command: str) -> str:
    """Extract target from security commands (e.g., 'nmap -p- google.com' → 'google.com')"""
    parts = command.split()
    # Skip tool name and flags
    for part in parts[1:]:
        if part.startswith("-"):  # Skip flags
            continue
        if part.endswith((".com", ".net", ".org")) or is_ip(part):
            return part
    return ""