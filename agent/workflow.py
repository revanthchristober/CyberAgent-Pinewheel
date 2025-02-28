# from langgraph.graph import StateGraph, START, END
# from langgraph.checkpoint.memory import MemorySaver
# from agent.state import CyberState
# from agent.nodes import scope_validator, tool_executor, reporter
# from agent.nodes import planner
# import logging
# from langgraph.graph import StateGraph
# import uuid
# from dotenv import load_dotenv
# import os
# load_dotenv()  # Load scope from .env

# logging.basicConfig(level=logging.INFO)

# builder = StateGraph(CyberState)

# # Nodes
# builder.add_node("planner", planner.plan_task)
# builder.add_node("validate_scope", scope_validator.validate_scope)
# builder.add_node("execute_tool", tool_executor.run_tool)
# builder.add_node("reporter", reporter.generate_report)

# # Edges
# builder.add_edge(START, "planner")
# builder.add_conditional_edges(
#     "planner",
#     lambda s: "validate_scope" if s["tasks"] else END
# )
# builder.add_conditional_edges(
#     "validate_scope",
#     lambda s: "execute_tool" if not s["violations"] else END
# )
# builder.add_edge("execute_tool", "reporter")

# graph = builder.compile(checkpointer=MemorySaver(), interrupt_before=["execute_tool"])

# # Main function to run the workflow
# def main(input_text: str):
#     # Generate unique thread ID
#     thread_id = str(uuid.uuid4())
#     config = {"configurable": {"thread_id": thread_id}}
    
#     # Initialize state with user input
#     initial_state = CyberState(
#         input=input_text,
#         tasks=[],
#         current_task=None,
#         logs=[],
#         scope={"domains": os.getenv("ALLOWED_DOMAINS", "").split(","),
#             "ips": os.getenv("ALLOWED_IPS", "").split(",")},  # Load from .env or user input
#         results={},
#         violations=[]
#     )
#     # graph.compile()

#     # Run the graph with config
#     for event in graph.stream(initial_state, config, stream_mode="values"):
#         print(event)
#         # Handle interruptions and user input here
#         if event.get("__interrupt__"):
#             print("Human approval required")
#             # Add logic to handle approval/resume

# if __name__ == "__main__":
#     import sys
#     if len(sys.argv) > 1:
#         input_text = sys.argv[1]
#         main(input_text)
#     else:
#         print("Please provide a task description.")

# from pydantic import BaseModel, Field


# agent/workflow.py
from typing import Annotated, List, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_community.tools import ShellTool
from langgraph.checkpoint.memory import MemorySaver
from langchain_groq import ChatGroq
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import AIMessage
# from langchain_core.prompts import Plan
import subprocess, json
import logging

logging.basicConfig(level=logging.DEBUG)
# Define State
class Task(BaseModel):
    id: str
    command: str
    target: str
    status: str = "pending"
    retries: int = 3

class CyberState(TypedDict):
    messages: Annotated[list, add_messages]
    input: str
    tasks: List[Task]
    current_task: Task
    logs: list
    scope: dict
    results: dict
    violations: list

# Initialize Tools
nmap_tool = ShellTool(name="nmap", description="Use nmap for network scanning")
gobuster_tool = ShellTool(name="gobuster", description="Use gobuster for directory brute-forcing")
ffuf_tool = ShellTool(name="ffuf", description="Use ffuf for web fuzzing")

tools = [nmap_tool, gobuster_tool, ffuf_tool]

# Initialize LLM
llm = ChatGroq(model_name="llama-3.3-70b-versatile", groq_api_key='<YOUR_GROQ_API_KEY>', temperature=0.3).bind_tools(tools)

prompt = ChatPromptTemplate.from_messages([
    ("system", "Break down security tasks into executable commands using **pre-installed tools** (nmap, gobuster, ffuf, sqlmap). Do NOT include installation steps. Output JSON with 'steps' array."),
    ("user", "{input}")
])

# Plan = prompt | llm

# Define Plan schema
class Plan(BaseModel):
    steps: list[str] = Field(description="List of executable security commands")

# Planner Node
# def plan_task(state: CyberState) -> CyberState:
#     try:
#         # Use with_structured_output to enforce JSON structure
#         llm_with_structured_output = llm.with_structured_output(Plan)
        
#         # Generate a plan using the LLM
#         plan_response = llm_with_structured_output.invoke([
#             ("system", """Break down security tasks into executable commands using **pre-installed tools** (nmap, gobuster, ffuf). 
#                          Output JSON with a 'steps' array containing commands."""),
#             ("user", state["input"])
#         ])
        
#         # Log the raw response for debugging
#         print("Raw LLM Response:", plan_response)
        
#         # Validate and create tasks from the plan
#         if not plan_response.steps:
#             raise ValueError("LLM returned an empty plan.")
        
#         state["tasks"] = [
#             Task(id=str(i), command=step, target=extract_target(step))
#             for i, step in enumerate(plan_response.steps)
#         ]
#         state["current_task"] = state["tasks"][0] if state["tasks"] else None
#         state["messages"].append(("assistant", f"Planning: {plan_response.steps}"))
#     except Exception as e:
#         # Fallback: Log the error and create a default task
#         state["logs"].append(f"Error during planning: {str(e)}")
#         state["tasks"] = [Task(id="0", command="nmap -p- google.com", target="google.com")]
#         state["current_task"] = state["tasks"][0]
    
#     return state
def plan_task(state: CyberState) -> CyberState:
    try:
        # Use structured output for Plan
        plan = llm.with_structured_output(Plan).invoke([
            ("system", """Break down security tasks into executable commands using **pre-installed tools** (nmap, gobuster, ffuf). 
                         Output JSON with 'steps' array containing commands."""),
            ("user", state["input"])
        ])
        
        state["tasks"] = [
            Task(id=str(i), command=step, target=extract_target(step))
            for i, step in enumerate(plan.steps)
        ]
        state["current_task"] = state["tasks"][0] if state["tasks"] else None
    except Exception as e:
        state["logs"].append(f"Planning failed: {str(e)}")
        state["tasks"] = [Task(id="0", command="nmap -p- google.com", target="google.com")]
        state["current_task"] = state["tasks"][0]
    return state


def update_tasks(state: CyberState, builder: StateGraph) -> CyberState:
    for task_id, result in state["results"].items():
        if "open ports" in result:
            # Create a new task
            new_task = {
                "id": str(len(state["tasks"])),
                "command": f"gobuster dir -u {state['tasks'][int(task_id)]['target']} -w /path/to/wordlist.txt",
                "target": state["tasks"][int(task_id)]["target"],
                "status": "pending"
            }
            
            # Add the new task to the state
            state["tasks"].append(new_task)
            
            # Add the new task as a node in the graph
            builder.add_node(new_task["id"], lambda s: {"messages": [f"Executing {new_task['command']}"]})
            
            # Define an edge from the current task to the new task
            builder.add_edge(task_id, new_task["id"])
            
            # Define an edge from the new task back to the next step
            builder.add_edge(new_task["id"], "chatbot")  # Assuming "chatbot" is the next step
    
    return state

def extract_target(command: str) -> str:
    # Extract target domain/IP from command
    parts = command.split()
    for part in parts:
        if part.endswith(".com") or part.replace(".", "").isdigit():
            return part
    return "unknown"

# Scope Validator Node
def validate_scope(state: CyberState) -> CyberState:
    task = state["current_task"]
    allowed_domains = state["scope"]["domains"]
    allowed_ips = state["scope"]["ips"]

    if task.target not in allowed_domains and not any(task.target.startswith(ip) for ip in allowed_ips):
        state["violations"].append(f"Scope violation: {task.target} is not in allowed domains/ips.")
        task.status = "failed"
    else:
        task.status = "ready"
    return state

# Tool Executor Node
# def run_tool(state: CyberState) -> CyberState:
#     task = state["current_task"]
#     try:
#         result = subprocess.run(
#             task.command.split(),
#             capture_output=True,
#             text=True,
#             timeout=300
#         )
#         state["results"][task.id] = result.stdout
#         task.status = "completed"
#         state["logs"].append(f"✅ {task.command} completed")
#     except subprocess.CalledProcessError as e:
#         task.status = "retry"
#         task.retries -= 1
#         state["logs"].append(f"❌ {task.command} failed: {e.stderr}")
#         if task.retries <= 0:
#             task.status = "failed"
#     except subprocess.TimeoutExpired:
#         task.status = "retry"
#         task.retries -= 1
#         state["logs"].append(f"⏳ {task.command} timed out")
#         if task.retries <= 0:
#             task.status = "failed"
#     return state
def run_tool(state: CyberState) -> CyberState:
    task = state["current_task"]
    try:
        result = subprocess.run(
            task.command.split(),
            capture_output=True,
            text=True,
            timeout=300,
            check=True
        )
        state["results"][task.id] = result.stdout
        task.status = "completed"
        state["logs"].append(f"✅ {task.command} completed")
        
        # Move to next task
        next_task = next((t for t in state["tasks"] if t.status == "pending"), None)
        state["current_task"] = next_task
        
    except subprocess.CalledProcessError as e:
        task.status = "retry"
        task.retries -= 1
        state["logs"].append(f"❌ {task.command} failed: {e.stderr}")
        if task.retries <= 0:
            task.status = "failed"
    except subprocess.TimeoutExpired:
        task.status = "retry"
        task.retries -= 1
        state["logs"].append(f"⏳ {task.command} timed out")
        if task.retries <= 0:
            task.status = "failed"
    return state

# Reporter Node
def generate_report(state: CyberState) -> CyberState:
    completed = [t.id for t in state["tasks"] if t.status == "completed"]
    failed = [t.id for t in state["tasks"] if t.status == "failed"]
    report = f"""
    Scan Report:
    - Tasks Completed: {completed}
    - Tasks Failed: {failed}
    - Scope Violations: {state['violations']}
    """
    state["messages"].append(("assistant", report))
    return state

# # Build Graph
# builder = StateGraph(CyberState)

# # Add Nodes
# builder.add_node("planner", plan_task)

# builder.add_node("validate_scope", validate_scope)
# builder.add_node("execute_tool", run_tool)
# builder.add_node("updater", lambda state: update_tasks(state, builder))  # Pass the builder to update tasks
# builder.add_node("reporter", generate_report)

# # Add Edges
# builder.add_edge(START, "planner")
# builder.add_edge("planner", "validate_scope")
# builder.add_conditional_edges(
#     "validate_scope",
#     lambda s: "execute_tool" if not s["violations"] else END
# )
# builder.add_edge("execute_tool", "reporter")
# builder.add_edge("updater", END)

# # Compile Graph
# graph = builder.compile()

# Build Graph
builder = StateGraph(CyberState)

# Nodes
builder.add_node("planner", plan_task)
builder.add_node("validate_scope", validate_scope)
builder.add_node("execute_tool", run_tool)
builder.add_node("reporter", generate_report)

# Edges
builder.add_edge(START, "planner")
builder.add_edge("planner", "validate_scope")
builder.add_conditional_edges(
    "validate_scope",
    lambda s: "execute_tool" if not s["violations"] else END
)
builder.add_conditional_edges(
    "execute_tool",
    lambda s: "execute_tool" if has_pending_tasks(s) else "reporter"
)

def has_pending_tasks(state: CyberState) -> bool:
    return any(task.status == "pending" for task in state["tasks"])

# Compile Graph
graph = builder.compile(checkpointer=MemorySaver())

# Run Workflow
def run_workflow(input_text: str, scope: dict, config: dict = None):
    state = {
        "messages": [],
        "input": input_text,
        "tasks": [],
        "current_task": None,
        "logs": [],
        "scope": scope,
        "results": {},
        "violations": []
    }
    # for event in graph.stream(state):
    #     print(event)
    
    # Yield events instead of printing
    yield from graph.stream(state, config)  # ✅ Return generator

# Example Usage
if __name__ == "__main__":
    scope = {
        "domains": ["google.com", ".example.com"],
        "ips": ["192.168.1.0/24"]
    }
    run_workflow("Scan google.com for open ports", scope)