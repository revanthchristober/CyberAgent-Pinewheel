import os
import subprocess
import json
from typing import Annotated, Dict, List, TypedDict, Optional

from typing_extensions import TypedDict

from langgraph.graph import StateGraph, END, START
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, ToolMessage
from langchain_core.tools import tool, ToolException
from langchain_groq import ChatGroq  # or your preferred LLM
import getpass
import logging
import time
from urllib.parse import urlparse
import ipaddress

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# --- Environment Setup ---
def _set_env(var: str):
    if not os.environ.get(var):
        os.environ[var] = input(f"{var}: ")  # getpass.getpass causes issues in some environments

_set_env("GROQ_API_KEY")  # Or your LLM API key
_set_env("LANGCHAIN_API_KEY")  # LangSmith API Key (optional, for tracing)
_set_env("LANGCHAIN_TRACING_V2")  # LangSmith tracing (optional)
_set_env("LANGCHAIN_PROJECT")  # LangSmith project name (optional)


# --- State Definition ---
class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    tasks: List[str]
    scan_results: Dict[str, str]  # Task: Result
    scope: List[str]  # Domains/IPs in scope
    current_task_index: int
    logs: List[str]
    session_report: str


# --- Scope Enforcement ---
def is_within_scope(target, scope_list):
    """Checks if the target is within the defined scope."""
    if not scope_list:  # Check if scope_list is empty FIRST
        logger.debug(f"Scope list is empty. Target '{target}' is OUT OF SCOPE.") # Debug log for empty scope
        return False

    try:
        target_uri = urlparse(target)
        hostname = target_uri.hostname if target_uri.hostname else target
        hostname = hostname.strip().lower()

        logger.debug(f"Checking scope for target: '{target}', hostname: '{hostname}', scope_list: {scope_list}")

        for scope_item in scope_list:
            scope_item_processed = scope_item.strip().lower()
            logger.debug(f"  Checking scope item: '{scope_item}', processed_scope_item: '{scope_item_processed}'")
            try:
                # Check if scope is a domain or wildcard domain
                if scope_item_processed.startswith("*."):
                    wildcard_domain = scope_item_processed[2:]
                    if hostname.endswith("." + wildcard_domain.lower()) or hostname == wildcard_domain.lower(): # Corrected wildcard matching
                        logger.debug(f"    Wildcard match: '{hostname}' is within wildcard '{scope_item}'")
                        return True
                elif scope_item_processed == hostname:
                    logger.debug(f"    Exact domain match: '{hostname}' == '{scope_item_processed}'")
                    return True
                # Check if scope is an IP address or range
                try:
                    ip_address = ipaddress.ip_address(hostname)
                    scope_network = ipaddress.ip_network(scope_item_processed, strict=False)
                    if ip_address in scope_network:
                        logger.debug(f"    IP address match: '{ip_address}' in network '{scope_item}'")
                        return True
                except ValueError:
                    pass  # Ignore if scope_item is not a valid IP range
            except Exception as e:
                logger.warning(f"Error processing scope item '{scope_item}': {e}")

        logger.debug(f"No scope match found for target: '{target}', hostname: '{hostname}'")
        return False  # Return False if no match is found after checking all scope items
    except Exception as e:
        logger.error(f"Error checking scope for target '{target}': {e}")
        return False


# --- Tools ---
@tool
def run_nmap(target: str, ports: str = "default", tool_kwargs: dict = None) -> str:
    """Run nmap scan on the target with specified ports within scope."""
    if tool_kwargs is None:
        tool_kwargs = {}
    
    # Correct way to access the state
    configurable = tool_kwargs.get("configurable", {})
    scope = configurable.get("scope", [])  # Directly access scope from configurable

    if not is_within_scope(target, scope):
        raise ToolException(f"Target '{target}' is outside of the defined scope: {scope}. Scan blocked.")
    
    try:
        if ports == "default":
            result = subprocess.run(["nmap", "-T4", "-F", target], capture_output=True, text=True, timeout=120)  # Fast scan, increased timeout
        else:
            result = subprocess.run(["nmap", "-T4", "-p", ports, target], capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return f"Nmap scan successful for {target}:\n{result.stdout}"
        else:
            return f"Nmap scan failed for {target}. Error:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        raise ToolException(f"Nmap scan timed out for {target}.") # Raise ToolException for retry logic
    except FileNotFoundError:
        raise ToolException("Error: nmap command not found. Ensure nmap is installed and in your PATH.")
    except Exception as e:
        raise ToolException(f"Error running nmap: {e}")

@tool
def run_gobuster(url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt", tool_kwargs: dict = None) -> str:
    """Run gobuster scan on the URL with the specified wordlist within scope."""
    if tool_kwargs is None:
        tool_kwargs = {}
    run_config = tool_kwargs.get("config", {}) # Get RunnableConfig from tool_kwargs
    configurable_config = run_config.get("configurable", {}) # Get "configurable" from RunnableConfig
    state = configurable_config.get("state", {}) # Access state from "configurable"

    scope = state.get("scope", [])
    if not is_within_scope(url, scope):
        raise ToolException(f"URL '{url}' is outside of the defined scope: {scope}. Scan blocked.")
    try:
        result = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist], capture_output=True, text=True, timeout=180
        )
        if result.returncode == 0:
            return f"Gobuster scan successful for {url}:\n{result.stdout}"
        else:
            return f"Gobuster scan failed for {url}. Error:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        raise ToolException(f"Gobuster scan timed out for {url}.")
    except FileNotFoundError:
        raise ToolException("Error: gobuster command not found. Ensure gobuster is installed and in your PATH.")
    except Exception as e:
        raise ToolException(f"Error running gobuster: {e}")


@tool
def run_ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt", threads: str = "1", tool_kwargs: dict = None) -> str:
    """Run ffuf scan on the URL with the specified wordlist and threads within scope."""
    if tool_kwargs is None:
        tool_kwargs = {}
    run_config = tool_kwargs.get("config", {}) # Get RunnableConfig from tool_kwargs
    configurable_config = run_config.get("configurable", {}) # Get "configurable" from RunnableConfig
    state = configurable_config.get("state", {}) # Access state from "configurable"

    scope = state.get("scope", [])
    if not is_within_scope(url, scope):
        raise ToolException(f"URL '{url}' is outside of the defined scope: {scope}. Scan blocked.")
    
    try:
        result = subprocess.run(
            ["ffuf", "-u", url + "/FUZZ", "-w", wordlist, "-t", threads, "-fc", "404,400,301,302,204,403,407,405,415,401,410,501,503,502,504,406,412,413,414,508,510,511,509,429,499,420,422,423,424,426,421,450,451,494,495,496,497,498,499,520,521,522,523,524,525,526,527,529,530,598,599"], capture_output=True, text=True, timeout=240
        )

        if result.returncode == 0:
            return f"Ffuf scan successful for {url}:\n{result.stdout}"
        else:
            return f"Ffuf scan failed for {url}. Error:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        raise ToolException(f"Ffuf scan timed out for {url}.")
    except FileNotFoundError:
        raise ToolException("Error: ffuf command not found. Ensure ffuf is installed and in your PATH.")
    except Exception as e:
        raise ToolException(f"Error running ffuf: {e}")



available_tools = [run_nmap, run_gobuster, run_ffuf]

# --- Nodes ---
def task_breakdown(state: AgentState):
    """Breaks down high-level instructions into a task list using LLM."""
    logger.info("Entering task_breakdown node")
    prompt_text = f"""You are an expert cybersecurity task manager. Given a user's high-level security objective, create a detailed, sequential task list to achieve it.
    Each task should be a specific, actionable step executable by a cybersecurity tool (nmap, gobuster, ffuf).

    Example:
    User Objective: "Perform a basic security scan of example.com"
    Task List:
    1. Run nmap scan on example.com to discover open ports and services.
    2. Run gobuster to discover directories and files on example.com.
    3. Analyze nmap and gobuster results for potential vulnerabilities.
    4. Generate a summary report of findings.

    User Objective: "{state['messages'][-1].content}"
    Task List:"""

    llm = ChatGroq(model="llama-3.3-70b-versatile")  # Or your preferred LLM
    response = llm.invoke(prompt_text)
    tasks_text = response.content.strip()

    tasks = [line.split('. ', 1)[1].strip() for line in tasks_text.split('\n') if line.strip() and '. ' in line and '. ' in line]

    logger.info(f"Task breakdown generated: {tasks}")
    return {"messages": [response], "tasks": tasks, "current_task_index": 0, "scan_results": {}, "session_report": "", "scope": state["scope"]}


def execute_task(state: AgentState):
    """Executes the current task using appropriate tools or LLM."""
    logger.info("Entering execute_task node")
    task_index = state["current_task_index"]
    tasks = state["tasks"]
    if task_index >= len(tasks):
        logger.info("All tasks completed.")
        return {"messages": [AIMessage(content="All tasks completed.")], "current_task_index": task_index}

    current_task = tasks[task_index]
    messages = state["messages"]
    logs = state["logs"]

    llm = ChatGroq(model="llama-3.3-70b-versatile").bind_tools(available_tools)

    task_execution_prompt = f"""You are a cybersecurity agent. Your current task is: "{current_task}".
    You have access to the following tools: {', '.join([tool.name for tool in available_tools])}.

    Analyze the task and determine the best tool to use. If a tool is applicable, use it to execute the task.
    If the task is analytical or does not require a tool, respond with a plan or analysis in plain text.

    Respond with tool calls in JSON format when using tools.

    Previous conversation history: {messages}
    Current task: {current_task}

    Respond in a way that is helpful for cybersecurity task execution and analysis."""

    response = llm.invoke(task_execution_prompt)

    time.sleep(20) # Increased delay for rate limiting

    tool_messages = []

    if response.tool_calls:
        logger.info("Tool calls detected in LLM response.")
        for tool_call in response.tool_calls:
            tool_name = tool_call['name']
            tool_arguments = tool_call['args']

            logger.info(f"Executing tool: {tool_name} with args: {tool_arguments}")
            tool_output = "Tool execution failed."
            logs.append(f"Tool Call: {tool_name}, Args: {tool_arguments}")

            try:
                if tool_name == "run_nmap":
                    tool_output = run_nmap.invoke({"target": tool_arguments.get("target"), "ports": tool_arguments.get("ports", "default")}, config={"configurable": {"state": state}})
                elif tool_name == "run_gobuster":
                    tool_output = run_gobuster.invoke({"url": tool_arguments.get("url"), "wordlist": tool_arguments.get("wordlist")}, config={"configurable": {"state": state}})
                elif tool_name == "run_ffuf":
                    tool_output = run_ffuf.invoke({"url": tool_arguments.get("url"), "wordlist": tool_arguments.get("wordlist"), "threads": tool_arguments.get("threads", "1")}, config={"configurable": {"state": state}})
                else:
                    tool_output = f"Error: Tool '{tool_name}' not implemented in agent."
                    logs.append(tool_output)

                logs.append(f"Tool Output: {tool_name} - {tool_output[:500]}...")
                tool_messages.append(ToolMessage(content=str(tool_output), tool_call_id=tool_call['id']))


            except ToolException as e:
                tool_output = f"Tool execution failed: {e}"
                logs.append(f"Tool Error: {tool_name} - {tool_output}")
                tool_messages.append(ToolMessage(content=tool_output, tool_call_id=tool_call['id']))

            except Exception as e:  # Catch other exceptions during tool execution
                tool_output = f"Unexpected error executing tool: {e}"
                logs.append(f"Tool Error: {tool_name} - {tool_output}")
                tool_messages.append(ToolMessage(content=tool_output, tool_call_id=tool_call['id']))

    return {"messages": [response] + tool_messages, "current_task_index": task_index, "scan_results": state["scan_results"], "logs": logs}


def parse_results(state: AgentState):
    """Parses tool outputs and updates session report."""
    logger.info("Entering parse_results node")
    messages = state["messages"]
    scan_results = state["scan_results"]
    session_report_list = state["session_report"] if isinstance(state["session_report"], list) else [state["session_report"]]

    last_message = messages[-1]

    if isinstance(last_message, ToolMessage):
        tool_name = last_message.tool_call_id
        result_content = last_message.content

        scan_results[tool_name] = result_content

        report_snippet = f"\n--- Tool: {tool_name} ---\nOutput:\n{result_content[:1000]}...\n(Full output in scan_results)"

        session_report_list.append(report_snippet)

        logger.info(f"Parsed results from tool: {tool_name}")
        return {"scan_results": scan_results, "session_report": "".join(session_report_list)}


    return {"scan_results": scan_results, "session_report": "".join(session_report_list)}


def update_task_list(state: AgentState):
    """Updates task list (currently just increments index for sequential execution)."""
    logger.info("Entering update_task_list node")
    next_task_index = state["current_task_index"] + 1
    return {
        "current_task_index": next_task_index,
        "messages": state["messages"],
        "tasks": state["tasks"],
        "scan_results": state["scan_results"],
        "session_report": state["session_report"],
        "scope": state["scope"],
        "logs": state["logs"]
    }


def should_continue(state):
    """Determines if there are more tasks to execute."""
    has_more_tasks = state["current_task_index"] < len(state["tasks"])
    logger.info(f"should_continue: current_task_index={state['current_task_index']}, num_tasks={len(state['tasks'])}, continue={has_more_tasks}")
    return has_more_tasks


def generate_report(state: AgentState):
    """Generates final session report."""
    logger.info("Entering generate_report node")
    report = f"""# Cybersecurity Scan Report

    ## Session Summary

    User Objective: {state['messages'][0].content}

    ## Scan Scope:
    {", ".join(state['scope'])}

    ## Task Execution Log:
    {chr(10).join(state['logs'])}


    ## Scan Results:
    {state['session_report']}

    --- End of Report ---
    """
    print(report)
    logger.info("Final report generated.")
    return {"session_report": report}



# --- Graph Definition ---
def create_agent_graph():
    builder = StateGraph(AgentState)

    builder.add_node("task_breakdown", task_breakdown)
    builder.add_node("execute_task", execute_task)
    builder.add_node("parse_results", parse_results)
    builder.add_node("update_task_list", update_task_list)
    builder.add_node("generate_report", generate_report)


    builder.set_entry_point("task_breakdown")
    builder.add_edge(START, "task_breakdown")

    builder.add_edge("task_breakdown", "execute_task")
    builder.add_edge("execute_task", "parse_results")
    builder.add_edge("parse_results", "update_task_list")

    builder.add_conditional_edges(
        "update_task_list",
        should_continue,
        {
            True: "execute_task",
            False: "generate_report"
        }
    )
    builder.add_edge("generate_report", END)


    graph = builder.compile(
        checkpointer=None,
        interrupt_before=None,
        interrupt_after=None,
        debug=False,
        # configurable={
        #     # Specify which state fields should be configurable
        #     "scope": lambda: ["example.com", "*.example.com"]  # Default value
        # }
    )
    return graph


# --- Run Agent ---
if __name__ == "__main__":
    agent = create_agent_graph()

    user_instruction = "Perform a comprehensive security scan of example.com to identify open ports, services, and potential web vulnerabilities."
    initial_scope = ["example.com", "*.example.com"]

    initial_state = {
        "messages": [HumanMessage(content=user_instruction)],
        "tasks": [],
        "scan_results": {},
        "scope": initial_scope,
        "current_task_index": 0,
        "logs": [],
        "session_report": "",
    }

    for event in agent.stream(initial_state, {"configurable": {'scope': initial_scope, "thread_id": "sec-agent-pipeline-1"}, "recursion_limit": 200}):
        if "messages" in event:
            message = event["messages"][-1]
            if isinstance(message, AIMessage):
                print(f"Agent: {message.content}")
            elif isinstance(message, ToolMessage):
                print(f"Tool Output ({message.tool_call_id}):\n{message.content}")

        if "generate_report" in event:
            report = event["generate_report"]
            if report:
                print("\n--- Final Session Report ---")
                print(report)
                print("--- End Report ---")

        if 'task_breakdown' in event:
            print("\n--- Task Breakdown Node Output ---")
            print(event['task_breakdown'])

    print("Cybersecurity pipeline execution completed.")