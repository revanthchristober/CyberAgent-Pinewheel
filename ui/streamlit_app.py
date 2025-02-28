import streamlit as st
import sys
import os

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from workflow import run_workflow
from agent.workflow import run_workflow
from typing import Dict
import uuid
from agent.workflow import CyberState, Task

# st.title("Cybersecurity Audit Assistant")
# st.sidebar.header("Scope Configuration")

# allowed_domains = st.sidebar.text_input("Allowed Domains (comma-separated)", "google.com")
# allowed_ips = st.sidebar.text_input("Allowed IPs (comma-separated)", "192.168.1.0/24")
# user_input = st.text_area("Security Task", "Scan google.com for open ports")

# if st.button("Start Audit"):
#     scope = {
#         "domains": allowed_domains.split(","),
#         "ips": allowed_ips.split(",")
#     }
#     state = CyberState(
#         messages=[],
#         input=user_input,
#         tasks=[],
#         logs=[],
#         scope=scope,
#         results={},
#         violations=[]
#     )
    
#     for event in run_workflow(user_input, scope):
#         st.write(f"**Node:** {event['name']}")
#         st.write(f"**Output:** {event['output']}")
        
#     # Display final report
#     if state["tasks"]:
#         st.subheader("Final Report")
#         st.write(f"""
#         - **Tasks Completed:** {[t.id for t in state['tasks'] if t.status == 'completed']}
#         - **Tasks Failed:** {[t.id for t in state['tasks'] if t.status == 'failed']}
#         - **Violations:** {state['violations']}
#         """)

st.title("Cybersecurity Audit Assistant")
st.sidebar.header("Scope Configuration")

allowed_domains = st.sidebar.text_input("Allowed Domains (comma-separated)", "google.com")
allowed_ips = st.sidebar.text_input("Allowed IPs (comma-separated)", "192.168.1.0/24")
user_input = st.text_area("Security Task", "Scan google.com for open ports")

if st.button("Start Audit"):
    scope = {
        "domains": allowed_domains.split(","),
        "ips": allowed_ips.split(",")
    }
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}  # Generate config
    state = CyberState(
        messages=[],
        input=user_input,
        tasks=[],
        logs=[],
        scope=scope,
        results={},
        violations=[]
    )
    
    for event in run_workflow(user_input, scope, config):
        st.write(event)
        # Update session state
        if "messages" in event:
            st.session_state.messages.extend(event["messages"])
        if "logs" in event:
            st.session_state.logs.extend(event["logs"])
        if "tasks" in event:
            st.session_state.tasks = event["tasks"]
        # st.write(f"**Node:** {event['name']}")
        # st.write(f"**Output:** {event['output']}")
        
    # Display final report
    if state["tasks"]:
        st.subheader("Final Report")
        st.write(f"""
        - **Tasks Completed:** {[t.id for t in state['tasks'] if t.status == 'completed']}
        - **Tasks Failed:** {[t.id for t in state['tasks'] if t.status == 'failed']}
        - **Violations:** {state['violations']}
        """)