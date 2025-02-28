# **LangGraph-Based Agentic Cybersecurity Workflow**

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Setup Guide](#setup-guide)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation)
   - [Configuration](#configuration)
5. [Running the Application](#running-the-application)
6. [Testing](#testing)
7. [Scope Enforcement](#scope-enforcement)
8. [Reporting and Logs](#reporting-and-logs)
9. [Bonus Features](#bonus-features)
10. [Contributing](#contributing)

---

## Overview
This project implements an **agentic cybersecurity pipeline** using **LangGraph** and **LangChain** to automate security audits. The system:
- Breaks down high-level security tasks into executable steps.
- Dynamically manages a task list, executing tools like `nmap`, `gobuster`, and `ffuf`.
- Enforces user-defined scope constraints to ensure scans stay within allowed domains and IP ranges.
- Handles task failures with retries and alternate strategies.
- Generates detailed logs and a final audit report.

The system is designed to simulate a real-world **security audit assistant**, providing a robust framework for penetration testing workflows.

---

## Architecture
The system is built using the following components:

### 1. **LangGraph Workflow**
- **State Management**: Uses `StateGraph` to manage the state of the workflow, including messages, tasks, logs, and results.
- **Nodes**:
  - **Planner**: Breaks down high-level tasks into a dynamic task list.
  - **Scope Validator**: Ensures all actions respect the defined scope.
  - **Tool Executor**: Executes security tools (`nmap`, `gobuster`, etc.) and processes their outputs.
  - **Reporter**: Generates logs and a final audit report.
- **Edges**: Define transitions between nodes based on task completion, failures, or scope violations.

### 2. **LangChain Integration**
- **LLM**: Uses **Qwen-2.5-Coder-32B** via the Groq API for task planning and decision-making.
- **Prompt Templates**: Predefined prompts for task breakdown and tool execution.
- **Tools**: Integrates external tools (`nmap`, `gobuster`, etc.) using LangChain's `Tool` interface.

### 3. **Human-in-the-Loop**
- Allows human oversight for critical decisions (e.g., approving tool calls, reviewing scan results).
- Implements `interrupt()` for pausing execution and collecting feedback.

### 4. **Dynamic Task Updates**
- Tasks are dynamically updated based on intermediate results (e.g., adding new scans for discovered subdomains).

---

## Features
- **Task Breakdown**: Converts high-level instructions into actionable steps.
- **Dynamic Task List**: Adds/removes tasks based on scan results.
- **Scope Enforcement**: Restricts actions to user-defined domains and IPs.
- **Failure Handling**: Retries failed tasks with alternate configurations.
- **Real-Time Monitoring**: Logs every action with timestamps and statuses.
- **Final Report**: Summarizes executed tasks, results, and scope violations.

---

## Setup Guide

#### **Using Poetry**
```markdown
### Using Poetry
1. Install Poetry if not already installed:
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```
2. Install dependencies:
   ```bash
   poetry install
   ```
3. Run the app:
   ```bash
   poetry run streamlit run ui/streamlit_app.py
   ```
```

### **Using Docker**

### Using Docker
1. Build the Docker image:
   ```bash
   docker build -t cybersecurity-agent-pinewheel .
   ```
2. Run the Docker container:
   ```bash
   docker run -p 8501:8501 cybersecurity-agent-pinewheel
   ```

### Prerequisites
1. **Python 3.11** installed.
2. **Poetry** for dependency management.
3. System-level tools: `nmap`, `gobuster`, `ffuf`, `sqlmap`.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/revanthchristober/CyberAgent-Pinewheel.git
   cd CyberAgent-Pinewheel
   ```

2. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install system-level tools:
   - On Ubuntu/Debian:
     ```bash
     sudo apt update && sudo apt install nmap gobuster ffuf sqlmap
     ```
   - On macOS:
     ```bash
     brew install nmap gobuster ffuf sqlmap
     ```

### Configuration
1. Create a `.env` file in the root directory:
   ```bash
   touch .env
   ```

2. Add the following variables to `.env`:
   ```env
   GROQ_API_KEY=your-groq-api-key
   ALLOWED_DOMAINS=google.com,.example.com
   ALLOWED_IPS=192.168.1.0/24
   ```

3. Define your target scope in the Streamlit app or `.env` file.

---

## Running the Application

### Start the Workflow
1. Run the Streamlit app:
   ```bash
   streamlit run ui/streamlit_app.py
   ```

2. In the app:
   - Define the scope (domains and IPs).
   - Input a high-level security task (e.g., `"Scan google.com for open ports and discover directories"`).
   - Click "Start Audit" to begin the workflow.

### Monitor Execution
- The app displays:
  - A dynamic task list with statuses (Pending, Running, Completed, Failed).
  - Real-time logs for each task.
  - Tool outputs and intermediate results.

### View Final Report
- At the end of the session, the app generates a final report summarizing:
  - Executed tasks and their results.
  - Discovered vulnerabilities.
  - Scope violations (if any).

---

## Testing
Run unit tests to verify functionality:
```bash
pytest tests/
```

### Test Coverage
- Task execution flow.
- Scope enforcement mechanisms.
- Failure detection and retry logic.

---

## Scope Enforcement
- The system enforces scope by:
  - Validating targets against user-defined domains and IPs.
  - Blocking out-of-scope actions and logging violations.
- Example:
  - Allowed domains: `google.com`, `.example.com`
  - Allowed IPs: `192.168.1.0/24`
  - Any attempt to scan `facebook.com` or `10.0.0.1` will be flagged.

---

## Reporting and Logs
- **Logs**:
  - Timestamped entries for each task.
  - Status (Success, Failed, Retried).
  - Output snippets for quick review.
- **Final Report**:
  - Executed steps and results.
  - Vulnerabilities discovered.
  - Summary of actions within and outside the scope.

---

## Bonus Features
### 1. **Streamlit App**
- Visualizes:
  - Ongoing scans and task execution.
  - Dynamic task list with statuses.
  - Tool outputs and logs.
  - Final audit report with vulnerabilities highlighted.

### 2. **Unit Tests**
- Comprehensive tests using Pytest:
  - Task execution flow.
  - Scope enforcement.
  - Failure handling.

---

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit changes:
   ```bash
   git commit -m "Add your feature"
   ```
4. Push to the branch:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a pull request.
