# Agentic SOC Analyst

An AI-powered threat hunting assistant that turns plain-English security questions into KQL, queries Microsoft Defender telemetry through Azure Log Analytics, and analyzes the results for potential threats — mapped to MITRE ATT&CK, scored by confidence, and logged to a searchable history.

<img width="596" height="404" alt="Agentic-4" src="https://github.com/user-attachments/assets/3ec5d70f-c1f6-473a-871e-a47e567e220a" />

---

## Project Walkthrough

This project started as a command-line threat hunting agent (`_main.py`) and grew into a full Flask web application with a real-time investigation UI, a searchable findings history, and guardrails to keep the AI from querying data it shouldn't.

### 1. Home Page

![Home page — ask a security question in plain English](PASTE_SCREENSHOT_HERE)

The landing page. A user types a question like *"Has windows-target-1 had any suspicious logons in the last 3 days?"* and hits **Investigate**. The page opens a Server-Sent Events (SSE) stream and shows live progress as the agent works through query planning, guardrail validation, the Log Analytics query, and the AI threat hunt.

---

### 2. Running the Flask App

![Terminal running the Flask development server](PASTE_SCREENSHOT_HERE)

`python gui/app.py` starts the Flask dev server, which wraps the same pipeline the CLI (`_main.py`) uses — so the web app and the terminal tool share one core engine instead of duplicating logic.

---

### 3. About Page

![About page — what the agent does and how the workflow is structured](PASTE_SCREENSHOT_HERE)

Explains the request lifecycle: **Natural Language → AI Query Planning → Guardrails → Azure Log Analytics → Threat Analysis**. The AI decides which table, fields, and time range are relevant to the question; those choices are checked against an allow-list before any KQL is allowed to run.

---

### 4. Threat Hunt History

![Threat hunt history — every finding ever logged, searchable](PASTE_SCREENSHOT_HERE)

Every finding produced by a hunt is appended to `_threats.jsonl` and rendered here, newest first, with full-text search over titles, descriptions, hosts, tags, and IOCs. It's the audit trail — a record of every question asked and every threat the agent surfaced.

---

## Investigation Flow

```text
User Question (natural language)
  ↓
AI Query Planning (table, fields, time range, device/user)
  ↓
Guardrails (table & field allow-list validation)
  ↓
KQL Query Construction
  ↓
Azure Log Analytics (Microsoft Defender telemetry, via DefaultAzureCredential)
  ↓
AI Threat Hunt Analysis
  ↓
Findings (MITRE ATT&CK mapping, confidence level, IOCs, recommendations)
  ↓
Logged to Threat Hunt History (_threats.jsonl)
```

The agent never queries Log Analytics directly off the model's output. `GUARDRAILS.py` validates the chosen table and fields against an explicit allow-list first — if the model picks something outside it, the request is blocked before a single KQL query runs.

---

## Key Takeaways

Through this project, I gained hands-on experience with:

- Designing an agentic pipeline where an LLM plans a query, not just answers a question
- Guardrailing untrusted model output (table/field allow-lists) before it reaches a real data source
- Constructing and executing KQL queries against Azure Log Analytics with the `azure-monitor-query` SDK
- Authenticating to Azure via `DefaultAzureCredential`
- Streaming multi-stage progress to the browser in real time with Flask + Server-Sent Events
- Structuring AI output into a consistent schema (confidence, MITRE ATT&CK tactic/ID, IOCs, recommendations)
- Building a persistent, searchable findings log (JSONL) shared between a CLI tool and a web app
- Designing a SOC-analyst-style dashboard around AI-generated threat intelligence
- Extending someone else's core logic (the threat-hunting engine) with a new interface, rather than building both from scratch

---

## Credits

The core AI threat-hunting logic, log analysis, guardrails, and model orchestration are based on code provided by **Josh Madakor**, founder of Cyber Range.

The Flask web application, browser interface, backend integration, and SOC dashboard were built by **David Pena**.
