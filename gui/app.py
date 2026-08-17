# pyright: reportMissingImports=false

import json
import os
import sys
from datetime import datetime

from flask import Flask, Response, render_template, request, stream_with_context
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Allow Python to find modules in the cyber_agent parent folder
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

# Existing cyber agent modules
import EXECUTOR
import PROMPT_MANAGEMENT
import MODEL_MANAGEMENT
import UTILITIES
import _keys
import GUARDRAILS

# Always read/write the same history file the CLI uses, regardless of the
# working directory Flask happens to be started from.
THREATS_LOG_PATH = os.path.join(PROJECT_ROOT, "_threats.jsonl")

# Set up OpenAI
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)
model = MODEL_MANAGEMENT.DEFAULT_MODEL

law_client = LogsQueryClient(
    credential=DefaultAzureCredential()
)


# Start Flask app
app = Flask(__name__)


def sse_pack(event, payload):
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n"


def run_investigation(question):
    """
    Runs the same pipeline as the CLI, yielding an SSE 'progress' event
    before each stage so the browser can show real-time status, and a
    final 'result' event containing the rendered results HTML.
    """

    user_message = PROMPT_MANAGEMENT.get_user_message(question)

    yield sse_pack("progress", {"step": "context", "label": "Deciding log search parameters..."})
    query_context = EXECUTOR.get_query_context(openai_client, user_message, model)
    query_context = UTILITIES.sanitize_query_context(query_context)

    yield sse_pack("progress", {"step": "guardrails", "label": "Validating tables and fields..."})
    try:
        GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])
    except ValueError as e:
        html = render_template(
            "results.html",
            question=question,
            query_context=query_context,
            kql_query=None,
            number_of_records=None,
            hunt_results=None,
            error_title="Guardrail Blocked This Query",
            error_message="The AI selected a table or field that isn't in the allowed list, so nothing was queried. Try rephrasing your question.",
            error_detail=str(e),
        )
        yield sse_pack("result", {"html": html})
        return

    yield sse_pack("progress", {"step": "query", "label": "Querying Log Analytics..."})
    law_query_results = EXECUTOR.query_log_analytics(
        log_analytics_client=law_client,
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        timerange_hours=query_context["time_range_hours"],
        table_name=query_context["table_name"],
        device_name=query_context["device_name"],
        fields=query_context["fields"],
        caller=query_context["caller"],
        user_principal_name=query_context["user_principal_name"],
    )
    number_of_records = law_query_results["count"]
    kql_query = law_query_results["query"]

    if number_of_records == 0:
        html = render_template(
            "results.html",
            question=question,
            query_context=query_context,
            kql_query=kql_query,
            number_of_records=0,
            hunt_results=None,
            error_title=None,
            error_message=None,
            error_detail=None,
        )
        yield sse_pack("result", {"html": html})
        return

    yield sse_pack("progress", {"step": "prompt", "label": "Building threat hunt prompt..."})
    threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
        user_prompt=user_message["content"],
        table_name=query_context["table_name"],
        log_data=law_query_results["records"],
    )

    yield sse_pack("progress", {"step": "hunt", "label": "Running AI threat hunt..."})
    hunt_results = EXECUTOR.hunt(
        openai_client=openai_client,
        threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
        threat_hunt_user_message=threat_hunt_user_message,
        openai_model=model,
    )

    if not hunt_results:
        html = render_template(
            "results.html",
            question=question,
            query_context=query_context,
            kql_query=kql_query,
            number_of_records=number_of_records,
            hunt_results=None,
            error_title="Threat Analysis Failed",
            error_message="The AI analysis call failed (rate limit or API error). Check the server terminal for details.",
            error_detail=None,
        )
        yield sse_pack("result", {"html": html})
        return

    UTILITIES.append_threats_to_jsonl(
        hunt_results.get("findings", []),
        question=question,
        table_name=query_context["table_name"],
        filename=THREATS_LOG_PATH,
    )

    html = render_template(
        "results.html",
        question=question,
        query_context=query_context,
        kql_query=kql_query,
        number_of_records=number_of_records,
        hunt_results=hunt_results,
        error_title=None,
        error_message=None,
        error_detail=None,
    )
    yield sse_pack("result", {"html": html})


@app.route("/")
def home():
    return render_template("index.html", active_page="home")


@app.route("/investigate")
def investigate():
    question = request.args.get("question", "").strip()

    if not question:
        return Response(
            sse_pack("result", {"html": "<div class=\"panel error-panel\"><h2>No Question Provided</h2></div>"}),
            mimetype="text/event-stream",
        )

    def generate():
        try:
            for chunk in run_investigation(question):
                yield chunk
        except Exception as e:
            html = render_template(
                "results.html",
                question=question,
                query_context=None,
                kql_query=None,
                number_of_records=None,
                hunt_results=None,
                error_title="Something Went Wrong",
                error_message="An unexpected error interrupted the investigation.",
                error_detail=str(e),
            )
            yield sse_pack("result", {"html": html})

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/history")
def history():
    query = request.args.get("q", "").strip().lower()
    entries = []

    if os.path.exists(THREATS_LOG_PATH):
        with open(THREATS_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # File is append-only, so reversing gives newest-first without
    # relying on a timestamp field (older entries don't have one).
    entries.reverse()

    for entry in entries:
        raw_timestamp = entry.get("timestamp")
        if raw_timestamp:
            try:
                entry["timestamp"] = datetime.fromisoformat(raw_timestamp).strftime("%Y-%m-%d %H:%M UTC")
            except ValueError:
                pass

    if query:
        def matches(entry):
            haystack = " ".join([
                str(entry.get("title", "")),
                str(entry.get("description", "")),
                str(entry.get("question", "")),
                str(entry.get("table_name", "")),
                " ".join(entry.get("tags", []) or []),
                " ".join(entry.get("indicators_of_compromise", []) or []),
            ]).lower()
            return query in haystack

        entries = [e for e in entries if matches(e)]

    return render_template(
        "history.html",
        entries=entries,
        query=request.args.get("q", ""),
        active_page="history",
    )


@app.route("/about")
def about():
    return render_template("about.html", active_page="about")


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
