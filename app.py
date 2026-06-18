"""KeyFindr local GUI server.

Binds to 127.0.0.1 only. Runs each script as a subprocess and streams
its stdout to the browser over Server-Sent Events.
"""

from __future__ import annotations

import json
import queue
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, abort, send_from_directory

from gui.runner import ProcessRunner, RunRegistry
from gui.tools import TOOLS, build_command, get_tool

PROJECT_ROOT = Path(__file__).resolve().parent

app = Flask(
    __name__,
    static_folder=str(PROJECT_ROOT / "static"),
    template_folder=str(PROJECT_ROOT / "templates"),
)
registry = RunRegistry()


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/tools")
def list_tools():
    return jsonify({"tools": list(TOOLS.values())})


@app.route("/api/runs", methods=["POST"])
def create_run():
    payload = request.get_json(silent=True) or {}
    tool_id = payload.get("tool_id")
    values = payload.get("values") or {}

    tool = get_tool(tool_id) if isinstance(tool_id, str) else None
    if tool is None:
        return jsonify({"error": "unknown tool"}), 400

    try:
        argv = build_command(tool_id, values)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    runner = ProcessRunner(tool_id=tool_id, argv=argv, cwd=PROJECT_ROOT)
    runner.start()
    registry.add(runner)
    return jsonify(runner.status()), 201


@app.route("/api/runs")
def list_runs():
    return jsonify({"runs": registry.list()})


@app.route("/api/runs/<run_id>")
def get_run(run_id: str):
    runner = registry.get(run_id)
    if runner is None:
        abort(404)
    return jsonify(runner.status())


@app.route("/api/runs/<run_id>/stop", methods=["POST"])
def stop_run(run_id: str):
    runner = registry.get(run_id)
    if runner is None:
        abort(404)
    stopped = runner.stop()
    return jsonify({"stopped": stopped, "status": runner.status()})


@app.route("/api/runs/<run_id>/stream")
def stream_run(run_id: str):
    runner = registry.get(run_id)
    if runner is None:
        abort(404)

    def event_stream():
        backlog, q = runner.subscribe()
        try:
            for line in backlog:
                yield _format_event("line", line)
            while True:
                try:
                    line = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                if line is None:
                    yield _format_event("end", json.dumps(runner.status()))
                    return
                yield _format_event("line", line)
        finally:
            runner.unsubscribe(q)

    response = Response(event_stream(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/api/reports")
def list_reports():
    reports_dir = PROJECT_ROOT / "reports"
    if not reports_dir.exists():
        return jsonify({"reports": []})
    files: list[dict] = []
    for path in reports_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(PROJECT_ROOT)
        except ValueError:
            continue
        stat = path.stat()
        files.append({
            "path": str(rel),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
        })
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return jsonify({"reports": files[:100]})


@app.route("/reports/<path:filename>")
def serve_report(filename: str):
    reports_dir = PROJECT_ROOT / "reports"
    target = (reports_dir / filename).resolve()
    if not str(target).startswith(str(reports_dir.resolve())):
        abort(404)
    if not target.is_file():
        abort(404)
    return send_from_directory(reports_dir, filename)


def _format_event(event: str, data: str) -> str:
    payload = "\n".join(f"data: {line}" for line in data.rstrip("\n").splitlines() or [""])
    return f"event: {event}\n{payload}\n\n"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
