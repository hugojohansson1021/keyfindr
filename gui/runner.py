"""Subprocess runner with line-buffered stdout streaming.

A ProcessRunner wraps one execution of a script. Stdout (with stderr
merged in) is consumed by a background thread that pushes each line
into per-subscriber queues so multiple SSE clients can attach to the
same run. A ring buffer of recent lines lets a late subscriber still
see what was printed before they connected.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


@dataclass
class RunRecord:
    id: str
    tool_id: str
    argv: list[str]
    started_at: float
    status: str = "running"  # running | exited | killed | error
    exit_code: int | None = None
    error: str | None = None
    ended_at: float | None = None


class ProcessRunner:
    """One subprocess + fan-out of its output to subscribers."""

    BUFFER_LIMIT = 2000

    def __init__(
        self,
        tool_id: str,
        argv: list[str],
        cwd: Path,
    ) -> None:
        self.record = RunRecord(
            id=uuid.uuid4().hex,
            tool_id=tool_id,
            argv=argv,
            started_at=time.time(),
        )
        self._cwd = cwd
        self._buffer: deque[str] = deque(maxlen=self.BUFFER_LIMIT)
        self._subscribers: list[queue.Queue[str | None]] = []
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None

    def start(self) -> None:
        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        try:
            self._proc = subprocess.Popen(
                [sys.executable, "-u", *self.record.argv],
                cwd=str(self._cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                env=env,
            )
        except OSError as error:
            self.record.status = "error"
            self.record.error = str(error)
            self.record.ended_at = time.time()
            self._broadcast(f"[runner] failed to start: {error}\n")
            self._close_subscribers()
            return

        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self._proc is not None
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                self._broadcast(line)
        except Exception as error:
            self._broadcast(f"[runner] read error: {error}\n")
        finally:
            code = self._proc.wait()
            with self._lock:
                if self.record.status == "running":
                    self.record.status = "exited"
                self.record.exit_code = code
                self.record.ended_at = time.time()
            self._broadcast(f"[runner] process exited with code {code}\n")
            self._close_subscribers()

    def _broadcast(self, line: str) -> None:
        with self._lock:
            self._buffer.append(line)
            subscribers = list(self._subscribers)
        for q in subscribers:
            q.put(line)

    def _close_subscribers(self) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
            self._subscribers.clear()
        for q in subscribers:
            q.put(None)

    def subscribe(self) -> tuple[list[str], queue.Queue[str | None]]:
        q: queue.Queue[str | None] = queue.Queue()
        with self._lock:
            backlog = list(self._buffer)
            finished = self.record.status != "running"
            if not finished:
                self._subscribers.append(q)
        if finished:
            q.put(None)
        return backlog, q

    def unsubscribe(self, q: queue.Queue[str | None]) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def stop(self, kill_after: float = 4.0) -> bool:
        if self._proc is None or self._proc.poll() is not None:
            return False
        try:
            self._proc.terminate()
        except ProcessLookupError:
            return False
        try:
            self._proc.wait(timeout=kill_after)
        except subprocess.TimeoutExpired:
            try:
                self._proc.kill()
            except ProcessLookupError:
                pass
        with self._lock:
            self.record.status = "killed"
        return True

    def status(self) -> dict:
        with self._lock:
            return {
                "id": self.record.id,
                "tool_id": self.record.tool_id,
                "argv": self.record.argv,
                "started_at": self.record.started_at,
                "ended_at": self.record.ended_at,
                "status": self.record.status,
                "exit_code": self.record.exit_code,
                "error": self.record.error,
            }


class RunRegistry:
    """Thread-safe map of run_id -> ProcessRunner."""

    MAX_RUNS = 50

    def __init__(self) -> None:
        self._runs: dict[str, ProcessRunner] = {}
        self._order: deque[str] = deque()
        self._lock = threading.Lock()

    def add(self, runner: ProcessRunner) -> None:
        with self._lock:
            self._runs[runner.record.id] = runner
            self._order.append(runner.record.id)
            while len(self._order) > self.MAX_RUNS:
                old_id = self._order.popleft()
                self._runs.pop(old_id, None)

    def get(self, run_id: str) -> ProcessRunner | None:
        with self._lock:
            return self._runs.get(run_id)

    def list(self) -> list[dict]:
        with self._lock:
            runners = [self._runs[r] for r in self._order if r in self._runs]
        return [r.status() for r in reversed(runners)]
