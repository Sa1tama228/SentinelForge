from __future__ import annotations

import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable

from . import events


@dataclass
class Job:
    id: str
    kind: str
    label: str
    status: str = "queued"
    progress: float = 0.0
    error: str = ""
    created_ts: float = field(default_factory=time.time)
    started_ts: float = 0.0
    finished_ts: float = 0.0
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "progress": self.progress,
            "error": self.error,
            "created_ts": self.created_ts,
            "started_ts": self.started_ts,
            "finished_ts": self.finished_ts,
            "cancel_requested": self.cancel_event.is_set(),
        }


_lock = threading.Lock()
_jobs: dict[str, Job] = {}


def start(job_id: str, kind: str, label: str, target: Callable[[threading.Event], None]) -> Job:
    job = Job(id=job_id, kind=kind, label=label)
    with _lock:
        _jobs[job_id] = job
    events.emit("jobs", {"phase": "queued", "job": job.as_dict()})

    def _run() -> None:
        job.started_ts = time.time()
        job.status = "running"
        events.emit("jobs", {"phase": "started", "job": job.as_dict()})
        try:
            target(job.cancel_event)
            if job.status == "running":
                job.status = "cancelled" if job.cancel_event.is_set() else "done"
                job.progress = 1.0
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
            job.progress = 1.0
            job_trace = traceback.format_exc(limit=5)
            events.emit("jobs", {"phase": "exception", "job": job.as_dict(), "traceback": job_trace})
        finally:
            job.finished_ts = time.time()
            events.emit("jobs", {"phase": job.status, "job": job.as_dict()})

    threading.Thread(target=_run, daemon=True).start()
    return job


def update(job_id: str, *, status: str | None = None, progress: float | None = None,
           error: str | None = None, label: str | None = None) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        if status is not None:
            job.status = status
        if progress is not None:
            job.progress = max(0.0, min(float(progress), 1.0))
        if error is not None:
            job.error = error
        if label is not None:
            job.label = label
        payload = job.as_dict()
    events.emit("jobs", {"phase": "updated", "job": payload})


def cancel(job_id: str) -> bool:
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job.status not in {"queued", "running"}:
            return False
        job.cancel_event.set()
        job.status = "cancelling"
        payload = job.as_dict()
    events.emit("jobs", {"phase": "cancelling", "job": payload})
    return True


def get(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return job.as_dict() if job else None


def list_jobs(kind: str | None = None, *, include_finished: bool = True) -> list[dict]:
    with _lock:
        rows = [job for job in _jobs.values() if kind is None or job.kind == kind]
        if not include_finished:
            rows = [job for job in rows if job.status in {"queued", "running", "cancelling"}]
        return [job.as_dict() for job in sorted(rows, key=lambda item: item.created_ts, reverse=True)]


def prune_finished(max_age_seconds: float = 3600.0) -> int:
    cutoff = time.time() - max_age_seconds
    removed = 0
    with _lock:
        for job_id, job in list(_jobs.items()):
            if job.finished_ts and job.finished_ts < cutoff:
                _jobs.pop(job_id, None)
                removed += 1
    return removed
