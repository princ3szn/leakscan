import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .engine import Scanner
from .gitscan import GitError, scan_history
from .remote import RemoteError, shallow_clone
from .walker import scan_path

MAX_FINDINGS = 500
RATE_LIMIT = 5  # scans per window, per IP
RATE_WINDOW = 60.0  # seconds
MAX_CONCURRENT = 2  # simultaneous scans on the server

app = FastAPI(title="leakscan API", version="0.1.0")

_origins = [
    o.strip()
    for o in os.environ.get(
        "LEAKSCAN_ALLOWED_ORIGINS", "http://localhost:3000"
    ).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

_scanner = Scanner()
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)
_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


class ScanRequest(BaseModel):
    url: str = Field(max_length=200)
    history: bool = False


def check_rate_limit(ip: str) -> None:
    now = time.monotonic()
    with _hits_lock:
        window = _hits[ip]
        while window and now - window[0] > RATE_WINDOW:
            window.popleft()
        if len(window) >= RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Too many scans. Please wait a minute and try again.",
            )
        window.append(now)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest, request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)

    if not _slots.acquire(blocking=False):
        raise HTTPException(
            status_code=503, detail="Server is busy. Please try again shortly."
        )

    started = time.monotonic()
    try:
        with shallow_clone(req.url, full_history=req.history) as repo:
            if req.history:
                findings = scan_history(repo, _scanner)
            else:
                findings = scan_path(repo, _scanner)
    except (RemoteError, GitError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        _slots.release()

    shown = findings[:MAX_FINDINGS]
    return {
        "url": req.url,
        "history": req.history,
        "total": len(findings),
        "truncated": len(findings) > MAX_FINDINGS,
        "duration_seconds": round(time.monotonic() - started, 2),
        "findings": [{**asdict(f), "severity": f.severity.value} for f in shown],
    }