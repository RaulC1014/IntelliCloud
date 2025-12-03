import time, json, uuid, collections, queue
from flask import Blueprint, Response, jsonify

bp = Blueprint("audit", __name__)

_log = collections.deque(maxlen=1000)
_subs = set()

# Updated signature to accept level and proto (defaulting to System/Info)
def log_event(actor: str, action: str, target: str, details: str, level: str = "Info", proto: str = "System"):
    """Call from anywhere to append and broadcast"""
    ev = {
        "aid": f"a-{uuid.uuid4().hex[:8]}",
        "actor": actor,
        "action": action,
        "target": target,
        "level": level,    # New Field
        "proto": proto,    # New Field
        "at": time.time(),
        "details": details,
    }

    _log.appendleft(ev)
    dead = []
    for q in list(_subs):
        try: q.put_nowait(ev)
        except Exception: dead.append(q)
    for q in dead: _subs.discard(q)
    return ev


@bp.route("/audit-log")
def list_recent():
    return jsonify(list(_log)[:200])

@bp.route("/stream/audit")
def stream():
    def event_stream():
        q = queue.Queue()
        _subs.add(q)
        try:
            # replay last 50
            for ev in list(_log)[:50][::-1]:
                yield f"data: {json.dumps(ev)}\n\n"
            last_beat = 0.0
            while True:
                try:
                    ev = q.get(timeout=1.0)
                    yield f"data: {json.dumps(ev)}\n\n"
                except queue.Empty:
                    pass
                now = time.time()
                if now - last_beat >= 3.0:
                    yield ": keep-alive\n\n"
                    last_beat = now
        finally:
            _subs.discard(q)
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)