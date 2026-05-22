import json
import time
from pathlib import Path

import redis

from .repository import ResultRepository

_RUN_KEY   = "run:{}"
_RUN_INDEX = "runs"        # sorted set — score = timestamp, member = run_id
_EGRESS    = "egress:hits" # list of JSON-encoded hit records
_STREAM    = "egress:stream"


class RedisAdapter(ResultRepository):

    def __init__(self, url: str = "redis://localhost:6379/0", sidecar_dir: Path | None = None):
        self._r = redis.from_url(url, decode_responses=True)
        self._sidecar_dir = sidecar_dir
        if sidecar_dir:
            sidecar_dir.mkdir(parents=True, exist_ok=True)

    # ── ASR run storage ───────────────────────────────────────────────────────

    def save_run(self, run_id: str, data: dict) -> None:
        encoded = json.dumps(data)
        self._r.set(_RUN_KEY.format(run_id), encoded)
        self._r.zadd(_RUN_INDEX, {run_id: time.time()})
        self._r.set("run:latest", run_id)
        if self._sidecar_dir:
            payload = json.dumps(data, indent=2)
            (self._sidecar_dir / f"asr_{run_id}.json").write_text(payload)
            (self._sidecar_dir / "latest.json").write_text(payload)

    def get_run(self, run_id: str) -> dict | None:
        raw = self._r.get(_RUN_KEY.format(run_id))
        return json.loads(raw) if raw else None

    def list_runs(self) -> list[str]:
        return self._r.zrange(_RUN_INDEX, 0, -1)

    # ── Egress log ────────────────────────────────────────────────────────────

    def append_egress_hit(self, record: dict) -> None:
        encoded = json.dumps(record)
        self._r.rpush(_EGRESS, encoded)
        self._r.publish(_STREAM, encoded)

    def count_egress_hits(self) -> int:
        return self._r.llen(_EGRESS)

    def get_egress_hits_since(self, baseline: int) -> list[dict]:
        raws = self._r.lrange(_EGRESS, baseline, -1)
        return [json.loads(r) for r in raws]
