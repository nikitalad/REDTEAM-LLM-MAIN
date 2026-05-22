import json
from pathlib import Path

from .repository import ResultRepository


class JsonlAdapter(ResultRepository):

    def __init__(self, results_dir: Path, egress_log: Path):
        self._results_dir = results_dir
        self._results_dir.mkdir(parents=True, exist_ok=True)
        self._egress_log = egress_log
        self._egress_log.parent.mkdir(parents=True, exist_ok=True)

    # ── ASR run storage ───────────────────────────────────────────────────────

    def save_run(self, run_id: str, data: dict) -> None:
        (self._results_dir / f"asr_{run_id}.json").write_text(json.dumps(data, indent=2))
        (self._results_dir / "latest.json").write_text(json.dumps(data, indent=2))

    def get_run(self, run_id: str) -> dict | None:
        path = self._results_dir / f"asr_{run_id}.json"
        return json.loads(path.read_text()) if path.exists() else None

    def list_runs(self) -> list[str]:
        return sorted(
            p.stem.removeprefix("asr_")
            for p in self._results_dir.glob("asr_*.json")
        )

    # ── Egress log ────────────────────────────────────────────────────────────

    def append_egress_hit(self, record: dict) -> None:
        with self._egress_log.open("a") as f:
            f.write(json.dumps(record) + "\n")

    def count_egress_hits(self) -> int:
        if not self._egress_log.exists():
            return 0
        with self._egress_log.open() as f:
            return sum(1 for _ in f)

    def get_egress_hits_since(self, baseline: int) -> list[dict]:
        if not self._egress_log.exists():
            return []
        hits = []
        with self._egress_log.open() as f:
            for i, line in enumerate(f):
                if i >= baseline:
                    try:
                        hits.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return hits
