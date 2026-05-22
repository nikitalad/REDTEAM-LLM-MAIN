import logging
import os
from pathlib import Path

from .repository import ResultRepository
from .jsonl_adapter import JsonlAdapter

_ROOT = Path(__file__).parent.parent.parent


def get_repository() -> ResultRepository:
    """
    Read RESULT_BACKEND and return the matching impl.
    Validates connectivity at startup so failures are loud and early.

    Failure modes:
      RESULT_BACKEND=redis + Redis unreachable  → raise (fail loud).
        Silent fallback masks misconfiguration — runs go to JSONL only,
        the UI shows nothing, and we lose days of data before noticing.
        Set RESULT_BACKEND=jsonl explicitly if you want JSONL on purpose.
      RESULT_BACKEND unset / jsonl              → JSONL (default, no Redis).
    """
    backend = os.environ.get("RESULT_BACKEND", "jsonl").lower()
    results_dir = Path(os.environ.get("RESULTS_DIR", str(_ROOT / "results" / "asr")))
    egress_log  = Path(os.environ.get("EGRESS_LOG_PATH", str(_ROOT / "results" / "egress-log" / "egress_attempts.jsonl")))

    if backend == "redis":
        from .redis_adapter import RedisAdapter
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        try:
            repo = RedisAdapter(url, sidecar_dir=results_dir)
            repo._r.ping()
            logging.info("[storage] Redis connected at %s (sidecar → %s)", url, results_dir)
            return repo
        except Exception as exc:
            raise RuntimeError(
                f"RESULT_BACKEND=redis was set but Redis at {url} is unreachable: {exc}. "
                f"Either start the redis container (and ensure its port is published via "
                f"REDIS_HOST_PORT in .env for host-side runs), run the experiment via "
                f"`docker compose --profile run up eval-runner` which uses the internal "
                f"results-net, or set RESULT_BACKEND=jsonl explicitly to use file storage."
            ) from exc

    if backend not in ("jsonl", ""):
        logging.warning("[storage] unknown RESULT_BACKEND=%r — using JSONL", backend)

    return JsonlAdapter(results_dir, egress_log)
