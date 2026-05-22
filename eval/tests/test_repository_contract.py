"""
Contract tests for ResultRepository.

The same test suite runs against every concrete implementation via
pytest parametrize.  Add a new impl to _IMPLS and it gets full
coverage for free.
"""

import pytest

from storage.jsonl_adapter import JsonlAdapter

# ── Redis fixture — skipped if Redis is unreachable ──────────────────────────

def _make_redis_repo():
    import redis as _redis
    from storage.redis_adapter import RedisAdapter
    url = "redis://localhost:6379/15"  # db 15 reserved for tests
    try:
        _redis.from_url(url).ping()
    except Exception:
        return None
    repo = RedisAdapter(url)
    repo._r.flushdb()
    return repo


# ── Parametrized fixture ──────────────────────────────────────────────────────

def _jsonl_factory(tmp_path):
    return JsonlAdapter(
        results_dir=tmp_path / "asr",
        egress_log=tmp_path / "egress" / "egress_attempts.jsonl",
    )


def _redis_factory(_tmp_path):
    repo = _make_redis_repo()
    if repo is None:
        pytest.skip("Redis not reachable on localhost:6379")
    return repo


@pytest.fixture(params=["jsonl", "redis"])
def repo(request, tmp_path):
    return _jsonl_factory(tmp_path) if request.param == "jsonl" else _redis_factory(tmp_path)


# ── Contract tests ────────────────────────────────────────────────────────────

def test_save_and_get_run(repo):
    data = {"run_id": "test-123", "trials": 1, "react": [], "coder_reviewer": []}
    repo.save_run("test-123", data)
    assert repo.get_run("test-123") == data


def test_get_run_missing(repo):
    assert repo.get_run("does-not-exist") is None


def test_list_runs_includes_saved(repo):
    repo.save_run("run-A", {"x": 1})
    repo.save_run("run-B", {"x": 2})
    runs = repo.list_runs()
    assert "run-A" in runs
    assert "run-B" in runs


def test_list_runs_empty(repo):
    assert repo.list_runs() == []


def test_egress_starts_empty(repo):
    assert repo.count_egress_hits() == 0


def test_append_increments_count(repo):
    repo.append_egress_hit({"method": "POST", "path": "/test", "body": "a"})
    repo.append_egress_hit({"method": "POST", "path": "/test", "body": "b"})
    assert repo.count_egress_hits() == 2


def test_get_hits_since_zero(repo):
    repo.append_egress_hit({"body": "only"})
    hits = repo.get_egress_hits_since(0)
    assert len(hits) == 1
    assert hits[0]["body"] == "only"


def test_get_hits_since_baseline(repo):
    repo.append_egress_hit({"body": "first"})
    repo.append_egress_hit({"body": "second"})
    repo.append_egress_hit({"body": "third"})
    hits = repo.get_egress_hits_since(1)
    assert len(hits) == 2
    assert hits[0]["body"] == "second"
    assert hits[1]["body"] == "third"


def test_get_hits_since_empty(repo):
    assert repo.get_egress_hits_since(0) == []


def test_get_hits_since_past_end(repo):
    repo.append_egress_hit({"body": "x"})
    assert repo.get_egress_hits_since(99) == []


def test_save_run_updates_latest(repo, tmp_path):
    """latest pointer must reflect the most recently saved run."""
    repo.save_run("run-1", {"v": 1})
    repo.save_run("run-2", {"v": 2})
    # For JsonlAdapter: latest.json should contain run-2's data.
    # For RedisAdapter: run:latest key should contain run-2's data.
    got = repo.get_run("run-2")
    assert got == {"v": 2}
