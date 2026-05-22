from abc import ABC, abstractmethod


class ResultRepository(ABC):

    # ── ASR run storage ───────────────────────────────────────────────────────

    @abstractmethod
    def save_run(self, run_id: str, data: dict) -> None:
        """Persist a completed experiment run. Also updates the latest pointer."""

    @abstractmethod
    def get_run(self, run_id: str) -> dict | None:
        """Return the run dict for run_id, or None if not found."""

    @abstractmethod
    def list_runs(self) -> list[str]:
        """Return all known run IDs in ascending order."""

    # ── Egress log ────────────────────────────────────────────────────────────

    @abstractmethod
    def append_egress_hit(self, record: dict) -> None:
        """Append one egress capture record."""

    @abstractmethod
    def count_egress_hits(self) -> int:
        """Return the total number of egress hits recorded so far."""

    @abstractmethod
    def get_egress_hits_since(self, baseline: int) -> list[dict]:
        """Return all hits appended after the baseline index (0-based)."""
