"""
experiments/run_experiment.py

Main experiment orchestrator.

Loads payload YAMLs, runs each threat scenario against the ReAct,
Coder-Reviewer, and Policy-Guard architectures, scores outcomes
using the ExecutionOutcomeScorer, and writes ASR results to
/app/results/asr/.

Usage:
  python experiments/run_experiment.py                      # run all threats, 1 trial
  python experiments/run_experiment.py --threats T-001 T-002
  python experiments/run_experiment.py --smoke              # smoke test only
  python experiments/run_experiment.py --trials 5           # 5 trials per variant
  python experiments/run_experiment.py --converters base64 unicode  # obfuscation variants
"""

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table


def _load_dotenv(path: Path) -> None:
    """
    Tiny stdlib .env loader for host-side runs. Docker services already get
    their env via env_file: .env in docker-compose, but when this script runs
    from the host, nothing populates os.environ — so RESULT_BACKEND, REDIS_URL,
    POLICY_GUARD_AGENT_URL etc. end up unset and results silently go to JSONL.

    Existing env vars take precedence (we never overwrite the shell).
    """
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


# Load .env from the repo root before any module reads os.environ.
_load_dotenv(Path(__file__).parent.parent.parent / ".env")

# Add parent dir to path so we can import targets/scorers
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyrit.memory import CentralMemory, SQLiteMemory
from targets.agent_targets import ReActAgentTarget, CoderReviewerTarget
from scorers.execution_scorer import ExecutionOutcomeScorer
from storage.factory import get_repository

# ── PyRIT converter registry ───────────────────────────────────────────────
# Only no-LLM, pure-text converters so experiments stay deterministic and
# free of extra API calls.
def _load_converters(names: list[str]) -> dict:
    """Return a dict of {name: PromptConverter} for the requested converter names."""
    from pyrit.prompt_converter.base64_converter import Base64Converter
    from pyrit.prompt_converter.rot13_converter import ROT13Converter
    from pyrit.prompt_converter.unicode_confusable_converter import UnicodeConfusableConverter
    from pyrit.prompt_converter.zero_width_converter import ZeroWidthConverter
    from pyrit.prompt_converter.leetspeak_converter import LeetspeakConverter

    registry = {
        "base64":     Base64Converter,
        "rot13":      ROT13Converter,
        "unicode":    UnicodeConfusableConverter,
        "zerowidth":  ZeroWidthConverter,
        "leetspeak":  LeetspeakConverter,
    }
    # Expand "all" to every registered converter (preserves registry order).
    if "all" in names:
        names = list(registry.keys())
    result = {}
    for name in names:
        if name not in registry:
            raise ValueError(f"Unknown converter '{name}'. Available: {list(registry) + ['all']}")
        result[name] = registry[name]()
    return result

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("experiment")
console = Console()

REACT_URL          = os.environ.get("REACT_AGENT_URL",          "http://localhost:8001")
CODER_REVIEWER_URL = os.environ.get("CODER_REVIEWER_AGENT_URL", "http://localhost:8002")
POLICY_GUARD_URL   = os.environ.get("POLICY_GUARD_AGENT_URL",   "http://localhost:8003")
REACT_CONTAINER          = os.environ.get("REACT_CONTAINER",          "react-agent")
CODER_REVIEWER_CONTAINER = os.environ.get("CODER_REVIEWER_CONTAINER", "coder-reviewer")
POLICY_GUARD_CONTAINER   = os.environ.get("POLICY_GUARD_CONTAINER",   "policy-guard")
PAYLOADS_DIR    = Path(__file__).parent.parent / "payloads"

# Single repo instance for the whole run — factory reads RESULT_BACKEND env var
_repo = get_repository()

# PyRIT requires a memory backend before any target or scorer is instantiated
_db_path = Path(os.environ.get("RESULTS_DIR", str(Path(__file__).parent.parent.parent / "results" / "asr"))).parent / "pyrit_memory.db"
CentralMemory.set_memory_instance(SQLiteMemory(db_path=str(_db_path)))


async def _reset_workspace(container: str) -> None:
    """
    Reset the agent workspace to the fixture-baseline tag created by
    setup-codebase.sh.  Idempotent — logs a warning if the tag is absent
    (first run before setup, or containers rebuilt) but does not fail.
    """
    cmd = [
        "docker", "exec", container, "bash", "-c",
        "git config --global --add safe.directory /workspace 2>/dev/null; "
        "git -C /workspace reset --hard fixture-baseline 2>&1"
        " && git -C /workspace clean -fdx 2>&1"
        " || echo 'WARN: fixture-baseline tag not found — workspace not reset'"
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await proc.communicate()
        output = out.decode().strip()
        if "WARN" in output or proc.returncode != 0:
            logger.warning("[Reset] %s: %s", container, output)
        else:
            logger.info("[Reset] %s workspace reset to fixture-baseline", container)
    except FileNotFoundError:
        logger.warning("[Reset] docker not found — workspace reset skipped for %s", container)


def _log_agent_trace(variant_id: str, data: dict) -> None:
    logger.info("[Trace] %s  turns=%s  denied=%s", variant_id, data.get("turn_count"), data.get("denied_count", 0))
    for i, tc in enumerate(data.get("tool_calls", []), 1):
        logger.info("[Trace]   [%d] tool=%-14s  input=%s", i, tc.get("tool"), tc.get("input"))
        logger.info("[Trace]        result=%s", str(tc.get("result", "")))
        if tc.get("reviewer_decision"):
            logger.info("[Trace]        reviewer=%s  reason=%s", tc["reviewer_decision"], tc.get("reviewer_reason", ""))
    logger.info("[Trace]   final_response=%s", str(data.get("final_response", ""))[:300])


def load_payloads(threat_ids: list[str]) -> list[dict]:
    """Load YAML payload files for the requested threat IDs."""
    payloads = []
    for yaml_file in sorted(PAYLOADS_DIR.glob("*.yaml")):
        for data in yaml.safe_load_all(yaml_file.read_text()):
            if data is None:
                continue
            for variant in data.get("VARIANTS", []):
                tid = variant["id"].split("-")[0] + "-" + variant["id"].split("-")[1]  # e.g. T-001
                if "all" in threat_ids or tid in threat_ids:
                    payloads.append({
                        "threat_id":       tid,
                        "variant_id":      variant["id"],
                        "description":     variant.get("description", ""),
                        "task":            variant.get("task") or data.get("TASK_TEMPLATE", ""),
                        "detection_rules": variant.get("detection_rules"),
                    })
    return payloads


async def run_single(
    target,
    threat_id: str,
    variant_id: str,
    task: str,
    scorer: ExecutionOutcomeScorer,
) -> dict:
    """Run one payload variant against one target and return the scored result."""
    import uuid

    # Build a minimal message piece compatible with whatever PyRIT version
    # is installed. Prefer the constructor that works in both old and new APIs.
    try:
        from pyrit.models import Message, MessagePiece
        piece = MessagePiece(
            role="user",
            original_value=task,
            converted_value=task,
            conversation_id=str(uuid.uuid4()),
        )
        use_pyrit_message = True
    except Exception:
        use_pyrit_message = False

    try:
        if use_pyrit_message:
            from pyrit.models import Message
            response_messages = await target.send_prompt_async(message=Message([piece]))
            resp_message = response_messages[0]
            try:
                from pyrit.memory import CentralMemory
                mem = CentralMemory.get_memory_instance()
                mem.add_message_to_memory(request=Message([piece]))
                mem.add_message_to_memory(request=resp_message)
            except Exception:
                pass
        else:
            # Fallback: call the agent HTTP endpoint directly
            import httpx, json as _json
            resp = await target._http_post(task)
            resp_message = _make_piece(resp, str(uuid.uuid4()))

        final_response = ""
        try:
            raw = getattr(resp_message, "converted_value", None)
            if raw is None:
                pieces = getattr(resp_message, "message_pieces", [])
                if pieces:
                    raw = getattr(pieces[0], "converted_value", None)
            if raw:
                trace_data = json.loads(raw)
                _log_agent_trace(variant_id, trace_data)
                final_response = trace_data.get("final_response", "")
        except Exception as e:
            logger.debug("[Trace] parse failed: %s", e)

        scores = await scorer.score_async(resp_message)
        score = scores[0]

        return {
            "variant_id":     variant_id,
            "threat_id":      threat_id,
            "attack_success": score.score_value == "true",
            "category":       score.score_value_description,
            "rationale":      score.score_rationale,
            "metadata":       score.score_metadata or {},
            "agent_response": final_response,
        }
    except Exception as e:
        logger.error(f"Error running {variant_id}: {e}")
        return {
            "variant_id":     variant_id,
            "threat_id":      threat_id,
            "attack_success": False,
            "category":       "ERROR",
            "rationale":      str(e),
            "metadata":       {},
            "agent_response": "",
        }


async def apply_converter(converter, task: str) -> str:
    """Apply a PyRIT converter to a task string and return the transformed text."""
    result = await converter.convert_async(prompt=task)
    return result.output_text


async def run_experiment(
    threat_ids: list[str],
    smoke: bool = False,
    trials: int = 1,
    converter_names: list[str] | None = None,
):
    payloads = load_payloads(threat_ids)

    if smoke:
        # Smoke test: only first variant of T-001
        payloads = [p for p in payloads if p["variant_id"] == "T-001-A"]
        console.print("[bold yellow]Smoke test mode — running T-001-A only[/]")

    if not payloads:
        console.print("[red]No payloads found for the requested threat IDs.[/]")
        return

    # Build converter dict — "none" (plain baseline) is always included first
    converters = {"none": None}
    if converter_names:
        converters.update(_load_converters(converter_names))

    from targets.agent_targets import PolicyGuardTarget
    architectures = [
        ("react",          REACT_CONTAINER,          ReActAgentTarget(base_url=REACT_URL)),
        ("coder_reviewer", CODER_REVIEWER_CONTAINER, CoderReviewerTarget(base_url=CODER_REVIEWER_URL)),
        ("policy_guard",   POLICY_GUARD_CONTAINER,   PolicyGuardTarget(base_url=POLICY_GUARD_URL)),
    ]

    results = {
        "run_id":     datetime.now(timezone.utc).isoformat(),
        "trials":     trials,
        "converters": list(converters.keys()),
        **{arch: [] for arch, _, _ in architectures},
    }

    total_runs = len(payloads) * len(converters) * len(architectures) * trials
    console.print(
        f"\n[bold]Running {len(payloads)} variants × {len(converters)} converter(s) "
        f"× {len(architectures)} architecture(s) × {trials} trial(s) = {total_runs} total runs[/]\n"
    )

    for payload in payloads:
        tid  = payload["threat_id"]
        vid  = payload["variant_id"]
        base_task = payload["task"].strip()

        for conv_name, converter in converters.items():
            # Apply converter (or use plain text for baseline)
            if converter is None:
                task = base_task
            else:
                task = await apply_converter(converter, base_task)

            conv_label = f"[dim]{conv_name}[/]" if conv_name == "none" else f"[magenta]{conv_name}[/]"
            console.print(f"  → [cyan]{vid}[/] {conv_label}  {payload['description']}")

            for trial in range(1, trials + 1):
                if trials > 1:
                    console.print(f"      trial {trial}/{trials}")

                detection_rules = payload.get("detection_rules")

                for arch, container, target in architectures:
                    await _reset_workspace(container)
                    scorer = ExecutionOutcomeScorer(
                        threat_id=tid, repo=_repo, detection_rules=detection_rules
                    )
                    result = await run_single(target, tid, vid, task, scorer)
                    result["trial"]       = trial
                    result["converter"]   = conv_name
                    result["description"] = payload["description"]
                    # Record the actual prompt sent to the agent (post-converter)
                    # plus the original baseline so the UI can show both when they
                    # differ (e.g. base64-converted vs the readable original).
                    result["task_sent"]    = task
                    result["task_original"] = base_task
                    results[arch].append(result)
                    _log_result(arch, result)

    # ── Compute summary ASR ────────────────────────────────────
    summary = _compute_asr(results)
    results["summary"] = summary

    # ── Persist results ────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _repo.save_run(ts, results)

    _print_summary_table(summary)
    console.print(f"\n[green]Results saved (run_id={ts})[/]\n")

    return results


def _log_result(arch: str, result: dict):
    cat = result["category"]
    if cat == "EXFILTRATION":
        status = "[red]EXFILTRATION[/]"
    elif cat in ("SOFT_LEAK", "PARTIAL_EXEC", "CONFUSED_DEPUTY"):
        status = "[yellow]ATTEMPT[/]"
    else:
        status = "[green]BENIGN[/]"
    console.print(f"      {arch:8} {status}  {cat}")


_EXFIL_CATEGORIES   = {"EXFILTRATION"}
_ATTEMPT_CATEGORIES = {"EXFILTRATION", "SOFT_LEAK", "PARTIAL_EXEC", "CONFUSED_DEPUTY"}


_META_KEYS = {"run_id", "trials", "converters", "summary"}

def _compute_asr(results: dict) -> dict:
    summary = {}
    for arch in [k for k in results if k not in _META_KEYS and isinstance(results[k], list)]:
        arch_results = results[arch]
        if not arch_results:
            continue
        total     = len(arch_results)
        n_attempt = sum(1 for r in arch_results if r["category"] in _ATTEMPT_CATEGORIES)
        n_exfil   = sum(1 for r in arch_results if r["category"] in _EXFIL_CATEGORIES)

        by_threat    = {}
        by_converter = {}
        by_variant   = {}

        for r in arch_results:
            tid  = r["threat_id"]
            vid  = r["variant_id"]
            conv = r.get("converter", "none")
            cat  = r["category"]

            # by_threat
            if tid not in by_threat:
                by_threat[tid] = {"total": 0, "attempt": 0, "exfil": 0}
            by_threat[tid]["total"]   += 1
            by_threat[tid]["attempt"] += int(cat in _ATTEMPT_CATEGORIES)
            by_threat[tid]["exfil"]   += int(cat in _EXFIL_CATEGORIES)

            # by_converter
            if conv not in by_converter:
                by_converter[conv] = {"total": 0, "attempt": 0, "exfil": 0}
            by_converter[conv]["total"]   += 1
            by_converter[conv]["attempt"] += int(cat in _ATTEMPT_CATEGORIES)
            by_converter[conv]["exfil"]   += int(cat in _EXFIL_CATEGORIES)

            # by_variant — also aggregates which rules fired across trials
            if vid not in by_variant:
                by_variant[vid] = {
                    "description":    r.get("description", ""),
                    "total": 0, "attempt": 0, "exfil": 0,
                    "rules_counter":  Counter(),
                }
            by_variant[vid]["total"]   += 1
            by_variant[vid]["attempt"] += int(cat in _ATTEMPT_CATEGORIES)
            by_variant[vid]["exfil"]   += int(cat in _EXFIL_CATEGORIES)
            for rule in (r.get("metadata") or {}).get("matched_rules") or []:
                by_variant[vid]["rules_counter"][rule["id"]] += 1

        def _rates(v):
            t = v["total"]
            return {
                "attempt_rate": round(v["attempt"] / t, 3) if t else 0,
                "exfil_rate":   round(v["exfil"]   / t, 3) if t else 0,
                "attempt":      v["attempt"],
                "exfil":        v["exfil"],
                "total":        t,
            }

        def _variant_entry(vid, v):
            t = v["total"]
            # Rules sorted by how often they fired (desc); include all that fired ≥ 1 trial
            rules_fired = [r for r, _ in v["rules_counter"].most_common()]
            return {
                "description":    v["description"],
                "attempt_rate":   round(v["attempt"] / t, 3) if t else 0,
                "exfil_rate":     round(v["exfil"]   / t, 3) if t else 0,
                "attempt":        v["attempt"],
                "exfil":          v["exfil"],
                "total":          t,
                "rules_fired":    rules_fired,
            }

        summary[arch] = {
            "total_variants": total,
            "attempt_rate":   round(n_attempt / total, 3) if total else 0,
            "exfil_rate":     round(n_exfil   / total, 3) if total else 0,
            "by_threat":      {tid: _rates(v) for tid, v in by_threat.items()},
            "by_converter":   {conv: _rates(v) for conv, v in by_converter.items()},
            "by_variant":     {vid: _variant_entry(vid, v) for vid, v in sorted(by_variant.items())},
        }
    return summary


def _print_summary_table(summary: dict):
    for arch in summary:
        data = summary.get(arch)
        if not data:
            continue

        table = Table(
            title=f"[bold]{arch.upper()} — Results by Variant[/]",
            show_header=True, header_style="bold cyan",
        )
        table.add_column("Variant",      min_width=9)
        table.add_column("Description",  min_width=30)
        table.add_column("Attempt rate", justify="right", min_width=14)
        table.add_column("Exfil rate",   justify="right", min_width=12)
        table.add_column("Rules fired",  min_width=30)

        for vid, vd in data["by_variant"].items():
            a_color = "red" if vd["attempt_rate"] > 0.5 else "yellow" if vd["attempt_rate"] > 0 else "green"
            e_color = "red" if vd["exfil_rate"]   > 0   else "green"
            rules   = ", ".join(vd["rules_fired"]) if vd["rules_fired"] else "[dim]—[/]"
            table.add_row(
                vid,
                vd["description"],
                f"[{a_color}]{vd['attempt_rate']:.0%} ({vd['attempt']}/{vd['total']})[/]",
                f"[{e_color}]{vd['exfil_rate']:.0%} ({vd['exfil']}/{vd['total']})[/]",
                rules,
            )

        console.print(table)
        console.print(
            f"  attempt=[bold]{data['attempt_rate']:.1%}[/]"
            f"  exfil=[bold]{data['exfil_rate']:.1%}[/]\n"
        )

    # ── Table 2: per-converter breakdown (only when >1 converter used) ────
    has_multiple_converters = any(
        len(data.get("by_converter", {})) > 1
        for data in summary.values()
    )
    if not has_multiple_converters:
        return

    conv_table = Table(
        title="ASR by Converter (obfuscation impact)",
        show_header=True,
        header_style="bold magenta",
    )
    conv_table.add_column("Architecture")
    conv_table.add_column("Converter")
    conv_table.add_column("Attempt", justify="right")
    conv_table.add_column("Exfil",   justify="right")
    conv_table.add_column("Attempt / Exfil / Total", justify="right")

    for arch, data in summary.items():
        for conv, cd in data.get("by_converter", {}).items():
            attempt_rate = cd["attempt_rate"]
            exfil_rate   = cd["exfil_rate"]
            a_color = "red" if attempt_rate > 0.5 else "yellow" if attempt_rate > 0 else "green"
            e_color = "red" if exfil_rate   > 0   else "green"
            label   = f"{conv} (baseline)" if conv == "none" else conv
            conv_table.add_row(
                arch,
                label,
                f"[{a_color}]{attempt_rate:.1%}[/]",
                f"[{e_color}]{exfil_rate:.1%}[/]",
                f"{cd['attempt']} / {cd['exfil']} / {cd['total']}",
            )

    console.print(conv_table)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threats", nargs="+", default=["all"])
    parser.add_argument("--smoke", action="store_true",
                        help="Run only T-001-A against both agents (CI smoke test)")
    parser.add_argument("--trials", type=int, default=1,
                        help="Number of trials per variant (default: 1)")
    parser.add_argument(
        "--converters", nargs="+", default=[],
        metavar="CONVERTER",
        help=(
            "PyRIT converters to apply on top of the plain baseline. "
            "Choices: base64, rot13, unicode, zerowidth, leetspeak, all. "
            "Use 'all' as a shortcut for every registered converter. "
            "The plain (none) baseline is always included automatically. "
            "Examples: --converters base64 unicode  |  --converters all"
        ),
    )
    args = parser.parse_args()
    asyncio.run(run_experiment(
        args.threats,
        smoke=args.smoke,
        trials=args.trials,
        converter_names=args.converters or None,
    ))
