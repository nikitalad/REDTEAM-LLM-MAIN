"""
tools.py — LangChain tool wrappers for the Policy-Guard agent sandbox.

Same underlying implementations as react/tools.py so the attack surface
is identical. Tools are exposed as LangChain @tool objects (for LLM schema
binding) plus an execute_tool() dispatcher called by the policy_gate node.
"""

import logging
import os
import pathlib
import sqlite3
import subprocess
import urllib.error
import urllib.request

from langchain_core.tools import tool

logger = logging.getLogger("tools")

WORKSPACE = pathlib.Path(os.getenv("WORKSPACE_PATH", "/workspace"))
WORK_DIR  = pathlib.Path(os.getenv("WORK_DIR", "/tmp/work"))
DB_PATH   = WORKSPACE / "db" / "app.db"
WORK_DIR.mkdir(parents=True, exist_ok=True)


# ── Implementations ───────────────────────────────────────────────────────────

def _file_read(path: str) -> str:
    p = pathlib.Path(path)
    target = p if p.is_absolute() else (WORKSPACE / path)
    target = target.resolve()
    allowed = [WORKSPACE.resolve(), pathlib.Path("/secrets").resolve()]
    if not any(str(target).startswith(str(a)) for a in allowed):
        return f"ERROR: Access denied: {path}"
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        logger.info("TOOL file_read path=%s len=%d", path, len(content))
        return content
    except FileNotFoundError:
        return f"ERROR: File not found: {path}"
    except Exception as e:
        return f"ERROR: {e}"


def _file_write(path: str, content: str) -> str:
    target = (WORK_DIR / path).resolve()
    if not str(target).startswith(str(WORK_DIR)):
        return "ERROR: Access denied — writes restricted to /tmp/work"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        logger.info("TOOL file_write path=%s bytes=%d", path, len(content))
        return f"OK: wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"ERROR: {e}"


def _shell_exec(command: str) -> str:
    logger.info("TOOL shell_exec command=%s", command[:120])
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=15, cwd=str(WORK_DIR),
        )
        output = result.stdout + result.stderr
        logger.info("TOOL shell_exec result_len=%d", len(output))
        return output or "(no output)"
    except subprocess.TimeoutExpired:
        return "ERROR: command timed out after 15s"
    except Exception as e:
        return f"ERROR: {e}"


def _git_ops(operation: str, args: str = "") -> str:
    allowed = {"clone", "status", "log", "add", "commit", "push", "pull", "diff"}
    if operation not in allowed:
        return f"ERROR: git operation '{operation}' not allowed"
    return _shell_exec(
        f"GIT_TERMINAL_PROMPT=0 git -C {WORKSPACE} -c credential.helper='' {operation} {args}".strip()
    )


def _list_files(directory: str = ".") -> str:
    target = (WORKSPACE / directory).resolve()
    if not str(target).startswith(str(WORKSPACE)):
        return "ERROR: Access denied"
    try:
        files = sorted(str(p.relative_to(WORKSPACE)) for p in target.rglob("*") if p.is_file())
        return "\n".join(files) or "(empty)"
    except Exception as e:
        return f"ERROR: {e}"


def _db_query(query: str) -> str:
    logger.info("TOOL db_query query=%s", query[:120])
    if not DB_PATH.exists():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password_hash TEXT, role TEXT)")
        conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin@example.com','$2b$12$FAKEHASH','admin')")
        conn.execute("INSERT OR IGNORE INTO products VALUES (1,'Widget',9.99),(2,'Gadget',19.99)")
        conn.commit()
        conn.close()
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(query)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        result = f"Rows returned: {len(rows)}\n" + "\n".join(str(r) for r in rows[:20])
        logger.info("TOOL db_query rows=%d", len(rows))
        return result
    except sqlite3.Error as e:
        return f"DB ERROR: {e}"


def _web_fetch(url: str) -> str:
    logger.info("TOOL web_fetch url=%s", url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AwesomeProject-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode("utf-8", errors="replace")[:8000]
            logger.info("TOOL web_fetch len=%d", len(content))
            return content
    except urllib.error.URLError as e:
        return f"FETCH ERROR: {e}"
    except Exception as e:
        return f"ERROR: {e}"


# ── LangChain tool objects (for LLM schema binding) ───────────────────────────

@tool
def file_read(path: str) -> str:
    """Read a file from the workspace codebase or /secrets directory."""
    return _file_read(path)

@tool
def file_write(path: str, content: str) -> str:
    """Write content to a file in the /tmp/work directory."""
    return _file_write(path, content)

@tool
def shell_exec(command: str) -> str:
    """Execute a shell command in the work directory."""
    return _shell_exec(command)

@tool
def git_ops(operation: str, args: str = "") -> str:
    """Run a git operation: clone | status | log | add | commit | push | pull | diff."""
    return _git_ops(operation, args)

@tool
def list_files(directory: str = ".") -> str:
    """List all files in a workspace directory recursively."""
    return _list_files(directory)

@tool
def db_query(query: str) -> str:
    """Execute a SQL query against the application SQLite database."""
    return _db_query(query)

@tool
def web_fetch(url: str) -> str:
    """Fetch a web page and return its full source content."""
    return _web_fetch(url)


TOOLS = {t.name: t for t in [file_read, file_write, shell_exec, git_ops, list_files, db_query, web_fetch]}

_IMPL = {
    "file_read":  _file_read,
    "file_write": _file_write,
    "shell_exec": _shell_exec,
    "git_ops":    _git_ops,
    "list_files": _list_files,
    "db_query":   _db_query,
    "web_fetch":  _web_fetch,
}


def execute_tool(name: str, args: dict) -> str:
    """Execute a named tool with the given argument dict. Called by policy_gate."""
    fn = _IMPL.get(name)
    if fn is None:
        return f"ERROR: unknown tool '{name}'"
    try:
        return fn(**args)
    except Exception as e:
        return f"ERROR: {e}"
