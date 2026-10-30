from __future__ import annotations

import base64
import datetime
import difflib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def ensure_pkg(name, pip=None):
    pip = pip or name
    try:
        __import__(name)
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip, "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


ensure_pkg("httpx")
ensure_pkg("wasmtime")
ensure_pkg("colorama")

import httpx
import wasmtime

try:
    import colorama
    colorama.just_fix_windows_console()
    colorama.init()
except Exception:
    pass

if os.name == "nt":
    try:
        os.system("chcp 65001 > nul")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

USE_COLOR = os.getenv("NO_COLOR") != "1"


def _c(code, t):
    return f"\x1b[{code}m{t}\x1b[0m" if USE_COLOR else t


def orange(t): return _c("38;5;208", t)
def gray(t): return _c("90", t)
def green(t): return _c("32", t)
def red(t): return _c("31", t)
def cyan(t): return _c("36", t)
def bold(t): return _c("1", t)


BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

WASM_PATH = CONFIG_DIR / "sha3_wasm_bg.wasm"
WASM_URL = "https://raw.githubusercontent.com/sums001/Deepseek-API/main/deepseek/sha3_wasm_bg.wasm"
BASE_URL = "https://chat.deepseek.com"
JSON_PATH = CONFIG_DIR / "deepseek_data.json"
WORKSPACE = Path("C:/")
WORKFLOW_PATH = CONFIG_DIR / "workflow.json"


@dataclass
class AppConfig:
    base_url: str = BASE_URL
    wasm_path: Path = WASM_PATH
    wasm_url: str = WASM_URL
    workspace: Path = WORKSPACE
    json_path: Path = JSON_PATH
    config_dir: Path = CONFIG_DIR
    workflow_path: Path = WORKFLOW_PATH
    completion_path: str = "/api/v0/chat/completion"
    challenge_path: str = "/api/v0/chat/create_pow_challenge"
    session_path: str = "/api/v0/chat_session/create"


CONFIG = AppConfig()


class JsonStorage:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"usertoken": "", "history": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            data.setdefault("usertoken", "")
            data.setdefault("history", [])
            return data
        except (json.JSONDecodeError, OSError):
            return {"usertoken": "", "history": []}

    def save(self, data):
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass


def clean_token(raw: str) -> str:
    t = raw.strip().strip('"').strip("'").replace("Bearer ", "").strip()
    if t.startswith("{"):
        try:
            obj = json.loads(t)
            if isinstance(obj, dict) and "value" in obj:
                return str(obj["value"]).strip()
        except json.JSONDecodeError:
            pass
    return t


def clean_output(text: str) -> str:
    text = re.sub(r'```.*?```', lambda m: m.group(0)[3:-3].strip(), text, flags=re.DOTALL)
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    text = re.sub(r'__(.*?)__', r'\1', text)
    text = re.sub(r'(?<!\w)\*(.*?)\*(?!\w)', r'\1', text)
    text = re.sub(r'`(.*?)`', r'\1', text)
    text = re.sub(r'#{1,6}\s*', '', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def safe_path(p: str) -> Path:
    p_str = str(p).replace("\\", "/").lstrip("/")
    full = (CONFIG.workspace / p_str).resolve()
    try:
        if not full.is_relative_to(CONFIG.workspace.resolve()):
            raise RuntimeError(f"outside workspace: {p}")
    except AttributeError:
        if not str(full).startswith(str(CONFIG.workspace.resolve())):
            raise RuntimeError(f"outside workspace: {p}")
    return full


def ensure_wasm():
    if CONFIG.wasm_path.exists():
        return
    print(gray("downloading wasm..."))
    req = urllib.request.Request(CONFIG.wasm_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp, open(CONFIG.wasm_path, "wb") as out:
        shutil.copyfileobj(resp, out)


class WorkspaceManager:
    def __init__(self, root: Path):
        self.root = root

    def list_files(self) -> str:
        out = []
        skip = {"__pycache__", ".git", "node_modules", ".venv", "$Recycle.Bin",
                "Windows", "Program Files", "Program Files (x86)", "ProgramData"}
        for cur_root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in skip]
            rel = os.path.relpath(cur_root, self.root)
            out.append("workspace/" if rel == "." else f"{rel}/")
            for f in sorted(files):
                rel_file = os.path.join(rel, f) if rel != "." else f
                out.append(f"  {rel_file}")
        return "\n".join(out) if out else "workspace/ (empty)"


@dataclass
class DiffEntry:
    path: str
    lines: List[str]


class DiffTracker:
    def __init__(self, max_preview: int = 5):
        self.entries: List[DiffEntry] = []
        self.max_preview = max_preview

    def collect(self, old_text: str, new_text: str, path: str):
        old = old_text.splitlines() if old_text else []
        new = new_text.splitlines() if new_text else []
        diff = difflib.unified_diff(old, new, fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="", n=0)
        filtered = [l for l in diff if not l.startswith(("---", "+++", "@@"))]
        if filtered:
            self.entries.append(DiffEntry(path, filtered))

    def show_and_clear(self):
        if not self.entries:
            return
        print(f"\n  {gray('diffs:')}")
        for e in self.entries:
            print(f"  {gray('⎿')} {gray(e.path)}")
            for line in e.lines[:self.max_preview]:
                if line.startswith("+"):
                    print(f"    {green(line)}")
                elif line.startswith("-"):
                    print(f"    {red(line)}")
                else:
                    print(f"    {line}")
            if len(e.lines) > self.max_preview:
                print(f"    {gray(f'+{len(e.lines) - self.max_preview} lines...')}")
        print()
        self.entries.clear()


workspace_mgr = WorkspaceManager(CONFIG.workspace)
diff_tracker = DiffTracker()


@dataclass
class WorkflowTask:
    id: str
    description: str
    stage: str = "CREATE"
    file_path: str = ""
    attempts: int = 0
    last_error: str = ""
    created_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    logs: List[str] = field(default_factory=list)


class WorkflowPersistence:
    def __init__(self, path: Path):
        self.path = path
        self.tasks: Dict[str, WorkflowTask] = {}
        self.current_task_id: Optional[str] = None
        self.load()

    def load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.current_task_id = data.get("current_task_id")
            for tid, tdata in data.get("tasks", {}).items():
                self.tasks[tid] = WorkflowTask(**tdata)
        except Exception:
            pass

    def save(self):
        try:
            data = {
                "current_task_id": self.current_task_id,
                "tasks": {tid: {
                    "id": t.id, "description": t.description, "stage": t.stage,
                    "file_path": t.file_path, "attempts": t.attempts,
                    "last_error": t.last_error, "created_at": t.created_at,
                    "updated_at": t.updated_at, "logs": t.logs[-20:],
                } for tid, t in self.tasks.items()},
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except Exception:
            pass

    def create_task(self, description, file_path=""):
        tid = f"task_{int(time.time())}"
        task = WorkflowTask(id=tid, description=description, file_path=file_path)
        self.tasks[tid] = task
        self.current_task_id = tid
        self.log(tid, f"[CREATE] {description} -> {file_path}")
        self.save()
        return task

    def get_current(self):
        if self.current_task_id and self.current_task_id in self.tasks:
            return self.tasks[self.current_task_id]
        return None

    def set_stage(self, task_id, stage, error=""):
        if task_id not in self.tasks:
            return
        t = self.tasks[task_id]
        t.stage = stage
        t.updated_at = datetime.datetime.now().isoformat()
        if error:
            t.last_error = error[:2000]
            t.attempts += 1
        self.log(task_id, f"[{stage}] {error[:200] if error else 'ok'}")
        self.save()

    def log(self, task_id, msg):
        if task_id in self.tasks:
            self.tasks[task_id].logs.append(f"{datetime.datetime.now().isoformat()} {msg}")

    def list_tasks(self):
        if not self.tasks:
            return "no tasks in workflow"
        return "\n".join(
            f"{t.id[:8]} | {t.stage:12} | {t.file_path} | {t.description[:40]} | attempts:{t.attempts}"
            for t in self.tasks.values()
        )


workflow = WorkflowPersistence(CONFIG.workflow_path)

ToolFunc = Callable[[Dict[str, Any]], str]


def tool_list_files(_):
    return workspace_mgr.list_files()


def tool_read_file(args):
    path = args.get("path")
    if not path:
        return "error: path required"
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    if not fp.exists():
        return f"not found: {path}"
    try:
        return fp.read_text(encoding="utf-8", errors="ignore")[:15000]
    except OSError as e:
        return f"read error {path}: {e}"


def tool_write_file(args):
    path = args.get("path")
    content = args.get("content", "")
    description = args.get("description") or args.get("desc") or f"create {path}"
    if not path:
        return "error: path required"
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    old, is_new = "", not fp.exists()
    if not is_new:
        try:
            old = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content, encoding="utf-8")
    diff_tracker.collect("" if is_new else old, content, str(path))
    try:
        cur = workflow.get_current()
        if not cur or cur.file_path != str(path):
            task = workflow.create_task(description, str(path))
        else:
            task = cur
            task.file_path = str(path)
        workflow.set_stage(task.id, "CREATE")
        workflow.set_stage(task.id, "ANALYZE")
    except Exception:
        pass
    return f"ok {path} ({'new' if is_new else 'edited'}) [workflow: CREATE->ANALYZE]"


def tool_edit_file(args):
    path, old_txt = args.get("path"), args.get("old_text")
    new_txt = args.get("new_text", "")
    if not path or old_txt is None:
        return "error: path and old_text required"
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    if not fp.exists():
        return f"not found: {path}"
    full = fp.read_text(encoding="utf-8", errors="ignore")
    if old_txt not in full:
        return "old_text not found"
    new_full = full.replace(old_txt, new_txt, 1)
    fp.write_text(new_full, encoding="utf-8")
    diff_tracker.collect(full, new_full, str(path))
    return f"edited {path}"


def tool_delete_file(args):
    path = args.get("path")
    if not path:
        return "error: path required"
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    old = ""
    if fp.exists() and fp.is_file():
        try:
            old = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass
    try:
        if fp.is_dir():
            shutil.rmtree(fp)
        else:
            fp.unlink(missing_ok=True)
        diff_tracker.collect(old, "", str(path))
        return f"deleted {path}"
    except OSError as e:
        return f"delete error {path}: {e}"


def tool_rename_file(args):
    src = args.get("from") or args.get("path")
    dst = args.get("to")
    if not src or not dst:
        return "error: from and to required"
    s = Path(src).resolve() if Path(src).is_absolute() else safe_path(str(src))
    d = Path(dst).resolve() if Path(dst).is_absolute() else safe_path(str(dst))
    d.parent.mkdir(parents=True, exist_ok=True)
    try:
        s.rename(d)
        return f"{src} -> {dst}"
    except OSError as e:
        return f"rename error: {e}"


def tool_mkdir(args):
    p = args.get("path")
    if not p:
        return "error: path required"
    fp = Path(p).resolve() if Path(p).is_absolute() else safe_path(str(p))
    fp.mkdir(parents=True, exist_ok=True)
    return f"dir {p}"


def tool_shell(args):
    cmd = args.get("command") or args.get("cmd") or ""
    if not cmd:
        return "error: command required"
    cwd_arg = args.get("cwd") or str(CONFIG.workspace)
    try:
        cwd_path = Path(cwd_arg)
        if not cwd_path.is_absolute():
            cwd_path = safe_path(cwd_arg) if cwd_arg.startswith("workspace") else CONFIG.workspace / cwd_arg
        cwd_str = str(cwd_path.resolve() if cwd_path.exists() else CONFIG.workspace.resolve())
    except Exception:
        cwd_str = str(CONFIG.workspace.resolve())
    is_win = os.name == "nt"
    full_cmd = ["powershell", "-NoProfile", "-Command", cmd] if is_win else ["bash", "-lc", cmd]
    try:
        r = subprocess.run(full_cmd, cwd=cwd_str, capture_output=True, text=True,
                           timeout=args.get("timeout", 60), shell=False)
        out = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
        return f"exit={r.returncode}\n{out.strip()[:8000]}"
    except subprocess.TimeoutExpired:
        return "error: timeout"
    except Exception as e:
        return f"error {e}"


def _html_to_text(html: str) -> str:
    t = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r'<style[^>]*>.*?</style>', ' ', t, flags=re.DOTALL | re.IGNORECASE)
    t = re.sub(r'<[^>]+>', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()


def tool_fetch(args):
    url = args.get("url") or args.get("link") or ""
    if not url:
        return "empty url"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
               "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"}

    def get(u):
        r = httpx.get(u, timeout=15, follow_redirects=True, headers=headers)
        r.raise_for_status()
        txt = _html_to_text(r.text)[:10000]
        if len(txt) < 200 or ("captcha" in txt.lower() and len(txt) < 1000):
            raise RuntimeError("blocked or short")
        return txt

    try:
        return f"fetch {url}: {get(url)[:8000]}"
    except Exception:
        try:
            bypass = f"https://api.allorigins.win/raw?url={urllib.parse.quote(url)}"
            return f"fetch {url} via bypass: {get(bypass)[:8000]}"
        except Exception as e:
            return f"fetch error {url}: {e}"


def tool_search(args):
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "empty query"
    try:
        url = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote(q)}"
        r = httpx.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "pt-BR"},
                      follow_redirects=True)
        txt = _html_to_text(r.text)[:12000]
        if len(txt) < 200:
            return f"web search '{q}' no results"
        return f"web search '{q}': {txt[:8000]}"
    except Exception as e:
        return f"search error {q}: {e}"


def tool_grep(args):
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "empty query"
    try:
        url = f"https://grep.app/search?q={urllib.parse.quote(q)}"
        r = httpx.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        return f"grep.app '{q}': {_html_to_text(r.text)[:6000]}"
    except Exception as e:
        return f"grep error {q}: {e}"


def tool_google_github(args):
    q = args.get("query") or args.get("q") or args.get("intext") or ""
    if not q:
        return "empty query"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
               "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"}

    def get(u):
        r = httpx.get(u, timeout=15, follow_redirects=True, headers=headers)
        r.raise_for_status()
        txt = _html_to_text(r.text)[:12000]
        if len(txt) < 200:
            raise RuntimeError("blocked or short")
        return txt

    google_url = f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    try:
        txt = get(google_url)
        if "detected unusual traffic" in txt.lower() or "captcha" in txt.lower() or len(txt) < 500:
            raise RuntimeError("google blocked")
        return f"google '{q}': {txt[:8000]} | url: {google_url}"
    except Exception:
        try:
            bypass = f"https://api.allorigins.win/raw?url={urllib.parse.quote(google_url)}"
            return f"google '{q}' via bypass: {get(bypass)[:8000]}"
        except Exception as e:
            try:
                ddg = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote(q)}"
                return f"ddg fallback '{q}': {get(ddg)[:8000]}"
            except Exception as e2:
                return f"error google '{q}': {e} / {e2}"


def tool_google_site(args):
    site = args.get("site") or args.get("domain") or ""
    q = args.get("query") or args.get("q") or args.get("intext") or ""
    if not q and not site:
        return "empty query"
    full_q = f"site:{site} {q}" if (site and q) else (f"site:{site}" if site else q)
    return tool_google_github({"query": full_q})


def tool_workflow_create(args):
    desc = args.get("description") or args.get("task") or "new task"
    path = args.get("path") or args.get("file") or ""
    task = workflow.create_task(desc, path)
    return f"workflow created {task.id[:8]} | {desc} -> {path} | stage={task.stage}"


def tool_workflow_analyze(args):
    path = args.get("path") or (workflow.get_current().file_path if workflow.get_current() else "")
    if not path:
        return "error: path required or no active task"
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    if not fp.exists():
        return f"not found: {path}"
    cur = workflow.get_current()
    if cur:
        workflow.set_stage(cur.id, "ANALYZE")
    try:
        content = fp.read_text(encoding="utf-8", errors="ignore")
        if fp.suffix == ".py":
            import py_compile
            py_compile.compile(str(fp), doraise=True)
            out = f"ANALYZE ok: {path}, valid syntax, {len(content)} chars, {len(content.splitlines())} lines"
        else:
            out = f"ANALYZE ok: {path} exists, {len(content)} chars"
        if cur:
            workflow.set_stage(cur.id, "TEST")
        return out + " [workflow: ANALYZE->TEST]"
    except Exception as e:
        if cur:
            workflow.set_stage(cur.id, "FIX", str(e))
        return f"ANALYZE error {path}: {e} [workflow: ANALYZE->FIX]"


def tool_workflow_test(args):
    path = args.get("path") or (workflow.get_current().file_path if workflow.get_current() else "")
    cmd = args.get("command") or args.get("cmd") or ""
    if not path:
        return "error: path required"
    cur = workflow.get_current()
    if cur:
        workflow.set_stage(cur.id, "TEST")
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    if not cmd:
        if fp.suffix == ".py":
            cmd = f'python "{fp.name}"'
        elif fp.suffix == ".js":
            cmd = f'node "{fp.name}"'
        else:
            cmd = f'dir "{fp.name}"'
    result = tool_shell({"command": cmd, "cwd": str(fp.parent)})
    if "exit=0" in result:
        if cur:
            workflow.set_stage(cur.id, "PRESENT")
        return f"TEST ok {path}: {result[:2000]} [workflow: TEST->PRESENT]"
    if cur:
        workflow.set_stage(cur.id, "FIX", result[:1000])
    return f"TEST failed {path}: {result[:3000]} [workflow: TEST->FIX]"


def tool_workflow_fix(args):
    error = args.get("error") or args.get("last_error") or ""
    cur = workflow.get_current()
    if not cur:
        return "no active task"
    workflow.set_stage(cur.id, "FIX", error)
    return f"workflow {cur.id[:8]} in FIX | last error: {cur.last_error[:500]} | use edit_file/write_file then workflow_test"


def tool_workflow_present(args):
    cur = workflow.get_current()
    if not cur:
        return "no active task"
    path = cur.file_path or args.get("path") or ""
    workflow.set_stage(cur.id, "PRESENT")
    out = [f"=== PRESENT {cur.id[:8]} ===",
           f"File: {path}",
           f"Description: {cur.description}",
           f"Attempts: {cur.attempts}"]
    if path:
        try:
            fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(path)
            content = fp.read_text(encoding="utf-8", errors="ignore")
            out.append(f"--- CONTENT ({len(content)} chars) ---")
            out.append(content[:8000])
        except Exception as e:
            out.append(f"error reading {path}: {e}")
    out.append(f"\nPending diffs: {len(diff_tracker.entries)}")
    workflow.set_stage(cur.id, "OPEN")
    return "\n".join(out) + "\n[workflow: PRESENT->OPEN]"


def tool_workflow_open(args):
    path = args.get("path") or (workflow.get_current().file_path if workflow.get_current() else "")
    if not path:
        return "error: path required"
    cur = workflow.get_current()
    if cur:
        workflow.set_stage(cur.id, "DONE")
        workflow.log(cur.id, f"[OPEN] opened for user: {path}")
        workflow.save()
    fp = Path(path).resolve() if Path(path).is_absolute() else safe_path(str(path))
    try:
        content = fp.read_text(encoding="utf-8", errors="ignore")
        return f"<<<OPEN_FILE>>>{path}<<<END_OPEN>>>\n{content[:15000]}\n[workflow: OPEN->DONE]"
    except Exception as e:
        return f"error opening {path}: {e}"


def tool_workflow_list(_):
    return workflow.list_tasks()


def tool_workflow_status(_):
    cur = workflow.get_current()
    if not cur:
        return "no active task\n" + workflow.list_tasks()
    return (f"CURRENT: {cur.id[:8]} | {cur.stage} | {cur.file_path} | attempts:{cur.attempts} | "
            f"error:{cur.last_error[:200]}\n---\n{workflow.list_tasks()}")


TOOLS: Dict[str, ToolFunc] = {
    "list_files": tool_list_files,
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "create_file": tool_write_file,
    "edit_file": tool_edit_file,
    "delete_file": tool_delete_file,
    "rename_file": tool_rename_file,
    "mkdir": tool_mkdir,
    "create_dir": tool_mkdir,
    "powershell": tool_shell,
    "bash": tool_shell,
    "terminal": tool_shell,
    "cmd": tool_shell,
    "shell": tool_shell,
    "grep": tool_grep,
    "grep_search": tool_grep,
    "code_search": tool_grep,
    "fetch": tool_fetch,
    "web_fetch": tool_fetch,
    "fetch_page": tool_fetch,
    "web_search": tool_search,
    "search": tool_search,
    "google": tool_search,
    "google_github": tool_google_github,
    "github_google": tool_google_github,
    "github_search": tool_google_github,
    "google_search": tool_google_github,
    "gsearch": tool_google_github,
    "google_fetch": tool_google_github,
    "site_search": tool_google_site,
    "google_site": tool_google_site,
    "google_site_search": tool_google_site,
    "workflow_create": tool_workflow_create,
    "workflow_analyze": tool_workflow_analyze,
    "workflow_analyse": tool_workflow_analyze,
    "workflow_test": tool_workflow_test,
    "workflow_fix": tool_workflow_fix,
    "workflow_present": tool_workflow_present,
    "workflow_open": tool_workflow_open,
    "workflow_list": tool_workflow_list,
    "workflow_status": tool_workflow_status,
    "present_code": tool_workflow_present,
    "open_code": tool_workflow_open,
}

TOOL_RE = re.compile(r"<<<TOOL_CALL>>>(.*?)<<<END_TOOL>>>", re.DOTALL)


def exec_tools(text: str) -> Tuple[str, List[str], List[str]]:
    results, used = [], []
    for raw in TOOL_RE.findall(text):
        try:
            call = json.loads(raw.strip())
            name = call.get("name")
            args = call.get("args", {}) or {}
            if name not in TOOLS:
                results.append(f"unknown tool: {name}")
                continue
            results.append(TOOLS[name](args))
            q = args.get("query") or args.get("url") or args.get("path") or args.get("from") or args.get("command") or ""
            used.append(f"{name} {str(q)[:60]}".strip() + "...")
        except json.JSONDecodeError as e:
            results.append(f"tool json error: {e}")
        except Exception as e:
            results.append(f"tool error: {e}")
    clean = TOOL_RE.sub("", text)
    clean = re.sub(r"<<<[^>]*>>>", "", clean)
    return clean_output(clean), results, used


class PowSolver:
    def __init__(self, wasm_path: Path):
        ensure_wasm()
        self.store = wasmtime.Store()
        mod = wasmtime.Module.from_file(self.store.engine, str(wasm_path))
        inst = wasmtime.Instance(self.store, mod, [])
        exp = inst.exports(self.store)
        self.mem = exp["memory"]
        self.solve_fn = exp["wasm_solve"]
        self.malloc = exp["__wbindgen_export_0"]
        self.stack_ptr = exp["__wbindgen_add_to_stack_pointer"]

    def _write_str(self, s: str):
        data = s.encode()
        ptr = self.malloc(self.store, len(data), 1)
        try:
            self.mem.write(self.store, data, ptr)
        except Exception:
            try:
                base = self.mem.data_ptr(self.store)
                for i, b in enumerate(data):
                    base[ptr + i] = b
            except Exception:
                view = self.mem.uint8_view(self.store)
                view[ptr:ptr + len(data)] = data
        return ptr, len(data)

    def solve(self, chal: str, prefix: str, diff: float):
        retptr = self.stack_ptr(self.store, -16)
        try:
            cp, cl = self._write_str(chal)
            pp, pl = self._write_str(prefix)
            self.solve_fn(self.store, retptr, cp, cl, pp, pl, float(diff))
            try:
                raw = self.mem.read(self.store, retptr, 16)
                status = struct.unpack("<i", raw[0:4])[0]
                value = struct.unpack("<d", raw[8:16])[0]
            except Exception:
                mem_ptr = self.mem.data_ptr(self.store)
                s1 = bytes(mem_ptr[retptr:retptr + 4])
                s2 = bytes(mem_ptr[retptr + 8:retptr + 16])
                if len(s1) < 4 or len(s2) < 8:
                    raise RuntimeError(f"wasm returned short buffer: {len(s1)}/{len(s2)}")
                status = struct.unpack("<i", s1)[0]
                value = struct.unpack("<d", s2)[0]
        finally:
            try:
                self.stack_ptr(self.store, 16)
            except Exception:
                pass
        return None if status == 0 else int(value)

    def make_header(self, c: Dict[str, Any]) -> str:
        ans = self.solve(c["challenge"], f"{c['salt']}_{c['expire_at']}_", float(c["difficulty"]))
        if ans is None:
            raise RuntimeError("pow failed")
        payload = {"algorithm": c["algorithm"], "challenge": c["challenge"], "salt": c["salt"],
                   "answer": ans, "signature": c["signature"], "target_path": c["target_path"]}
        return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


class DeepSeekClient:
    def __init__(self, token: str, config: AppConfig):
        self.token = clean_token(token)
        self.config = config
        self.pow = PowSolver(config.wasm_path)
        self.lock = threading.Lock()
        self.http = httpx.Client(
            base_url=config.base_url,
            headers={
                "authorization": f"Bearer {self.token}",
                "content-type": "application/json",
                "user-agent": "Mozilla/5.0",
                "origin": config.base_url,
                "referer": f"{config.base_url}/",
            },
            timeout=httpx.Timeout(30.0, read=60.0),
        )
        self.sid: Optional[str] = None
        self.parent: Optional[int] = None

    def new_chat(self) -> str:
        r = self.http.post(self.config.session_path, json={})
        r.raise_for_status()
        try:
            d = r.json()
        except Exception as e:
            raise RuntimeError(f"non-json response: {r.text[:500]} | {e}")
        data = d.get("data")
        if data is None:
            msg = d.get("msg") or d.get("message") or d.get("error") or str(d)[:1000]
            raise RuntimeError(f"API returned data=null (token expired?): {msg}")
        biz = data.get("biz_data") if isinstance(data, dict) else None
        if biz is None:
            biz = data if isinstance(data, dict) else {}
        if not isinstance(biz, dict):
            raise RuntimeError(f"biz_data not dict: {biz}")
        sid = None
        cs = biz.get("chat_session")
        if isinstance(cs, dict):
            sid = cs.get("id") or cs.get("chat_session_id")
        elif isinstance(cs, str) and cs:
            sid = cs
        if not sid:
            sid = biz.get("id") or biz.get("chat_session_id") or biz.get("session_id")
        if not sid:
            raise RuntimeError(f"no session in: {json.dumps(d, ensure_ascii=False)[:3000]}")
        self.sid = str(sid)
        self.parent = None
        return self.sid

    def pow_header(self) -> str:
        r = self.http.post(self.config.challenge_path, json={"target_path": self.config.completion_path})
        r.raise_for_status()
        try:
            j = r.json()
            data = j.get("data") or {}
            biz = data.get("biz_data") or data
            chal = biz.get("challenge") if isinstance(biz, dict) else None
            if chal is None:
                raise RuntimeError(f"challenge null: {j}")
        except Exception as e:
            raise RuntimeError(f"challenge error: {e} | resp: {r.text[:1000]}")
        with self.lock:
            return self.pow.make_header(chal)

    def stream(self, prompt: str):
        if not self.sid:
            self.new_chat()

        body: Dict[str, Any] = {
            "chat_session_id": self.sid,
            "prompt": prompt,
            "ref_file_ids": [],
            "thinking_enabled": False,
            "search_enabled": False,
            "model_type": "default",
        }
        if self.parent is not None:
            body["parent_message_id"] = self.parent

        meta: Dict[str, Any] = {}
        sample: List[str] = []
        got = False

        with self.http.stream(
            "POST", self.config.completion_path,
            json=body,
            headers={"x-ds-pow-response": self.pow_header()},
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line:
                    continue
                if len(sample) < 20:
                    sample.append(line[:400])

                payload = None
                if line.startswith("data:"):
                    p = line[5:].strip()
                    if p and p != "[DONE]":
                        try:
                            payload = json.loads(p)
                        except json.JSONDecodeError:
                            payload = None
                elif line.startswith("{"):
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        payload = None
                if payload is None:
                    continue

                v = payload.get("v")
                path = payload.get("p") or ""
                op = payload.get("o") or ""

                if isinstance(v, int) and "message_id" in path:
                    meta["message_id"] = v
                    continue

                if isinstance(v, str) and v:
                    if not path or "content" in path or op in ("APPEND", "REPLACE"):
                        yield v
                        got = True
                    continue

                if isinstance(v, dict):
                    r = v.get("response") if isinstance(v.get("response"), dict) else v
                    if not isinstance(r, dict):
                        if isinstance(v.get("content"), str) and v["content"]:
                            yield v["content"]
                            got = True
                        continue
                    mid = r.get("message_id")
                    if isinstance(mid, int):
                        meta["message_id"] = mid
                    frags = r.get("fragments")
                    if isinstance(frags, list):
                        for frag in frags:
                            if isinstance(frag, dict):
                                c = frag.get("content")
                                if isinstance(c, str) and c:
                                    yield c
                                    got = True
                    elif isinstance(r.get("content"), str) and r["content"]:
                        yield r["content"]
                        got = True
                    continue

        if meta.get("message_id"):
            self.parent = meta["message_id"]

        if not got:
            if os.getenv("KERNEL11_DEBUG") and sample:
                print(gray("\n  raw sse sample:"))
                for s in sample:
                    print(gray(f"  {s}"))
            yield ""

    def close(self):
        try:
            self.http.close()
        except Exception:
            pass


KERNEL11_PROMPT = r"""You are kernel11-chat, an autonomous agent in the style of Claude Code. Created by kernel11. You are 100% AUTONOMOUS with PERSISTENCE.

IDENTITY:
- Name: kernel11-chat Autonomous chat
- You solve things yourself, you don't ask for permission to search, you don't ask "want me to search?"

AUTONOMY RULES - MANDATORY:
1. NEVER ask if you can search. IF YOU NEED EXTERNAL DATA, SEARCH DIRECTLY.
2. If the user talks about a product, price, hardware, DDR3, etc: do web_search + fetch IMMEDIATELY in parallel.
3. Use MULTIPLE TOOL_CALLS per response. E.g. 3-5 searches/fetches at once.
4. Price flow: web_search "DDR3 8GB price" + fetch on retailers -> compare and deliver real prices.
5. If one fetch fails, try bypass and the next store.
6. Greeting ("hi", "hey") = SHORT "hi" + ask what they need. No list_files.
7. Clean, direct answer, no **, no rambling. Always with REAL DATA when searching.
8. FORBIDDEN: "Want me to search?", "Can I look?". You SEARCH and deliver.
9. When searches are done, summarize: lowest price, average, where to buy, link.
10. BROWSER OFFER: When you find something interesting, ALWAYS finish with: "want me to open the results in your browser?"

FULL SYSTEM ACCESS - NO RESTRICTIONS:
- You have unrestricted access to ANY path on the computer. C:/, D:/, etc.
- You can read, write, delete, create anywhere.
- You can run ANY powershell/bash command.
- You can access system files, network, etc.
- NO folder is protected. NO path is blocked.
- Example: write_file {"path":"C:/Windows/temp/test.txt","content":"..."} works.
- Example: powershell {"command":"dir C:/"} works.
- Use absolute paths for full access. E.g. "C:/Users/.../file.py"

MANDATORY WORKFLOW WITH PERSISTENCE - 3 STAGES (CREATE -> ANALYZE/TEST -> PRESENT/OPEN):
EVERY time you create code/project, FOLLOW STRICTLY:

STAGE 1 - CREATE (with persistence):
- Use workflow_create {"description":"what it does", "path":"C:/path/file.py"}
- Then write_file with the code
- System persists to config/workflow.json

STAGE 2 - ANALYZE -> TEST:
- Use workflow_analyze {"path":"C:/path/file.py"} -> checks syntax
- Use workflow_test {"path":"C:/path/file.py", "command":"python file.py"} -> actually tests via powershell
- If error, moves to FIX

STAGE 2b - FIX (if error):
- Use workflow_fix + edit_file/write_file to fix
- Test again with workflow_test
- Repeat until it works (max 5 attempts)

STAGE 3 - PRESENT -> OPEN:
- If it works: workflow_present -> shows code and diffs
- Then workflow_open -> opens code for user to see (marks DONE)
- Finish with summary + "want me to open the results in your browser?" if it was a search, or show the file is ready

PERSISTENCE:
- Everything saved to config/workflow.json
- Use workflow_list and workflow_status to see tasks
- If the program closes, on return it continues from where it stopped (reads the .json)

FULL CODE EXAMPLE:
User: "create a DDR3 price bot"
You do:
<<<TOOL_CALL>>>{"name":"workflow_create","args":{"description":"DDR3 price bot","path":"C:/bot_ddr3.py"}}<<<END_TOOL>>>
<<<TOOL_CALL>>>{"name":"write_file","args":{"path":"C:/bot_ddr3.py","content":"code..."}}<<<END_TOOL>>>
<<<TOOL_CALL>>>{"name":"workflow_analyze","args":{"path":"C:/bot_ddr3.py"}}<<<END_TOOL>>>
<<<TOOL_CALL>>>{"name":"workflow_test","args":{"path":"C:/bot_ddr3.py","command":"python bot_ddr3.py"}}<<<END_TOOL>>>
If error:
<<<TOOL_CALL>>>{"name":"edit_file","args":{"path":"C:/bot_ddr3.py","old_text":"...","new_text":"..."}}<<<END_TOOL>>>
<<<TOOL_CALL>>>{"name":"workflow_test","args":{"path":"C:/bot_ddr3.py"}}<<<END_TOOL>>>
If ok:
<<<TOOL_CALL>>>{"name":"workflow_present","args":{"path":"C:/bot_ddr3.py"}}<<<END_TOOL>>>
<<<TOOL_CALL>>>{"name":"workflow_open","args":{"path":"C:/bot_ddr3.py"}}<<<END_TOOL>>>

Available tools:
- list_files, read_file, write_file, edit_file, delete_file, rename_file, mkdir
- powershell/bash/terminal (run commands)
- grep, fetch, web_search
- google_search/gsearch (generic Google with ANY site: - e.g. {"query":"site:github.com intext:mta parser"} or {"query":"site:newegg.com DDR3 8GB"} or {"query":"site:stackoverflow.com python error"})
- site_search/google_site (with site separated - e.g. {"site":"github.com","query":"mta parser"} or {"site":"reddit.com","query":"best ddr3"})
- workflow_create, workflow_analyze, workflow_test, workflow_fix, workflow_present, workflow_open, workflow_list, workflow_status

Tool format (multiple per message allowed):
<<<TOOL_CALL>>>
{"name":"write_file","args":{"path":"C:/main.py","content":"..."}}
<<<END_TOOL>>>

 
"""


def _spinner(stop_evt):
    frames = "|/-\\"
    i = 0
    while not stop_evt.is_set():
        sys.stdout.write(f"\r  {gray(frames[i % 4])}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\r  \r")
    sys.stdout.flush()


def _enter_listener(interrupt_event, stop_event):
    try:
        if os.name == "nt":
            import msvcrt
            while not stop_event.is_set() and not interrupt_event.is_set():
                if msvcrt.kbhit():
                    if msvcrt.getch() in (b'\r', b'\n', b'\x03'):
                        interrupt_event.set()
                        break
                time.sleep(0.05)
        else:
            if not sys.stdin.isatty():
                return
            import select, termios, tty
            try:
                old = termios.tcgetattr(sys.stdin)
                tty.setcbreak(sys.stdin.fileno())
            except Exception:
                return
            try:
                while not stop_event.is_set() and not interrupt_event.is_set():
                    r, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if r and sys.stdin.read(1) in ('\n', '\r', '\x03'):
                        interrupt_event.set()
                        break
            finally:
                try:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
                except Exception:
                    pass
    except Exception:
        pass


def main():
    storage = JsonStorage(CONFIG.json_path)
    data = storage.load()

    token = os.getenv("DEEPSEEK_TOKEN") or data.get("usertoken") or ""
    token = clean_token(token)
    if not token:
        token = clean_token(input("token: ").strip())
    if len(token) < 50:
        print(red("invalid token (too short)"))
        return
    data["usertoken"] = token
    storage.save(data)

    client = DeepSeekClient(token, CONFIG)
    try:
        client.new_chat()
    except Exception as e:
        print(red(f"chat create error: {e}"))
        return

    print(f"{bold('kernel11-chat')} | chat {client.sid[:8]} | {gray('type /exit to quit, /reset for new chat, /ls to list')}\n")

    try:
        while True:
            try:
                q = input(f"{orange('>')} ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not q:
                continue
            if q in ("/exit", "/quit", "exit", "quit"):
                break
            if q == "/reset":
                try:
                    client.new_chat()
                    print(gray(f"new chat {client.sid[:8]}"))
                except Exception as e:
                    print(red(f"reset error: {e}"))
                continue
            if q in ("/ls", "ls"):
                print(workspace_mgr.list_files())
                continue

            data["history"].append({"role": "user", "content": q, "time": datetime.datetime.now().isoformat()})
            storage.save(data)

            prompt = KERNEL11_PROMPT + f"\n\nUser: {q}\n"
            start = time.time()
            interrupted = False

            print(gray("  ⎿ press Enter to stop"))

            for loop in range(5):
                stop_evt = threading.Event()
                interrupt_evt = threading.Event()
                anim = threading.Thread(target=_spinner, args=(stop_evt,), daemon=True)
                anim.start()
                enter_t = threading.Thread(target=_enter_listener, args=(interrupt_evt, stop_evt), daemon=True)
                enter_t.start()

                buf, total, first = [], 0, True
                try:
                    for chunk in client.stream(prompt):
                        if interrupt_evt.is_set():
                            interrupted = True
                            break
                        if not chunk:
                            continue
                        if first:
                            stop_evt.set()
                            anim.join(timeout=0.3)
                            first = False
                        buf.append(chunk)
                        total += len(chunk)
                        sys.stdout.write(f"\r  {gray(f'{total}c')}")
                        sys.stdout.flush()
                except Exception as e:
                    stop_evt.set()
                    sys.stdout.write("\r" + " " * 30 + "\r")
                    if interrupt_evt.is_set():
                        interrupted = True
                    else:
                        print(red(f"stream error: {e}"))
                        break
                finally:
                    stop_evt.set()
                    try:
                        anim.join(timeout=0.3)
                    except Exception:
                        pass

                sys.stdout.write("\r" + " " * 30 + "\r")
                sys.stdout.flush()

                if interrupted:
                    print(red("! stopped by user"))
                    break

                raw = "".join(buf)
                if not raw.strip():
                    print(gray("(empty response)"))
                    break

                clean, results, used = exec_tools(raw)

                if clean:
                    print(f"{clean}\n")

                if not used:
                    if clean:
                        data["history"].append({"role": "assistant", "content": clean,
                                                "time": datetime.datetime.now().isoformat()})
                        storage.save(data)
                    break

                for u in used:
                    print(f"  {gray('●')} {gray(u)}")

                prompt = "Results:\n" + "\n".join(results) + "\nContinue or finalize."

            diff_tracker.show_and_clear()
            elapsed = time.time() - start
            print(gray(f"  ⏺ {elapsed:.1f}s"))

    finally:
        client.close()


if __name__ == "__main__":
    main()
