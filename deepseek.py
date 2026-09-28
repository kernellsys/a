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


# O acesso total fica desativado por padrao. Para habilita-lo, inicie com
# `python deepseek.py --unsafe` e confirme digitando a frase exigida.
FULL_ACCESS_MODE = False
FULL_ACCESS_CONFIRMATION = "LIBERAR ACESSO TOTAL"


def ensure_pkg(import_name: str, pip_name: Optional[str] = None) -> None:
    pip_name = pip_name or import_name
    try:
        __import__(import_name)
    except ImportError:
        print(f"[deps] instalando {pip_name}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name, "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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


def setup_console_utf8() -> None:
    if os.name != "nt":
        return
    try:
        os.system("chcp 65001 > nul")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        m = ctypes.c_ulong()
        if k.GetConsoleMode(h, ctypes.byref(m)):
            k.SetConsoleMode(h, m.value | 0x0004)
    except Exception:
        pass


setup_console_utf8()

USE_COLOR = os.getenv("NO_COLOR") != "1"

def _detect_unicode() -> bool:
    if os.getenv("NO_UNICODE") == "1":
        return False
    try:
        "\u25cf\u25c6\u25ba\u2713\u00e9".encode(sys.stdout.encoding or "utf-8")
        return True
    except Exception:
        return False

USE_UNICODE = _detect_unicode()


class Colors:
    """Paleta restrita: SOMENTE cinza e branco (+ bold/dim que sao estilos, nao cores).
    Qualquer chamada legada para outras cores cai para cinza ou branco.
    NADA de ciano."""

    @staticmethod
    def _wrap(code: str, t: str) -> str:
        return f"\x1b[{code}m{t}\x1b[0m" if USE_COLOR else t

    @classmethod
    def gray(cls, t: str) -> str:
        return cls._wrap("90", t)

    @classmethod
    def white(cls, t: str) -> str:
        return cls._wrap("97", t)

    @classmethod
    def bold(cls, t: str) -> str:
        return cls._wrap("1", t)

    @classmethod
    def dim(cls, t: str) -> str:
        return cls._wrap("2", t)


    # --- cores EXCLUSIVAS do diff (unica excecao a paleta cinza/branco) ---
    @classmethod
    def diff_add(cls, t: str) -> str:
        # linha nova no diff -> verde
        return cls._wrap("32", t)

    @classmethod
    def diff_del(cls, t: str) -> str:
        # linha removida no diff -> fundo vermelho + texto branco
        return cls._wrap("41;97", t)

    # --- aliases legados (mantidos p/ compatibilidade, sem criar novas cores) ---
    @classmethod
    def cyan(cls, t: str) -> str:
        # REMOVIDO: ciano virou cinza
        return cls.gray(t)

    @classmethod
    def green(cls, t: str) -> str:
        # sucesso/destaque -> branco
        return cls.white(t)

    @classmethod
    def red(cls, t: str) -> str:
        # erro/aviso -> branco (visivel no fundo escuro)
        return cls.white(t)

    @classmethod
    def orange(cls, t: str) -> str:
        return cls.white(t)

    @classmethod
    def yellow(cls, t: str) -> str:
        return cls.gray(t)

    @classmethod
    def magenta(cls, t: str) -> str:
        return cls.gray(t)

    @classmethod
    def blue(cls, t: str) -> str:
        return cls.gray(t)


def print_tool_debug(used_msg: str) -> None:
    """Debug de tool: linha discreta em cinza (ex: used dorks: alvo)."""
    s = str(used_msg or "").strip()
    if not s:
        return
    print(Colors.gray(f"  {s}"))


_SYM_ASCII = {
    "dot": ".",
    "star": "*",
    "star2": "*",
    "star3": "*",
    "star4": "*",
    "star5": "*",
    "bullet": "*",
    "circle": "o",
    "corner": ">",
    "box_tl": "+",
    "box_tr": "+",
    "box_bl": "+",
    "box_br": "+",
    "box_h": "-",
    "box_v": "|",
    "claude_dot": "o",
    "claude_tool": ">",
    "claude_bullet": "*",
    "ok": "+",
    "fail": "x",
    "warn": "!",
    "info": "i",
    "search": "?",
    "link": ">",
    "bar_full": "#",
    "bar_empty": "-",
}

_SYM_UNI = {
    "dot": "\u00b7",
    "star": "\u2726",
    "star2": "\u2727",
    "star3": "\u22c6",
    "star4": "\u2736",
    "star5": "\u2737",
    "bullet": "\u25cf",
    "circle": "\u25cb",
    "corner": "\u2514",
    "box_tl": "\u250c",
    "box_tr": "\u2510",
    "box_bl": "\u2514",
    "box_br": "\u2518",
    "box_h": "\u2500",
    "box_v": "\u2502",
    "claude_dot": "\u25cf",
    "claude_tool": "\u25ba",
    "claude_bullet": "\u2022",
    "ok": "\u2713",
    "fail": "\u2717",
    "warn": "\u26a0",
    "info": "\u2139",
    "search": "\u2315",
    "link": "\u2197",
    "bar_full": "\u2588",
    "bar_empty": "\u2591",
}

SYM = _SYM_UNI if USE_UNICODE else _SYM_ASCII

BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

WASM_PATH = CONFIG_DIR / "sha3_wasm_bg.wasm"
WASM_URL = "https://raw.githubusercontent.com/sums001/Deepseek-API/main/deepseek/sha3_wasm_bg.wasm"
BASE_URL = "https://chat.deepseek.com"
JSON_PATH = CONFIG_DIR / "deepseek_data.json"
WORKSPACE = BASE_DIR / "workspace"
WORKSPACE.mkdir(parents=True, exist_ok=True)
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
    sessions_path: str = "/api/v0/chat_session/fetch_page"
    delete_path: str = "/api/v0/chat_session/delete"
    history_path: str = "/api/v0/chat/history_messages"
    continue_path: str = "/api/v0/chat/continue"


CONFIG = AppConfig()


class JsonStorage:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"usertoken": "", "history": []}
        try:
            raw = self.path.read_text(encoding="utf-8")
            if not raw.strip():
                raise ValueError("arquivo vazio")
            data = json.loads(raw)
            data.setdefault("usertoken", "")
            data.setdefault("history", [])
            return data
        except Exception:
            try:
                self.path.unlink(missing_ok=True)
            except Exception:
                pass
            return {"usertoken": "", "history": []}

    def save(self, data: Dict[str, Any]) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass


def clean_token(raw: str) -> str:
    t = raw.strip().strip('"').strip("'").replace("Bearer ", "").strip()
    if not t:
        return t
    if t.startswith("{"):
        try:
            obj = json.loads(t)
            if isinstance(obj, dict) and "value" in obj:
                return str(obj["value"]).strip()
        except json.JSONDecodeError:
            pass
    return t


def clean_output(text: str) -> str:
    text = re.sub(
        r"```[a-zA-Z0-9_+.#\-]*[ \t]*\r?\n?(.*?)(?:```|\Z)",
        lambda m: m.group(1).rstrip(),
        text,
        flags=re.DOTALL,
    )
    text = re.sub(r"[ \t]+\r?\n", "\n", text)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"__(.*?)__", r"\1", text)
    text = re.sub(r"(?<!\w)\*(.*?)\*(?!\w)", r"\1", text)
    text = re.sub(r"`(.*?)`", r"\1", text)
    text = re.sub(r"#{1,6}\s*", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def safe_path(p: str) -> Path:
    """Resolve caminhos conforme o modo selecionado.

    No modo normal, os arquivos ficam confinados a CONFIG.workspace.
    No modo --unsafe, caminhos absolutos e relativos podem apontar para
    qualquer local acessível pelo usuário do processo.
    """
    raw = os.path.expandvars(os.path.expanduser(str(p).strip()))

    if FULL_ACCESS_MODE:
        # Mantém a convenção da interface: workspace/foo continua sendo
        # relativo à pasta de trabalho, enquanto caminhos absolutos são
        # preservados sem a barreira de workspace.
        normalized = raw.replace("\\", "/")
        if normalized.startswith("workspace/"):
            return (CONFIG.workspace / normalized[len("workspace/"):]).resolve()
        return Path(raw).resolve()

    p_str = raw.replace("\\", "/").lstrip("/")
    if p_str.startswith("workspace/"):
        p_str = p_str[len("workspace/"):]
    full = (CONFIG.workspace / p_str).resolve()
    try:
        if not full.is_relative_to(CONFIG.workspace.resolve()):
            raise RuntimeError(f"fora de workspace: {p}")
    except AttributeError:
        if not str(full).startswith(str(CONFIG.workspace.resolve())):
            raise RuntimeError(f"fora de workspace: {p}")
    return full


def ensure_wasm() -> None:
    if CONFIG.wasm_path.exists():
        try:
            if CONFIG.wasm_path.stat().st_size < 1000:
                CONFIG.wasm_path.unlink(missing_ok=True)
            else:
                return
        except Exception:
            pass
    print(f"[wasm] baixando {CONFIG.wasm_url}...")
    try:
        CONFIG.config_dir.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(CONFIG.wasm_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(CONFIG.wasm_path, "wb") as out:
            shutil.copyfileobj(resp, out)
        if CONFIG.wasm_path.stat().st_size < 1000:
            CONFIG.wasm_path.unlink(missing_ok=True)
            raise RuntimeError("wasm baixado corrompido")
    except Exception as e:
        try:
            CONFIG.wasm_path.unlink(missing_ok=True)
        except Exception:
            pass
        print(f"[wasm] erro: {e}")
        raise


class WorkspaceManager:
    def __init__(self, root: Path):
        self.root = root

    def list_files(self) -> str:
        out: List[str] = []
        for cur_root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules", ".venv"}]
            rel = os.path.relpath(cur_root, self.root)
            out.append("workspace/" if rel == "." else f"{rel}/")
            for f in sorted(files):
                rel_file = os.path.join(rel, f) if rel != "." else f
                out.append(f"  {rel_file}")
        return "\n".join(out) if out else "workspace/ (vazio)"


@dataclass
class DiffEntry:
    path: str
    lines: List[str]
    kind: str = "edit"


class DiffTracker:
    PREVIEW = 2
    GROUP = 3

    def __init__(self) -> None:
        self.entries: List[DiffEntry] = []

    def collect(self, old_text: str, new_text: str, path: str, kind: str = "edit") -> None:
        if kind == "edit" and not (old_text or "").strip():
            kind = "new"
        old = old_text.splitlines() if old_text else []
        new = new_text.splitlines() if new_text else []
        if kind != "new" and old == new:
            return
        diff = difflib.unified_diff(old, new, fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="", n=0)
        body = [
            l for l in diff
            if not l.startswith("---") and not l.startswith("+++") and not l.startswith("@@")
        ]
        if not body:
            return
        self.entries.append(DiffEntry(path, body, kind))

    def snapshot(self) -> List[DiffEntry]:
        entries = self.entries
        self.entries = []
        return entries

    def render(self, entry: DiffEntry) -> List[str]:
        lines = entry.lines
        out: List[str] = []

        if entry.kind == "new":
            header = f"new file -> {entry.path}:"
        elif entry.kind == "delete":
            header = f"delete -> {entry.path}:"
        else:
            header = f"edit -> {entry.path}:"
        out.append(Colors.bold("  " + header))
        out.append("")

        if entry.kind == "new":
            # arquivo novo: 5 primeiras linhas em verde + resumo do resto
            for line in lines[:5]:
                body = line[1:] if line[:1] in "+-" else line
                out.append("  " + Colors.diff_add("+ " + _clip(body, 96)))
            rest = lines[5:]
            if rest:
                word = "linha" if len(rest) == 1 else "linhas"
                out.append(f"  {Colors.gray(f'- +{len(rest)} {word}')}")
        else:
            shown = lines[: self.PREVIEW]
            rest = lines[self.PREVIEW:]

            for line in shown:
                sign = line[:1]
                text = _clip(line[1:], 96)
                if sign == "+":
                    out.append("  " + Colors.diff_add("+ " + text))
                elif sign == "-":
                    out.append("  " + Colors.diff_del("- " + text))
                else:
                    out.append(f"  {text}")

            if rest:
                group = rest[: self.GROUP]
                nums = ", ".join(str(i) for i in range(self.PREVIEW + 1, self.PREVIEW + 1 + len(group)))
                word = "linha" if len(group) == 1 else "linhas"
                out.append(f"  {Colors.gray(f'- {word} ' + nums)}")
                rest = rest[self.GROUP:]

            if rest:
                word = "linha" if len(rest) == 1 else "linhas"
                out.append(f"  {Colors.gray(f'- +{len(rest)} {word}')}")

        while out and not out[-1].strip():
            out.pop()
        out.append("")
        return out

    def print_pending(self) -> int:
        entries = self.snapshot()
        for entry in entries:
            for line in self.render(entry):
                print(line)
        return len(entries)

    def show_and_clear(self) -> None:
        self.print_pending()


workspace_mgr = WorkspaceManager(CONFIG.workspace)
diff_tracker = DiffTracker()


@dataclass
class WorkflowTask:
    id: str
    description: str
    stage: str = "CRIAR"
    file_path: str = ""
    attempts: int = 0
    last_error: str = ""
    created_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    logs: List[str] = field(default_factory=list)


class WorkflowPersistence:
    STAGES = ["CRIAR", "ANALISAR", "TESTAR", "CORRIGIR", "APRESENTAR", "ABRIR", "CONCLUIDO"]

    def __init__(self, path: Path):
        self.path = path
        self.tasks: Dict[str, WorkflowTask] = {}
        self.current_task_id: Optional[str] = None
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            if not raw.strip():
                raise ValueError("vazio")
            data = json.loads(raw)
            self.current_task_id = data.get("current_task_id")
            for tid, tdata in data.get("tasks", {}).items():
                self.tasks[tid] = WorkflowTask(**tdata)
        except Exception:
            try:
                self.path.unlink(missing_ok=True)
            except Exception:
                pass
            self.tasks = {}
            self.current_task_id = None

    def save(self) -> None:
        try:
            data = {
                "current_task_id": self.current_task_id,
                "tasks": {tid: {
                    "id": t.id,
                    "description": t.description,
                    "stage": t.stage,
                    "file_path": t.file_path,
                    "attempts": t.attempts,
                    "last_error": t.last_error,
                    "created_at": t.created_at,
                    "updated_at": t.updated_at,
                    "logs": t.logs[-20:]
                } for tid, t in self.tasks.items()}
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except Exception:
            pass

    def create_task(self, description: str, file_path: str = "") -> WorkflowTask:
        # id unico (evita colisao se criar 2 tarefas no mesmo segundo)
        import uuid
        tid = f"task_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        # se ja existe tarefa ativa no mesmo arquivo, reutiliza em vez de duplicar
        for t in self.tasks.values():
            if t.file_path and t.file_path == file_path and t.stage != "CONCLUIDO":
                self.current_task_id = t.id
                self.log(t.id, f"[CRIAR] reutilizada tarefa ativa p/ {file_path}: {description[:80]}")
                self.save()
                return t
        task = WorkflowTask(id=tid, description=description, file_path=file_path, stage="CRIAR")
        self.tasks[tid] = task
        self.current_task_id = tid
        self.log(tid, f"[CRIAR] Tarefa criada: {description} -> {file_path}")
        self.save()
        return task

    def progress(self, task_id: str) -> str:
        """Barra textual de progresso do workflow (7 estagios)."""
        order = self.STAGES
        t = self.tasks.get(task_id)
        if not t:
            return ""
        try:
            idx = order.index(t.stage)
        except ValueError:
            idx = 0
        total = len(order)
        feito = "#" * (idx + 1) + "-" * (total - idx - 1)
        return f"[{feito}] {idx+1}/{total} {t.stage}"

    def next_action(self, task_id: str) -> str:
        """Diz ao agente qual o proximo passo valido (maquina de estados)."""
        t = self.tasks.get(task_id)
        if not t:
            return "crie uma tarefa com workflow_create"
        nxt = {
            "CRIAR": "use write_file para criar o codigo, depois workflow_analyze",
            "ANALISAR": "aguarde ANALISAR concluir, depois workflow_test",
            "TESTAR": "se ok -> workflow_present; se erro -> workflow_fix + edit_file + workflow_test",
            "CORRIGIR": "use edit_file/write_file para corrigir, depois workflow_test (max 5 tentativas)",
            "APRESENTAR": "depois de apresentar, use workflow_open para concluir",
            "ABRIR": "use workflow_open para marcar CONCLUIDO",
            "CONCLUIDO": "tarefa concluida. Crie outra com workflow_create se precisar.",
        }
        return nxt.get(t.stage, "use workflow_status")

    def get_current(self) -> Optional[WorkflowTask]:
        if self.current_task_id and self.current_task_id in self.tasks:
            return self.tasks[self.current_task_id]
        return None

    # transicoes validas (impede pular etapa)
    ALLOWED = {
        "CRIAR": ("ANALISAR", "CRIAR"),
        "ANALISAR": ("TESTAR", "CORRIGIR", "ANALISAR"),
        "TESTAR": ("APRESENTAR", "CORRIGIR", "TESTAR"),
        "CORRIGIR": ("TESTAR", "ANALISAR", "CORRIGIR"),
        "APRESENTAR": ("ABRIR", "APRESENTAR", "CORRIGIR"),
        "ABRIR": ("CONCLUIDO", "ABRIR"),
        "CONCLUIDO": ("CONCLUIDO",),
    }

    def set_stage(self, task_id: str, stage: str, error: str = "") -> None:
        if task_id not in self.tasks:
            return
        task = self.tasks[task_id]
        # valida transicao (mas nunca trava CORRIGIR/CONCLUIDO)
        allowed = self.ALLOWED.get(task.stage, ())
        if stage not in allowed and stage not in ("CORRIGIR", "CONCLUIDO"):
            self.log(task_id, f"[AVISO] transicao {task.stage}->{stage} fora de ordem (permitido: {allowed})")
        task.stage = stage
        task.updated_at = datetime.datetime.now().isoformat()
        if error:
            task.last_error = error[:2000]
            task.attempts += 1
            if task.attempts >= 5 and stage == "CORRIGIR":
                self.log(task_id, "[AVISO] 5 tentativas de correcao - considere reescrever ou pedir mais contexto")
        self.log(task_id, f"[{stage}] {error[:200] if error else 'ok'}")
        self.save()

    def log(self, task_id: str, msg: str) -> None:
        if task_id in self.tasks:
            self.tasks[task_id].logs.append(f"{datetime.datetime.now().isoformat()} {msg}")

    def list_tasks(self) -> str:
        if not self.tasks:
            return "nenhuma tarefa no workflow"
        out = []
        for t in self.tasks.values():
            cur = " <- atual" if t.id == self.current_task_id else ""
            out.append(f"{t.id[:8]} | {t.stage:12} | {t.file_path} | {t.description[:40]} | tentativas:{t.attempts}{cur}")
            out.append(f"         {self.progress(t.id)} | proximo: {self.next_action(t.id)}")
        return "\n".join(out)


workflow = WorkflowPersistence(CONFIG.workflow_path)


ToolFunc = Callable[[Dict[str, Any]], str]


def tool_list_files(_: Dict[str, Any]) -> str:
    return workspace_mgr.list_files()


def tool_read_file(args: Dict[str, Any]) -> str:
    path = args.get("path")
    if not path:
        return "erro: path obrigatorio"
    fp = safe_path(str(path))
    if not fp.exists():
        return f"nao existe: {path}"
    try:
        return fp.read_text(encoding="utf-8", errors="ignore")[:15000]
    except OSError as e:
        return f"erro leitura {path}: {e}"


def tool_write_file(args: Dict[str, Any]) -> str:
    path = args.get("path")
    content = args.get("content", "")
    description = args.get("description") or args.get("desc") or f"criar {path}"
    if not path:
        return "erro: path obrigatorio"
    fp = safe_path(str(path))
    old = ""
    is_new = not fp.exists()
    if not is_new:
        try:
            old = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            old = ""
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content, encoding="utf-8")
    diff_tracker.collect("" if is_new else old, content, str(path), "new" if is_new else "edit")

    try:
        current = workflow.get_current()
        if not current or current.file_path != str(path):
            task = workflow.create_task(description, str(path))
        else:
            task = current
            task.file_path = str(path)
        workflow.set_stage(task.id, "CRIAR")
        workflow.set_stage(task.id, "ANALISAR")
    except Exception:
        pass

    return f"ok {path} ({'novo' if is_new else 'editado'}) [workflow: CRIAR->ANALISAR]"


def tool_edit_file(args: Dict[str, Any]) -> str:
    path = args.get("path")
    old_txt = args.get("old_text")
    new_txt = args.get("new_text", "")
    if not path or old_txt is None:
        return "erro: path e old_text obrigatorios"
    fp = safe_path(str(path))
    if not fp.exists():
        return f"nao existe: {path}"
    full = fp.read_text(encoding="utf-8", errors="ignore")
    if old_txt not in full:
        return "old_text nao encontrado"
    new_full = full.replace(old_txt, new_txt, 1)
    fp.write_text(new_full, encoding="utf-8")
    diff_tracker.collect(full, new_full, str(path))
    return f"editado {path}"


def tool_delete_file(args: Dict[str, Any]) -> str:
    path = args.get("path")
    if not path:
        return "erro: path obrigatorio"
    fp = safe_path(str(path))
    old = ""
    if fp.exists() and fp.is_file():
        try:
            old = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            old = ""
    try:
        if fp.is_dir():
            shutil.rmtree(fp)
        else:
            fp.unlink(missing_ok=True)
        diff_tracker.collect(old, "", str(path), "delete")
        return f"deletado {path}"
    except OSError as e:
        return f"erro deletar {path}: {e}"


def tool_rename_file(args: Dict[str, Any]) -> str:
    src = args.get("from") or args.get("path")
    dst = args.get("to")
    if not src or not dst:
        return "erro: from e to obrigatorios"
    s = safe_path(str(src))
    d = safe_path(str(dst))
    d.parent.mkdir(parents=True, exist_ok=True)
    try:
        s.rename(d)
        return f"{src} -> {dst}"
    except OSError as e:
        return f"erro rename: {e}"


def tool_mkdir(args: Dict[str, Any]) -> str:
    p = args.get("path")
    if not p:
        return "erro: path obrigatorio"
    safe_path(str(p)).mkdir(parents=True, exist_ok=True)
    return f"dir {p}"


def tool_shell(args: Dict[str, Any]) -> str:
    cmd = args.get("command") or args.get("cmd") or ""
    if not cmd:
        return "erro: command obrigatorio"
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
        result = subprocess.run(
            full_cmd, cwd=cwd_str, capture_output=True, text=True,
            timeout=args.get("timeout", 60), shell=False
        )
        out = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        return f"exit={result.returncode}\n{out.strip()[:8000]}"
    except subprocess.TimeoutExpired:
        return "erro: timeout"
    except Exception as e:
        return f"erro {e}"


def _clean_html_to_text(html: str) -> str:
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


_BROWSER_FILE_EXTS = frozenset(
    "py js ts jsx tsx java c h cpp hpp go rs php rb sh bat ps1 md rst txt log "
    "json yml yaml toml ini cfg conf csv tsv html htm css scss sql pdf png jpg "
    "jpeg gif svg webp ico mp4 mp3 zip tar gz exe dll so db sqlite".split()
)


def _looks_like_local_file(u: str) -> bool:
    """True se a string parece caminho de arquivo local, nao URL."""
    s = str(u or "").strip()
    if not s:
        return False
    low = s.lower()
    if low.startswith("file:"):
        return True
    if re.match(r"^[a-zA-Z]:[\\/]", s):
        return True
    if s.startswith(("/", "./", "../", "~/", "\\")):
        return True
    try:
        if pathlib.Path(s).exists():
            return True
    except Exception:
        pass
    if "://" in s:
        return False  # tem scheme (http etc) -> trata como URL
    host = s.split("/")[0].split("?")[0].split("#")[0]
    bare = host.split(":")[0].strip().lower()
    if bare == "localhost":
        return False
    if not host or "." not in host:
        return True
    if "/" not in s and "?" not in s and "#" not in s:
        suf = host.rsplit(".", 1)[-1].lower()
        if suf in _BROWSER_FILE_EXTS:
            return True
    return False


def tool_open_browser(args: Dict[str, Any]) -> str:
    """Abre uma URL http(s) no navegador padrao. NAO abre arquivo local."""
    import webbrowser
    url = str(args.get("url") or args.get("link") or args.get("target") or "").strip().strip("'\"")
    if not url:
        return "erro: mande 'url'"
    if _looks_like_local_file(url):
        return (f"erro: open_browser abre URL http(s), nao arquivo local ('{url}'). "
                'Para ler arquivo use read_file. Para site use {"url":"https://..."}')
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url.lstrip("/")
    try:
        webbrowser.open(url)
    except Exception as e:
        return f"erro ao abrir {url}: {e}"
    return f"aberto no navegador: {url}"


def tool_fetch(args: Dict[str, Any]) -> str:
    url = args.get("url") or args.get("link") or ""
    if not url:
        return "url vazia"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
    }

    def try_get(u: str) -> str:
        r = _osint_client().get(u, timeout=10.0, headers=headers)
        r.raise_for_status()
        txt = _clean_html_to_text(r.text)[:10000]
        if len(txt) < 200 or ("captcha" in txt.lower() and len(txt) < 1000):
            raise RuntimeError("conteudo bloqueado ou muito curto")
        return txt

    try:
        txt = try_get(url)
        return f"fetch {url}: {txt[:8000]}"
    except Exception:
        try:
            bypass = f"https://api.allorigins.win/raw?url={urllib.parse.quote(url)}"
            txt = try_get(bypass)
            return f"fetch {url} via bypass: {txt[:8000]}"
        except Exception as e:
            return f"erro fetch {url}: {e}"


def tool_search(args: Dict[str, Any]) -> str:
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "query vazia"
    try:
        url = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote(q)}"
        r = httpx.get(
            url, timeout=15,
            headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "pt-BR"},
            follow_redirects=True
        )
        txt = _clean_html_to_text(r.text)[:12000]
        if len(txt) < 200:
            return f"web search '{q}' sem resultados"
        return f"web search '{q}': {txt[:8000]}"
    except Exception as e:
        return f"erro search {q}: {e}"


def tool_grep(args: Dict[str, Any]) -> str:
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "query vazia"
    try:
        url = f"https://grep.app/search?q={urllib.parse.quote(q)}"
        r = httpx.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        txt = _clean_html_to_text(r.text)[:8000]
        return f"grep.app '{q}': {txt[:6000]}"
    except Exception as e:
        return f"erro grep {q}: {e}"


def tool_google_github(args: Dict[str, Any]) -> str:
    q = args.get("query") or args.get("q") or args.get("intext") or ""
    if not q:
        return "query vazia"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
    }

    def try_get(u: str) -> str:
        r = httpx.get(u, timeout=15, follow_redirects=True, headers=headers)
        r.raise_for_status()
        txt = _clean_html_to_text(r.text)[:12000]
        if len(txt) < 200:
            raise RuntimeError("bloqueado ou curto")
        return txt

    google_url = f"https://www.google.com/search?q={urllib.parse.quote(q)}"
    try:
        txt = try_get(google_url)
        if "detected unusual traffic" in txt.lower() or "captcha" in txt.lower() or len(txt) < 500:
            raise RuntimeError("google bloqueou")
        return f"google '{q}': {txt[:8000]} | url: {google_url}"
    except Exception:
        try:
            bypass_url = f"https://api.allorigins.win/raw?url={urllib.parse.quote(google_url)}"
            txt = try_get(bypass_url)
            return f"google '{q}' via bypass: {txt[:8000]}"
        except Exception as e:
            try:
                ddg_url = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote(q)}"
                txt = try_get(ddg_url)
                return f"ddg fallback '{q}': {txt[:8000]}"
            except Exception as e2:
                return f"erro google '{q}': {e} / {e2}"


def tool_google_site(args: Dict[str, Any]) -> str:
    site = args.get("site") or args.get("domain") or ""
    q = args.get("query") or args.get("q") or args.get("intext") or ""
    if not q and not site:
        return "query vazia - use site e query, ex: site=github.com query=mta parser"
    if site and q:
        full_q = f"site:{site} {q}"
    elif site:
        full_q = f"site:{site}"
    else:
        full_q = q
    return tool_google_github({"query": full_q})


_FREEMAIL = {
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.com.br",
    "live.com", "icloud.com", "protonmail.com", "proton.me", "bol.com.br",
    "uol.com.br", "terra.com.br", "globo.com", "globomail.com", "msn.com",
    "aol.com", "zoho.com", "mail.com", "gmx.com", "yandex.com",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:com\.br|com|net|org|io|dev|app|info|biz|gov\.br|edu\.br|br|co|me|tv|xyz|site|online|store)\b", re.IGNORECASE)
_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])@([A-Za-z0-9_][A-Za-z0-9_.]{2,29})\b")
_PHONE_RE = re.compile(r"(?:\+?55[\s\-.]?)?\(?\d{2}\)?[\s\-.]?9?\d{4}[\s\-.]?\d{4}\b")
_CNPJ_RE = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}\-?\d{2}\b")
_NAME_QUOTED_RE = re.compile(r"[\"'\u201c\u201d]([^\n\"'\u201c\u201d]{3,60})[\"'\u201c\u201d]")
_NAME_CAPS_RE = re.compile(r"\b([A-Z\u00c0-\u00dd]{3,}(?:\s+(?:D[AEOS]?\s+)?[A-Z\u00c0-\u00dd]{2,}){1,3})\b")
_NAME_TITLE_RE = re.compile(r"\b([A-Z\u00c0-\u00dd][a-z\u00e0-\u00ff]{1,20}(?:\s+(?:d[aeo]s?\s+)?[A-Z\u00c0-\u00dd][a-z\u00e0-\u00ff]{1,20}){1,3})\b")

_NAME_NOISE = {
    "OSINT", "CNPJ", "CPF", "RG", "PDF", "HTTP", "HTTPS", "JSON", "HTML", "SITE",
    "GOOGLE", "BUSQUE", "BUSCAR", "PROCURE", "ACHE", "INFORMA", "INFORMACOES",
    "DOCUMENTO", "PROCESSO", "TELEFONE", "EMAIL", "ENDERECO", "EMPRESA", "NOME",
    "CIDADE", "ESTADO", "BRASIL", "ALVO", "DADOS", "PESSOA", "PERFIL", "CONTA",
}


# ---- higiene anti-falso-positivo (buscadores vazam lixo nas respostas) ----
_SERVICE_HOSTS = {
    # busca / erro / infra
    "google.com", "bing.com", "duckduckgo.com", "mojeek.com", "brave.com",
    "yahoo.com", "ecosia.org", "googleusercontent.com", "gstatic.com",
    "allorigins.win", "startpage.com",
    # social / tec / docs (infraestrutura, nao ativo do alvo)
    "instagram.com", "facebook.com", "fb.com", "x.com", "twitter.com",
    "linkedin.com", "tiktok.com", "youtube.com", "youtu.be", "kwai.com",
    "threads.net", "pinterest.com", "reddit.com", "telegram.me", "t.me",
    "github.com", "gitlab.com", "gist.github.com", "pastebin.com", "paste.ee",
    "ghostbin.com", "rentry.co", "shodan.io", "censys.io", "crt.sh",
    "web.archive.org", "who.is", "viewdns.info", "urlscan.io", "virustotal.com",
    "jusbrasil.com.br", "escavador.com", "cnpj.biz", "cnpj.ws",
    "lattes.cnpq.br", "brasilapi.com.br",
}


def _is_service_host(host: str) -> bool:
    h = str(host or "").lower().strip().replace("www.", "")
    if not h:
        return True
    for s in _SERVICE_HOSTS:
        if h == s or h.endswith("." + s):
            return True
    if h.endswith(".gov.br") or h.endswith(".edu.br"):
        return True
    return False


_JUNK_EMAIL_USERS = {"error", "error-lite", "noreply", "no-reply", "donotreply"}

_HANDLE_BLOCK = {
    "linkedin", "facebook", "instagram", "github", "google", "duckduckgo",
    "youtube", "tiktok", "twitter", "reddit", "pinterest", "threads", "roblox",
    "telegram", "bing", "mojeek", "yahoo", "yandex", "brave", "ecosia",
    "site", "https", "http", "www", "com", "net", "org", "gov", "html",
    "aspx", "php", "perfil", "profile", "user", "users", "search", "login",
}
_HANDLE_TLD_RE = re.compile(
    r"\.(com|br|net|org|io|dev|app|info|biz|gov|edu|co|me|tv|xyz|site|online|store)(\b|$)",
    re.IGNORECASE,
)


def _valid_handle(h: str) -> bool:
    h = str(h or "").strip().lstrip("@").lower()
    if not (3 <= len(h) <= 30):
        return False
    if h in _HANDLE_BLOCK:
        return False
    if _HANDLE_TLD_RE.search(h):  # "linkedin.com" e dominio, nao handle
        return False
    if not re.fullmatch(r"[a-z0-9_.]+", h):
        return False
    if h.startswith((".", "_")) or h.endswith((".", "_")):
        return False
    return True


_COMPANY_WORDS = {
    "duck", "duckduckgo", "google", "bing", "mojeek", "yahoo", "yandex", "brave",
    "ecosia", "github", "gitlab", "linkedin", "facebook", "instagram", "tiktok",
    "youtube", "twitter", "reddit", "pinterest", "threads", "roblox", "telegram",
    "error", "lite", "search", "results", "result", "found", "page", "site",
    "http", "https", "www", "html", "login", "profile", "perfil", "user",
    "filetype", "intext", "intitle", "inurl", "ext", "or", "and", "not",
    "com", "net", "org", "gov", "br", "index", "backup", "dump",
}
_CONECTIVOS_LOWER = {"de", "da", "do", "das", "dos", "e", "del", "della", "van", "von", "d"}


def _valid_person_name(s: str) -> bool:
    """Nome de pessoa plausivel: 2-5 palavras, sem sintaxe de busca, sem marca."""
    s = " ".join(str(s or "").split())
    if not s or len(s) < 4 or len(s) > 60:
        return False
    low = s.lower()
    if "@" in s or "http" in low or ".com" in low or "site:" in low or "filetype" in low:
        return False
    if re.search(r'[0-9_(){}\[\]:;!?$%#&*+=|<>]', s):
        return False
    if '"' in s or "'" in s:
        return False
    words = s.split()
    if len(words) < 2 or len(words) > 5:
        return False
    for w in words:
        wl = w.lower().strip(".")
        if wl in _COMPANY_WORDS:
            return False
        if w.upper() in _NAME_NOISE:
            return False
        if wl in _CONECTIVOS_LOWER:
            continue
        if len(wl) < 2:
            return False
        if not re.fullmatch(r"[A-Za-z\u00c0-\u00ff]+", w):
            return False
    return True


def _dedupe(items: List[str]) -> List[str]:
    out: List[str] = []
    seen: set = set()
    for i in items:
        k = str(i).strip()
        if not k or k.lower() in seen:
            continue
        seen.add(k.lower())
        out.append(k)
    return out


def osint_entities(text: str) -> Dict[str, List[str]]:
    t = str(text or "")
    out: Dict[str, List[str]] = {
        "emails": [], "domains": [], "phones": [], "cnpjs": [], "handles": [], "names": [],
    }

    _raw_emails = _dedupe(_EMAIL_RE.findall(t))
    _clean_emails = []
    for em in _raw_emails:
        user, _, dom = em.partition("@")
        ul = user.lower()
        if ul in _JUNK_EMAIL_USERS or ul.startswith("error") or ul.startswith("noreply"):
            continue  # ex: error-lite+xxxx@duckduckgo.com (pagina de erro do buscador)
        if _is_service_host(dom):
            continue
        _clean_emails.append(em)
    out["emails"] = _clean_emails

    for dm in _DOMAIN_RE.findall(t):
        low = dm.lower()
        if low in _FREEMAIL or _is_service_host(low):
            continue
        out["domains"].append(low)
    for em in out["emails"]:
        dom = em.split("@")[-1].lower()
        if dom not in _FREEMAIL and not _is_service_host(dom):
            out["domains"].append(dom)
    out["domains"] = _dedupe(out["domains"])

    for ph in _PHONE_RE.findall(t):
        digits = re.sub(r"\D", "", ph)
        if 10 <= len(digits) <= 13:
            out["phones"].append(ph.strip())
    out["phones"] = _dedupe(out["phones"])
    out["cnpjs"] = _dedupe(_CNPJ_RE.findall(t))
    out["handles"] = [h for h in _dedupe(_HANDLE_RE.findall(t)) if _valid_handle(h)]

    names: List[str] = []
    for m in _NAME_QUOTED_RE.findall(t):
        cand = m.strip()
        if len(cand) >= 4 and " " in cand and not _EMAIL_RE.search(cand):
            names.append(cand)
    for m in _NAME_CAPS_RE.findall(t):
        words = [w for w in m.split() if w.lower() not in ("d", "de", "da", "do", "dos", "das")]
        if len(words) >= 2 and not any(w in _NAME_NOISE for w in words):
            names.append(m.strip())
    for m in _NAME_TITLE_RE.findall(t):
        words = [w for w in m.split() if w.lower() not in ("d", "de", "da", "do", "dos", "das")]
        if len(words) < 2:
            continue
        if any(w.upper() in _NAME_NOISE for w in words):
            continue
        if len(" ".join(words)) < 5:
            continue
        names.append(m.strip())
    out["names"] = _dedupe(names)[:4]
    return out


_OSINT_TRIGGER_RE = re.compile(
    r"busc|procur|ache|investiga|descobr|osint|dork|quem e|telefone|endereco|"
    r"cnpj|cpf|perfil|rede social|processo|diario oficial|vazou|vazamento",
    re.IGNORECASE,
)


def _looks_like_osint_target(q: str) -> bool:
    """Heuristica rapida: a mensagem parece um pedido de investigacao com alvo?"""
    try:
        ent = osint_entities(q or "")
        if any(ent.values()):
            return True
    except Exception:
        pass
    return bool(_OSINT_TRIGGER_RE.search(q or ""))


_GREETING_WORDS = {
    "eai", "e", "ai", "oi", "oie", "oii", "opa", "ola", "hey", "hello", "hi",
    "tudo", "bem", "bom", "boa", "dia", "tarde", "noite", "como", "vai",
    "beleza", "blz", "fala", "salve", "mano", "cara", "brother", "tru",
    "tranquilo", "tranquila", "suave", "certo", "ok", "valeu", "obrigado",
    "obrigada", "por", "favor", "me", "ajuda", "ajudar", "preciso", "de",
}


def _is_greeting_only(text_in: str) -> bool:
    """True se a entrada e so saudacao/smalltalk, sem identificador OSINT.
    'eai tudo bem', 'oi', 'bom dia', 'fala mano' -> True (NAO investigar).
    Qualquer e-mail/@/telefone/CNPJ/nome proprio -> False (investigar)."""
    t = str(text_in or "")
    if not t.strip():
        return True
    # qualquer entidade OSINT valida => nao e saudacao
    try:
        ent = osint_entities(t)
        if any(ent.values()):
            return False
    except Exception:
        pass
    toks = re.findall(r"[a-z]+", _strip_accents(t).lower())
    if not toks:
        return True
    if len(toks) > 14:
        return False
    # nome proprio com sobrenome (2+ palavras fora do dicionario) => possivel alvo
    estranhas = [w for w in toks if w not in _GREETING_WORDS]
    if len(estranhas) >= 2:
        return False
    return all(w in _GREETING_WORDS for w in toks)


_SELF_REF_RE = re.compile(
    r"\b(voce|você|vc|cê|tu|ti|contigo|seu|seus|sua|suas|teu|teus|tua|tuas)\b",
    re.IGNORECASE,
)
_QUESTION_RE = re.compile(
    r"\?|^\s*(quais?|como|o\s*que|oque|por\s*que|porque|quando|onde|quem|"
    r"me\s+(explica|fala|diz|conta)|explica|lista|liste|cita|cite)\b",
    re.IGNORECASE,
)
_CAPABILITY_RE = re.compile(
    r"\b(aces?sos?|frameworks?|arsenal|tools?|ferramentas?|buscadores?|"
    r"como funciona|capaz|capacidade|consegue fazer)\b",
    re.IGNORECASE,
)


def _is_meta_question(text_in: str) -> bool:
    """Pergunta sobre o proprio agente, sem identificador OSINT: NAO cobrar investigacao.
    'quais seus acessos', 'como voce funciona', 'quais suas tools' -> True.
    Qualquer e-mail/@/telefone/CNPJ/nome proprio -> False (pode ser alvo)."""
    t = str(text_in or "")
    if not t.strip():
        return True
    try:
        ent = osint_entities(t)
        if any(ent.values()):
            return False
    except Exception:
        pass
    if _SELF_REF_RE.search(t) and _QUESTION_RE.search(t):
        return True
    if _CAPABILITY_RE.search(t) and _QUESTION_RE.search(t):
        return True
    return False


_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")
_SKIP_URL = ("google.com", "duckduckgo.com", "gstatic", "googleusercontent", "bing.com", "allorigins")


def _recon_jobs(user_text: str) -> List[Tuple[str, Dict[str, Any]]]:
    ent = osint_entities(user_text)
    jobs: List[Tuple[str, Dict[str, Any]]] = []
    if ent.get("handles"):
        jobs.append(("osint_handles", {"handle": ent["handles"][0]}))
    elif ent.get("names"):
        for prob in _probable_handles(ent["names"][0], 1):
            jobs.append(("osint_handles", {"handle": prob}))
    if ent.get("emails"):
        jobs.append(("osint_email", {"email": ent["emails"][0]}))
    if ent.get("domains"):
        jobs.append(("osint_domain", {"domain": ent["domains"][0]}))
    if ent.get("cnpjs"):
        jobs.append(("osint_cnpj", {"cnpj": ent["cnpjs"][0]}))
    if ent.get("phones"):
        jobs.append(("osint_phone", {"phone": ent["phones"][0]}))
    return jobs


# =====================================================================
# MOTOR DE RACIOCINIO OSINT v2 - varredura humana com interligacoes
# - Pensa como pessoa: cada achado gera nova busca (grafo de entidades)
# - META: minimo 5 fatos do ALVO + 3 do PAI + 3 da MAE (com link)
# - OVERLAP: ate 5 variacoes sobrepostas por categoria; se nao achar, pula
# =====================================================================
OSINT_MIN_TARGET_FACTS = 5
OSINT_MIN_PARENT_FACTS = 3
OSINT_OVERLAP_ROUNDS = 5

# filiacao / parentesco (pt-BR)
_FILIACAO_RE = re.compile(
    r"(?:filho|filha)\s*(?:de|do|da)\s*([A-ZÀ-Ü][A-Za-zÀ-ÿ\.\'\-]+(?:\s+(?:de|da|do|das|dos|e)\s+)?(?:\s+[A-ZÀ-Ü][A-Za-zÀ-ÿ\.\'\-]+){1,4})",
    re.IGNORECASE,
)
_PAI_RE = re.compile(
    r"(?:nome\s*do\s*pai|pai\s*[:\-]\s*|paternidade\s*[:\-]\s*)([A-ZÀ-Ü][A-Za-zÀ-ÿ]+(?:\s+[A-Za-zÀ-ÿ]+){1,4})",
    re.IGNORECASE,
)
_MAE_RE = re.compile(
    r"(?:nome\s*da\s*m[ãa]e|m[ãa]e\s*[:\-]\s*|maternidade\s*[:\-]\s*)([A-ZÀ-Ü][A-Za-zÀ-ÿ]+(?:\s+[A-Za-zÀ-ÿ]+){1,4})",
    re.IGNORECASE,
)
_PAI_LOOSE_RE = re.compile(r"\bpai\b[^\n]{0,40}?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})")
_MAE_LOOSE_RE = re.compile(r"\bm[ãa]e\b[^\n]{0,40}?([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})")
_NASC_RE2 = re.compile(r"(?:nasc(?:eu|imento|ido)?[^\d]{0,20})(\d{2}/\d{2}/\d{4}|\d{4})", re.IGNORECASE)

# categorias de varredura (ordem humana: do facil ao dificil)
OSINT_SWEEP_CATEGORIES = ("redes", "telefone", "endereco", "docs", "processos", "pai", "mae")


def _clean_person_name(s: str) -> str:
    s = " ".join(str(s or "").split()).strip(" .,-:|\"'")
    if len(s) < 4 or len(s) > 70:
        return ""
    # precisa ter ao menos nome + sobrenome
    if " " not in s:
        return ""
    # remove sujeira comum
    low = s.lower()
    for ruim in ("não confirmado", "nao confirmado", "desconhecido", "nome do pai", "nome da mae",
                 "nome da mãe", "filiacao", "filiação", "processo", "telefone", "endereco"):
        if ruim in low:
            return ""
    if not _valid_person_name(s):  # mata "Go Duck", sintaxe de dork, marca, etc
        return ""
    return s


def osint_extract_parents(evidence: str) -> Dict[str, List[str]]:
    """Extrai candidatos a PAI e MAE da evidencia bruta (como humano leria)."""
    ev = str(evidence or "")
    pais: List[str] = []
    maes: List[str] = []
    for rx in (_PAI_RE, _FILIACAO_RE):
        for m in rx.findall(ev):
            n = _clean_person_name(m)
            if n and n not in pais and n not in maes:
                pais.append(n)
    for m in _MAE_RE.findall(ev):
        n = _clean_person_name(m)
        if n and n not in maes and n not in pais:
            maes.append(n)
    # fallback solto (menos confiavel): so adiciona se ainda vazio
    if not pais:
        for m in _PAI_LOOSE_RE.findall(ev):
            n = _clean_person_name(m)
            if n and n not in pais and n not in maes:
                pais.append(n)
            if len(pais) >= 3:
                break
    if not maes:
        for m in _MAE_LOOSE_RE.findall(ev):
            n = _clean_person_name(m)
            if n and n not in maes and n not in pais:
                maes.append(n)
            if len(maes) >= 3:
                break
    return {"pai": _dedupe(pais)[:3], "mae": _dedupe(maes)[:3]}


def osint_build_parent_dorks(parent_name: str, alvo_last: str = "", city: str = "", uf: str = "") -> List[str]:
    """Dorks especificas para confirmar PAI/MAE (5 variacoes = 1 overlap completo)."""
    pn = " ".join(str(parent_name or "").split())
    if not pn:
        return []
    pn_nc = _strip_accents(pn)
    out = [
        f'"{pn}"',
        f'"{pn}" "{alvo_last}"' if alvo_last else f'"{pn}" filho',
        f'"{pn}" {city}' if city else f'"{pn}" {uf}' if uf else f'"{pn_nc}"',
        f'"{pn}" site:facebook.com OR site:instagram.com OR site:jusbrasil.com.br',
        f'"{pn_nc}" filetype:pdf OR site:gov.br OR site:escavador.com',
    ]
    return [d for d in out if d.strip()][:OSINT_OVERLAP_ROUNDS]


def osint_interlinks(evidence: str, alvo: str = "") -> List[str]:
    """Monta as INTERLIGACOES como uma pessoa normal faria:
    mesmo email/@/telefone/sobrenome/empresa/cidade em 2+ fontes => mesma pessoa/nucleo."""
    ev = str(evidence or "")
    links: List[str] = []
    try:
        ent = osint_entities(ev)
    except Exception:
        return []
    # email repetido
    for em in (ent.get("emails") or [])[:4]:
        if ev.lower().count(em.lower()) >= 2:
            user = em.split("@")[0]
            links.append(f"mesmo e-mail {em} em 2+ fontes => mesmo dono; buscar '{user}' como @handle")
    # handle repetido
    for h in (ent.get("handles") or [])[:4]:
        if len(h) >= 4 and ev.lower().count(h.lower()) >= 2:
            links.append(f"mesmo @{h} em 2+ sites => mesma pessoa; abrir perfis e extrair nome/cidade/bio")
    # telefone / DDD
    for ph in (ent.get("phones") or [])[:4]:
        dg = re.sub(r"\D", "", ph)
        if len(dg) >= 10:
            links.append(f"telefone {ph} => buscar com/sem mascara, com/sem 55, e cruzar DDD com cidade")
            break
    # dominio
    for dm in (ent.get("domains") or [])[:2]:
        links.append(f"dominio {dm} => crt.sh/wayback/DNS + buscar \"@{dm}\" fora do proprio site")
    # sobrenome + cidade (possivel parente)
    try:
        vals = _dork_values(alvo or ev[:300])
        last = vals.get("last", "")
        city = vals.get("city", "") or vals.get("uf", "")
        if last and city:
            links.append(f"sobrenome '{last}' + '{city}' => possivel nucleo familiar; buscar pai/mae com filiacao")
        elif last:
            links.append(f"sobrenome '{last}' sozinho => buscar \"{last}\" + cidade/empresa/profissao")
    except Exception:
        pass
    # CNPJ/socios
    if ent.get("cnpjs"):
        links.append("CNPJ achado => abrir socios e cruzar mesmo sobrenome/endereco/CEP = mesmo grupo")
    return _dedupe(links)[:8]


def osint_count_facts(evidence: str) -> Dict[str, int]:
    """Conta fatos com link (proxy rapido da meta 5/3/3)."""
    ev = str(evidence or "")
    urls = set()
    for u in _URL_RE.findall(ev):
        u = u.rstrip(".,);]'\"")
        if any(s in u for s in _SKIP_URL):
            continue
        urls.add(u)
    return {"links": len(urls)}


def osint_sweep_overlap(
    alvo: str,
    base_evidence: str = "",
    progress: Optional[Callable] = None,
    max_rounds: int = OSINT_OVERLAP_ROUNDS,
) -> Tuple[str, List[str], Dict[str, Any]]:
    """VARREDURA COM OVERLAP (raciocinio humano):
    - Roda ate `max_rounds` (padrao 5) rodadas sobrepostas.
    - Cada rodada gera novas buscas A PARTIR do que foi descoberto (pivo).
    - Se uma categoria nao rende apos 5 overlaps, pula pra proxima (pai/mae inclusive).
    - Retorna (texto_evidence, dorks_usadas, resumo {pais, maes, interligacoes, cobertura}).
    """
    import concurrent.futures

    alvo = " ".join(str(alvo or "").split())
    if not alvo:
        return "", [], {}
    try:
        vals = _dork_values(alvo)
    except Exception:
        vals = {}
    name = vals.get("name", "") or alvo
    last = vals.get("last", "")
    city = vals.get("city", "")
    uf = vals.get("uf", "")

    evidences: List[str] = []
    if base_evidence:
        evidences.append(str(base_evidence))
    todas_dorks: List[str] = []
    conhecimento = str(base_evidence or "")
    sem_progresso = 0

    for rodada in range(1, max_rounds + 1):
        # --- pivo: o que ja sabemos vira nova busca (como humano faria) ---
        try:
            ent = osint_entities(conhecimento)
        except Exception:
            ent = {}
        pais_maes = osint_extract_parents(conhecimento)

        candidatas: List[str] = []
        # 1) se achou pai/mae candidato, confirma com dorks proprias
        for pn in (pais_maes.get("pai") or [])[:1]:
            candidatas += osint_build_parent_dorks(pn, last, city, uf)
        for mn in (pais_maes.get("mae") or [])[:1]:
            candidatas += osint_build_parent_dorks(mn, last, city, uf)
        # 2) se achou email/handle novo, pivota neles
        for em in (ent.get("emails") or [])[:1]:
            u = em.split("@")[0]
            candidatas.append(f'"{em}"')
            if u and len(u) >= 3:
                candidatas.append(f'"{u}" site:github.com OR site:instagram.com OR site:x.com')
        for h in (ent.get("handles") or [])[:1]:
            if h and h.lower() not in alvo.lower():
                candidatas.append(f'"{h}"')
        # 3) se achou telefone, varia mascara
        for ph in (ent.get("phones") or [])[:1]:
            dg = re.sub(r"\D", "", ph)
            if dg:
                candidatas.append(f'"{dg}"')
                if len(dg) >= 10:
                    candidatas.append(f'"{dg[-11:]}"' if len(dg) >= 11 else f'"{dg[-10:]}"')
        # 4) sobrenome + cidade/empresa (parentes e vinculos)
        if last:
            if city:
                candidatas.append(f'"{last}" "{city}"')
            if uf and uf != city:
                candidatas.append(f'"{last}" {uf}')
            candidatas.append(f'"{name}" "filho de"')
            candidatas.append(f'"{name}" filiacao')
        # 5) fallback: varia o nome (ordem/grafia) - overlap classico
        first = vals.get("first", "")
        if first and last:
            nc = _strip_accents(name)
            candidatas += [f'"{last} {first}"', f'"{nc}"', f'intext:"{last}" intext:"{first}"']

        # dedupe contra as ja usadas
        novas: List[str] = []
        for d in candidatas:
            d = " ".join(str(d or "").split())
            if d and d.lower() not in {x.lower() for x in todas_dorks} and d not in novas:
                novas.append(d)
            if len(novas) >= 5:
                break
        if not novas:
            break

        # --- executa a rodada em paralelo ---
        before_links = osint_count_facts(conhecimento).get("links", 0)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(5, len(novas)), thread_name_prefix="overlap"
        ) as ex:
            futs = {ex.submit(osint_search_one, d, "auto", 5.0): d for d in novas}
            try:
                for fut in concurrent.futures.as_completed(futs, timeout=40):
                    d = futs[fut]
                    try:
                        res = fut.result(timeout=25)
                    except Exception as e:
                        res = f"erro: {type(e).__name__}: {e}"
                    todas_dorks.append(d)
                    bloco = f"[OVERLAP r{rodada}] {d}\n{_clip(str(res), 800)}"
                    evidences.append(bloco)
                    conhecimento += "\n" + bloco
                    if progress:
                        try:
                            progress(f"overlap r{rodada}", len(todas_dorks), len(todas_dorks) + 1, d)
                        except Exception:
                            pass
            except concurrent.futures.TimeoutError:
                evidences.append(f"(overlap r{rodada}: tempo esgotado, parcial)")
        after_links = osint_count_facts(conhecimento).get("links", 0)
        # se 2 rodadas sem link novo, para cedo (pula pra proxima coisa)
        if after_links <= before_links:
            sem_progresso += 1
        else:
            sem_progresso = 0
        if sem_progresso >= 2:
            break

    pais_maes = osint_extract_parents(conhecimento)
    resumo = {
        "pai_candidatos": pais_maes.get("pai", []),
        "mae_candidatos": pais_maes.get("mae", []),
        "interligacoes": osint_interlinks(conhecimento, alvo),
        "cobertura": osint_count_facts(conhecimento),
        "rodadas": min(max_rounds, (len(todas_dorks) + 4) // 5) if todas_dorks else 0,
    }
    return "\n\n".join(evidences), todas_dorks, resumo


def osint_recon_target(user_text: str, progress: Optional[Callable] = None) -> str:
    import concurrent.futures

    jobs = _recon_jobs(user_text)
    if not jobs:
        return ""

    fn_map = {
        "osint_handles": tool_osint_handles,
        "osint_email": tool_osint_email,
        "osint_domain": tool_osint_domain,
        "osint_cnpj": tool_osint_cnpj,
        "osint_phone": tool_osint_phone,
    }
    labels = {"osint_handles": "perfis", "osint_email": "e-mail", "osint_domain": "dominio",
              "osint_cnpj": "cnpj", "osint_phone": "telefone"}
    parts: List[str] = []
    total = len(jobs)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=total, thread_name_prefix="recon") as ex:
        futs = {}
        for name, args in jobs:
            fn = fn_map.get(name) or TOOLS.get(name)
            if fn:
                futs[ex.submit(fn, args)] = name
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=50):
                name = futs[fut]
                try:
                    parts.append(f"=== {name} ===\n{_clip(str(fut.result(timeout=45)), 2800)}")
                except Exception as e:
                    parts.append(f"=== {name} ===\n erro: {type(e).__name__}: {e}")
                done += 1
                if progress:
                    try:
                        progress("recon", done, total, labels.get(name, name))
                    except Exception:
                        pass
        except concurrent.futures.TimeoutError:
            parts.append("(recon: tempo esgotado, resultados parciais acima)")
    return "\n\n".join(parts)


def osint_autopilot(
    user_text: str,
    limit: int = 10,
    fetches: int = 2,
    progress: Optional[Callable] = None,
) -> Tuple[str, List[str]]:
    """Bateria automatica: dorks em paralelo, depois fetch+recon em paralelo."""
    import concurrent.futures

    dorks = osint_build_dorks(user_text, limit)
    if not dorks:
        return "", []

    # FASE 1 - dorks em paralelo
    blocks: List[str] = []
    total = len(dorks)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(10, total), thread_name_prefix="dork"
    ) as ex:
        futs = {ex.submit(osint_search_one, d, "auto", 5.0): d for d in dorks}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=45):
                dork = futs[fut]
                try:
                    res = fut.result(timeout=30)
                except Exception as e:
                    res = f"erro: {type(e).__name__}: {e}"
                blocks.append(f"[DORK] {dork}\n{_clip(str(res), 900)}")
                done += 1
                if progress:
                    try:
                        progress("dorks", done, total, dork)
                    except Exception:
                        pass
        except concurrent.futures.TimeoutError:
            blocks.append("(tempo esgotado nas buscas: resultados parciais)")

    # FASE 2 - fetch + recon
    urls: List[str] = []
    for b in blocks:
        for u in _URL_RE.findall(b):
            u = u.rstrip(".,);]")
            if any(s in u for s in _SKIP_URL):
                continue
            if u not in urls:
                urls.append(u)
    urls = urls[:max(fetches, 0)]

    fetch_blocks: List[str] = []
    recon_parts: List[str] = []
    jobs = _recon_jobs(user_text)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, max(1, len(urls) + len(jobs))), thread_name_prefix="osint2"
    ) as ex:
        fut_fetch = {ex.submit(tool_fetch, {"url": u}): u for u in urls}
        fn_map = {
            "osint_handles": tool_osint_handles,
            "osint_email": tool_osint_email,
            "osint_domain": tool_osint_domain,
            "osint_cnpj": tool_osint_cnpj,
            "osint_phone": tool_osint_phone,
        }
        fut_recon = {}
        for name, args in jobs:
            fn = fn_map.get(name) or TOOLS.get(name)
            if fn:
                fut_recon[ex.submit(fn, args)] = name
        all_futs: Dict[Any, str] = {f: u for f, u in fut_fetch.items()}
        for f, n in fut_recon.items():
            all_futs[f] = f"recon:{n}"
        phase_total = len(all_futs)
        phase_done = 0
        try:
            for fut in concurrent.futures.as_completed(all_futs, timeout=50):
                tag = all_futs[fut]
                try:
                    res = fut.result(timeout=45)
                except Exception as e:
                    res = f"erro: {type(e).__name__}: {e}"
                if tag.startswith("recon:"):
                    recon_parts.append(f"=== {tag[6:]} ===\n{_clip(str(res), 2800)}")
                else:
                    fetch_blocks.append(f"[FETCH] {tag}\n{_clip(str(res), 1500)}")
                phase_done += 1
                if progress:
                    try:
                        progress("confirma", phase_done, phase_total, tag)
                    except Exception:
                        pass
        except concurrent.futures.TimeoutError:
            fetch_blocks.append("(tempo esgotado na fase 2: parcial)")

    # FASE 3 - VARREDURA COM OVERLAP 5x (raciocinio humano: cada achado gera nova busca)
    overlap_text = ""
    overlap_dorks: list = []
    overlap_info: dict = {}
    try:
        _base = "\n\n".join(blocks + fetch_blocks + recon_parts)
        overlap_text, overlap_dorks, overlap_info = osint_sweep_overlap(
            user_text, base_evidence=_base, progress=progress, max_rounds=OSINT_OVERLAP_ROUNDS
        )
    except Exception as e:
        overlap_text = f"(overlap: erro {type(e).__name__}: {e})"

    parts = []
    if blocks:
        parts.append("=== RESULTADOS DAS BUSCAS (tool osint_dorks) ===\n" + "\n\n".join(blocks))
    if fetch_blocks:
        parts.append("=== PAGINAS ABERTAS (fetch automatico, dados crus) ===\n" + "\n\n".join(fetch_blocks))
    if recon_parts:
        parts.append("\n\n".join(recon_parts))
    if overlap_text:
        parts.append("=== VARREDURA OVERLAP 5x (pivos automaticos: pai/mae/@/email/telefone) ===\n" + overlap_text)
    if overlap_info:
        try:
            _pc = overlap_info.get("pai_candidatos") or []
            _mc = overlap_info.get("mae_candidatos") or []
            _il = overlap_info.get("interligacoes") or []
            _cov = (overlap_info.get("cobertura") or {}).get("links", 0)
            _rr = overlap_info.get("rodadas", 0)
            parts.append(
                "=== RESUMO DA VARREDURA ===\n"
                f"rodadas overlap: {_rr}/{OSINT_OVERLAP_ROUNDS} | links distintos: {_cov}\n"
                f"pai candidato(s): {', '.join(_pc) if _pc else 'nenhum'} \n"
                f"mae candidata(s): {', '.join(_mc) if _mc else 'nenhuma'}\n"
                + ("INTERLIGACOES:\n" + "\n".join(f"- {x}" for x in _il) if _il else "INTERLIGACOES: nenhuma evidente ainda")
                + f"\nMETA: alvo {OSINT_MIN_TARGET_FACTS}+ fatos | pai {OSINT_MIN_PARENT_FACTS}+ | mae {OSINT_MIN_PARENT_FACTS}+ (com link)"
            )
        except Exception:
            pass
    try:
        _br = brazuca_suggest_for_entities(user_text, per_type=2)
        if _br:
            parts.append("=== FONTES BR SUGERIDAS (osint-brazuca: onde consultar cada identificador) ===\n" + _br)
    except Exception:
        pass
    todas = list(dorks) + list(overlap_dorks or [])
    return "\n\n".join(parts), todas


def tool_osint_dorks(args: Dict[str, Any]) -> str:
    target = args.get("target") or args.get("query") or args.get("alvo") or ""
    if not target:
        return "erro: mande target (nome, email, dominio, @handle, telefone ou CNPJ)"
    if _is_greeting_only(str(target)):
        return ("erro: alvo invalido - isso e saudacao/entrada vazia, nao identificador OSINT. "
                "Responda em texto pedindo o alvo real (nome completo, @, e-mail, telefone, cidade) "
                "e nao rode buscas.")
    try:
        limit = int(args.get("limit") or 10)
    except (TypeError, ValueError):
        limit = 10
    limit = min(max(limit, 1), 30)
    fetches = 2 if str(args.get("fetch", "sim")).lower() not in ("0", "nao", "não", "false") else 0
    progress = args.get("_progress") if callable(args.get("_progress")) else None
    try:
        text, dorks = osint_autopilot(str(target), limit=limit, fetches=fetches, progress=progress)
    except Exception as e:
        return f"erro osint_dorks: {type(e).__name__}: {e}"
    if not dorks:
        return "nenhuma dork gerada - informe um alvo (nome completo, email, dominio, @handle, telefone, CNPJ)"
    head = (
        f"osint_dorks: {len(dorks)} buscas executadas (+fetch+recon+overlap{OSINT_OVERLAP_ROUNDS}x). "
        f"META {OSINT_MIN_TARGET_FACTS}+ fatos do alvo / {OSINT_MIN_PARENT_FACTS}+ pai / {OSINT_MIN_PARENT_FACTS}+ mae (com link). "
        "Resultados crus abaixo - confirme com fetch antes de afirmar qualquer dado:"
    )
    return head + "\n\n" + text


_CONECTIVOS = {"de", "da", "do", "das", "dos", "e", "del", "della", "van", "von"}


def _strip_accents(s: str) -> str:
    import unicodedata
    return "".join(
        c for c in unicodedata.normalize("NFD", str(s or "")) if unicodedata.category(c) != "Mn"
    )


def name_variants(name: str) -> List[str]:
    raw = " ".join(str(name or "").split())
    if not raw:
        return []
    sem_acento = _strip_accents(raw)
    toks = [t for t in raw.split() if t]
    parts = [t for t in toks if t.lower() not in _CONECTIVOS]
    out = [raw, sem_acento]

    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        out += [
            f"{last} {first}",
            f"{first} {last}",
            " ".join(parts[:2]),
            " ".join(parts[-2:]),
            f"{first[0]}. {last}",
            f"{first} {last[0]}.",
            f"{first[0]}{last}",
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first}{last[0]}",
        ]
        if len(parts) >= 3:
            out.append(" ".join(parts[:2] + [parts[-1]]))
            out.append(" ".join([parts[0]] + parts[2:]))
        out += [
            f"{parts[0]} {_strip_accents(parts[-1])}",
            _strip_accents(f"{last} {first}"),
        ]
    seen: set = set()
    final: List[str] = []
    for v in out:
        k = v.strip().lower()
        if len(k) >= 3 and k not in seen:
            seen.add(k)
            final.append(v.strip())
    return final[:14]


DORK_GROUPS: List[Dict[str, Any]] = [
    {
        "id": "identidade",
        "label": "identidade / nome real",
        "when": "name",
        "dorks": [
            '"{name}"',
            '"{name_nc}"',
            '"{last_first}"',
            '"{first}" "{last}"',
            '"{name}" "nome completo"',
            '"{name}" (curriculo OR curriculum OR CV) filetype:pdf',
            '"{name}" "nascido" (em OR no ano de OR a) filetype:pdf',
            '"{name}" ("data de nascimento" OR "nascimento:")',
            '"{name}" ("idade" OR "anos")',
            '"{name}" ("natural de" OR "nascido em" OR "naturalidade")',
            '"{name}" -site:facebook.com -site:instagram.com',
        ],
    },
    {
        "id": "social",
        "label": "redes sociais",
        "when": "name",
        "dorks": [
            '"{name}" (site:linkedin.com OR site:br.linkedin.com)',
            '"{name}" site:instagram.com',
            '"{name}" site:facebook.com',
            '"{name}" site:tiktok.com',
            '"{name}" (site:x.com OR site:twitter.com)',
            '"{name}" site:threads.net',
            '"{name}" site:youtube.com',
            '"{name}" (site:twitch.tv OR site:kick.com)',
            '"{name}" (site:reddit.com OR site:9gag.com)',
            '"{name}" (site:t.me OR site:telegram.me)',
            '"{name}" (site:linktr.ee OR site:beacons.ai OR site:bio.link)',
            '"{name}" (site:about.me OR site:gravatar.com OR site:keybase.io)',
            '"{name}" (site:pinterest.com OR site:flickr.com OR site:500px.com)',
            '"{name}" site:strava.com',
            '"{name}" site:letterboxd.com',
        ],
    },
    {
        "id": "documentos",
        "label": "documentos e planilhas",
        "when": "name",
        "dorks": [
            '"{name}" filetype:pdf',
            '"{name}" (filetype:doc OR filetype:docx)',
            '"{name}" (filetype:xls OR filetype:xlsx OR filetype:csv)',
            '"{name}" (filetype:ppt OR filetype:pptx)',
            '"{name}" (filetype:txt OR filetype:rtf OR filetype:odt)',
            'intitle:"curriculo" "{name}"',
            'intitle:"lista" "{name}" filetype:pdf',
            'intitle:"ata" "{name}" filetype:pdf',
            'intitle:"edital" "{name}"',
            'intitle:"resultado" "{name}" filetype:pdf',
            'intitle:"portaria" "{name}"',
            'intitle:"termo" "{name}" filetype:pdf',
        ],
    },
    {
        "id": "juridico",
        "label": "juridico / processos / diarios",
        "when": "name",
        "dorks": [
            '"{name}" (site:jusbrasil.com.br OR site:escavador.com OR site:juridico.ai)',
            '"{name}" (site:stj.jus.br OR site:stf.jus.br OR site:tst.jus.br)',
            '"{name}" (site:tjce.jus.br OR site:tjsp.jus.br OR site:tjrj.jus.br)',
            '"{name}" (site:trt7.jus.br OR site:trt.jus.br)',
            '"{name}" (site:mpce.mp.br OR site:mpf.mp.br OR site:mpsp.mp.br)',
            '"{name}" site:in.gov.br',
            '"{name}" (site:dou.{uf}.gov.br OR site:dom.{uf}.gov.br OR site:doe.{uf}.gov.br)',
            '"{name}" ("diario oficial" OR "d.o.e" OR "diario oficial da uniao") filetype:pdf',
            '"{name}" (inquerito OR "acao penal" OR "processo n") ',
            '"{name}" (autor OR reu OR testemunha OR vitima)',
            '"{name}" (advogado OR OAB OR "inscricao na oab")',
        ],
    },
    {
        "id": "governo",
        "label": "governo / transparencia / concursos",
        "when": "name",
        "dorks": [
            '"{name}" site:gov.br',
            '"{name}" (site:transparencia.gov.br OR site:portaltransparencia.gov.br)',
            '"{name}" (site:pncp.gov.br OR site:comprasnet.gov.br OR site:licitacoes-e.com.br)',
            '"{name}" (site:camara.leg.br OR site:senado.leg.br OR site:*.leg.br)',
            '"{name}" (site:tse.jus.br OR site:divulgacandcontas.tse.jus.br OR site:tre-{uf}.jus.br)',
            '"{name}" (concurso OR "processo seletivo") ("resultado final" OR aprovado OR classificado) filetype:pdf',
            '"{name}" ("nomeacao" OR "nomeado" OR "exoneracao" OR "exonerado")',
            '"{name}" ("servidor" OR "matricula" OR "cargo de")',
            '"{name}" ("licitacao" OR "contrato" OR "dispensa") filetype:pdf',
            '"{name}" ("diaria" OR "viagem a servico")',
            '"{name}" (site:esic.gov.br OR site:fala.br)',
        ],
    },
    {
        "id": "empresa",
        "label": "empresas / CNPJ / MEI",
        "when": "name",
        "dorks": [
            '"{name}" (site:cnpj.biz OR site:casadosdados.com.br OR site:consultacnpj.com)',
            '"{name}" (site:econodata.com.br OR site:empresascnpj.com OR site:cndonline)',
            '"{name}" (MEI OR "microempreendedor individual")',
            '"{name}" (socio OR administrador OR "quadro societario")',
            '"{name}" (site:linkedin.com/company OR site:crunchbase.com OR site:glassdoor)',
            '"{name}" site:jusbrasil.com.br/empresa',
            '"{name}" ("razao social" OR "nome fantasia")',
            '"{name}" site:cnpj.info',
        ],
    },
    {
        "id": "academico",
        "label": "academico / lattes / pesquisador",
        "when": "name",
        "dorks": [
            '"{name}" (site:lattes.cnpq.br OR site:buscatextual.cnpq.br)',
            '"{name}" (site:scholar.google.com OR site:scholar.google.com.br)',
            '"{name}" (site:researchgate.net OR site:academia.edu OR site:orcid.org)',
            '"{name}" (site:scielo.br OR site:periodicos.capes.gov.br)',
            '"{name}" (tcc OR monografia OR dissertacao OR tese OR artigo) filetype:pdf',
            '"{name}" (aluno OR egresso OR formando OR formado) ("turma" OR "ano")',
            '"{name}" (site:edu.br OR site:ufc.br OR site:usp.br OR site:ufpe.br)',
            '"{name}" ("orientador" OR "coautoria" OR "co-autor") filetype:pdf',
            '"{name}" site:repositorio.ufc.br',
        ],
    },
    {
        "id": "codigo",
        "label": "codigo / dev",
        "when": "name",
        "dorks": [
            '"{name}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)',
            '"{name}" (site:stackoverflow.com OR site:stackexchange.com OR site:pt.stackoverflow.com)',
            '"{name}" (site:npmjs.com OR site:pypi.org OR site:packagist.org OR site:pub.dev)',
            '"{name}" (site:codepen.io OR site:jsfiddle.net OR site:replit.com OR site:glitch.me)',
            '"{name}" (site:kaggle.com OR site:huggingface.co OR site:colab.research.google.com)',
            '"{name}" (site:hackerrank.com OR site:codeforces.com OR site:beecrowd.com.br)',
            '"{name}" (site:dev.to OR site:medium.com OR site:hashnode.dev)',
            '"{name}" (site:beehiiv.com OR site:substack.com)',
        ],
    },
    {
        "id": "pastes",
        "label": "pastes e vazamentos publicos indexados",
        "when": "any",
        "dorks": [
            '"{key}" (site:pastebin.com OR site:pastebin.pl OR site:paste.ee)',
            '"{key}" (site:gist.github.com OR site:gitlab.com/snippets)',
            '"{key}" (site:rentry.co OR site:ghostbin.com OR site:justpaste.it)',
            '"{key}" (site:controlc.com OR site:ideone.com OR site:dpaste.org)',
            '"{key}" (site:hastebin.com OR site:0bin.net OR site:privatebin.net)',
            '"{key}" (site:codepad.org OR site:pastebin.ai OR site:doxbin*)',
            '"{key}" filetype:txt (site:mediafire.com OR site:mega.nz OR site:drive.google.com)',
        ],
    },
    {
        "id": "foruns",
        "label": "foruns e comunidades",
        "when": "name",
        "dorks": [
            '"{name}" (site:reddit.com OR site:old.reddit.com)',
            '"{name}" (site:medium.com OR site:quora.com OR site:quora.com.br)',
            '"{name}" (site:clubedohardware.com.br OR site:adrenaline.com.br OR site:hardware.com.br)',
            '"{name}" (site:forum.outerspace.com.br OR site:guiamais.com.br OR site:htforum.com)',
            '"{name}" (site:forum.pcspecs.com.br OR site:forum.gdhardware.com)',
            '"{name}" (site:discord.com OR site:discord.gg OR site:disboard.org)',
            '"{name}" (site:steamcommunity.com OR site:gamebanana.com)',
            '"{name}" "membro desde"',
        ],
    },
    {
        "id": "infra",
        "label": "dominio / infraestrutura",
        "when": "domain_or_email",
        "dorks": [
            'site:{domain} -www',
            'site:*.{domain}',
            'site:{domain} (inurl:wp-content OR inurl:uploads OR inurl:images)',
            'site:{domain} (inurl:perfil OR inurl:user OR inurl:membro OR inurl:equipe)',
            'intitle:"index of" site:{domain}',
            'intitle:"index of" (backup OR bkp OR dump) site:{domain}',
            'site:{domain} (ext:env OR ext:sql OR ext:bak OR ext:log OR ext:zip OR ext:tar.gz)',
            'site:{domain} (ext:pdf OR ext:xlsx OR ext:docx)',
            'site:{domain} robots.txt',
            'site:{domain} sitemap.xml',
            'site:{domain} ("security.txt" OR ".well-known")',
            '"{domain}" -site:{domain}',
            '"{domain}" (site:virustotal.com OR site:urlscan.io OR site:shodan.io OR site:censys.io)',
            '"{domain}" (site:webcache.googleusercontent.com OR site:web.archive.org)',
            'related:{domain}',
        ],
    },
    {
        "id": "infra_ext",
        "label": "dominio: certificados, DNS, historico",
        "when": "domain",
        "dorks": [
            'https://crt.sh/?q=%25.{domain}',
            'https://crt.sh/?q={domain}&output=json',
            'https://api.hackertarget.com/hostsearch/?q={domain}',
            'https://api.hackertarget.com/dnslookup/?q={domain}',
            'https://api.hackertarget.com/whois/?q={domain}',
            'http://web.archive.org/cdx/search/cdx?url={domain}*&output=json&fl=original,timestamp&collapse=urlkey&limit=200',
            'https://urlscan.io/api/v1/search/?q=domain:{domain}',
            'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
            'https://jldc.me/anubis/subdomains/{domain}',
            'https://api.github.com/search/repositories?q=%22{domain}%22',
            'https://searchcode.com/api/codesearch_I/?q={domain}',
        ],
    },
    {
        "id": "email",
        "label": "e-mail: perfil, commits, vazamentos",
        "when": "email",
        "dorks": [
            '"{email}"',
            '"{email}" -site:{email_dom}',
            '"{email}" filetype:pdf',
            '"{email}" (site:github.com OR site:gitlab.com OR site:gist.github.com)',
            '"{email}" (site:pastebin.com OR site:rentry.co OR site:ghostbin.com OR site:controlc.com)',
            '"{email}" ("senha" OR "password" OR "vazamento" OR "leak")',
            '"{email_user}" site:{email_dom}',
            '"{email_user}" (curriculo OR contato OR portfolio)',
            '"{email}" (site:gravatar.com OR site:keybase.io OR site:about.me)',
            '"{email}" (site:facebook.com OR site:instagram.com OR site:linkedin.com)',
            'https://haveibeenpwned.com/account/{email}',
            'https://emailrep.io/{email}',
            'https://api.github.com/search/users?q={email_user}',
            'https://api.github.com/search/commits?q=author-email:{email}',
            'https://api.github.com/search/commits?q=committer-email:{email}',
            'https://plus.google.com/s2/photos/profile/{email}',
        ],
    },
    {
        "id": "handle",
        "label": "username / handle em todos os sites",
        "when": "handle",
        "dorks": [
            '"{handle}"',
            '"{handle}" -site:{handle}.com',
            '"{handle}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)',
            '"{handle}" (site:instagram.com OR site:tiktok.com OR site:x.com OR site:twitter.com)',
            '"{handle}" (site:twitch.tv OR site:kick.com OR site:youtube.com)',
            '"{handle}" (site:reddit.com OR site:steamcommunity.com OR site:roblox.com)',
            '"{handle}" (site:t.me OR site:telegram.me)',
            '"{handle}" (site:dev.to OR site:medium.com OR site:hashnode.dev)',
            '"{handle}" (site:pastebin.com OR site:gist.github.com OR site:rentry.co)',
            '"{handle}" (site:npmjs.com OR site:pypi.org OR site:docker.com)',
            '"{handle}" (site:spotify.com OR site:soundcloud.com OR site:deezer.com)',
            '"{handle}" (anime OR games OR forum OR "nick")',
        ],
    },
    {
        "id": "telefone",
        "label": "telefone",
        "when": "phone",
        "dorks": [
            '"{phone}"',
            '"{phone_digits}"',
            '"{phone}" (site:facebook.com OR site:linkedin.com OR site:instagram.com)',
            '"{phone}" (site:olx.com.br OR site:mercadolivre.com.br OR site:shopee.com.br)',
            '"{phone}" (site:facebook.com/marketplace OR site:enjoei.com.br)',
            '"{phone}" (site:apontador.com.br OR site:telelistas.net OR site:guiamais.com.br)',
            '"{phone}" filetype:pdf',
            '"{phone}" (whatsapp OR wpp OR "zap")',
            'https://brasilapi.com.br/api/ddd/v1/{ddd}',
        ],
    },
    {
        "id": "cnpj",
        "label": "CNPJ / empresa",
        "when": "cnpj",
        "dorks": [
            '"{cnpj}"',
            '"{cnpj_digits}"',
            '"{cnpj}" (site:cnpj.biz OR site:casadosdados.com.br OR site:consultacnpj.com)',
            '"{cnpj}" (site:transparencia.gov.br OR site:pncp.gov.br OR site:comprasnet.gov.br)',
            '"{cnpj}" (site:jusbrasil.com.br OR site:escavador.com)',
            '"{cnpj}" ("contrato" OR "licitacao" OR "empenho") filetype:pdf',
            '"{cnpj}" (site:econodata.com.br OR site:cnpj.info OR site:cndonline.com.br)',
            'https://brasilapi.com.br/api/cnpj/v1/{cnpj_digits}',
        ],
    },
    {
        "id": "midia",
        "label": "noticias / midia / mencoes",
        "when": "name",
        "dorks": [
            '"{name}" (site:g1.globo.com OR site:globo.com OR site:uol.com.br)',
            '"{name}" (site:folha.uol.com.br OR site:estadao.com.br OR site:oglobo.globo.com)',
            '"{name}" (site:r7.com OR site:terra.com.br OR site:metropoles.com)',
            '"{name}" (site:diariodonordeste.verdesmares.com.br OR site:opovo.com.br OR site:jangadeiro.com.br)',
            '"{name}" (site:portalcm7.com OR site:cearaagora.com.br OR site:miseria.com.br)',
            '"{name}" (noticia OR reportagem OR entrevista OR materia)',
            '"{name}" (premiado OR homenagem OR medalha OR destaque OR condecorado)',
            '"{name}" (preso OR condenado OR investigado OR indiciado OR acusado)',
            '"{name}" (morreu OR faleceu OR obito OR velorio OR sepultamento)',
            '"{name}" (eleito OR candidato OR vereador OR prefeito OR deputado)',
            '"{name}" (site:youtube.com OR site:vimeo.com) (entrevista OR podcast OR palestra)',
        ],
    },
    {
        "id": "local",
        "label": "localizacao / geografia",
        "when": "name",
        "dorks": [
            '"{name}" ("endereco" OR "rua" OR "avenida" OR "bairro")',
            '"{name}" ("CEP" OR "cep:")',
            '"{name}" ("mora em" OR "mudou-se" OR "reside em" OR "residente em")',
            '"{name}" ("bairro") "{city}"',
            '"{name}" "{uf}" ("cidade" OR "municipio")',
            '"{name}" (site:maplink.com.br OR site:foursquare.com OR site:swarmapp.com)',
            '"{name}" ("check-in" OR "estive em" OR "passando por")',
            '"{name}" (site:facebook.com) ("Ceara" OR "{uf}" OR "Fortaleza")',
            '"{name}" ("natural de" OR "nascido em") "{city}"',
        ],
    },
    {
        "id": "esporte",
        "label": "esporte (data de nascimento costuma ser publica)",
        "when": "name",
        "dorks": [
            '"{name}" (site:ogol.com.br OR site:transfermarkt.com.br OR site:sofascore.com)',
            '"{name}" (site:flashscore.com.br OR site:ge.globo.com OR site:placar)',
            '"{name}" (site:cbf.com.br OR site:cob.org.br OR site:cbat.org.br)',
            '"{name}" ("ficha tecnica" OR "data de nascimento" OR "nascimento:") atleta',
            '"{name}" (atleta OR jogador OR "corrida" OR "campeonato" OR federacao)',
            '"{name}" (site:strava.com OR site:garmin.com OR site:suunto.com)',
            '"{name}" (site:esportenacidade.com.br OR site:ludopedio.org.br)',
        ],
    },
    {
        "id": "imagem",
        "label": "imagem / rosto (abrir no navegador)",
        "when": "handle_or_name",
        "dorks": [
            'https://www.google.com/search?q=%22{name}%22&tbm=isch',
            'https://yandex.com/images/search?text={name}',
            'https://tineye.com/search?url=',
            'https://lens.google.com/uploadbyurl?url=',
            '"{name}" (site:flickr.com OR site:500px.com OR site:unsplash.com OR site:pexels.com)',
            '"{handle}" profile picture',
            '"{name}" (site:instagram.com) (foto OR perfil)',
        ],
    },
    {
        "id": "correlacao",
        "label": "correlacao cruzada (fechar o cerco)",
        "when": "name",
        "dorks": [
            '"{name}" "{handle}"',
            '"{name}" "{email}"',
            '"{name}" "{phone}"',
            '"{name}" "{city}" "{uf}"',
            '"{handle}" "{email}"',
            '"{handle}" "{phone}"',
            '"{email}" "{phone}"',
            '"{name}" ("@" OR arroba)',
            '"{name}" ("instagram" OR "@" ) ("{city}" OR "{uf}")',
            '"{last}" "{city}"',
        ],
    },
    {
        "id": "arquivos_vazados",
        "label": "bancos e indices publicos",
        "when": "any",
        "dorks": [
            '"{key}" site:scylla.sh',
            '"{key}" site:leakcheck.io',
            '"{key}" site:dehashed.com',
            '"{key}" site:breachdirectory.org',
            '"{key}" site:intelx.io',
            '"{key}" site:hunter.how',
            '"{key}" site:publicwww.com',
            '"{key}" site:searchcode.com',
            '"{key}" site:hunter.io',
            '"{key}" site:vigilante.pw',
        ],
    },
]


def _dork_values(text: str) -> Dict[str, str]:
    ent = osint_entities(text)
    names = ent.get("names") or []
    raw_name = names[0] if names else ""
    variants = name_variants(raw_name) if raw_name else []

    first = last = last_first = ""
    if raw_name:
        parts = [t for t in raw_name.split() if t.lower() not in _CONECTIVOS] or raw_name.split()
        if parts:
            first = parts[0]
            last = parts[-1] if len(parts) > 1 else ""
            last_first = f"{last} {first}".strip()
    if len(variants) > 2:
        last_first = variants[2]

    email = (ent.get("emails") or [""])[0]
    email_user, email_dom = ("", "")
    if email:
        email_user, _, email_dom = email.partition("@")

    domain = (ent.get("domains") or [""])[0]
    handle = (ent.get("handles") or [""])[0]
    phone = (ent.get("phones") or [""])[0]
    phone_digits = re.sub(r"\D", "", phone)
    ddd = ""
    if phone_digits:
        ddd = phone_digits[-11:-9] if len(phone_digits) >= 11 else phone_digits[-10:-8]
        if len(phone_digits) >= 12 and phone_digits.startswith("55"):
            ddd = phone_digits[2:4]
    cnpj = (ent.get("cnpjs") or [""])[0]
    cnpj_digits = re.sub(r"\D", "", cnpj)

    uf = ""
    city = ""
    for m in re.finditer(r"\b([A-Z]{2})\b", text or ""):
        cand = m.group(1)
        if cand not in ("OS", "SE", "DE", "DA", "DO", "E", "OU", "OK", "PDF", "CV", "ID"):
            uf = cand
            break
    mcity = re.search(
        r"(?:\b(?:cidade|munic[ií]pio|city)\s*[:=]?\s*|,\s*)([A-Z\u00c0-\u00dd][a-z\u00e0-\u00ff]{3,20})\b",
        text or "",
    )
    if mcity:
        city = mcity.group(1)

    key = handle or email or domain or phone_digits or cnpj_digits or raw_name

    return {
        "name": raw_name, "name_nc": _strip_accents(raw_name), "first": first, "last": last,
        "last_first": last_first, "email": email, "email_user": email_user, "email_dom": email_dom,
        "domain": domain, "handle": handle, "phone": phone, "phone_digits": phone_digits,
        "ddd": ddd, "cnpj": cnpj, "cnpj_digits": cnpj_digits, "uf": uf, "city": city, "key": key,
    }


_NEEDS = {
    "name": lambda v: bool(v["name"]),
    "email": lambda v: bool(v["email"]),
    "domain": lambda v: bool(v["domain"]),
    "handle": lambda v: bool(v["handle"]),
    "phone": lambda v: bool(v["phone"]),
    "cnpj": lambda v: bool(v["cnpj"]),
    "any": lambda v: bool(v["key"]),
    "domain_or_email": lambda v: bool(v["domain"] or v["email"]),
    "handle_or_name": lambda v: bool(v["handle"] or v["name"]),
}


def _render_dork(tpl: str, vals: Dict[str, str]) -> str:
    keys = re.findall(r"\{(\w+)\}", tpl)
    for k in keys:
        if not str(vals.get(k) or "").strip():
            return ""
    try:
        d = " ".join(tpl.format(**vals).split())
    except (KeyError, IndexError, ValueError):
        return ""
    if '""' in d or "( )" in d or "()" in d:
        return ""
    return d


def osint_build_dorks(user_text: str, limit: int = 20, groups: Optional[List[str]] = None) -> List[str]:
    vals = _dork_values(user_text)
    wanted = {g.lower() for g in groups} if groups else None

    per_group: List[List[str]] = []
    seen: set = set()
    for g in DORK_GROUPS:
        if wanted and g["id"].lower() not in wanted and g["label"].lower() not in wanted:
            continue
        if not _NEEDS.get(g["when"], lambda v: False)(vals):
            continue
        bucket: List[str] = []
        for tpl in g["dorks"]:
            d = _render_dork(tpl, vals)
            if d and d.lower() not in seen:
                seen.add(d.lower())
                bucket.append(d)
        if bucket:
            per_group.append(bucket)

    if not per_group:
        key = vals["key"]
        if key:
            out = [f'"{key}"', f'"{key}" site:linkedin.com', f'"{key}" filetype:pdf']
            return out[:limit] if limit else out
        return []

    picked: List[str] = []
    idx = 0
    while True:
        if limit and len(picked) >= limit:
            break
        progressed = False
        for bucket in per_group:
            if limit and len(picked) >= limit:
                break
            if idx < len(bucket):
                picked.append(bucket[idx])
                progressed = True
        if not progressed:
            break
        idx += 1
    return picked


def dorks_by_group(user_text: str, limit_per_group: int = 3) -> List[Tuple[str, List[str]]]:
    vals = _dork_values(user_text)
    result: List[Tuple[str, List[str]]] = []
    for g in DORK_GROUPS:
        if not _NEEDS.get(g["when"], lambda v: False)(vals):
            continue
        bucket: List[str] = []
        for tpl in g["dorks"]:
            d = _render_dork(tpl, vals)
            if d:
                bucket.append(d)
            if len(bucket) >= limit_per_group:
                break
        if bucket:
            result.append((g["label"], bucket))
    return result


_OSINT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"


_OSINT_HTTP_CACHE: Dict[str, str] = {}
_OSINT_HTTP_LOCK = threading.Lock()
_OSINT_CLIENT: Optional[httpx.Client] = None


def _osint_client() -> httpx.Client:
    """Cliente HTTP compartilhado com pool de conexoes (bem mais rapido que httpx.get solto)."""
    global _OSINT_CLIENT
    if _OSINT_CLIENT is None:
        with _OSINT_HTTP_LOCK:
            if _OSINT_CLIENT is None:
                _OSINT_CLIENT = httpx.Client(
                    timeout=httpx.Timeout(12.0, connect=5.0),
                    follow_redirects=True,
                    headers={"User-Agent": _OSINT_UA, "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"},
                    limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
                )
    return _OSINT_CLIENT


def osint_http_text(url: str, timeout: float = 6.0, max_len: int = 8000, use_cache: bool = True) -> str:
    key = f"{url}|{max_len}"
    if use_cache:
        with _OSINT_HTTP_LOCK:
            hit = _OSINT_HTTP_CACHE.get(key)
        if hit is not None:
            return hit
    try:
        r = _osint_client().get(url, timeout=timeout)
        if r.status_code >= 400:
            out = f"HTTP {r.status_code}"
        else:
            out = _clean_html_to_text(r.text)[:max_len]
    except Exception as e:
        out = f"erro {type(e).__name__}: {e}"
    if use_cache:
        with _OSINT_HTTP_LOCK:
            if len(_OSINT_HTTP_CACHE) < 600:
                _OSINT_HTTP_CACHE[key] = out
    return out


def osint_http_many(
    items: List[Tuple[str, str]],
    timeout: float = 7.0,
    max_len: int = 3000,
    max_workers: int = 8,
    overall_timeout: float = 50.0,
) -> Dict[str, str]:
    """Busca varias urls em paralelo com o cliente compartilhado. Retorna {nome: texto}."""
    import concurrent.futures

    results: Dict[str, str] = {}
    if not items:
        return results
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_workers, len(items)), thread_name_prefix="osinthttp"
    ) as ex:
        futs = {ex.submit(osint_http_text, url, timeout, max_len): name for name, url in items}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=overall_timeout):
                results[futs[fut]] = fut.result()
        except concurrent.futures.TimeoutError:
            for fut, name in futs.items():
                if name not in results:
                    results[name] = "erro timeout"
    return results


def _looks_blocked(txt: str) -> bool:
    low = (txt or "").lower()
    return (
        len(low) < 250
        or "unusual traffic" in low
        or "captcha" in low
        or "enable javascript" in low
        or "are you a human" in low
        or "access denied" in low
    )


_OSINT_SEARCH_CACHE: Dict[str, str] = {}


def osint_search_one(query: str, engine: str = "auto", timeout: float = 5.0) -> str:
    cache_key = f"{engine}|{query}"
    with _OSINT_HTTP_LOCK:
        hit = _OSINT_SEARCH_CACHE.get(cache_key)
    if hit is not None:
        return hit
    q = urllib.parse.quote(query)
    engines = [engine] if engine != "auto" else ["bing", "mojeek", "ddg"]
    errors: List[str] = []
    for eng in engines:
        if eng == "mojeek":
            url = f"https://www.mojeek.com/search?q={q}"
        elif eng == "bing":
            url = f"https://www.bing.com/search?q={q}&count=20&setlang=pt-br"
        elif eng == "ddg":
            url = f"https://html.duckduckgo.com/html/?q={q}"
        else:
            url = f"https://www.google.com/search?q={q}&num=20&hl=pt-BR"
        txt = osint_http_text(url, timeout=timeout, max_len=5000)
        if not _looks_blocked(txt):
            out = f"[{eng}] {txt}"
            with _OSINT_HTTP_LOCK:
                if len(_OSINT_SEARCH_CACHE) < 300:
                    _OSINT_SEARCH_CACHE[cache_key] = out
            return out
        errors.append(f"{eng}: {txt[:60] if txt else 'vazio'}")
    out = "[sem resultado] " + " | ".join(errors)[:300]
    with _OSINT_HTTP_LOCK:
        if len(_OSINT_SEARCH_CACHE) < 300:
            _OSINT_SEARCH_CACHE[cache_key] = out
    return out


def tool_bing_search(args: Dict[str, Any]) -> str:
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "query vazia"
    return f"bing '{q}': {osint_search_one(str(q), 'bing')}"


def tool_mojeek_search(args: Dict[str, Any]) -> str:
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "query vazia"
    return f"mojeek '{q}': {osint_search_one(str(q), 'mojeek')}"


def tool_multi_search(args: Dict[str, Any]) -> str:
    q = args.get("query") or args.get("q") or ""
    if not q:
        return "query vazia"
    return f"busca '{q}': {osint_search_one(str(q), 'auto')}"


PLATFORMS: List[Tuple[str, str, str]] = [
    ("github", "https://github.com/{h}", "code"),
    ("gitlab", "https://gitlab.com/{h}", "code"),
    ("bitbucket", "https://bitbucket.org/{h}", "code"),
    ("instagram", "https://www.instagram.com/{h}/", "social"),
    ("tiktok", "https://www.tiktok.com/@{h}", "social"),
    ("x/twitter", "https://x.com/{h}", "social"),
    ("facebook", "https://www.facebook.com/{h}", "social"),
    ("threads", "https://www.threads.net/@{h}", "social"),
    ("reddit", "https://www.reddit.com/user/{h}", "social"),
    ("pinterest", "https://www.pinterest.com/{h}/", "social"),
    ("twitch", "https://www.twitch.tv/{h}", "social"),
    ("youtube", "https://www.youtube.com/@{h}", "social"),
    ("telegram", "https://t.me/{h}", "social"),
    ("discord", "https://discord.com/users/{h}", "social"),
    ("medium", "https://medium.com/@{h}", "blog"),
    ("dev.to", "https://dev.to/{h}", "blog"),
    ("hashnode", "https://hashnode.com/@{h}", "blog"),
    ("substack", "https://{h}.substack.com", "blog"),
    ("about.me", "https://about.me/{h}", "perfil"),
    ("linktr.ee", "https://linktr.ee/{h}", "perfil"),
    ("behance", "https://www.behance.net/{h}", "perfil"),
    ("dribbble", "https://dribbble.com/{h}", "perfil"),
    ("soundcloud", "https://soundcloud.com/{h}", "audio"),
    ("spotify", "https://open.spotify.com/user/{h}", "audio"),
    ("steam", "https://steamcommunity.com/id/{h}", "games"),
    ("roblox", "https://www.roblox.com/user.aspx?username={h}", "games"),
    ("kaggle", "https://www.kaggle.com/{h}", "code"),
    ("huggingface", "https://huggingface.co/{h}", "code"),
    ("keybase", "https://keybase.io/{h}", "perfil"),
    ("last.fm", "https://www.last.fm/user/{h}", "audio"),
    ("strava", "https://www.strava.com/athletes/{h}", "esporte"),
    ("letterboxd", "https://letterboxd.com/{h}/", "perfil"),
]

_NOT_FOUND_MARKERS = (
    "page not found", "pagina nao encontrada", "página não encontrada", "not found",
    "doesn't exist", "does not exist", "nao existe", "não existe",
    "sorry, this page isn't available", "user not found", "couldn't find",
    "no user", "profile not found", "conta nao encontrada", "404",
    "this account doesn't exist", "account suspended", "account deactivated",
    "this page is unavailable", "no longer available",
)


def _profile_exists(url: str, timeout: float = 5.0, expect: str = "") -> Tuple[bool, str]:
    try:
        r = _osint_client().get(url, timeout=timeout)
    except Exception as e:
        return False, f"erro {type(e).__name__}"
    if r.status_code == 404:
        return False, "404"
    if r.status_code in (401, 403, 429):
        return False, f"HTTP {r.status_code} (bloqueou)"
    if r.status_code >= 400:
        return False, f"HTTP {r.status_code}"
    body = (r.text or "")[:15000].lower()
    if any(m in body for m in _NOT_FOUND_MARKERS):
        return False, "nao encontrado"
    if any(m in body for m in ("log in to continue", "faça login", "faca login", "consent", "cookie banner")):
        return True, "existe (pagina pede login)"
    # pagina 200 generica: so conta como EXISTE se o handle aparece no conteudo
    # (derruba falsos positivos tipo roblox/pinterest, que retornam 200 p/ inexistente)
    if expect and len(expect.strip()) >= 3:
        ex = expect.strip().lower()
        ex_q = urllib.parse.quote(expect.strip()).lower()
        if ex not in body and ex_q not in body:
            return False, "sem evidencia do handle"
    return True, "200"


def tool_osint_handles(args: Dict[str, Any]) -> str:
    import concurrent.futures

    raw = str(args.get("handle") or args.get("username") or args.get("user") or "").strip()
    h = raw.lstrip("@").strip()
    if not h:
        return 'erro: mande handle (ex: {"handle":"lolporfavor"})'

    found: List[str] = []
    inconclusive: List[str] = []
    missing = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="handle") as ex:
        futs = {ex.submit(_profile_exists, url.format(h=urllib.parse.quote(h)), 5.0, h): (name, url.format(h=h))
                for name, url, _ in PLATFORMS}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=45):
                name, url = futs[fut]
                try:
                    ok, why = fut.result(timeout=20)
                except Exception as e:
                    ok, why = False, f"erro {type(e).__name__}"
                if ok and "pede login" in why:
                    inconclusive.append(f"{name}: {url} ({why})")
                elif ok:
                    found.append(f"{name}: {url}")
                else:
                    missing += 1
        except concurrent.futures.TimeoutError:
            pass

    found.sort()
    inconclusive.sort()
    lines = [f"osint_handles '{h}': {len(found)} perfil(is) encontrado(s) em {len(PLATFORMS)} plataformas"]
    if found:
        lines.append("EXISTE:")
        lines += [f"  - {f}" for f in found]
    if inconclusive:
        lines.append("INCONCLUSIVO (pede login - confirme no navegador):")
        lines += [f"  - {f}" for f in inconclusive]
    if missing:
        lines.append(f"NAO EXISTE em {missing} plataforma(s).")
    lines.append(
        "PROXIMO PASSO: para cada perfil que existe, rode o dork "
        f"'\"{h}\" site:<dominio>' pra pegar o conteudo indexado (bio, nome real, cidade, foto)."
    )
    return "\n".join(lines)


def tool_osint_email(args: Dict[str, Any]) -> str:
    import concurrent.futures
    import hashlib

    email = str(args.get("email") or args.get("target") or "").strip()
    if not email or "@" not in email:
        return "erro: mande email valido"
    user, _, dom = email.partition("@")
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()

    checks: List[Tuple[str, str]] = [
        ("GRAVATAR", f"https://gravatar.com/{h}.json"),
        ("GRAVATAR-PERFIL", f"https://gravatar.com/{h}"),
        ("GITHUB-USERS", f"https://api.github.com/search/users?q={urllib.parse.quote(user)}"),
        ("GITHUB-COMMITS", f"https://api.github.com/search/commits?q=author-email:{urllib.parse.quote(email)}"),
        ("GITHUB-COMMITS-COMMITTER", f"https://api.github.com/search/commits?q=committer-email:{urllib.parse.quote(email)}"),
        ("GITHUB-CODE", f"https://api.github.com/search/users?q={urllib.parse.quote(email)}"),
        ("EMAILREP", f"https://emailrep.io/{urllib.parse.quote(email)}"),
        ("HIBP", f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"),
        ("KEYBASE", f"https://keybase.io/_/api/1.0/user/lookup.json?email={urllib.parse.quote(email)}"),
    ]

    out: List[str] = [f"osint_email {email} (md5 {h})"]
    results = osint_http_many(checks, timeout=8.0, max_len=2500, max_workers=6, overall_timeout=45)

    for name, _ in checks:
        txt = results.get(name, "")
        hit = txt and not txt.startswith("erro") and "HTTP 4" not in txt[:8] and "HTTP 5" not in txt[:8]
        if name == "GRAVATAR" and ('"entry"' in txt or "profileUrl" in txt):
            out.append(f"[{name}] PERFIL EXISTE -> https://gravatar.com/{h}\n{_clip(txt, 900)}")
            continue
        if name.startswith("GITHUB-COMMITS") and '"total_count"' in txt:
            try:
                n = json.loads(txt).get("total_count")
            except Exception:
                n = None
            if n:
                out.append(f"[{name}] {n} commit(s) com esse e-mail -> https://github.com/search?q=author-email:{email}&type=commits")
                out.append(_clip(txt, 700))
            continue
        if name == "GITHUB-USERS" and '"total_count"' in txt:
            try:
                n = json.loads(txt).get("total_count")
            except Exception:
                n = None
            if n:
                out.append(f"[{name}] {n} usuario(s) com esse nick -> https://github.com/search?q={user}&type=users")
                out.append(_clip(txt, 700))
            continue
        if name == "KEYBASE" and '"status":{"code":0}' in txt.replace(" ", ""):
            out.append(f"[{name}] existe conta keybase\n{_clip(txt, 600)}")
            continue
        if name == "HIBP" and hit and "haveibeenpwned" in txt.lower() and "found" in txt.lower():
            out.append(f"[{name}] confira no navegador -> https://haveibeenpwned.com/account/{email}")
            continue
        if hit and _clip(txt, 200).strip() and not txt.startswith("HTTP"):
            out.append(f"[{name}] {_clip(txt, 500)}")

    out.append(
        "PROXIMO PASSO: rode os dorks de e-mail (pastebin/gist/paste.ee), o 'osint_handles' com o nick "
        f"'{user}' e o 'osint_domain' em '{dom}' se o dominio for proprio."
    )
    return "\n".join(out)


def tool_osint_domain(args: Dict[str, Any]) -> str:
    import concurrent.futures

    dom = str(args.get("domain") or args.get("target") or "").strip().lower()
    dom = re.sub(r"^https?://", "", dom).strip("/").split("/")[0]
    if not dom or "." not in dom:
        return "erro: mande dominio valido (ex: empresa.com.br)"

    urls: List[Tuple[str, str]] = [
        ("CRT.SH", f"https://crt.sh/?q=%25.{urllib.parse.quote(dom)}&output=json"),
        ("WAYBACK", f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(dom)}*&output=json&fl=original,timestamp&collapse=urlkey&limit=80"),
        ("HACKERTARGET-HOSTS", f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(dom)}"),
        ("HACKERTARGET-DNS", f"https://api.hackertarget.com/dnslookup/?q={urllib.parse.quote(dom)}"),
        ("HACKERTARGET-HEADERS", f"https://api.hackertarget.com/httpheaders/?q={urllib.parse.quote(dom)}"),
        ("HACKERTARGET-WHOIS", f"https://api.hackertarget.com/whois/?q={urllib.parse.quote(dom)}"),
        ("URLSCAN", f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(dom)}"),
        ("JONLU", f"https://jldc.me/anubis/subdomains/{urllib.parse.quote(dom)}"),
        ("CERTSPOTTER", f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(dom)}&include_subdomains=true&expand=dns_names"),
        ("SHODAN-LINK", f"https://www.shodan.io/search?query={urllib.parse.quote(dom)}"),
        ("SECURITY.TXT", f"https://{dom}/.well-known/security.txt"),
        ("ROBOTS", f"https://{dom}/robots.txt"),
        ("SITEMAP", f"https://{dom}/sitemap.xml"),
    ]

    out: List[str] = [f"osint_domain {dom}"]
    results = osint_http_many(urls, timeout=9.0, max_len=3500, max_workers=8, overall_timeout=55)

    for name, _ in urls:
        txt = (results.get(name) or "").strip()
        if not txt or txt.startswith("erro") or txt.startswith("HTTP 4") or txt.startswith("HTTP 5"):
            continue
        if name == "CRT.SH" and txt.startswith("["):
            try:
                data = json.loads(txt)
                subs = sorted({str(d.get("name_value", "")).split("\n")[0] for d in data if isinstance(d, dict)})
                subs = [s for s in subs if s and s != dom][:40]
                out.append(f"[SUB DOMINIOS] {len(subs)} encontrados: {', '.join(subs[:25])}")
                out.append(f"   (fonte: https://crt.sh/?q=%25.{dom})")
                continue
            except Exception:
                pass
        if name == "WAYBACK" and txt.startswith("["):
            try:
                data = json.loads(txt)
                rows = [r for r in data if isinstance(r, list) and len(r) >= 2][:25]
                urls_found = [r[0] for r in rows]
                out.append(f"[WAYBACK] {len(rows)} urls historicas, ex: " + ", ".join(urls_found[:10]))
                continue
            except Exception:
                pass
        if name == "URLSCAN" and '"results"' in txt:
            out.append(f"[URLSCAN] {_clip(txt, 600)}")
            continue
        out.append(f"[{name}] {_clip(txt, 700)}")

    out.append(
        f"PROXIMO PASSO: dorks de dominio (site:*.{dom}, intitle:\"index of\", ext:env|sql|log), "
        f"abrir https://www.shodan.io/search?query={dom} e conferir subdominios achados um a um."
    )
    return "\n".join(out)


def tool_osint_cnpj(args: Dict[str, Any]) -> str:
    raw = str(args.get("cnpj") or args.get("target") or args.get("query") or "").strip()
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 14:
        return "erro: mande CNPJ com 14 digitos"
    txt = osint_http_text(f"https://brasilapi.com.br/api/cnpj/v1/{digits}", 8.0, 5000)
    if txt.startswith("erro") or txt.startswith("HTTP 4"):
        txt2 = osint_http_text(f"https://publica.cnpj.ws/cnpj/{digits}", 8.0, 5000)
        if txt2.startswith("erro") or txt2.startswith("HTTP 4"):
            return f"erro ao consultar CNPJ {digits}: {txt} | {txt2}"
        txt = txt2
    out = [f"osint_cnpj {digits}"]
    try:
        d = json.loads(txt)
    except Exception:
        return f"resposta inesperada: {_clip(txt, 800)}"

    def pick(*keys: str) -> str:
        for k in keys:
            v = d.get(k) if isinstance(d, dict) else None
            if v not in (None, "", []):
                return str(v)
        return ""

    razao = pick("razao_social", "nome")
    fantasia = pick("nome_fantasia")
    abertura = pick("data_inicio_atividade", "abertura", "data_abertura")
    situacao = pick("descricao_situacao_cadastral", "situacao", "situacao_cadastral")
    cnae = pick("cnae_fiscal_descricao")
    endereco = " ".join(
        x for x in [
            pick("descricao_tipo_de_logradouro"), pick("logradouro"), pick("numero"),
            pick("complemento"), pick("bairro"), pick("municipio"), pick("uf"), pick("cep"),
        ] if x
    )
    capital = pick("capital_social")
    porte = pick("porte", "descricao_porte")

    out.append(f"razao social: {razao or 'nao informado'}")
    if fantasia:
        out.append(f"nome fantasia: {fantasia}")
    out.append(f"abertura: {abertura or 'nao informado'} | situacao: {situacao or 'nao informado'}")
    if cnae:
        out.append(f"CNAE: {cnae}")
    if endereco:
        out.append(f"endereco: {endereco}")
    if porte:
        out.append(f"porte: {porte}")
    if capital:
        out.append(f"capital social: R$ {capital}")

    socios = None
    for k in ("qsa", "socios"):
        v = d.get(k) if isinstance(d, dict) else None
        if isinstance(v, list) and v:
            socios = v
            break
    if socios:
        out.append("SOCIOS / ADMINISTRADORES (dado publico):")
        for s in socios[:15]:
            if not isinstance(s, dict):
                continue
            nome = s.get("nome_socio") or s.get("nome") or ""
            qual = s.get("qualificacao_socio") or s.get("qual") or ""
            entrada = s.get("data_entrada_sociedade") or s.get("data_entrada") or ""
            extra = " | ".join(x for x in [qual, entrada] if x)
            out.append(f"  - {nome} {('(' + extra + ')') if extra else ''}")
    else:
        out.append("socios: nao informados pela fonte publica")
    out.append(
        "PROXIMO PASSO: cruzar cada socio com os dorks de nome (linkedin, diario oficial, jusbrasil, "
        "processos, doacoes) e com o endereco acima (mesmo CEP em outras empresas = mesmo grupo)."
    )
    return "\n".join(out)


# =====================================================================
# OSINT BRAZUCA - catalogo BR de fontes (github.com/osintbrazuca/osint-brazuca)
# Cada fonte sabe o que ACEITA (input: nome/cpf/cnpj/telefone...) e o que
# DEVOLVE (output: endereco/processo/socios...). Baixado 1x e cacheado.
# Linhas "[BR]" sao fontes do catalogo (NAO sao achados do alvo).
# =====================================================================
BRAZUCA_URL = "https://raw.githubusercontent.com/osintbrazuca/osint-brazuca/main/data/index.json"
BRAZUCA_PATH = CONFIG_DIR / "brazuca_index.json"
_BRAZUCA_MEM: Dict[str, Any] = {"links": [], "origin": ""}

_BRAZUCA_FALLBACK: List[Dict[str, Any]] = [
    {"fonte": "Jusbrasil", "url": "https://www.jusbrasil.com.br/", "categoria": "Consulta de Processos", "input": ["nome", "numero_processo"], "output": ["processo", "partes", "movimentacao"], "uf": "", "tipo": "privado"},
    {"fonte": "Escavador", "url": "https://www.escavador.com/", "categoria": "Consulta de Processos", "input": ["nome", "numero_processo"], "output": ["processo", "partes"], "uf": "", "tipo": "privado"},
    {"fonte": "DataJud CNJ", "url": "https://www.cnj.jus.br/datajud/", "categoria": "Consulta de Processos", "input": ["numero_processo"], "output": ["movimentacao", "partes"], "uf": "", "tipo": "judiciario"},
    {"fonte": "BNMP (mandados de prisao)", "url": "https://portalbnmp.cnj.jus.br/", "categoria": "Pessoas Procuradas", "input": ["nome"], "output": ["mandado_prisao"], "uf": "", "tipo": "judiciario"},
    {"fonte": "CNPJ.ws", "url": "https://cnpj.ws/", "categoria": "Busca via CPF/CNPJ", "input": ["cnpj", "razao_social"], "output": ["socios", "endereco", "cnae", "situacao_cadastral"], "uf": "", "tipo": "privado"},
    {"fonte": "CNPJ.biz", "url": "https://cnpj.biz/", "categoria": "Busca via CPF/CNPJ", "input": ["cnpj", "nome"], "output": ["socios", "endereco", "dados_cadastrais"], "uf": "", "tipo": "privado"},
    {"fonte": "Receita - Emissao CNPJ", "url": "https://solucoes.receita.fazenda.gov.br/servicos/cnpjreva/cnpjreva_solicitacao.asp", "categoria": "Busca via CPF/CNPJ", "input": ["cnpj"], "output": ["dados_cadastrais", "situacao_cadastral"], "uf": "", "tipo": "federal"},
    {"fonte": "Consulta Socio", "url": "https://www.consultasocio.com/", "categoria": "Busca via CPF/CNPJ", "input": ["cnpj", "nome"], "output": ["socios"], "uf": "", "tipo": "privado"},
    {"fonte": "Portal da Transparencia", "url": "https://portaldatransparencia.gov.br/", "categoria": "Transparencia Publica", "input": ["nome", "cnpj"], "output": ["beneficio", "contrato_publico", "licitacao", "sancao"], "uf": "", "tipo": "federal"},
    {"fonte": "DivulgaCand TSE", "url": "https://divulgacandcontas.tse.jus.br/", "categoria": "Registros Eleitorais", "input": ["nome", "municipio"], "output": ["dados_cadastrais"], "uf": "", "tipo": "judiciario"},
    {"fonte": "Lattes CNPq", "url": "https://lattes.cnpq.br/", "categoria": "Informacoes Academicas", "input": ["nome"], "output": ["curriculo", "publicacao_academica"], "uf": "", "tipo": "federal"},
    {"fonte": "Diario Oficial da Uniao", "url": "https://www.in.gov.br/", "categoria": "Diarios Oficiais", "input": ["nome"], "output": ["diario_oficial"], "uf": "", "tipo": "federal"},
    {"fonte": "Telelistas", "url": "https://www.telelistas.net/", "categoria": "Telecom", "input": ["telefone", "nome"], "output": ["endereco", "dados_cadastrais"], "uf": "", "tipo": "privado"},
    {"fonte": "Correios Busca CEP", "url": "https://buscacepinter.correios.com.br/app/endereco/index.php", "categoria": "Outras Buscas", "input": ["cep", "endereco"], "output": ["endereco"], "uf": "", "tipo": "federal"},
    {"fonte": "IBGE Cidades", "url": "https://cidades.ibge.gov.br/", "categoria": "Mapas e Georreferenciamento", "input": ["municipio"], "output": ["dados_cadastrais", "estatistica"], "uf": "", "tipo": "federal"},
    {"fonte": "OAB Nacional", "url": "https://www.oab.org.br/", "categoria": "Conselhos Profissionais", "input": ["nome", "oab"], "output": ["dados_cadastrais", "situacao_cadastral"], "uf": "", "tipo": "federal"},
    {"fonte": "CFM Medicina", "url": "https://portal.cfm.org.br/", "categoria": "Conselhos Profissionais", "input": ["nome", "registro_profissional"], "output": ["dados_cadastrais"], "uf": "", "tipo": "federal"},
    {"fonte": "Detran SP", "url": "https://www.detran.sp.gov.br/", "categoria": "Transporte Terrestre", "input": ["placa", "renavam"], "output": ["multa", "debito", "veiculo"], "uf": "SP", "tipo": "estadual"},
    {"fonte": "ReclameAqui", "url": "https://www.reclameaqui.com.br/", "categoria": "Defesa do Consumidor", "input": ["razao_social"], "output": ["dados_cadastrais"], "uf": "", "tipo": "privado"},
    {"fonte": "Desaparecidos RJ", "url": "https://desaparecidos.pcivil.rj.gov.br/pesquisar", "categoria": "Pessoas Desaparecidas", "input": ["nome"], "output": ["dados_cadastrais"], "uf": "RJ", "tipo": "estadual"},
    {"fonte": "LinkedIn", "url": "https://www.linkedin.com/", "categoria": "Rede Social", "input": ["nome"], "output": ["perfil_social", "curriculo"], "uf": "", "tipo": "privado"},
]

_BRAZUCA_SYN = {
    "nome": "nome", "name": "nome", "pessoa": "nome",
    "cpf": "cpf",
    "cnpj": "cnpj", "empresa": "cnpj", "razao_social": "razao_social", "razao": "razao_social",
    "telefone": "telefone", "fone": "telefone", "celular": "telefone", "phone": "telefone",
    "email": "email", "e-mail": "email", "e_mail": "email", "mail": "email",
    "placa": "placa", "carro": "placa", "veiculo": "placa", "renavam": "renavam", "chassi": "chassi",
    "processo": "numero_processo", "numero_processo": "numero_processo",
    "endereco": "endereco", "cep": "cep",
    "dominio": "dominio", "domain": "dominio", "site": "dominio", "ip": "ip",
    "oab": "oab", "advogado": "oab", "crm": "registro_profissional", "registro": "registro_profissional",
    "titulo": "titulo_eleitor", "eleitor": "titulo_eleitor",
    "municipio": "municipio", "cidade": "municipio", "uf": "uf", "estado": "uf",
    "matricula": "matricula_imovel", "imovel": "matricula_imovel",
    "aeronave": "prefixo_aeronave", "prefixo": "prefixo_aeronave",
    "embarcacao": "embarcacao", "barco": "embarcacao", "navio": "embarcacao",
    "socios": "socios", "socio": "socios",
    "cnae": "cnae", "atividade": "cnae",
    "partes": "partes", "movimentacao": "movimentacao", "andamento": "movimentacao",
    "certidao": "certidao", "antecedentes": "antecedentes", "criminal": "antecedentes",
    "mandado": "mandado_prisao", "procurado": "mandado_prisao",
    "beneficio": "beneficio", "bolsa": "beneficio",
    "licitacao": "licitacao", "contrato": "contrato_publico", "sancao": "sancao",
    "multa": "multa", "debito": "debito", "divida": "debito",
    "curriculo": "curriculo", "lattes": "curriculo", "academico": "publicacao_academica",
    "diario": "diario_oficial", "dou": "diario_oficial",
    "perfil": "perfil_social", "rede": "perfil_social", "social": "perfil_social",
    "dados": "dados_cadastrais", "cadastro": "dados_cadastrais",
    "situacao": "situacao_cadastral", "regularidade": "situacao_cadastral",
    "mapa": "mapa", "coordenadas": "coordenadas", "localizacao": "endereco",
    "operadora": "operadora", "erb": "erb", "antena": "erb",
    "api": "api_json", "json": "api_json", "dataset": "dataset", "dados_abertos": "dataset",
    "estatistica": "estatistica", "dork": "dork",
}


def _brazuca_norm_term(s: str) -> str:
    return _BRAZUCA_SYN.get(_strip_accents(str(s or "")).lower().strip(), "")


def _brazuca_cands(s: str) -> set:
    raw = _strip_accents(str(s or "")).lower().strip()
    return {x for x in (raw, _BRAZUCA_SYN.get(raw, "")) if x}


def _brazuca_norm(data: Any) -> List[Dict[str, Any]]:
    rows = data.get("links") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "").strip()
        if not url.startswith("http"):
            continue
        out.append({
            "fonte": str(r.get("fonte") or r.get("label") or "fonte").strip()[:80],
            "url": url,
            "categoria": str(r.get("categoria") or "").strip()[:60],
            "input": [str(x).lower() for x in (r.get("input") or []) if x],
            "output": [str(x).lower() for x in (r.get("output") or []) if x],
            "uf": str(r.get("uf") or "").upper().strip(),
            "tipo": str(r.get("tipo_fonte") or "").lower().strip(),
        })
    return out


def brazuca_links(max_age_days: int = 7) -> List[Dict[str, Any]]:
    """Catalogo: memoria > cache em disco (config/) > GitHub > fallback embutido."""
    if _BRAZUCA_MEM.get("links"):
        return _BRAZUCA_MEM["links"]
    try:
        if BRAZUCA_PATH.exists():
            age = (time.time() - BRAZUCA_PATH.stat().st_mtime) / 86400
            if age <= max_age_days:
                links = _brazuca_norm(json.loads(BRAZUCA_PATH.read_text(encoding="utf-8")))
                if links:
                    _BRAZUCA_MEM["links"] = links
                    _BRAZUCA_MEM["origin"] = "cache"
                    return links
    except Exception:
        pass
    try:
        import urllib.request as _ur
        req = _ur.Request(BRAZUCA_URL, headers={"User-Agent": "kernel11-osint"})
        with _ur.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        links = _brazuca_norm(data)
        if links:
            try:
                BRAZUCA_PATH.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass
            _BRAZUCA_MEM["links"] = links
            _BRAZUCA_MEM["origin"] = "github"
            return links
    except Exception:
        pass
    _BRAZUCA_MEM["links"] = [dict(x) for x in _BRAZUCA_FALLBACK]
    _BRAZUCA_MEM["origin"] = "fallback"
    return _BRAZUCA_MEM["links"]


def brazuca_search(tipo: str = "", quer: str = "", uf: str = "", limit: int = 12) -> Tuple[List[Dict[str, Any]], int, str]:
    links = brazuca_links()
    tset = _brazuca_cands(tipo) if tipo else set()
    qset = _brazuca_cands(quer) if quer else set()
    uf = str(uf or "").upper().strip()
    scored: List[Tuple[int, Dict[str, Any]]] = []
    for r in links:
        ins, outs = r["input"], r["output"]
        if tset and tset.isdisjoint(ins):
            continue
        if qset and qset.isdisjoint(outs):
            continue
        score = 0
        if tset:
            score += 2
        if qset:
            score += 2
        if uf and r["uf"] == uf:
            score += 3
        elif not r["uf"]:
            score += 1
        scored.append((score, r))
    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:limit]], len(scored), str(_BRAZUCA_MEM.get("origin") or "")


def brazuca_fmt(r: Dict[str, Any]) -> str:
    base = f"[BR] {r['fonte']} | {r['url']}"
    meta = []
    if r.get("categoria"):
        meta.append(str(r["categoria"])[:40])
    if r.get("input"):
        meta.append("tem:" + ",".join(r["input"][:3]))
    if r.get("output"):
        meta.append("da:" + ",".join(r["output"][:3]))
    if r.get("uf"):
        meta.append("UF " + str(r["uf"]))
    return base + (" | " + " ".join(meta) if meta else "")


def brazuca_suggest_for_entities(user_text: str, per_type: int = 2) -> str:
    """Top fontes BR para cada identificador detectado no alvo."""
    try:
        ent = osint_entities(user_text or "")
    except Exception:
        return ""
    wants: List[str] = []
    if ent.get("names"):
        wants.append("nome")
    if ent.get("emails"):
        wants.append("email")
    if ent.get("domains"):
        wants.append("dominio")
    if ent.get("phones"):
        wants.append("telefone")
    if ent.get("cnpjs"):
        wants.append("cnpj")
    if ent.get("handles") and "nome" not in wants:
        wants.append("nome")
    wants = list(dict.fromkeys(wants))[:4]
    if not wants:
        wants = ["nome"]
    try:
        uf = (_dork_values(user_text or "").get("uf") or "").upper()
    except Exception:
        uf = ""
    lines: List[str] = []
    for w in wants:
        try:
            rows, total, _ = brazuca_search(tipo=w, uf=uf, limit=per_type)
        except Exception:
            continue
        if not rows:
            continue
        lines.append(f"[BR] para {w.upper()} ({total} fontes; top {len(rows)}):")
        lines += [brazuca_fmt(r) for r in rows]
    return "\n".join(lines)


def tool_osint_br(args: Dict[str, Any]) -> str:
    tipo = str(args.get("tipo") or args.get("tem") or args.get("input") or "").strip()
    quer = str(args.get("quer") or args.get("output") or "").strip()
    uf = str(args.get("uf") or "").strip().upper()
    try:
        limit = int(args.get("limit") or 12)
    except (TypeError, ValueError):
        limit = 12
    limit = min(max(limit, 1), 30)
    if not tipo and not quer:
        return ("erro: diga o que voce TEM (tipo=nome|cpf|cnpj|telefone|email|placa|processo|...) "
                'e/ou o que QUER (quer=endereco|processo|socios|...). Ex: {"tipo":"nome","quer":"processo"}')
    try:
        rows, total, origin = brazuca_search(tipo=tipo, quer=quer, uf=uf, limit=limit)
    except Exception as e:
        return f"erro brazuca: {type(e).__name__}: {e}"
    if not rows:
        return (f"FONTES BR (catalogo osint-brazuca): nada para tipo='{tipo}' quer='{quer}'. "
                "Tente tipo=nome|cpf|cnpj|telefone|email|placa.")
    out = [f"FONTES BR (catalogo osint-brazuca, {total} compativeis, origem {origin} - mostrando {len(rows)}):"]
    out += [brazuca_fmt(r) for r in rows]
    out.append("Como usar: fetch na URL da fonte, ou dork site:<dominio> + identificador. [BR]=fonte do catalogo, nao achado.")
    return "\n".join(out)


def tool_osint_phone(args: Dict[str, Any]) -> str:
    raw = str(args.get("phone") or args.get("target") or args.get("query") or "").strip()
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 10:
        return "erro: mande telefone com DDD"
    ddd = digits[2:4] if digits.startswith("55") and len(digits) >= 12 else digits[:2]
    out = [f"osint_phone {raw} (digitos {digits}, DDD {ddd})"]
    txt = osint_http_text(f"https://brasilapi.com.br/api/ddd/v1/{ddd}", 10.0, 3000)
    if not txt.startswith("erro") and not txt.startswith("HTTP"):
        try:
            d = json.loads(txt)
            state = d.get("state")
            cities = d.get("cities") or []
            if state:
                out.append(f"regiao do DDD {ddd}: {state} ({len(cities)} cidades) -> {', '.join(cities[:12])}")
                out.append("USE ISSO para inferir localidade: cruze com o nome no dork '\"{name}\" \"{city}\"'")
        except Exception:
            out.append(_clip(txt, 400))
    out.append(
        "PROXIMO PASSO: dorks de telefone (facebook, olx, mercadolivre, apontador/telelistas) e checar o mesmo "
        "numero em pastes. Nao existe consulta publica gratuita de titular de linha."
    )
    return "\n".join(out)


REPORT_FIELDS = ("nome_real", "nascimento", "localidade")

_HOST_REDES = (
    "instagram.com", "facebook.com", "linkedin.com", "tiktok.com", "x.com", "twitter.com",
    "threads.net", "reddit.com", "youtube.com", "twitch.tv", "t.me", "telegram.me",
    "pinterest.com", "strava.com", "letterboxd.com", "spotify.com", "soundcloud.com",
    "last.fm", "steamcommunity.com", "roblox.com", "discord.com", "discord.gg",
    "linktr.ee", "beacons.ai", "about.me", "tumblr.com", "vk.com", "weibo.com",
    "snapchat.com", "kwai.com", "badoo.com", "tinder.com", "onlyfans.com",
)
_HOST_PROCESSOS = (
    "jusbrasil", "escavador", "juridico.ai", "jus.br", "mpf.mp.br", "mpsp.mp.br",
    "mppe.mp.br", "mpce.mp.br", "in.gov.br", "diariooficial", "imprensanacional",
    "leg.br", "tse.jus.br", "cnj.jus.br", "jf.jus.br", "trf", "publicacoes",
)
_HOST_REGISTROS = (
    "gov.br", "transparencia", "portaltransparencia", "pncp.gov.br", "comprasnet",
    "cnpj.biz", "casadosdados", "consultacnpj", "econodata", "cnpj.info", "cnpj.ws",
    "lattes.cnpq.br", "buscatextual.cnpq.br", "orcid.org", "scielo", "scholar.google",
    "repositorio", "edu.br", "cvm.gov.br", "receita.fazenda",
)
_KEY_PROCESSO = (
    "processo", "acao penal", "inquerito", "condenado", "condenacao", "indiciado",
    "denuncia", "sentenca", "autos", "reu ", "autor ", "intimacao", "mandado",
    "portaria", "nomeacao", "exoneracao", "diario oficial", "jurisprudencia",
)
_KEY_TELEFONE = ("telefone", "celular", "cel ", "whatsapp", "wpp", "fone", "contato:")
_BUCKET_TITLES = [
    ("redes", "redes sociais"),
    ("telefones", "telefones"),
    ("processos", "processos judiciais / diarios"),
    ("registros", "registros publicos"),
    ("pessoais", "outros dados pessoais"),
    ("outros", "links relacionados"),
]

_NASC_RE = re.compile(
    r"(?:nascid[oa]|born|nascimento|\bDOB\b|data de nascimento)[^0-9\n]{0,24}"
    r"((?:1[89]|20)\d{2}|(?:0?[1-9]|[12]\d|3[01])[/.\-](?:0?[1-9]|1[0-2])[/.\-](?:1[89]|20)\d{2})",
    re.IGNORECASE,
)
_LOC_CITY_RE = re.compile(
    r"\b((?:Fortaleza|Sao Paulo|São Paulo|Rio de Janeiro|Recife|Salvador|Belo Horizonte|Brasilia|Brasília|"
    r"Curitiba|Porto Alegre|Manaus|Belem|Belém|Goiania|Goiânia|Maceio|Maceió|Natal|Joao Pessoa|João Pessoa|"
    r"Teresina|Sao Luis|São Luís|Aracaju|Vitoria|Vitória|Campinas|Sorocaba|Niteroi|Niterói|Caucaia|Maracanau|"
    r"Maracanaú|Sobral|Juazeiro do Norte|Crato|Iguatu)\b)(?:\s*[/,-]\s*([A-Z]{2}))?",
)
_UF_RE = re.compile(r"\b(AC|AL|AP|AM|BA|CE|DF|ES|GO|MA|MT|MS|MG|PA|PB|PR|PE|PI|RJ|RN|RS|RO|RR|SC|SP|SE|TO)\b")

_FULLNAME_RE = re.compile(
    r"\b([A-Z\u00c0-\u00dd][\w\u00c0-\u00ff'\-]{2,}(?:\s+(?:d[aeo]s?\s+)?[A-Z\u00c0-\u00dd][\w\u00c0-\u00ff'\-]{1,}){1,4})\b"
)


def _slug(text: str) -> str:
    s = _strip_accents(str(text or "")).lower()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return (s or "alvo")[:40]


def _nao_conf(v: Any) -> str:
    v = " ".join(str(v or "").split())
    return v if v else "NAO CONFIRMADO"


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).netloc or "").replace("www.", "").lower()
    except Exception:
        return ""


def _bucket_of(fact: Dict[str, Any]) -> str:
    dado = str(fact.get("dado") or fact.get("data") or "").lower()
    link = str(fact.get("link") or fact.get("url") or "")
    host = _host_of(link)
    blob = dado + " " + link.lower()

    if any(h in host for h in _HOST_REDES):
        return "redes"
    if _PHONE_RE.search(dado) or _PHONE_RE.search(link):
        return "telefones"
    if any(k in dado for k in _KEY_TELEFONE):
        return "telefones"
    if any(h in host for h in _HOST_PROCESSOS) or any(k in dado for k in _KEY_PROCESSO):
        return "processos"
    if any(h in host for h in _HOST_REGISTROS):
        return "registros"
    if _NASC_RE.search(blob) or re.search(r"\b(nome real|nome completo|nascid[oa]|natural de)\b", dado):
        return "pessoais"
    return "outros"


def _clean_dado(dado: str, link: str, limit: int = 130) -> str:
    d = " ".join(str(dado or "").split())
    d = re.sub(r"^[-*\u2022\s]+", "", d)
    if not d or d.lower().startswith("link coletado"):
        host = _host_of(link)
        return host or link
    return _clip(d, limit)


def _phone_achados(evidence: str, limit: int = 8) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    ultimo_link = ""
    for line in str(evidence or "").splitlines():
        m_url = _URL_RE.search(line)
        if m_url:
            ultimo_link = m_url.group(0).rstrip(".,);]'\"")
        for ph in _PHONE_RE.findall(line):
            digits = re.sub(r"\D", "", ph)
            if 10 <= len(digits) <= 13:
                achado = {"dado": f"telefone {ph.strip()}", "link": ultimo_link, "confianca": "media"}
                if achado["dado"] not in [x["dado"] for x in out]:
                    out.append(achado)
        if len(out) >= limit:
            break
    return out


# =====================================================================
# DOSSIE / BANCO DE DADOS INVESTIGATIVO - estrutura viva de achados
# Acumula tudo que as tools encontram no caso atual:
# perfil investigativo > dossie organizado > banco cruzado entre turnos.
# =====================================================================
_SOCIAL_HOSTS = ("instagram.com", "facebook.com", "fb.com", "x.com", "twitter.com",
                 "linkedin.com", "tiktok.com", "youtube.com", "youtu.be", "kwai.com",
                 "threads.net", "pinterest.com", "reddit.com", "t.me", "telegram.me")
_TEC_HOSTS = ("github.com", "gitlab.com", "gist.github.com", "pastebin.com", "paste.ee",
              "ghostbin.com", "rentry.co", "shodan.io", "censys.io", "crt.sh",
              "web.archive.org", "who.is", "viewdns.info", "urlscan.io", "virustotal.com")
_DOC_HOSTS = ("jusbrasil.com.br", "escavador.com", "cnpj.biz", "gov.br", "lattes.cnpq.br",
              "diariooficial", "tse.jus.br", "receita.fazenda", "cnpj.ws",
              "brasilapi.com.br", "serasa", "boavista")


class DossieBoard:
    """Banco investigativo do caso atual. Ingere saidas das tools, dedupeia,
    anuncia so o que e novo ('> found ...') e rende tabela + resumo."""

    SECTIONS = (
        ("pessoa", "PERFIL"),
        ("contato", "CONTATO"),
        ("social", "SOCIAL"),
        ("tecnico", "TECNICO"),
        ("docs", "DOCS/PROCESSOS"),
        ("nucleo", "NUCLEO/PARENTES"),
    )
    PER_SECTION = 8
    MAX_SECTION = 40

    def __init__(self) -> None:
        self.alvo = ""
        self.items: Dict[str, List[Dict[str, str]]] = {}
        self._seen: set = set()
        self.reset()

    def reset(self, alvo: str = "") -> None:
        self.alvo = " ".join(str(alvo or "").split())
        self.items = {k: [] for k, _ in self.SECTIONS}
        self._seen = set()

    def count(self) -> int:
        return sum(len(v) for v in self.items.values())

    def values(self) -> set:
        out = set()
        for lst in self.items.values():
            for it in lst:
                out.add(str(it.get("valor", "")).lower())
        return out

    def _add(self, section: str, label: str, valor: str, fonte: str = "") -> Optional[Dict[str, str]]:
        valor = " ".join(str(valor or "").split())
        if not valor or len(valor) > 160:
            return None
        key = (section, valor.lower())
        if key in self._seen:
            return None
        self._seen.add(key)
        if len(self.items.get(section, [])) >= self.MAX_SECTION:
            return None
        it = {"label": str(label), "valor": valor, "fonte": " ".join(str(fonte or "").split())}
        self.items.setdefault(section, []).append(it)
        return it

    def ingest(self, tool_result: str, verbose: bool = True) -> List[Dict[str, str]]:
        """Extrai entidades da saida de uma tool; anuncia so achado novo."""
        txt = str(tool_result or "")
        if not txt or txt.startswith("erro") or len(txt) < 20:
            return []
        if txt.startswith("FONTES BR (catalogo"):
            return []  # catalogo de fontes, nao achado
        txt = "\n".join(ln for ln in txt.splitlines() if not ln.strip().startswith("[BR]"))
        novos: List[Dict[str, str]] = []
        try:
            ent = osint_entities(txt)
        except Exception:
            ent = {}
        email_doms: set = set()
        for em in (ent.get("emails") or [])[:6]:
            email_doms.add(em.split("@")[-1].lower())
            it = self._add("contato", "email", em)
            if it:
                novos.append(it)
        for ph in (ent.get("phones") or [])[:6]:
            it = self._add("contato", "telefone", ph)
            if it:
                novos.append(it)
        for h in (ent.get("handles") or [])[:8]:
            h = h if str(h).startswith("@") else "@" + str(h)
            it = self._add("social", "handle", h)
            if it:
                novos.append(it)
        for dm in (ent.get("domains") or [])[:6]:
            low = str(dm).lower()
            # servicos (linkedin, duckduckgo, jusbrasil...) ja filtrados no osint_entities;
            # aqui separa ativo provavel (dominio do proprio email) de mera citacao
            label = "dominio" if low in email_doms else "dominio citado"
            it = self._add("tecnico", label, dm)
            if it:
                novos.append(it)
        for cj in (ent.get("cnpjs") or [])[:4]:
            it = self._add("docs", "cnpj", cj)
            if it:
                novos.append(it)
        # identificadores do alvo p/ validar urls (perfil so entra se tem a ver com o alvo)
        idents: set = set()
        _IDENT_STOP = {"que", "para", "uma", "elle", "com", "sem", "por", "dos", "das",
                       "nas", "nos", "quem", "investiga", "investigar", "procura",
                       "procurar", "busca", "buscar", "ache", "achar", "descubra",
                       "descobrir", "perfil", "perfis", "dono", "este", "esta",
                       "esse", "essa", "isso", "sobre", "como", "onde", "quando",
                       "qual", "quais", "the", "and", "for", "http", "https",
                       "www", "site", "sites", "email", "telefone"}
        try:
            _vals = _dork_values(self.alvo)
            for _k in (_vals.get("first", ""), _vals.get("last", "")):
                _kl = _strip_accents(_k).lower()
                if len(_kl) >= 3:
                    idents.add(_kl)
            for _tok in re.findall(r"[a-z]{3,}", _strip_accents(self.alvo).lower()):
                if _tok not in _IDENT_STOP:
                    idents.add(_tok)
            _slug = re.sub(r"\W", "", _strip_accents(self.alvo)).lower()
            if len(_slug) >= 5:
                idents.add(_slug)
        except Exception:
            pass
        for em in (ent.get("emails") or [])[:6]:
            _eu = em.split("@")[0].lower()
            if len(_eu) >= 3:
                idents.add(_eu)
        for h in (ent.get("handles") or [])[:8]:
            _hl = str(h).lower().lstrip("@")
            if len(_hl) >= 3:
                idents.add(_hl)
        for it0 in self.items.get("social", []):
            if it0.get("label") == "handle":
                _hl = str(it0.get("valor", "")).lower().lstrip("@")
                if len(_hl) >= 3:
                    idents.add(_hl)

        fetched: set = set()
        for _ln in txt.splitlines():
            if _ln.strip().startswith("[FETCH]"):
                for _m in _URL_RE.findall(_ln):
                    fetched.add(_m.rstrip(".,);]'\""))

        def _url_ok(u: str) -> bool:
            if u in fetched:
                return True  # pagina aberta e lida = evidencia real
            ul = u.lower()
            return any(len(i) >= 3 and i in ul for i in idents)

        # saida do osint_handles: so as secoes EXISTE/INCONCLUSIVO valem
        # (sondagem lista a url testada; o resto do texto nao e evidencia)
        if "osint_handles '" in txt or "\nEXISTE:" in txt:
            _in_ok, _in_maybe = False, False
            for _ln in txt.splitlines():
                _s = _ln.strip()
                if _s == "EXISTE:":
                    _in_ok, _in_maybe = True, False
                    continue
                if _s.startswith("INCONCLUSIVO"):
                    _in_ok, _in_maybe = False, True
                    continue
                if _s.startswith("NAO EXISTE") or _s.startswith("PROXIMO PASSO"):
                    _in_ok = _in_maybe = False
                    continue
                if not (_in_ok or _in_maybe):
                    continue
                for _m in _URL_RE.findall(_ln):
                    u = _m.rstrip(".,);]'\"")
                    host = _host_of(u)
                    if not u or not host or any(s in u for s in _SKIP_URL):
                        continue
                    it = self._add("social", "perfil" if _in_ok else "perfil?", u, host)
                    if it:
                        novos.append(it)
        else:
            seen_u: set = set()
            for m in _URL_RE.findall(txt):
                u = m.rstrip(".,);]'\"")
                if not u or u in seen_u or any(s in u for s in _SKIP_URL):
                    continue
                seen_u.add(u)
                host = _host_of(u)
                if not host or not _url_ok(u):
                    continue
                if any(h in host for h in _SOCIAL_HOSTS):
                    it = self._add("social", "perfil", u, host)
                elif any(h in host for h in _TEC_HOSTS):
                    it = self._add("tecnico", "link", u, host)
                elif any(h in host for h in _DOC_HOSTS):
                    it = self._add("docs", "registro", u, host)
                else:
                    continue
                if it:
                    novos.append(it)
                if len(novos) > 30:
                    break
        try:
            pm = osint_extract_parents(txt)
            for pn in (pm.get("pai") or [])[:2]:
                it = self._add("nucleo", "possivel pai", pn)
                if it:
                    novos.append(it)
            for mn in (pm.get("mae") or [])[:2]:
                it = self._add("nucleo", "possivel mae", mn)
                if it:
                    novos.append(it)
        except Exception:
            pass
        try:
            last = (_dork_values(self.alvo).get("last") or "").lower()
            if last and len(last) > 2:
                for nm in (ent.get("names") or [])[:6]:
                    nl = _strip_accents(nm).lower()
                    if last in nl and nl != _strip_accents(self.alvo).lower() and _valid_person_name(nm):
                        it = self._add("pessoa", "nome visto", nm)
                        if it:
                            novos.append(it)
        except Exception:
            pass
        if verbose:
            for it in novos[:12]:
                print(f"  {Colors.gray('> found ' + it['label'] + ':')} {Colors.white(_clip(it['valor'], 80))}")
            if len(novos) > 12:
                print(Colors.gray(f"  > ... +{len(novos) - 12} achado(s) no dossie (/dossie pra ver tudo)"))
        return novos

    def render_table(self) -> str:
        total = self.count()
        if not total:
            return Colors.gray("  dossie vazio - nenhum achado no caso atual")
        out = [
            Colors.bold(f"  DOSSIE: {self.alvo or 'caso atual'}"),
            Colors.gray(f"  {total} item(ns) no banco investigativo"),
            "",
        ]
        for key, title in self.SECTIONS:
            lst = self.items.get(key) or []
            if not lst:
                continue
            out.append(f"  {Colors.white(title)} {Colors.gray('(%d)' % len(lst))}")
            for it in lst[: self.PER_SECTION]:
                lab = it["label"]
                dots = "." * max(2, 16 - len(lab))
                line = f"    {Colors.gray(lab)} {Colors.gray(dots)} {Colors.white(_clip(it['valor'], 48))}"
                if it.get("fonte"):
                    line += Colors.gray(f"  [{_clip(it['fonte'], 24)}]")
                out.append(line)
            if len(lst) > self.PER_SECTION:
                out.append(Colors.gray(f"    +{len(lst) - self.PER_SECTION} mais..."))
            out.append("")
        while out and not out[-1].strip():
            out.pop()
        return "\n".join(out)

    def summary_compact(self, width: int = 900) -> str:
        parts = []
        for key, title in self.SECTIONS:
            lst = self.items.get(key) or []
            if not lst:
                continue
            vals = "; ".join(f"{it['label']}: {it['valor']}" for it in lst[:6])
            parts.append(f"{title}: {vals}")
        return _clip(" | ".join(parts), width)


dossie = DossieBoard()


def dossie_rollover(q: str) -> None:
    """Troca de caso: se a mensagem traz identificador novo sem ligacao com o
    banco atual, zera o dossie. Saudacao e follow-up mantem o banco."""
    if _is_greeting_only(q):
        return
    if not dossie.alvo or not dossie.count():
        dossie.reset(q)
        return
    try:
        ent = osint_entities(q)
        qvals = {str(x).lower() for lst in ent.values() for x in (lst or [])}
    except Exception:
        qvals = set()
    if not qvals:
        return  # follow-up sem identificador novo ("e o pai dele?") -> mantem
    banco = dossie.values() | set(dossie.alvo.lower().split())
    for v in qvals:
        if not v or len(v) < 3:
            continue
        for b in banco:
            if not b or len(b) < 3:
                continue
            if v == b or v in b or b in v:
                return  # tem ligacao -> mesmo caso, mantem
    dossie.reset(q)  # caso novo, banco novo


def print_dossie_table() -> None:
    print(dossie.render_table())


def format_osint_report(
    alvo: str,
    nome_real: str = "",
    nascimento: str = "",
    localidade: str = "",
    pais: str = "",
    estado: str = "",
    cidade: str = "",
    achados: Optional[List[Any]] = None,
    inferencias: Optional[List[str]] = None,
    nao_encontrado: Optional[List[str]] = None,
    dorks: Optional[List[str]] = None,
    fontes: Optional[List[str]] = None,
    resumo: str = "",
    confianca: str = "",
    pai: str = "",
    mae: str = "",
    pai_fatos: Optional[List[Any]] = None,
    mae_fatos: Optional[List[Any]] = None,
    interligacoes: Optional[List[str]] = None,
) -> str:
    loc_parts = [x for x in [pais, estado, cidade] if str(x or "").strip()]
    if not loc_parts and localidade:
        loc_parts = [x.strip() for x in str(localidade).split(",") if x.strip()]
    local = ", ".join(loc_parts) if loc_parts else "NAO CONFIRMADO"

    buckets: Dict[str, List[Dict[str, str]]] = {k: [] for k, _ in _BUCKET_TITLES}
    vistos: set = set()
    for a in (achados or []):
        fact: Dict[str, Any] = a if isinstance(a, dict) else {"dado": str(a)}
        link = str(fact.get("link") or fact.get("url") or "").strip()
        conf = str(fact.get("confianca") or "").strip().lower()
        key = (link or str(fact.get("dado") or "")).lower()
        if not key or key in vistos:
            continue
        vistos.add(key)
        b = _bucket_of(fact)
        buckets.setdefault(b, []).append({
            "dado": _clean_dado(str(fact.get("dado") or ""), link),
            "link": link,
            "confianca": conf,
        })

    total = sum(len(v) for v in buckets.values())
    fontes_n = len({it["link"] for v in buckets.values() for it in v if it["link"]})
    quando = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    linhas: List[str] = []
    linhas.append(f"Alvo: {alvo or 'NAO INFORMADO'}")
    linhas.append(f"Nome real: {_nao_conf(nome_real)} | Nascimento: {_nao_conf(nascimento)} | Local: {local}")
    linhas.append(f"Pai: {_nao_conf(pai)} | Mae: {_nao_conf(mae)}")
    linhas.append(f"{total} achado(s) em {fontes_n} fonte(s) - gerado em {quando}")
    linhas.append("")

    mostrou = False
    for key, titulo in _BUCKET_TITLES:
        itens = buckets.get(key) or []
        if not itens:
            continue
        linhas.append(f"{titulo.upper()} ({len(itens)})")
        for i, it in enumerate(itens[:12], 1):
            linha = f"  {i}. {it['dado']}"
            if it["link"]:
                linha += f" | {it['link']}"
            if it["confianca"] and it["confianca"] not in ("media", "média"):
                linha += f" [{it['confianca']}]"
            linhas.append(linha)
        mostrou = True

    if not mostrou:
        linhas.append("Nada confirmado nas buscas (sem link verificavel).")

    # --- PAI / MAE (meta 3+3) ---
    def _norm_fatos(lst):
        out = []
        for a in (lst or []):
            if isinstance(a, dict):
                d = str(a.get("dado") or "").strip()
                l = str(a.get("link") or a.get("url") or "").strip()
            else:
                d, l = str(a).strip(), ""
            if d or l:
                out.append({"dado": _clean_dado(d, l) if d else "(sem descricao)", "link": l})
        return out[:6]

    pf = _norm_fatos(pai_fatos)
    mf = _norm_fatos(mae_fatos)
    if str(pai or "").strip() or pf:
        linhas.append("")
        linhas.append(f"PAI - {_nao_conf(pai)} ({len(pf)}/{OSINT_MIN_PARENT_FACTS})")
        if pf:
            for i, it in enumerate(pf, 1):
                linhas.append(f"  {i}. {it['dado']}" + (f" | {it['link']}" if it['link'] else ""))
        else:
            linhas.append("  (nenhum fato com link - buscar filiacao/'filho de'/jusbrasil/facebook)")
    if str(mae or "").strip() or mf:
        linhas.append("")
        linhas.append(f"MAE - {_nao_conf(mae)} ({len(mf)}/{OSINT_MIN_PARENT_FACTS})")
        if mf:
            for i, it in enumerate(mf, 1):
                linhas.append(f"  {i}. {it['dado']}" + (f" | {it['link']}" if it['link'] else ""))
        else:
            linhas.append("  (nenhum fato com link - buscar filiacao/'filho de'/jusbrasil/facebook)")

    # --- INTERLIGACOES (como um dado levou ao outro) ---
    ils = [str(x).strip() for x in (interligacoes or []) if str(x).strip()]
    if ils:
        linhas.append("")
        linhas.append("INTERLIGACOES (como os pontos se ligam):")
        linhas += [f"  - {_clip(x, 140)}" for x in ils[:8]]

    # --- placar da meta 5/3/3 ---
    try:
        linhas.append("")
        linhas.append(f"META: alvo {total}/{OSINT_MIN_TARGET_FACTS} | pai {len(pf)}/{OSINT_MIN_PARENT_FACTS} | mae {len(mf)}/{OSINT_MIN_PARENT_FACTS} (fatos com link)")
        faltas = []
        if total < OSINT_MIN_TARGET_FACTS:
            faltas.append(f"faltam {OSINT_MIN_TARGET_FACTS-total} do alvo")
        if len(pf) < OSINT_MIN_PARENT_FACTS:
            faltas.append(f"faltam {OSINT_MIN_PARENT_FACTS-len(pf)} do pai")
        if len(mf) < OSINT_MIN_PARENT_FACTS:
            faltas.append(f"faltam {OSINT_MIN_PARENT_FACTS-len(mf)} da mae")
        if faltas:
            linhas.append("PENDENTE: " + "; ".join(faltas) + " - rode overlap em outra categoria ou peca pista (cidade, @, empresa)")
    except Exception:
        pass

    inf = [str(i).strip() for i in (inferencias or []) if str(i).strip()]
    if inf:
        linhas.append("")
        linhas.append("INFERENCIAS (nao confirmado):")
        linhas += [f"  - {_clip(x, 130)}" for x in inf[:5]]

    nf = [str(i).strip() for i in (nao_encontrado or []) if str(i).strip()]
    if nf:
        linhas.append("SEM RESULTADO EM: " + ", ".join(_clip(x, 40) for x in nf[:8]))

    if resumo and not mostrou:
        frase = re.split(r"(?<=[.!?])\s", " ".join(str(resumo).split()))[0]
        frase = _clip(frase, 160)
        if frase and not any(frase[:40] in l for l in linhas):
            linhas.append(f"OBS: {frase}")

    return "\n".join(linhas)


_CONF_WORDS = ("alta", "media", "média", "baixa", "confirmado", "suspeita", "inferencia")


def _facts_from_answer(text: str, limit: int = 20) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: set = set()
    for line in str(text or "").splitlines():
        if "http" not in line:
            continue
        parts = [p.strip(" \t-*\u2022") for p in line.split("|")]
        link = ""
        for part in parts:
            m = _URL_RE.search(part)
            if m:
                link = m.group(0).rstrip(".,);]'\"")
                break
        if not link or link in seen or any(s in link for s in _SKIP_URL):
            continue
        seen.add(link)
        dado = ""
        conf = ""
        for part in parts:
            if part == link or "http" in part:
                continue
            if not dado:
                dado = part
            elif any(w in part.lower() for w in _CONF_WORDS):
                conf = part
        out.append({"dado": dado or "", "link": link, "fonte": "", "confianca": conf or "media"})
        if len(out) >= limit:
            break
    return out


def _facts_from_text(text: str, limit: int = 20) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: set = set()
    for url in _URL_RE.findall(text or ""):
        u = url.rstrip(".,);]'\"")
        if any(s in u for s in _SKIP_URL) or u in seen:
            continue
        seen.add(u)
        host = urllib.parse.urlparse(u).netloc.replace("www.", "") or "link"
        out.append({"dado": f"link coletado em {host}", "link": u, "confianca": "baixa"})
        if len(out) >= limit:
            break
    return out


def _probable_handles(alvo: str, maximo: int = 2) -> List[str]:
    vals = _dork_values(alvo)
    first, last = vals.get("first", ""), vals.get("last", "")
    if not first or not last:
        return []
    f = _strip_accents(first).lower()
    l = _strip_accents(last).lower()
    cands = [f"{f}{l}", f"{f}.{l}", f"{f[0]}{l}", f"{f}_{l}"]
    out: List[str] = []
    for c in cands:
        if 4 <= len(c) <= 30 and c.isascii() and c not in out:
            out.append(c)
    return out[:maximo]


def auto_extract_dossier(evidence: str, limit_urls: int = 20, alvo: str = "") -> Dict[str, Any]:
    ev = evidence or ""
    out: Dict[str, Any] = {"nascimento": "", "localidade": "", "cidade": "", "estado": "", "pais": "", "nome_real": "", "confianca": "media (extraido automaticamente)"}

    alvo_norm = {t for t in re.findall(r"[a-z\u00e0-\u00ff]{3,}", _strip_accents(alvo).lower())}
    if alvo and alvo_norm:
        for m in _FULLNAME_RE.findall(ev):
            cand = " ".join(m.split())
            toks = {t for t in re.findall(r"[a-z\u00e0-\u00ff]{3,}", _strip_accents(cand).lower())}
            if not toks or len(toks) <= len(alvo_norm):
                continue
            if alvo_norm.issubset(toks) and not (toks & _NAME_NOISE):
                out["nome_real"] = cand
                out["nome_real_conf"] = "media (forma mais completa encontrada na evidencia)"
                break

    m = _NASC_RE.search(ev)
    if m:
        out["nascimento"] = m.group(1)

    city = ""
    mc = _LOC_CITY_RE.search(ev)
    if mc:
        city = mc.group(1)
        if mc.group(2):
            out["estado"] = mc.group(2)
    if not out["estado"]:
        mu = _UF_RE.search(ev)
        if mu:
            out["estado"] = mu.group(1)
    out["cidade"] = city
    if city or out["estado"]:
        out["localidade"] = ", ".join(x for x in ["Brasil", out["estado"], city] if x)
        out["pais"] = "Brasil"
    # pai/mae automaticos (melhor esforco; agente confirma com link)
    try:
        pm = osint_extract_parents(ev)
        if pm.get("pai"):
            out["pai"] = pm["pai"][0]
        if pm.get("mae"):
            out["mae"] = pm["mae"][0]
        out["interligacoes"] = osint_interlinks(ev, alvo)
    except Exception:
        pass
    out["fontes"] = [f["link"] for f in _facts_from_text(ev, limit_urls)]
    return out


def tool_osint_report(args: Dict[str, Any]) -> str:
    alvo = " ".join(str(args.get("alvo") or args.get("target") or "").split())
    if not alvo:
        return "erro: mande 'alvo' (o nome/codigo que o usuario te deu)"
    if _is_greeting_only(alvo):
        return ("erro: alvo invalido - saudacao/entrada vazia ('%s') nao e alvo OSINT. "
                "Responda em texto curto pedindo o alvo real e NAO chame tools nem arquive relatorio."
                % alvo[:40])
    if len(alvo.split()) > 5 or len(alvo) > 60:
        vals = _dork_values(alvo)
        curto = vals.get("name") or vals.get("handle") or vals.get("email") or vals.get("domain") or vals.get("cnpj")
        if curto:
            alvo = curto.strip()
        else:
            alvo = "alvo"

    achados = args.get("achados") or args.get("dados") or []
    if isinstance(achados, str):
        achados = [achados]
    inferencias = args.get("inferencias") or []
    if isinstance(inferencias, str):
        inferencias = [inferencias]
    nao_encontrado = args.get("nao_encontrado") or args.get("nao_encontrados") or []
    if isinstance(nao_encontrado, str):
        nao_encontrado = [nao_encontrado]
    dorks = args.get("dorks") or []

    _pf = args.get("pai_fatos") or args.get("fatos_pai") or []
    _mf = args.get("mae_fatos") or args.get("fatos_mae") or []
    _il = args.get("interligacoes") or args.get("ligacoes") or []
    if isinstance(_pf, str):
        _pf = [_pf]
    if isinstance(_mf, str):
        _mf = [_mf]
    if isinstance(_il, str):
        _il = [_il]

    def _tem_link(lst) -> bool:
        for a in (lst or []):
            if isinstance(a, dict):
                if str(a.get("link") or a.get("url") or "").strip():
                    return True
            elif isinstance(a, str) and "http" in a:
                return True
        return False

    tem_fato = _tem_link(achados) or _tem_link(_pf) or _tem_link(_mf)
    relatorio = format_osint_report(
        alvo=str(alvo),
        nome_real=str(args.get("nome_real") or args.get("nome") or ""),
        nascimento=str(args.get("nascimento") or args.get("ano_nascimento") or ""),
        localidade=str(args.get("localidade") or ""),
        pais=str(args.get("pais") or ""),
        estado=str(args.get("estado") or args.get("uf") or ""),
        cidade=str(args.get("cidade") or ""),
        achados=list(achados) if isinstance(achados, list) else [],
        inferencias=list(inferencias) if isinstance(inferencias, list) else [],
        nao_encontrado=list(nao_encontrado) if isinstance(nao_encontrado, list) else [],
        fontes=list(args.get("fontes") or []) if isinstance(args.get("fontes"), list) else [],
        resumo=str(args.get("resumo") or ""),
        confianca=str(args.get("confianca") or ""),
        pai=str(args.get("pai") or args.get("nome_pai") or ""),
        mae=str(args.get("mae") or args.get("nome_mae") or ""),
        pai_fatos=list(_pf) if isinstance(_pf, list) else [],
        mae_fatos=list(_mf) if isinstance(_mf, list) else [],
        interligacoes=list(_il) if isinstance(_il, list) else [],
    )

    salvo = ""
    quer_salvar = str(args.get("salvar", "sim")).lower() not in ("0", "nao", "não", "false")
    if quer_salvar and not tem_fato:
        out = [relatorio]
        out.append("(nao salvo: nenhum fato com link - relatorio vazio nao e arquivado)")
        return "\n".join(out)
    if quer_salvar:
        try:
            path = safe_path(f"osint_{_slug(alvo)}.md")
            header = (
                f"# Relatorio OSINT - {alvo}\n\n"
                + datetime.datetime.now().strftime("Gerado em %d/%m/%Y %H:%M\n\n")
                + "> Fonte aberta e publica. Confira cada link antes de usar o dado.\n\n```text\n"
            )
            path.write_text(header + relatorio + "\n```\n", encoding="utf-8")
            salvo = str(path.name)
        except Exception as e:
            salvo = f"(falha ao salvar: {e})"

    out = [relatorio]
    if salvo:
        out.append(f"(salvo em workspace/{salvo})")
    return "\n".join(out)


def tool_workflow_create(args: Dict[str, Any]) -> str:
    desc = args.get("description") or args.get("task") or "nova tarefa"
    path = args.get("path") or args.get("file") or ""
    task = workflow.create_task(desc, path)
    return f"workflow criado {task.id[:8]} | {desc} -> {path} | stage={task.stage}"


def tool_workflow_analyze(args: Dict[str, Any]) -> str:
    path = args.get("path") or (workflow.get_current().file_path if workflow.get_current() else "")
    if not path:
        return "erro: path obrigatorio ou nenhuma tarefa ativa"
    fp = safe_path(str(path))
    if not fp.exists():
        return f"nao existe: {path}"
    current = workflow.get_current()
    if current:
        workflow.set_stage(current.id, "ANALISAR")
    try:
        content = fp.read_text(encoding="utf-8", errors="ignore")
        if fp.suffix == ".py":
            import py_compile
            py_compile.compile(str(fp), doraise=True)
            analise = f"ANALISAR ok: {path} sintaxe valida, {len(content)} chars, {len(content.splitlines())} linhas"
        else:
            analise = f"ANALISAR ok: {path} existe, {len(content)} chars"
        if current:
            workflow.set_stage(current.id, "TESTAR")
        return analise + " [workflow: ANALISAR->TESTAR]"
    except Exception as e:
        err = f"ANALISAR erro {path}: {e}"
        if current:
            workflow.set_stage(current.id, "CORRIGIR", str(e))
        return err + " [workflow: ANALISAR->CORRIGIR]"


def tool_workflow_test(args: Dict[str, Any]) -> str:
    path = args.get("path") or (workflow.get_current().file_path if workflow.get_current() else "")
    cmd = args.get("command") or args.get("cmd") or ""
    if not path:
        return "erro: path obrigatorio"
    current = workflow.get_current()
    if current:
        workflow.set_stage(current.id, "TESTAR")

    fp = safe_path(str(path))
    if not cmd:
        if fp.suffix == ".py":
            cmd = f'python "{fp.name}"'
        elif fp.suffix == ".js":
            cmd = f'node "{fp.name}"'
        else:
            cmd = f'dir "{fp.name}"'

    result = tool_shell({"command": cmd, "cwd": str(fp.parent)})
    if "exit=0" in result:
        msg = f"TESTAR ok {path}: {result[:2000]}"
        if current:
            workflow.set_stage(current.id, "APRESENTAR")
        return msg + " [workflow: TESTAR->APRESENTAR]"
    else:
        msg = f"TESTAR falhou {path}: {result[:3000]}"
        if current:
            workflow.set_stage(current.id, "CORRIGIR", result[:1000])
        return msg + " [workflow: TESTAR->CORRIGIR - precisa corrigir]"


def tool_workflow_fix(args: Dict[str, Any]) -> str:
    error = args.get("error") or args.get("last_error") or ""
    current = workflow.get_current()
    if not current:
        return "nenhuma tarefa ativa"
    workflow.set_stage(current.id, "CORRIGIR", error)
    return f"workflow {current.id[:8]} em CORRIGIR | ultimo erro: {current.last_error[:500]} | use edit_file/write_file para corrigir e depois workflow_test"


def tool_workflow_present(args: Dict[str, Any]) -> str:
    current = workflow.get_current()
    if not current:
        return "nenhuma tarefa ativa"
    path = current.file_path or args.get("path") or ""
    workflow.set_stage(current.id, "APRESENTAR")
    out = []
    out.append(f"=== APRESENTACAO {current.id[:8]} ===")
    out.append(f"Arquivo: {path}")
    out.append(f"Descricao: {current.description}")
    out.append(f"Tentativas: {current.attempts}")
    if path:
        try:
            fp = safe_path(path)
            content = fp.read_text(encoding="utf-8", errors="ignore")
            out.append(f"--- CONTEUDO ({len(content)} chars) ---")
            out.append(content[:8000])
        except Exception as e:
            out.append(f"erro ao ler {path}: {e}")
    out.append(f"\nDiffs pendentes: {len(diff_tracker.entries)}")
    workflow.set_stage(current.id, "ABRIR")
    return "\n".join(out) + "\n[workflow: APRESENTAR->ABRIR]"


def tool_workflow_open(args: Dict[str, Any]) -> str:
    path = args.get("path") or (workflow.get_current().file_path if workflow.get_current() else "")
    if not path:
        return "erro: path obrigatorio"
    current = workflow.get_current()
    if current:
        workflow.set_stage(current.id, "CONCLUIDO")
        workflow.log(current.id, f"[ABRIR] codigo aberto para usuario: {path}")
        workflow.save()
    fp = safe_path(str(path))
    try:
        content = fp.read_text(encoding="utf-8", errors="ignore")
        return f"<<<OPEN_FILE>>>{path}<<<END_OPEN>>>\n{content[:15000]}\n[workflow: ABRIR->CONCLUIDO] codigo aberto para usuario ver"
    except Exception as e:
        return f"erro ao abrir {path}: {e}"


def tool_workflow_list(_: Dict[str, Any]) -> str:
    return workflow.list_tasks()


def tool_workflow_status(_: Dict[str, Any]) -> str:
    cur = workflow.get_current()
    if not cur:
        return "nenhuma tarefa ativa\n" + workflow.list_tasks()
    return f"ATUAL: {cur.id[:8]} | {cur.stage} | {cur.file_path} | tentativas:{cur.attempts} | erro:{cur.last_error[:200]}\n---\n{workflow.list_tasks()}"


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
    "google_site_github": tool_google_github,
    "site_github_search": tool_google_github,
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
    "osint_dorks": tool_osint_dorks,
    "osint_report": tool_osint_report,
    "relatorio": tool_osint_report,
    "osint_handles": tool_osint_handles,
    "osint_email": tool_osint_email,
    "osint_domain": tool_osint_domain,
    "osint_cnpj": tool_osint_cnpj,
    "osint_phone": tool_osint_phone,
    "bing_search": tool_bing_search,
    "bing": tool_bing_search,
    "mojeek_search": tool_mojeek_search,
    "mojeek": tool_mojeek_search,
    "multi_search": tool_multi_search,
    "busca": tool_multi_search,
    "dorks": tool_osint_dorks,
    "osint": tool_osint_dorks,
    "open_browser": tool_open_browser,
    "abrir": tool_open_browser,
    "browser": tool_open_browser,
    "open_url": tool_open_browser,
    "abrir_navegador": tool_open_browser,
    "brazuca": tool_osint_br,
    "osint_br": tool_osint_br,
    "fontes_br": tool_osint_br,
}

TOOL_RE = re.compile(r"<<<TOOL_CALL>>>(.*?)<<<END_TOOL>>>", re.DOTALL)

SILENT_TOOLS = {
    "write_file", "edit_file", "delete_file", "rename_file", "mkdir",
    "list_files", "read_file",
    "workflow_create", "workflow_analyze", "workflow_test", "workflow_fix",
    "workflow_present", "workflow_open", "workflow_list", "workflow_status",
}

_CALL_TAGS = r"tool[_\- ]?calls?|tool|function[_\- ]?call|invoke|dsml|antml:invoke"
TAG_BLOCK_RE = re.compile(
    r"<{1,2}\s*[|｜]*\s*(?:" + _CALL_TAGS + r")[^>]{0,60}>.*?<{1,2}\s*/\s*[|｜]*\s*(?:" + _CALL_TAGS + r")[^>]{0,60}>",
    re.DOTALL | re.IGNORECASE,
)
DSML_BLOCK_RE = re.compile(r"<[^>]*[|｜][^>]*>.*?</[^>]*[|｜][^>]*>", re.DOTALL)
STRAY_TAG_RE = re.compile(r"<{1,2}\s*/?\s*[|｜]*\s*(?:" + _CALL_TAGS + r")[^>]{0,60}>{1,2}", re.IGNORECASE)
STRAY_DSML_RE = re.compile(r"<[|｜][^>\n]{0,60}[|｜]?>")
FENCE_EMPTY_RE = re.compile(r"```[a-zA-Z0-9_+.\-]*[ \t]*\r?\n?[ \t]*(?:\{\}|\[\])?[ \t]*```", re.DOTALL)

MACHINERY_LINE_RE = re.compile(
    r'^\{?\s*["\']?(?:name|tool_name|recipient|args|arguments|parameters|tool_input)["\']?\s*:'
    r'|["\'](?:args|arguments|tool_input)["\']\s*:.*["\'](?:content|path|query|command)["\']\s*:'
)

DSML_INVOKE_RE = re.compile(
    r"<[^>]*invoke\s+name=[\"']([^\"']+)[\"'][^>]*>(.*?)</[^>]*invoke[^>]*>", re.DOTALL | re.IGNORECASE)
DSML_PARAM_RE = re.compile(r"<[^>]*parameter\s+name=[\"']([^\"']+)[\"'][^>]*>(.*?)</[^>]*parameter[^>]*>", re.DOTALL | re.IGNORECASE)

_NAME_KEYS = ("name", "tool", "tool_name", "function", "recipient", "action")
_ARG_KEYS = ("args", "arguments", "parameters", "params", "input", "tool_input")


def _looks_like_call(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    if not any(k in obj for k in _NAME_KEYS):
        return False
    if any(isinstance(obj.get(k), dict) or isinstance(obj.get(k), list) for k in _ARG_KEYS):
        return True
    nested = obj.get("function")
    return isinstance(nested, dict) and any(k in nested for k in _NAME_KEYS)


def _normalize_call(obj: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(obj.get("function"), dict):
        inner = obj["function"]
        name = inner.get("name") or obj.get("name")
        args = inner.get("arguments", inner.get("args", {}))
    else:
        name = obj.get("name") or obj.get("tool") or obj.get("tool_name") or obj.get("recipient") or obj.get("action")
        args = {}
        for k in _ARG_KEYS:
            if k in obj:
                args = obj[k]
                break
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    if not isinstance(args, dict):
        args = {}
    return {"name": str(name or "").strip(), "args": args}


def _find_json_calls(text: str) -> List[Tuple[int, int, Dict[str, Any]]]:
    dec = json.JSONDecoder()
    found: List[Tuple[int, int, Dict[str, Any]]] = []
    i = 0
    while True:
        i = text.find("{", i)
        if i < 0:
            break
        try:
            obj, end = dec.raw_decode(text[i:])
        except ValueError:
            i += 1
            continue
        if _looks_like_call(obj):
            call = _normalize_call(obj)
            if call["name"] in TOOLS or call["name"].startswith("__"):
                found.append((i, i + end, call))
                i += end
                continue
        i += 1
    return found


_CALL_START_RE = re.compile(r'\{\s*"(?:name|tool|tool_name|function|recipient|action)"\s*:')
_CALL_NAME_RE = re.compile(r'"(?:name|tool|tool_name|recipient|action)"\s*:\s*"([^"\\\s]{1,64})"')
_HAS_ARGS_RE = re.compile(r'"(?:args|arguments|parameters|params|input|tool_input)"\s*:')
_CALL_PATH_RE = re.compile(r'"(?:path|file|filename)"\s*:\s*"([^"\n]{1,200})"')


def _scan_json_end(text: str, start: int) -> int:
    depth = 0
    i = start
    n = len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c in "{[": 
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth <= 0:
                    return i + 1
        i += 1
    return n


def _find_lenient_calls(text: str) -> List[Tuple[int, int, Dict[str, Any]]]:
    found: List[Tuple[int, int, Dict[str, Any]]] = []
    for m in _CALL_START_RE.finditer(text):
        start = m.start()
        end = _scan_json_end(text, start)
        span = text[start:end]
        nm = _CALL_NAME_RE.search(span[:300])
        name = (nm.group(1) if nm else "").strip()
        if name not in TOOLS and not _HAS_ARGS_RE.search(span[:1500]):
            continue

        call: Optional[Dict[str, Any]] = None
        try:
            obj = json.loads(span)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            call = _normalize_call(obj)

        if not call or not call.get("name"):
            call = {"name": name, "args": {}, "__broken__": True}
            pm = _CALL_PATH_RE.search(span)
            if pm:
                call["args"]["path"] = pm.group(1)

        found.append((start, end, call))
    return found


def _find_dsml_calls(text: str) -> List[Tuple[int, int, Dict[str, Any]]]:
    found: List[Tuple[int, int, Dict[str, Any]]] = []
    for m in DSML_INVOKE_RE.finditer(text):
        name = (m.group(1) or "").strip()
        if name not in TOOLS:
            continue
        args: Dict[str, Any] = {}
        for pm in DSML_PARAM_RE.finditer(m.group(2)):
            key = (pm.group(1) or "").strip()
            val = (pm.group(2) or "").strip()
            try:
                parsed = json.loads(val)
                args[key] = parsed
            except json.JSONDecodeError:
                args[key] = val
        found.append((m.start(), m.end(), {"name": name, "args": args}))
    return found


def extract_tool_calls(text: str) -> List[Tuple[int, int, Dict[str, Any]]]:
    calls: List[Tuple[int, int, Dict[str, Any]]] = []

    for m in TOOL_RE.finditer(text):
        raw = m.group(1).strip()
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            calls.append((m.start(), m.end(), {"name": "__json_error__", "args": {}, "error": str(e), "raw": raw}))
            continue
        if isinstance(obj, dict):
            call = _normalize_call(obj)
            if not call.get("name"):
                call["__broken__"] = True
            calls.append((m.start(), m.end(), call))
        else:
            calls.append((m.start(), m.end(), {"name": "", "args": {}, "__broken__": True}))

    for start, end, call in _find_dsml_calls(text) + _find_json_calls(text) + _find_lenient_calls(text):
        if not any(s <= start and end <= e for s, e, _ in calls):
            calls.append((start, end, call))

    calls.sort(key=lambda c: c[0])
    return calls


def strip_tool_markup(text: str) -> str:
    spans = extract_tool_calls(text)

    keep: List[Tuple[int, int, Dict[str, Any]]] = []
    for span in spans:
        if not any(s <= span[0] and span[1] <= e for s, e, _ in keep):
            keep.append(span)

    out = text
    for start, end, _ in sorted(keep, key=lambda s: s[0], reverse=True):
        line_start = out.rfind("\n", 0, start) + 1
        line_end = out.find("\n", end)
        if line_end == -1:
            line_end = len(out)

        head_cut = start
        head = out[line_start:start]
        if "`" in head and re.fullmatch(r"[ \t`]*[a-zA-Z0-9_+.#\-]*[ \t`]*", head):
            head_cut = line_start

        tail_cut = end
        tail = out[end:line_end]
        if re.fullmatch(r"[ \t`{}\[\](),;:]*", tail):
            tail_cut = line_end

        out = out[:head_cut] + out[tail_cut:]

    out = TAG_BLOCK_RE.sub("", out)
    out = DSML_BLOCK_RE.sub("", out)
    out = re.sub(r"<<<[^>]*>>>", "", out)
    out = re.sub(r"<{1,2}\s*/?\s*[|｜]*\s*(?:" + _CALL_TAGS + r")[^>]{0,60}>{1,2}", "", out, flags=re.IGNORECASE)
    out = STRAY_DSML_RE.sub("", out)
    out = FENCE_EMPTY_RE.sub("", out)
    out = re.sub(r"```[a-zA-Z0-9_+.\-]*[ \t]*\r?\n[ \t]*\r?\n?[ \t]*```", "", out)

    lines = []
    for line in out.split("\n"):
        s = line.strip()
        if s and MACHINERY_LINE_RE.search(s):
            continue
        lines.append(line)
    out = "\n".join(lines)

    out = re.sub(r"[ \t]+\r?\n", "\n", out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


_DORK_HEADER_RE = re.compile(
    r"^[\s\[\]()*#>-]*(?:dorks?|dorks? usad[oa]s?|arsenal de dorks|buscas? usad[ao]s?|"
    r"queries? usadas?|operadores? usados?)[\s:.\-\[\]()*#]*$",
    re.IGNORECASE,
)
_DORK_OPERATOR_RE = re.compile(
    r"(?:^|\s)(?:site:|filetype:|intitle:|allintitle:|inurl:|allinurl:|intext:|allintext:|"
    r"inanchor:|related:|cache:|ext:|OR site:|https?://crt\.sh|tbm=isch)",
    re.IGNORECASE,
)


def strip_dorks(text: str) -> str:
    linhas: List[str] = []
    pulando_lista = False
    for line in str(text or "").splitlines():
        s = line.strip()
        if _DORK_HEADER_RE.match(s):
            pulando_lista = True
            continue
        if pulando_lista:
            if not s:
                continue
            if re.match(r"^\d+[.)]\s", s) or s.startswith(("-", "*", "\u2022")):
                continue
            pulando_lista = False
        if _DORK_OPERATOR_RE.search(s):
            continue
        linhas.append(line)
    out = "\n".join(linhas)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


_SECTION_HDR_RE = re.compile(r"^\s*[\[\u3010]{0,2}\s*[A-Z\u00c0-\u00dc][A-Z\u00c0-\u00dc /_-]{2,}\s*[\]\u3011]{0,2}\s*:?\s*$")
_OSINT_FILLER_RE = re.compile(
    r"sem resultado|n[aã]o encontrei|nada [uú]til|me manda|manda uma pista|"
    r"pr[oó]ximo passo|quer que eu|posso continuar|se quiser|aguardo|preciso de mais|"
    r"nao localizei|não localizei|sem dados",
    re.IGNORECASE,
)


def osint_visible_text(text: str, max_linhas: int = 5, max_chars: int = 600) -> str:
    keep: List[str] = []
    for raw_line in strip_dorks(text).splitlines():
        s = raw_line.strip()
        if not s:
            continue
        if _SECTION_HDR_RE.match(s):
            continue
        if re.match(r"^[\[\u3010][^\]\u3011]{1,30}[\]\u3011]", s):
            continue
        if "|" in s and "http" in s:
            continue
        if _DORK_OPERATOR_RE.search(s):
            continue
        if s.startswith(("-", "*", "\u2022")):
            corpo = s.lstrip("-*\u2022 ").strip()
            if not corpo or "http" in corpo or len(corpo) > 160:
                continue
            s = corpo
        if _OSINT_FILLER_RE.search(s):
            continue
        keep.append(s)
        if len(keep) >= max_linhas:
            break
    return _clip(" ".join(keep), max_chars)


def looks_truncated(text: str) -> bool:
    t = str(text or "")
    if not t.strip():
        return False
    if t.count("```") % 2 == 1:
        last_fence = t.rfind("```")
        tail = t[last_fence + 3:]
        if not tail.strip() or len(tail.strip()) < 40:
            return True
    if t.count("<<<TOOL_CALL>>>") > t.count("<<<END_TOOL>>>"):
        return True
    if t.rstrip().endswith("\\"):
        return True
    return False


def exec_tools(text: str) -> Tuple[str, List[str], List[str]]:
    import concurrent.futures
    calls = [call for _, _, call in extract_tool_calls(text)]

    def run_one(call: Dict[str, Any]) -> Tuple[str, str]:
        try:
            if call.get("name") == "__json_error__":
                return (
                    "erro: tool call com JSON invalido (aspas nao escapadas no content?). "
                    "Reenvie usando <<<TOOL_CALL>>>{\"name\":\"write_file\",\"args\":{...}}<<<END_TOOL>>> "
                    "e quebre arquivos grandes em varios write_file/edit_file menores.",
                    "",
                )
            if call.get("__broken__"):
                where = (call.get("args") or {}).get("path") or "?"
                return (
                    f"erro: tool call truncado ou JSON quebrado (path {where}). "
                    "A resposta comecou a chamada e cortou no meio. Reenvie a chamada completa com "
                    "<<<TOOL_CALL>>>{\"name\":\"write_file\",\"args\":{\"path\":\"...\",\"content\":\"...\"}}<<<END_TOOL>>> "
                    "e mande arquivos grandes em pedacos (um write_file por vez, ou write_file + edit_file).",
                    "",
                )
            name = call.get("name")
            args = call.get("args", {}) or {}
            if name not in TOOLS:
                return f"tool desconhecida: {name}", f"used {name}: tool desconhecida"
            _tt0 = time.time()
            try:
                res = TOOLS[name](args)
            except Exception as e:
                res = f"erro tool {name}: {e}"
            _dt = time.time() - _tt0
            if name in SILENT_TOOLS:
                return res, ""
            # DEBUG uniforme: mesmo modelo "used <tool>: <detalhe>" para todas as tools.
            # Ex: used dorks: Joao Silva | used fetch: https://... | used report | used shell: $ ...
            disp = str(name)
            if disp.startswith("osint_"):
                disp = disp[len("osint_"):]
            detail = (
                args.get("target") or args.get("query") or args.get("url")
                or args.get("handle") or args.get("email") or args.get("domain")
                or args.get("cnpj") or args.get("phone") or args.get("path")
                or args.get("command") or args.get("site") or args.get("alvo") or args.get("tipo") or ""
            )
            detail = str(detail).strip()
            _tt = f" ({_dt:.1f}s)"
            if str(res or "").startswith("erro"):
                used_msg = f"used {disp}: erro{_tt}"
            elif detail:
                used_msg = f"used {disp}: {_clip(detail, 50)}{_tt}"
            else:
                used_msg = f"used {disp}{_tt}"
            return res, used_msg
        except Exception as e:
            return f"erro thread tool: {e}", f"used {call.get('name','?')}: erro thread"

    results: List[str] = []
    used: List[str] = []
    if not calls:
        return clean_output(strip_tool_markup(text)), results, used

    _TOOL_TIMEOUTS = {"osint_dorks": 150, "dorks": 150, "osint": 150,
                      "osint_domain": 100, "osint_email": 100, "osint_handles": 100}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6, thread_name_prefix="tool") as executor:
        futures = [executor.submit(run_one, call) for call in calls]
        for idx, future in enumerate(futures):
            call = calls[idx]
            _tmo = _TOOL_TIMEOUTS.get(str(call.get("name") or ""), 60)
            try:
                res, used_msg = future.result(timeout=_tmo)
                results.append(res)
                used.append(used_msg)
            except concurrent.futures.TimeoutError:
                results.append(f"erro timeout: tool {call.get('name')} travou apos {_tmo}s e foi abortada")
                used.append(f"used {call.get('name')}: timeout")
            except Exception as e:
                results.append(f"erro thread: {e}")
                used.append(f"used {call.get('name','?')}: erro")

    return clean_output(strip_tool_markup(text)), results, used


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

    def _write_str(self, s: str) -> Tuple[int, int]:
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
                try:
                    view = self.mem.uint8_view(self.store)
                    view[ptr:ptr + len(data)] = data
                except Exception as e:
                    raise RuntimeError(f"falha ao escrever na memoria wasm: {e}")
        return ptr, len(data)

    def solve(self, chal: str, prefix: str, diff: float) -> Optional[int]:
        retptr = self.stack_ptr(self.store, -16)
        try:
            cp, cl = self._write_str(chal)
            pp, pl = self._write_str(prefix)
            self.solve_fn(self.store, retptr, cp, cl, pp, pl, float(diff))
            try:
                raw = self.mem.read(self.store, retptr, 16)
                if len(raw) < 16:
                    raise ValueError("read curto")
                status = struct.unpack("<i", raw[0:4])[0]
                value = struct.unpack("<d", raw[8:16])[0]
            except Exception:
                mem_ptr = self.mem.data_ptr(self.store)
                try:
                    s1 = bytes(mem_ptr[retptr:retptr + 4])
                    s2 = bytes(mem_ptr[retptr + 8:retptr + 16])
                except Exception:
                    view = self.mem.uint8_view(self.store)
                    s1 = bytes(view[retptr:retptr + 4])
                    s2 = bytes(view[retptr + 8:retptr + 16])
                if len(s1) < 4 or len(s2) < 8:
                    raise RuntimeError(f"memoria wasm retornou buffer curto: {len(s1)}/{len(s2)} - wasm corrompido?")
                status = struct.unpack("<i", s1)[0]
                value = struct.unpack("<d", s2)[0]
        finally:
            try:
                self.stack_ptr(self.store, 16)
            except Exception:
                pass
        return None if status == 0 else int(value)

    def make_header(self, c: Dict[str, Any]) -> str:
        challenge_obj = c
        ans = self.solve(
            challenge_obj["challenge"],
            f"{challenge_obj['salt']}_{challenge_obj['expire_at']}_",
            float(challenge_obj["difficulty"]),
        )
        if ans is None:
            raise RuntimeError("pow fail")
        payload = {
            "algorithm": challenge_obj["algorithm"],
            "challenge": challenge_obj["challenge"],
            "salt": challenge_obj["salt"],
            "answer": ans,
            "signature": challenge_obj["signature"],
            "target_path": challenge_obj["target_path"],
        }
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
            timeout=httpx.Timeout(120.0, read=300.0),
        )
        self.sid: Optional[str] = None
        self.parent: Optional[int] = None
        self._sessions_route: Optional[str] = None
        self._history_route: Optional[str] = None
        self._continue_route: Optional[str] = None
        self.last_finish: str = ""
        self.last_truncated: bool = False
        self.last_error: str = ""
        self.last_parent: Optional[int] = None

    def new_chat(self) -> str:
        r = self.http.post(self.config.session_path, json={})
        r.raise_for_status()
        try:
            d = r.json()
        except Exception as e:
            raise RuntimeError(f"resposta nao-json ao criar chat: {r.text[:500]} | erro {e}")

        data = d.get("data")
        if data is None:
            msg = d.get("msg") or d.get("message") or d.get("error") or str(d)[:1000]
            raise RuntimeError(f"API retornou data=null (token expirado ou bloqueado?): {msg}")

        biz = data.get("biz_data") if isinstance(data, dict) else None
        if biz is None:
            biz = data if isinstance(data, dict) else {}

        if not isinstance(biz, dict):
            raise RuntimeError(f"biz_data nao e dict: {biz} | full: {d}")

        sid = None
        cs = biz.get("chat_session")
        if isinstance(cs, dict):
            sid = cs.get("id") or cs.get("chat_session_id")
        elif isinstance(cs, str) and cs:
            sid = cs

        if not sid:
            sid = (
                biz.get("id")
                or biz.get("chat_session_id")
                or biz.get("session_id")
                or (data.get("id") if isinstance(data, dict) else None)
                or (data.get("chat_session", {}).get("id") if isinstance(data.get("chat_session"), dict) else None)
            )

        if not sid:
            raise RuntimeError(f"sem sessao, resposta completa: {json.dumps(d, ensure_ascii=False)[:3000]}")

        self.sid = str(sid)
        self.parent = None
        return self.sid

    @staticmethod
    def _biz(d: Dict[str, Any]) -> Any:
        data = d.get("data") if isinstance(d, dict) else None
        if data is None:
            return None
        if isinstance(data, dict):
            biz = data.get("biz_data")
            return data if biz is None else biz
        return data

    def _unwrap(self, d: Any) -> Any:
        if not isinstance(d, dict):
            return d
        biz = self._biz(d)
        return d if biz is None else biz

    def _extract_list(self, d: Any, keys: Tuple[str, ...]) -> Optional[List[Dict[str, Any]]]:
        biz = self._unwrap(d)
        if isinstance(biz, list):
            return [x for x in biz if isinstance(x, dict)]
        if isinstance(biz, dict):
            for key in keys:
                cand = biz.get(key)
                if isinstance(cand, list):
                    return [x for x in cand if isinstance(x, dict)]
        return None

    def list_sessions(self, count: int = 100) -> List[Dict[str, Any]]:
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 100
        count = max(1, min(count, 100))

        path = self.config.sessions_path
        calls: List[Tuple[str, str, str, Dict[str, Any]]] = [
            ("GET-count", "GET", path, {"params": {"count": count}}),
            ("GET-cursor", "GET", path, {"params": {"count": count, "cursor": ""}}),
            ("GET-plain", "GET", path, {}),
            ("POST-count", "POST", path, {"json": {"count": count}}),
            ("POST-plain", "POST", path, {"json": {}}),
        ]
        if self._sessions_route:
            calls.sort(key=lambda c: 0 if c[0] == self._sessions_route else 1)

        errors: List[str] = []
        for key, method, pth, kw in calls:
            try:
                r = self.http.request(method, pth, **kw)
                r.raise_for_status()
                d = r.json()
            except Exception as e:
                errors.append(f"{method} {pth} -> {type(e).__name__}: {e}")
                if self._sessions_route == key:
                    self._sessions_route = None
                continue

            items = self._extract_list(
                d, ("chat_sessions", "sessions", "chat_session_list", "list", "items"),
            )
            if items is None:
                errors.append(f"{method} {pth} -> resposta sem lista: {json.dumps(d, ensure_ascii=False)[:160]}")
                continue

            self._sessions_route = key
            return items

        raise RuntimeError(" | ".join(errors) if errors else "falha desconhecida ao listar sessoes")

    def fetch_messages(self, sid: Optional[str] = None, count: int = 100) -> List[Dict[str, Any]]:
        sid = str(sid or self.sid or "").strip()
        if not sid:
            raise RuntimeError("sem sessao")

        path = self.config.history_path
        calls: List[Tuple[str, str, str, Dict[str, Any]]] = [
            ("GET-plain", "GET", path, {"params": {"chat_session_id": sid}}),
            ("GET-count", "GET", path, {"params": {"chat_session_id": sid, "count": count}}),
            ("POST-plain", "POST", path, {"json": {"chat_session_id": sid}}),
            ("POST-count", "POST", path, {"json": {"chat_session_id": sid, "count": count}}),
        ]
        if self._history_route:
            calls.sort(key=lambda c: 0 if c[0] == self._history_route else 1)

        errors: List[str] = []
        for key, method, pth, kw in calls:
            try:
                r = self.http.request(method, pth, **kw)
                r.raise_for_status()
                d = r.json()
            except Exception as e:
                errors.append(f"{method} {pth} -> {type(e).__name__}: {e}")
                if self._history_route == key:
                    self._history_route = None
                continue

            msgs = self._extract_list(d, ("chat_messages", "messages", "chat_message_list", "list", "items"))
            if msgs is None:
                errors.append(f"{method} {pth} -> resposta sem mensagens: {str(d)[:160]}")
                continue

            self._history_route = key
            return msgs

        raise RuntimeError(" | ".join(errors))

    def load_chat(self, sid: str, recover_parent: bool = True) -> str:
        sid = str(sid or "").strip()
        if not sid:
            raise RuntimeError("sid vazio")

        self.sid = sid
        self.parent = None
        if not recover_parent:
            return sid

        try:
            ids = [
                m.get("message_id")
                for m in self.fetch_messages(sid)
                if isinstance(m.get("message_id"), int)
            ]
            if ids:
                self.parent = max(ids)
        except Exception:
            self.parent = None
        return sid

    def pow_header(self) -> str:
        r = self.http.post(self.config.challenge_path, json={"target_path": self.config.completion_path})
        r.raise_for_status()
        try:
            j = r.json()
            data = j.get("data") or {}
            biz = data.get("biz_data") or data
            chal = biz.get("challenge") if isinstance(biz, dict) else None
            if chal is None:
                chal = j.get("data", {}).get("biz_data", {}).get("challenge") if isinstance(j.get("data"), dict) else None
            if chal is None:
                raise RuntimeError(f"challenge null: {j}")
        except Exception as e:
            raise RuntimeError(f"erro ao pegar challenge: {e} | resp: {r.text[:1000]}")
        with self.lock:
            return self.pow.make_header(chal)

    _TRUNC_VALUES = (
        "length", "max_tokens", "max_output", "token_limit", "content_length",
        "incomplete", "truncated", "output_limit",
    )

    def _note_signal(self, key: str, value: Any) -> None:
        if value is None or value == "":
            return
        v = str(value).strip()
        low = v.lower()
        if "code" in key and low in ("0", "none"):
            return
        if key in ("finish_reason", "stop_reason", "status", "quasi_status", "fragment", "code"):
            self.last_finish = f"{key}={v[:60]}"
        if low in self._TRUNC_VALUES or "truncat" in low or "incomplete" in low or "length" in low:
            self.last_truncated = True
        if key == "code" and low not in ("0", "none"):
            self.last_error = v[:300]
        if key in ("msg", "message") and low not in ("ok",):
            self.last_error = v[:300]

    def _consume_stream(self, resp: Any, meta: Dict[str, Any]):
        for raw_line in resp.iter_lines():
            if not raw_line.startswith("data:"):
                continue
            payload = raw_line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue

            v = obj.get("v")

            for key in ("finish_reason", "stop_reason", "status", "quasi_status", "code", "msg"):
                val = obj.get(key)
                if isinstance(val, (str, int)):
                    self._note_signal(key, val)

            if isinstance(v, dict) and "response" in v:
                response = v["response"] if isinstance(v["response"], dict) else {}
                mid = response.get("message_id")
                if isinstance(mid, int):
                    meta["message_id"] = mid
                for key in ("finish_reason", "stop_reason", "status", "quasi_status"):
                    val = response.get(key)
                    if isinstance(val, str):
                        self._note_signal(key, val)
                for frag in response.get("fragments", []):
                    if not isinstance(frag, dict):
                        continue
                    ftype = str(frag.get("type") or "").upper()
                    if "FINISH" in ftype or "INCOMPLETE" in ftype:
                        self._note_signal("fragment", str(frag.get("content") or ftype))
                    if frag.get("type") == "RESPONSE" and frag.get("content"):
                        yield frag["content"]
                continue

            if "p" in obj:
                path = str(obj.get("p") or "")
                if path.endswith("message_id") and isinstance(v, int):
                    meta["message_id"] = v
                if path.endswith("status") and isinstance(v, str):
                    self._note_signal("status", v)
                if obj.get("o") == "APPEND" and isinstance(v, str) and path.endswith("content"):
                    yield v
                continue

            if isinstance(v, str):
                yield v

    def stream(self, prompt: str):
        if not self.sid:
            self.new_chat()
        self.last_finish = ""
        self.last_truncated = False
        self.last_error = ""
        self.last_parent = self.parent

        body: Dict[str, Any] = {
            "chat_session_id": self.sid,
            "parent_message_id": self.parent,
            "prompt": prompt,
            "ref_file_ids": [],
            "thinking_enabled": False,
            "search_enabled": False,
        }
        if self.parent is None:
            body["model_type"] = "default"

        meta: Dict[str, Any] = {}
        with self.http.stream(
            "POST", self.config.completion_path,
            json=body,
            headers={"x-ds-pow-response": self.pow_header()}
        ) as resp:
            resp.raise_for_status()
            yield from self._consume_stream(resp, meta)

        if meta.get("message_id"):
            self.parent = meta["message_id"]

    def continue_chat(self):
        self.last_finish = ""
        self.last_truncated = False
        self.last_error = ""

        sid = str(self.sid or "")
        mid = self.parent
        if not sid or not isinstance(mid, int):
            yield from self.stream(CONTINUE_PROMPT)
            return

        variants: List[Tuple[str, Dict[str, Any]]] = [
            ("mid+parent", {
                "chat_session_id": sid,
                "message_id": mid,
                "parent_message_id": self.last_parent,
                "thinking_enabled": False,
                "search_enabled": False,
            }),
            ("mid", {"chat_session_id": sid, "message_id": mid}),
            ("empty-prompt", {
                "chat_session_id": sid,
                "parent_message_id": mid,
                "prompt": "",
                "ref_file_ids": [],
                "thinking_enabled": False,
                "search_enabled": False,
            }),
            ("mid+flags", {
                "chat_session_id": sid,
                "message_id": mid,
                "thinking_enabled": False,
                "search_enabled": False,
            }),
        ]
        if self._continue_route:
            variants.sort(key=lambda v: 0 if v[0] == self._continue_route else 1)

        errors: List[str] = []
        for key, body in variants:
            meta: Dict[str, Any] = {}
            try:
                header = {"x-ds-pow-response": self.pow_header()}
            except Exception as e:
                errors.append(f"pow: {type(e).__name__}")
                break
            try:
                with self.http.stream(
                    "POST", self.config.continue_path, json=body, headers=header
                ) as resp:
                    if resp.status_code >= 400:
                        try:
                            resp.read()
                        except Exception:
                            pass
                        errors.append(f"{key}: HTTP {resp.status_code}")
                        if self._continue_route == key:
                            self._continue_route = None
                        continue
                    self._continue_route = key
                    yield from self._consume_stream(resp, meta)
                    if meta.get("message_id") and not self.last_parent:
                        self.last_parent = self.parent
                    return
            except Exception as e:
                errors.append(f"{key}: {type(e).__name__}: {_clip(e, 80)}")
                continue

        yield from self.stream(CONTINUE_PROMPT)

    def close(self):
        try:
            self.http.close()
        except Exception:
            pass


KERNEL11_PROMPT = """Voce e kernel11-chat, agente autonomo estilo Claude Code. Criado por Kernel11. 100% AUTONOMO: resolve sozinho, nao pede permissao, nao pergunta "quer que eu busque?".
Estilo: direto, tecnico, sem enrolacao, sem "**", sem emoji, portugues simples. Plano curto (1-3 linhas) -> tools em paralelo -> valida -> entrega.

ARQUIVOS GRANDES: >~120 linhas = esqueleto no write_file + edit_file em pedacos de ~80. Nunca reenvie o arquivo inteiro pra corrigir 1 linha. Antes de sobrescrever: read_file.
Se sua resposta for cortada, o sistema emenda sozinho: continue do ponto exato, sem recomecar.

AUTONOMIA:
1. Precisou de dado externo? BUSQUE DIRETO (3-5 calls em paralelo). Tente 3+ fontes; fetch falhou = bypass + proxima.
2. Preco/produto: web_search + fetch em ML/Terabyte/Buscape/Zoom -> entregue menor preco, media, onde comprar, links.
3. Saudacao = "fala" curto + pergunta o que precisa. Sem list_files.
4. NAVEGADOR: pediu pra ABRIR ("abre X", "open", "mostra no navegador") -> ache o link e ABRA DIRETO com open_browser {"url":"..."}, SEM perguntar. So URL http(s); arquivo local NUNCA (leia com read_file). So pergunte "quer que eu abra?" quando ele NAO pediu.
5. ANTI-ALUCINACAO: nunca invente caminho, funcao, preco ou versao. Nao viu = "nao confirmado" + busque.
6. CHECKLIST antes de responder: dado real? fonte/link? codigo testado? workflow ate o fim? Se NAO, corrija.

BUSCA (qual tool):
- CODIGO/API/LIB/DOC: grep (grep.app) PRIMEIRO. Google NUNCA pra source puro.
- PRECO/PRODUTO/NOTICIA/GERAL: web_search + google_search/site_search + fetch pra CONFIRMAR (2+ fontes antes de afirmar).
- GitHub issues/discussao: google_search com site:github.com.
ORDEM: grep|web_search -> google/site refinando -> fetch -> comparar.

WORKFLOW DE CODIGO (sempre, sem pular etapa):
CRIAR: cheque workflow_status (nao duplique tarefa) -> workflow_create {"description","path"} -> write_file.
TESTAR: workflow_analyze -> workflow_test (rode de verdade). Nunca diga "pronto" sem teste verde.
CORRIGIR (se erro): workflow_fix + edit_file, 1 causa por vez, ate 5 tentativas; na 5a: log + alternativa.
APRESENTAR: workflow_present -> workflow_open (= CONCLUIDO) -> resumo curto (o que fez, como rodar, onde esta).
PERSISTENCIA: tudo em workspace/.kernel11_workflow.json; "continua" = workflow_status + read_file antes de agir.

TOOLS: list_files, read_file, write_file, edit_file, delete_file, rename_file, mkdir | powershell/bash/terminal | grep, fetch, web_search | google_search {"query":"site:github.com ..."} | site_search {"site":"...","query":"..."} | open_browser {"url":"https://..."} (DIRETO quando pedir; NUNCA arquivo) | workflow_create/analyze/test/fix/present/open/list/status
Formato (varios por mensagem):
<<<TOOL_CALL>>>
{"name":"write_file","args":{"path":"workspace/main.py","content":"..."}}
<<<END_TOOL>>>

Workspace atual:
__FILES__
"""

OSINT_PROMPT = """Voce e kernel11-osint, agente de OSINT do Kernel11. So fonte ABERTA e PUBLICA. DADO REAL, CONFERIVEL, COM LINK. Zero teoria, zero "procure no Google", zero invencao.
IDIOMA: SEMPRE portugues do Brasil (pt-BR). NUNCA chines/ingles - nem sob cobranca.
Raciocinio de analista CYBER SEC FULL STACK senior: hipotese -> enumera -> pivoteia -> confirma (2+ evidencias) -> documenta. Sem amadorismo, sem achismo.

MISSAO: pista -> buscas -> fetch -> NOME REAL + 5 FATOS DO ALVO + 3 DO PAI + 3 DA MAE (tudo com link) + redes/telefones/processos + nascimento/localidade. META 5/3/3 obrigatoria; nao atingiu = explique o que faltou e qual pista resolveria.

NAO E ALVO (responda so texto, SEM tools, SEM relatorio):
- SAUDACAO: "oi", "eai", "opa", "bom dia" -> "fala, manda o alvo: nome completo, @, e-mail, telefone ou cidade".
- PERGUNTA SOBRE VOCE: "quais seus acessos/tools/frameworks", "como voce funciona" -> liste o arsenal em texto (buscadores, osint_dorks, brazuca = catalogo 1000+ fontes BR, fechamento osint_report).
- So 1 pista? COMECE com ela e peca o resto em 1 linha. Nunca "quer que eu busque?" - busque.

METODO (sempre nesta ordem):
1. VOCE inicia tudo sozinho: 1a acao = <<<TOOL_CALL>>>{"name":"osint_dorks","args":{"target":"<alvo>"}}<<<END_TOOL>>> (overlap 5x + fetch + recon). Repita pra cada alvo novo (PAI, MAE, @). Responder sem tool call e sem osint_report = FALHA + cobranca.
2. FINA (4+ buscas + 1+ fetch) no que faltar pra META (google/site/web/grep). Nao sabe ONDE consultar? brazuca {"tipo":"nome"} + leia FONTES BR SUGERIDAS do osint_dorks.
3. INTERLIGUE ("isso me leva a quem/onde?"): mesmo sobrenome+cidade = parente | mesmo email/@/telefone em 2 fontes = mesma pessoa | mesma empresa/CNPJ = mesmo grupo | mesma bio = busque o trecho exato entre aspas. 1 linha por interligacao no relatorio.
4. OVERLAP 5x POR CATEGORIA (redes, telefone, processo, pai, mae, endereco, docs): ate 5 variacoes (grafia, ordem, recorte, pt/en, operador, pivo) antes de trocar de categoria; zerou = nao_encontrado.
5. CONFIRME com fetch. Snippet = pista, NAO prova.
6. ENTREGUE no padrao (link + confianca) + o que NAO achou + pista que destravaria.

PAI E MAE (tentar sempre): Jusbrasil/Escavador (filiacao), CNPJ.ws (socios), LinkedIn/Facebook ("filho de"/"mae de"), DOU, Lattes, obituarios. Dorks: "alvo" "filho de"|"mae"|"pai"|filiacao | "sobrenome" + cidade + "mae/pai" | site:facebook|jusbrasil. Candidato = osint_dorks nele + 1 link de vinculo (senao = inferencia). META 3+3 com link.

CAMADAS (L1 identidade, L2 social, L3 contato, L4 tecnica, L5 institucional, L6 nucleo): DESAMBIGUACAO obrigatoria (mesmo nome NAO e mesma pessoa: cruze cidade + idade + vinculo, anote descartes). 2+ evidencias independentes pra afirmar. Fonte primaria > agregador. DOSSIE PARCIAL do harness: leia antes de repetir, pivoteie dele ("perfil?" = inconclusivo, confirme; "dominio citado" = so mencao). Cadeia de evidencia sempre refezivel (pista -> fonte -> confirmacao -> interligacao). PROIBIDO: 1 busca e desistir, homonimo sem prova, snippet como fato, inventar pra preencher meta.

AUTONOMIA: so termina o turno apos osint_report (caso real sem relatorio = NADA gerado; o harness nao faz nada por voce). "Sem resultado" exige 4+ buscas + 1 fetch no turno; se vazio, +3 variando grafia/idioma/operador/alvo. Sem nada no nome? sobrenome + cidade/empresa/profissao, site:jusbrasil/escavador/cnpj.biz/lattes/github/instagram, PDFs, @ provavel (nome.sobrenome, iniciais). Peca pista extra SO depois de entregar. ABRIR ("abre o perfil/site") = open_browser DIRETO, so http(s), arquivo = read_file; so pergunte quando NAO pediu. Nunca peca permissao.

DORKS (uso interno - NUNCA liste na resposta; nunca escreva "dork" pro usuario):
- "alvo" site:linkedin|github|instagram|x|facebook | "handle" site:t.me
- "@dominio.com" -site:dominio.com | "@gmail.com" "alvo" site:pastebin|ghostbin|rentry|gist
- filetype:pdf|xlsx|doc "alvo|empresa" | "alvo" (site:gov.br OR site:jusbrasil OR site:escavador OR site:cnpj.biz) | "alvo" "processo|diario oficial|licitacao"
- intext:"alvo" intext:"telefone|cidade" | intitle:"index of" site:dominio | inurl:wp-content|uploads|perfil site:dominio | ext:sql|env|log|bak site:dominio | related:dominio | "alvo" site:reddit|medium|quora|stackoverflow | "alvo" "filho de"|filiacao | "membro desde" "alvo"
- shodan/censys via fetch: https://www.shodan.io/search?query=dominio.com | https://search.censys.io/search?resource=hosts&q=dominio.com

QUALIDADE: PROIBIDO inventar (nao confirmou = "nao confirmado"). Achado = LINK (+ data); sem link = inferencia. So fonte publica: sem login/invasao/senha; dado sensivel NAO se reproduz (diga que existe). Separe FATO x INFERENCIA x INTERLIGACAO. Parentesco so e FATO com link de vinculo. Resposta curta, em blocos, sem "**".

TOOLS: osint_dorks {"target"} (varredura inicial: 1x alvo + 1x por alvo novo) | osint_handles {"handle"} (~32 plataformas) | osint_email {"email"} (gravatar, commits github, keybase) | osint_domain {"domain"} (crt.sh, wayback, DNS, robots) | osint_cnpj {"cnpj"} (socios, endereco, CNAE) | osint_phone {"phone"} (DDD + buscas) | brazuca {"tipo":"nome","quer":"processo"} (ONDE consultar cada identificador BR) | google_search/site_search/web_search/grep/fetch (finas + CONFIRMACAO) | bing/mojeek/multi_search (quando Google bloqueia) | shell (whois/dig) | write_file (salva workspace/osint_<alvo>.md) | open_browser {"url"} (DIRETO quando pedir; NUNCA arquivo)

RELATORIO (chame osint_report no fim):
<<<TOOL_CALL>>>{"name":"osint_report","args":{"alvo":"...","nome_real":"...","nascimento":"1990","pais":"Brasil","estado":"CE","cidade":"Fortaleza","pai":"...","mae":"...","achados":[{"dado":"perfil no instagram","link":"https://..."},{"dado":"processo 0001234-56.2020","link":"https://..."}],"pai_fatos":[{"dado":"...","link":"..."}],"mae_fatos":[{"dado":"...","link":"..."}],"interligacoes":["..."],"inferencias":["..."],"nao_encontrado":["..."]}}<<<END_TOOL>>>
Ela imprime e salva workspace/osint_<alvo>.md neste padrao:
Alvo: {...} | Nome real: {...} | Nasc: {...} | Local: {pais, estado, cidade} | Pai/Mae: {... ou NAO CONFIRMADO} | {total} achados, alvo {x}/5 pai {y}/3 mae {z}/3
REDES / TELEFONES / PROCESSOS / REGISTROS (n): 1. {dado} | {link} ... PAI (n/3), MAE (n/3), INTERLIGACOES.
REGRAS: sem link nao entra (vai pra inferencia). Nao confirmado = "" (vira NAO CONFIRMADO). Nunca chute nome/nascimento/pai/mae. NUNCA relate saudacao ou entrada sem identificador (0 fatos = nao salva).
SUA RESPOSTA NA TELA: max 5 linhas, sem "dork", sem explicar metodo, sem repetir o relatorio. Depois do texto, chame osint_report.

Workspace atual:
__FILES__
"""

CONTINUE_PROMPT = (
    "Sua resposta anterior foi CORTADA pelo limite de saida. Continue AGORA, exatamente do ponto onde parou.\n"
    "REGRAS: nao repita nada do que ja escreveu, nao escreva introducao, nao comente, nao recomece, "
    "nao resuma o trabalho feito.\n"
    "- Se estava dentro de codigo: continue o codigo do caractere exato, mantendo indentacao e a mesma cerca ```.\n"
    "- Se estava no meio de uma tool call: continue o JSON do ponto exato e feche com <<<END_TOOL>>>. "
    "Nao reenvie o inicio da chamada.\n"
    "- Se ja terminou de escrever, responda apenas: FIM"
)

AGENTS: Dict[str, Dict[str, str]] = {
    "code": {
        "name": "Code Agent",
        "desc": "cria, edita e testa codigo no workspace (padrao)",
        "prompt": KERNEL11_PROMPT,
    },
    "osint": {
        "name": "Osint Agent",
        "desc": "OSINT com dorks: dados reais de fonte aberta, com link",
        "prompt": OSINT_PROMPT,
    },
}


# ---------------------------------------------------------------------------
# Apresentacao no chat (minima: apenas Agent Mode, chat e ANSI)
# ---------------------------------------------------------------------------

def _progress_bar(done: int, total: int, width: int = 18) -> str:
    return ""


def print_osint_banner(target: str) -> None:
    return


def print_osint_progress(stage: str, done: int, total: int, detail: str = "") -> None:
    return


def print_osint_agent_text(text: str) -> None:
    t = str(text or "").strip()
    if t:
        print(t)


def print_osint_report(text: str) -> None:
    t = str(text or "").strip()
    if t:
        print(t)


def chat_display_name(agents: Optional["AgentManager"] = None) -> str:
    """Nome do chat atual: titulo remoto (nome no DeepSeek) > titulo local
    (primeira mensagem) > '(novo chat)'. Nunca mostra sid."""
    try:
        sid = str(agents.client.sid or "") if agents else ""
    except Exception:
        sid = ""
    if not sid:
        return "----"
    try:
        for s in (agents.registry.remote or []):
            _id = str(s.get("id") or s.get("chat_session_id") or "")
            if _id == sid:
                t = SessionRegistry._remote_title(s)
                if t:
                    return _clip(t, 40)
    except Exception:
        pass
    try:
        t = agents.registry.title_of(sid)
        if t:
            return _clip(t, 40)
    except Exception:
        pass
    return "(novo chat)"


def print_header(agents: Optional["AgentManager"] = None):
    if not agents:
        return
    print(
        f"{Colors.gray('Agent Mode:')} {Colors.bold(agents.label())}"
        f"   {Colors.gray('Chat:')} {Colors.white(chat_display_name(agents))}"
    )


class _LivePrinter:
    """Imprime chunks do stream escondendo tool calls (mesmo partidas em chunks)."""

    OPEN = "<<<TOOL_CALL>>>"
    CLOSE = "<<<END_TOOL>>>"

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self._buf = ""
        self._in_tool = False
        self.printed_any = False

    @staticmethod
    def _tail_keep(s: str, marker: str) -> int:
        n = min(len(s), len(marker) - 1)
        for k in range(n, 0, -1):
            if s.endswith(marker[:k]):
                return k
        return 0

    def _write(self, s: str) -> None:
        if s:
            try:
                sys.stdout.write(s)
                sys.stdout.flush()
                self.printed_any = True
            except Exception:
                pass

    def feed(self, chunk: str) -> None:
        if not self.enabled or not chunk:
            return
        self._buf += chunk
        while True:
            if not self._in_tool:
                i = self._buf.find(self.OPEN)
                if i == -1:
                    keep = self._tail_keep(self._buf, self.OPEN)
                    out, self._buf = self._buf[: len(self._buf) - keep], self._buf[len(self._buf) - keep :]
                    self._write(out)
                    break
                self._write(self._buf[:i])
                self._buf = self._buf[i + len(self.OPEN):]
                self._in_tool = True
            else:
                j = self._buf.find(self.CLOSE)
                if j == -1:
                    keep = self._tail_keep(self._buf, self.CLOSE)
                    self._buf = self._buf[len(self._buf) - keep :] if keep else ""
                    break
                self._buf = self._buf[j + len(self.CLOSE):]
                self._in_tool = False

    def finish(self) -> None:
        if self.enabled and not self._in_tool and self._buf:
            self._write(self._buf)
        self._buf = ""
        if self.enabled and self.printed_any:
            try:
                sys.stdout.write("\n")
                sys.stdout.flush()
            except Exception:
                pass


def thinking_anim(stop_event: threading.Event, t0=None):
    base = t0 or time.time()
    try:
        while not stop_event.wait(1.0):
            el = time.time() - base
            sys.stdout.write(f"\r  {Colors.gray(f'... {el:.0f}s')}")
            sys.stdout.flush()
    except Exception:
        pass
    finally:
        try:
            sys.stdout.write("\r" + " " * 20 + "\r")
            sys.stdout.flush()
        except Exception:
            pass


def enter_listener(interrupt_event: threading.Event, stop_event: threading.Event):
    try:
        if os.name == "nt":
            import msvcrt
            while not stop_event.is_set() and not interrupt_event.is_set():
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in (b'\r', b'\n', b'\x03'):
                        interrupt_event.set()
                        break
                time.sleep(0.05)
        else:
            if not sys.stdin.isatty():
                return
            import select, termios, tty
            old = None
            try:
                old = termios.tcgetattr(sys.stdin)
                tty.setcbreak(sys.stdin.fileno())
            except Exception:
                old = None
            try:
                while not stop_event.is_set() and not interrupt_event.is_set():
                    r, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if r:
                        ch = sys.stdin.read(1)
                        if ch in ('\n', '\r', '\x03'):
                            interrupt_event.set()
                            break
            finally:
                if old:
                    try:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
                    except Exception:
                        pass
    except Exception:
        pass


def _clip(text: Any, width: int) -> str:
    t = " ".join(str(text).split())
    if width <= 3:
        return t[:width]
    return t if len(t) <= width else t[: width - 3] + "..."


def _fmt_time(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e11:
            ts /= 1000.0
        try:
            return datetime.datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")
        except Exception:
            return ""
    s = str(value).strip()
    if not s:
        return ""
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%d/%m %H:%M")
    except Exception:
        return s[:16]


def _message_text(msg: Dict[str, Any]) -> str:
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return content

    frags = None
    if isinstance(content, list):
        frags = content
    elif isinstance(content, dict):
        for key in ("fragments", "content"):
            inner = content.get(key)
            if isinstance(inner, list):
                frags = inner
                break
            if isinstance(inner, str) and inner.strip():
                return inner
    if frags is None:
        frags = msg.get("fragments")

    if isinstance(frags, list):
        parts: List[str] = []
        for f in frags:
            if isinstance(f, str):
                parts.append(f)
                continue
            if isinstance(f, dict):
                if f.get("type") not in (None, "RESPONSE", "REQUEST"):
                    continue
                c = f.get("content")
                if isinstance(c, str):
                    parts.append(c)
        return "".join(parts)
    return ""


def clear_screen() -> None:
    if os.name == "nt":
        try:
            os.system("cls")
        except Exception:
            pass
    elif sys.stdout.isatty():
        try:
            os.system("clear")
        except Exception:
            pass
    try:
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()
    except Exception:
        pass


class SessionRegistry:
    MAX_SESSIONS = 50
    MAX_TRANSCRIPT = 40

    def __init__(self, data: Dict[str, Any], storage: JsonStorage):
        self.data = data
        self.storage = storage
        raw = data.get("sessions")
        self.sessions: List[Dict[str, Any]] = (
            [s for s in raw if isinstance(s, dict)] if isinstance(raw, list) else []
        )
        raw_t = data.get("transcripts")
        self.transcripts: Dict[str, List[Dict[str, str]]] = raw_t if isinstance(raw_t, dict) else {}
        self.remote: List[Dict[str, Any]] = []

    def _save(self) -> None:
        self.data["sessions"] = self.sessions
        self.data["transcripts"] = self.transcripts
        self.storage.save(self.data)

    def remember(self, sid: str, title: Optional[str] = None, agent: Optional[str] = None) -> Dict[str, Any]:
        sid = str(sid)
        now = datetime.datetime.now().isoformat(timespec="seconds")
        for s in self.sessions:
            if str(s.get("id")) == sid:
                s["last_used"] = now
                if title and not s.get("title"):
                    s["title"] = _clip(title, 80)
                if agent:
                    s["agent"] = agent
                self._save()
                return s
        entry: Dict[str, Any] = {
            "id": sid,
            "title": _clip(title, 80) if title else "",
            "agent": agent or "",
            "created": now,
            "last_used": now,
        }
        self.sessions.insert(0, entry)
        del self.sessions[self.MAX_SESSIONS:]
        self._save()
        return entry

    def set_title(self, sid: str, title: str) -> bool:
        sid = str(sid)
        clean = _clip(title, 60)
        if not clean:
            return False
        for s in self.sessions:
            if str(s.get("id")) == sid and not s.get("title"):
                s["title"] = clean
                self._save()
                return True
        return False

    def record(self, sid: str, role: str, text: str) -> None:
        sid = str(sid or "")
        if not sid or not text:
            return
        bucket = self.transcripts.setdefault(sid, [])
        if not isinstance(bucket, list):
            bucket = self.transcripts[sid] = []
        bucket.append({
            "role": role,
            "content": _clip(text, 1500),
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
        })
        del bucket[: -self.MAX_TRANSCRIPT]
        self._save()

    def transcript(self, sid: str) -> List[Dict[str, str]]:
        bucket = self.transcripts.get(str(sid))
        return [m for m in bucket if isinstance(m, dict)] if isinstance(bucket, list) else []

    @staticmethod
    def _remote_title(s: Dict[str, Any]) -> str:
        for key in ("title", "name", "topic"):
            t = s.get(key)
            if isinstance(t, str) and t.strip():
                return t.strip()[:60]
        return ""

    def refresh(self, client: "DeepSeekClient") -> Optional[str]:
        try:
            self.remote = client.list_sessions()
        except Exception as e:
            self.remote = []
            return str(e)
        for s in self.remote:
            sid = s.get("id") or s.get("chat_session_id")
            if sid:
                self.remember(str(sid), self._remote_title(s))
        return None

    def merged(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: set = set()

        for s in self.remote:
            sid = str(s.get("id") or s.get("chat_session_id") or "").strip()
            if not sid or sid in seen:
                continue
            seen.add(sid)
            out.append({
                "id": sid,
                "title": self._remote_title(s) or self.title_of(sid) or "(sem titulo)",
                "time": s.get("updated_at") or s.get("last_updated") or s.get("created_at") or s.get("created"),
                "source": "conta",
                "agent": self.agent_of(sid),
            })

        for s in self.sessions:
            sid = str(s.get("id") or "").strip()
            if not sid or sid in seen:
                continue
            seen.add(sid)
            out.append({
                "id": sid,
                "title": str(s.get("title") or "(sem titulo)"),
                "time": s.get("last_used") or s.get("created"),
                "source": "local",
                "agent": str(s.get("agent") or ""),
            })
        return out

    def agent_of(self, sid: str) -> str:
        for s in self.sessions:
            if str(s.get("id")) == str(sid):
                a = s.get("agent")
                if isinstance(a, str) and a:
                    return a
        return ""

    def title_of(self, sid: str) -> str:
        for s in self.sessions:
            if str(s.get("id")) == str(sid):
                t = s.get("title")
                if isinstance(t, str) and t.strip():
                    return t.strip()
        return ""

    def find(self, key: str) -> Optional[Dict[str, Any]]:
        key = str(key or "").strip()
        if not key:
            return None
        items = self.merged()
        if key.isdigit():
            idx = int(key)
            if 1 <= idx <= len(items):
                return items[idx - 1]
            return None
        for s in items:
            sid = str(s.get("id") or "")
            if sid == key or sid.startswith(key):
                return s
        return None

    def render(self, current_sid: Optional[str] = None, limit: int = 100) -> str:
        items = self.merged()
        if not items:
            return Colors.gray("  nenhum chat salvo ainda - use /new para criar um")

        extra = ""
        if len(items) > limit:
            extra = Colors.gray(f" (mostrando os {limit} mais recentes)")
            items = items[:limit]

        lines = [Colors.bold(f"  {len(items)} chat(s) encontrado(s)") + extra]
        for i, s in enumerate(items, 1):
            sid = str(s.get("id") or "")
            mark = Colors.white(" <- atual") if current_sid and sid == str(current_sid) else ""
            when = _fmt_time(s.get("time"))
            ag = str(s.get("agent") or "")
            tag = Colors.gray(f"[{ag}]").ljust(4 + len(ag)) if ag else "     "
            row = (
                f"  {Colors.gray(str(i).rjust(2))}  "
                f"{Colors.gray(sid[:8])} {tag} "
                f"{_clip(s['title'], 40).ljust(40)}"
            )
            if when:
                row += f"  {Colors.gray(when)}"
            lines.append(row + mark)
        lines.append(Colors.gray("  use /load <numero> ou /load <id> para carregar"))
        return "\n".join(lines)


class AgentManager:
    DEFAULT = "code"

    def __init__(
        self,
        client: "DeepSeekClient",
        storage: JsonStorage,
        data: Dict[str, Any],
        registry: SessionRegistry,
    ):
        self.client = client
        self.storage = storage
        self.data = data
        self.registry = registry

        raw = data.get("agent_sessions")
        self.sessions: Dict[str, str] = {}
        if isinstance(raw, dict):
            for k, v in raw.items():
                if k in AGENTS and v:
                    self.sessions[str(k)] = str(v)

        key = str(data.get("agent") or self.DEFAULT)
        self.current = key if key in AGENTS else self.DEFAULT

    def keys(self) -> List[str]:
        return list(AGENTS.keys())

    def spec(self, key: Optional[str] = None) -> Dict[str, str]:
        return AGENTS.get(key or self.current) or AGENTS[self.DEFAULT]

    def prompt(self) -> str:
        return self.spec()["prompt"]

    def label(self, key: Optional[str] = None) -> str:
        return self.spec(key)["name"]

    def session_of(self, key: Optional[str] = None) -> str:
        return self.sessions.get(key or self.current, "")

    def _save(self) -> None:
        self.data["agent"] = self.current
        self.data["agent_sessions"] = self.sessions
        if self.client.sid:
            self.data["current_sid"] = str(self.client.sid)
        self.storage.save(self.data)

    def _resolve(self, key: str) -> str:
        k = str(key or "").strip().lower()
        if not k:
            return ""
        keys = self.keys()
        if k.isdigit():
            idx = int(k)
            return keys[idx - 1] if 1 <= idx <= len(keys) else ""
        if k in AGENTS:
            return k
        for kk in keys:
            if kk.startswith(k) or k in AGENTS[kk]["name"].lower():
                return kk
        return ""

    def remember_current(self) -> None:
        sid = str(self.client.sid or "")
        if not sid:
            return
        self.sessions[self.current] = sid
        self.registry.remember(sid, agent=self.current)
        self._save()

    def bind(self, key: str, sid: str) -> bool:
        key = self._resolve(key) or self.current
        sid = str(sid or "")
        if not sid:
            return False
        self.sessions[key] = sid
        self.current = key
        self._save()
        return True

    def switch(self, key: str) -> Tuple[bool, str]:
        target = self._resolve(key)
        if not target:
            return False, f"agente desconhecido: {key}"
        if target == self.current and self.client.sid:
            self._save()
            return True, f"ja esta no {self.label()} (chat {str(self.client.sid)[:8]})"

        self.remember_current()
        self.current = target
        # troca de agente SEMPRE abre chat novo (nunca retoma o anterior)
        return self.new_chat()

    def new_chat(self, note: str = "") -> Tuple[bool, str]:
        try:
            sid = self.client.new_chat()
        except Exception as e:
            return False, f"erro ao criar chat do {self.label()}: {e}"
        sid = str(sid)
        self.sessions[self.current] = sid
        self.registry.remember(sid, agent=self.current)
        self._save()
        return True, f"{self.label()} | novo chat {sid[:8]}{note}"

    def render(self) -> str:
        lines = [Colors.bold("  agentes") + Colors.gray(f"  (ativo: {self.label()})"), ""]
        for i, key in enumerate(self.keys(), 1):
            spec = AGENTS[key]
            sid = self.sessions.get(key, "")
            mark = Colors.white(" <- ativo") if key == self.current else ""
            if sid:
                nm = self.registry.title_of(sid) or "(novo chat)"
                chat = Colors.gray(f"chat {_clip(nm, 30)}")
            else:
                chat = Colors.gray("sem chat ainda")
            lines.append(
                f"  {Colors.gray(str(i).rjust(2))}  {spec['name'].ljust(13)} "
                f"{Colors.gray(_clip(spec['desc'], 40))}"
            )
            lines.append(f"      {chat}{mark}")
        lines.append("")
        lines.append(Colors.gray("  use /agents <numero|nome> para trocar - cada agente tem o proprio chat"))
        return "\n".join(lines)


class CommandHandler:
    ALIASES = {
        "exit": "/exit", "quit": "/exit", "/sair": "/exit", "/quit": "/exit", "/q": "/exit",
        "/reset": "/new", "new": "/new", "/novo": "/new", "/chat": "/new",
        "ls": "/ls", "dir": "/ls",
        "/ajuda": "/help", "/?": "/help", "?": "/help", "help": "/help",
        "/agentes": "/agents", "/agent": "/agents",
        "/cls": "/clear", "/limpar": "/clear", "clear": "/clear",
        "/chats": "/load", "/sessions": "/load", "/sessoes": "/load", "/carregar": "/load",
        "dossie": "/dossie", "/dossier": "/dossie",
    }

    def __init__(
        self,
        client: "DeepSeekClient",
        storage: JsonStorage,
        data: Dict[str, Any],
        registry: SessionRegistry,
        workspace_mgr: "WorkspaceManager",
        agents: "AgentManager",
    ):
        self.client = client
        self.storage = storage
        self.data = data
        self.registry = registry
        self.workspace_mgr = workspace_mgr
        self.agents = agents
        self.table: Dict[str, Tuple[Any, str]] = {
            "/help": (self.cmd_help, "mostra os comandos disponiveis"),
            "/new": (self.cmd_new, "cria um chat novo (limpa o contexto)"),
            "/load": (self.cmd_load, "lista os chats (1-100) e pergunta qual carregar | /load <n|id> direto"),
            "/agents": (self.cmd_agents, "lista os agentes e troca (Code / Osint) - cada um com seu chat"),
            "/clear": (self.cmd_clear, "limpa o terminal"),
            "/ls": (self.cmd_ls, "lista os arquivos do workspace"),
            "/dossie": (self.cmd_dossie, "mostra o dossie/banco investigativo do caso atual | /dossie clear limpa"),
            "/exit": (self.cmd_exit, "sai do programa"),
        }

    @staticmethod
    def _out(text: str) -> None:
        print(text)

    def prompt(self) -> str:
        sid = str(self.client.sid or "")
        tag = sid[:4] if sid else "----"
        if self.agents.current != "code":
            tag = f"{self.agents.current}:{tag}"
        return f"{Colors.gray(tag)} > "

    def handle(self, q: str) -> Tuple[bool, bool]:
        raw = str(q or "").strip()
        if not raw:
            return True, False

        first, _, rest = raw.partition(" ")
        name = self.ALIASES.get(first.lower(), first.lower())
        entry = self.table.get(name)

        if entry is None:
            if raw.startswith("/"):
                self._out(
                    Colors.white(f"  comando desconhecido: {first}")
                    + Colors.gray("  (use /help)")
                )
                return True, False
            return False, False

        return True, bool(entry[0](rest.strip()))

    def cmd_dossie(self, arg: str) -> bool:
        a = str(arg or "").strip().lower()
        if a in ("clear", "limpar", "reset", "novo", "nova"):
            dossie.reset()
            self._out(Colors.gray("  dossie limpo"))
            return False
        self._out(dossie.render_table())
        return False

    def cmd_help(self, arg: str) -> bool:
        lines = [Colors.bold("  comandos"), ""]
        for name in sorted(self.table):
            _, desc = self.table[name]
            lines.append(f"  {Colors.gray(name.ljust(9))} {Colors.gray(desc)}")
        lines.append("")
        lines.append(Colors.gray("  atalhos: /reset (=/new)  /chats (=/load)  /cls (=/clear)  ls  exit"))
        lines.append(Colors.gray("  durante uma resposta, Enter interrompe; Ctrl+C sai"))
        self._out("\n".join(lines))
        return False

    def cmd_new(self, arg: str) -> bool:
        ok, msg = self.agents.new_chat()
        if not ok:
            self._out(Colors.white(f"  {msg}"))
            return False
        self._out(f"  {Colors.white('novo chat')} {Colors.gray(msg)}")
        return False

    MAX_LIST = 100

    def cmd_load(self, arg: str) -> bool:
        arg = str(arg or "").strip()

        if arg:
            if not self.registry.remote:
                self.registry.refresh(self.client)
            entry = self.registry.find(arg)
            if not entry:
                self._out(Colors.white(f"  chat '{arg}' nao encontrado") + Colors.gray("  (use /load para listar)"))
                return False
            self._open(entry)
            return False

        err = self.registry.refresh(self.client)
        items = self.registry.merged()[: self.MAX_LIST]
        self._out(self.registry.render(self.client.sid, limit=self.MAX_LIST))
        if err:
            self._out(Colors.gray(f"  aviso: lista da conta indisponivel ({_clip(err, 140)})"))
            self._out(Colors.gray("  mostrando apenas os chats que este programa ja abriu"))
        if not items:
            return False

        chosen = self._ask_selection(items)
        if chosen is None:
            self._out(Colors.gray("  selecao cancelada"))
            return False

        self._open(chosen)
        return False

    def _ask_selection(self, items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        total = len(items)
        hint = f"1-{total}" if total > 1 else "1"
        for _ in range(3):
            try:
                raw = input(f"  {Colors.gray('carregar chat')} ({hint}) ou {Colors.gray('0')} para cancelar: ").strip()
            except (EOFError, KeyboardInterrupt):
                self._out("")
                return None

            low = raw.lower()
            if low in ("", "0", "q", "c", "n", "cancel", "cancelar", "nao", "sair", "/exit"):
                return None

            if low.isdigit():
                idx = int(low)
                if 1 <= idx <= total:
                    return items[idx - 1]
                self._out(Colors.white(f"  numero fora da lista ({hint})") + Colors.gray("  use 0 para cancelar"))
                continue

            entry = self.registry.find(low)
            if entry:
                return entry
            self._out(Colors.white(f"  opcao invalida: {_clip(low, 30)}") + Colors.gray(f"  digite {hint} ou 0"))
        self._out(Colors.gray("  muitas tentativas invalidas - selecao cancelada"))
        return None

    def _open(self, entry: Dict[str, Any]) -> bool:
        sid = str(entry.get("id") or "")
        try:
            self.client.load_chat(sid)
        except Exception as e:
            self._out(Colors.white(f"  erro ao carregar: {e}"))
            return False

        agent_key = str(entry.get("agent") or self.agents.current)
        self.agents.bind(agent_key, sid)
        self.registry.remember(sid, entry.get("title"), agent=agent_key)
        self.data["current_sid"] = sid
        self.storage.save(self.data)

        self._out(
            f"  {Colors.white('chat carregado')} {Colors.gray(sid[:8])} "
            f"{_clip(entry.get('title') or '', 40)}"
        )
        if agent_key:
            self._out(Colors.gray(f"  agente: {self.agents.label(agent_key)}"))
        if self.client.parent is None:
            self._out(Colors.gray("  aviso: nao achei o ultimo message_id; a proxima pergunta pode abrir um ramo novo"))
        self._print_history(sid)
        print_header(self.agents)
        return True

    def _print_history(self, sid: str) -> None:
        msgs: List[Dict[str, Any]] = []
        try:
            msgs = self.client.fetch_messages(sid)
        except Exception:
            msgs = []

        local = not msgs
        if local:
            msgs = self.registry.transcript(sid)
        if not msgs:
            return

        shown = msgs[-8:]
        self._out(Colors.gray(f"  ultimas {len(shown)} mensagens" + (" (transcript local)" if local else "") + ":"))
        for m in shown:
            role = str(m.get("role") or m.get("sender") or ("user" if local else "?")).lower()
            text = _message_text(m)
            if not text:
                continue
            label = "voce" if role.startswith("u") else "chat"
            color = Colors.gray if role.startswith("u") else Colors.white
            self._out(f"  {color(label.ljust(4))} {Colors.gray(_clip(text, 150))}")

    def cmd_agents(self, arg: str) -> bool:
        arg = str(arg or "").strip()

        if arg:
            ok, msg = self.agents.switch(arg)
            if ok:
                self._out(f"  {Colors.white('agente ativo')}: {msg}")
            else:
                self._out(Colors.white(f"  {msg}") + Colors.gray("  (use /agents para ver a lista)"))
            return False

        self._out(self.agents.render())
        keys = self.agents.keys()
        if len(keys) < 2:
            return False

        for _ in range(3):
            try:
                raw = input(
                    f"  {Colors.gray('trocar para agente')} (1-{len(keys)}) ou "
                    f"{Colors.gray('0')} para cancelar: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                self._out("")
                return False

            low = raw.lower()
            if low in ("", "0", "q", "c", "n", "cancel", "cancelar", "nao"):
                self._out(Colors.gray("  troca cancelada"))
                return False

            ok, msg = self.agents.switch(low)
            if ok:
                self._out(f"  {Colors.white('agente ativo')}: {msg}")
                return False
            self._out(Colors.white(f"  {msg}") + Colors.gray(f"  digite 1-{len(keys)} ou 0"))
        self._out(Colors.gray("  muitas tentativas invalidas - troca cancelada"))
        return False

    def cmd_clear(self, arg: str) -> bool:
        clear_screen()
        sid = str(self.client.sid or "")
        self._out(Colors.gray(f"  workspace {CONFIG.workspace} | chat ") + Colors.white(chat_display_name(self.agents)))
        return False

    def cmd_ls(self, arg: str) -> bool:
        self._out(self.workspace_mgr.list_files())
        return False

    def cmd_exit(self, arg: str) -> bool:
        return True


MAX_CONTINUATIONS = 6


def enable_full_access_from_cli() -> None:
    """Habilita acesso fora do workspace somente após confirmação explícita."""
    global FULL_ACCESS_MODE
    if "--unsafe" not in sys.argv:
        return

    print("ATENÇÃO: --unsafe permite ler, criar, alterar e apagar arquivos fora do workspace.")
    print("Também permite executar comandos com o usuário atual do sistema.")
    try:
        answer = input(f"Digite exatamente '{FULL_ACCESS_CONFIRMATION}' para continuar: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nModo irrestrito cancelado.")
        raise SystemExit(2)

    if answer != FULL_ACCESS_CONFIRMATION:
        print("Confirmação incorreta; modo irrestrito não foi ativado.")
        raise SystemExit(2)

    FULL_ACCESS_MODE = True
    print("Modo irrestrito ATIVADO. Use somente em ambiente confiável.")


def main():
    enable_full_access_from_cli()
    storage = JsonStorage(CONFIG.json_path)
    data = storage.load()

    token = os.getenv("DEEPSEEK_TOKEN") or data.get("usertoken") or ""
    token = clean_token(token)
    if not token:
        token = clean_token(input("token: ").strip())
    if len(token) < 50:
        print("token invalido (muito curto)")
        return
    data["usertoken"] = token
    data.setdefault("history", [])
    storage.save(data)

    registry = SessionRegistry(data, storage)
    client = DeepSeekClient(token, CONFIG)
    agents = AgentManager(client, storage, data, registry)

    # STARTUP: sempre comeca com chat novo (nunca retoma sessao anterior).
    # Chats antigos continuam acessiveis via /load.
    ok, msg = agents.new_chat()
    if not ok:
        print(Colors.white(msg))
        return

    agents.remember_current()
    print_header(agents)

    commands = CommandHandler(client, storage, data, registry, workspace_mgr, agents)

    try:
        while True:
            try:
                q = input(commands.prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not q:
                continue

            handled, should_exit = commands.handle(q)
            if should_exit:
                break
            if handled:
                continue

            if registry.set_title(str(client.sid or ""), q):
                print_header(agents)
            registry.record(str(client.sid or ""), "user", q)
            data["history"].append({"role": "user", "content": q, "time": datetime.datetime.now().isoformat()})
            storage.save(data)

            prompt = agents.prompt().replace("__FILES__", workspace_mgr.list_files()) + f"\n\nUsuario: {q}\n"
            interrupted = False
            turn_t0 = time.time()
            resumo_buf: List[str] = []
            report_done = False
            osint_nudges = 0

            # BUSCA AUTOMATICA DESATIVADA: o harness NAO investiga sozinho.
            # Quem recebe o alvo e conduz TODA a investigacao e a IA
            # (osint_dorks, buscas finas, fetch, recon e osint_report).
            # Nenhuma pre-busca e executada ou injetada aqui.
            if agents.current == "osint":
                dossie_rollover(q)

            for loop in range(15):
                buf: List[str] = []
                continuations = 0
                live = _LivePrinter(enabled=(agents.current != "osint"))

                while True:
                    stop_evt = threading.Event()
                    interrupt_evt = threading.Event()
                    anim_t = threading.Thread(target=thinking_anim, args=(stop_evt, time.time()), daemon=True)
                    anim_t.start()
                    enter_t = threading.Thread(target=enter_listener, args=(interrupt_evt, stop_evt), daemon=True)
                    enter_t.start()

                    first_chunk = True
                    tentativa = list(buf)

                    try:
                        fonte = client.continue_chat() if continuations else client.stream(prompt)
                        for chunk in fonte:
                            if interrupt_evt.is_set():
                                interrupted = True
                                break
                            if first_chunk:
                                if live.enabled:
                                    stop_evt.set()
                                    anim_t.join(timeout=0.5)
                                first_chunk = False
                            buf.append(chunk)
                            live.feed(chunk)
                    except Exception as e:
                        if interrupt_evt.is_set():
                            interrupted = True
                        else:
                            stop_evt.set()
                            anim_t.join(timeout=0.5)
                            print(Colors.white(f"erro stream: {e}"))
                            break
                    finally:
                        stop_evt.set()
                        try:
                            anim_t.join(timeout=0.5)
                        except Exception:
                            pass

                    if first_chunk:
                        stop_evt.set()
                        try:
                            anim_t.join(timeout=0.5)
                        except Exception:
                            pass

                    if interrupted:
                        break

                    parcial = "".join(buf)
                    vazio = not "".join(buf[len(tentativa):]).strip()

                    if client.last_error and "".join(buf).strip() == "":
                        print(Colors.white(f"  erro da API: {client.last_error}"))
                        break

                    cortado = bool(client.last_truncated) or looks_truncated(parcial)
                    if not cortado and not (vazio and continuations):
                        break
                    if continuations >= MAX_CONTINUATIONS:
                        break

                    continuations += 1
                    if vazio and not looks_truncated(parcial):
                        continue

                live.finish()
                if interrupted:
                    break

                raw = "".join(buf)
                clean, results, used = exec_tools(raw)
                _n = max(len(used), len(results))
                for _i in range(_n):
                    print_tool_debug(used[_i] if _i < len(used) else "")
                    if agents.current == "osint" and _i < len(results):
                        dossie.ingest(results[_i], verbose=True)
                if clean and agents.current == "osint":
                    clean = strip_dorks(clean)
                if clean:
                    resumo_buf.append(clean)
                if any(
                    str(c.get("name", "")).startswith("osint_report") or str(c.get("name", "")) == "relatorio"
                    for _, _, c in extract_tool_calls(raw)
                ):
                    report_done = True

                if clean:
                    if agents.current == "osint":
                        visivel = osint_visible_text(clean)
                        if visivel:
                            print_osint_agent_text(visivel)
                    elif not live.printed_any:
                        print(f"\n{clean}\n")

                try:
                    for (_s, _e, _c), _res in zip(extract_tool_calls(raw), results):
                        if str(_c.get("name", "")) in ("osint_report", "relatorio"):
                            if _res and not str(_res).startswith("erro"):
                                print_osint_report(_res)
                except Exception:
                    pass

                auto_workflow_results = []
                try:
                    cur = workflow.get_current() if agents.current == "code" else None
                    if cur:
                        if cur.stage == "TESTAR" and cur.file_path:
                            _au_t0 = time.time()
                            auto_res = tool_workflow_test({"path": cur.file_path})
                            auto_workflow_results.append(auto_res)
                            results.append(auto_res)
                            _au = f"used workflow_test {cur.file_path} auto... ({time.time() - _au_t0:.1f}s)"
                            used.append(_au)
                            print_tool_debug(_au)
                        elif cur.stage == "ANALISAR" and cur.file_path:
                            _au_t0 = time.time()
                            auto_res = tool_workflow_analyze({"path": cur.file_path})
                            auto_workflow_results.append(auto_res)
                            results.append(auto_res)
                            _au = f"used workflow_analyze {cur.file_path} auto... ({time.time() - _au_t0:.1f}s)"
                            used.append(_au)
                            print_tool_debug(_au)
                        elif cur.stage == "APRESENTAR":
                            _au_t0 = time.time()
                            auto_res = tool_workflow_present({})
                            auto_workflow_results.append(auto_res)
                            results.append(auto_res)
                            _au = f"used workflow_present auto... ({time.time() - _au_t0:.1f}s)"
                            used.append(_au)
                            print_tool_debug(_au)
                        elif cur.stage == "ABRIR" and cur.file_path:
                            _au_t0 = time.time()
                            auto_res = tool_workflow_open({"path": cur.file_path})
                            auto_workflow_results.append(auto_res)
                            results.append(auto_res)
                            _au = f"used workflow_open {cur.file_path} auto... ({time.time() - _au_t0:.1f}s)"
                            used.append(_au)
                            print_tool_debug(_au)
                except Exception as e:
                    results.append(f"erro auto workflow: {e}")

                # SEM AUTOMACAO: o harness nao busca nada e nao fabrica relatorio.
                # Se o agente OSINT nao usou nenhuma tool e nao entregou relatorio,
                # ele recebe uma COBRANCA e tem que agir sozinho (max 2).
                nudged = False
                if not used and agents.current == "osint" and not report_done and not _is_greeting_only(q) and not _is_meta_question(q):
                    if osint_nudges < 2:
                        osint_nudges += 1
                        nudged = True
                    else:
                        print_osint_agent_text(
                            "investigacao nao iniciada pelo agente apos cobrancas - "
                            "nenhuma busca automatica foi executada. "
                            "Reformule o alvo (nome completo, @, e-mail, cidade) e tente de novo."
                        )

                if not used and not nudged:
                    data["history"].append({
                        "role": "assistant",
                        "content": clean,
                        "time": datetime.datetime.now().isoformat(),
                    })
                    storage.save(data)
                    registry.record(str(client.sid or ""), "assistant", clean)
                    break

                diff_tracker.print_pending()

                if auto_workflow_results:
                    prompt = (
                        "Resultados (incluindo auto workflow):\n"
                        + "\n".join(results)
                        + f"\nArquivos:\n{workspace_mgr.list_files()}\nContinue o workflow ate CONCLUIDO."
                    )
                elif nudged:
                    prompt = (
                        f"COBRANCA {osint_nudges}/2 - FALHA: voce respondeu sem investigar. "
                        "Nenhuma tool foi executada e nenhum relatorio foi entregue. "
                        "O harness NAO busca nada por voce: quem investiga e VOCE.\n"
                        f"Alvo original: {q}\n"
                        "Execute AGORA, nesta ordem, com raciocinio cyber sec full stack:\n"
                        "1. Comece com <<<TOOL_CALL>>>{\"name\":\"osint_dorks\",\"args\":{\"target\":\"<alvo>\"}}<<<END_TOOL>>> "
                        "(sua varredura ampla: overlap 5x + fetch + recon).\n"
                        "2. Leia os resultados e rode buscas finas nas camadas que faltarem "
                        "(google_search / site_search / web_search / grep): minimo 4 buscas + 1 fetch.\n"
                        "3. Pivoteie cada achado (mesmo @/e-mail/telefone/sobrenome/empresa => nova busca) "
                        "e tente descobrir PAI e MAE (filiacao, 'filho de', jusbrasil, redes).\n"
                        "4. Confirme com fetch antes de afirmar. Snippet e pista, NAO e prova. "
                        "Desambiguacao obrigatoria: mesmo nome NAO e mesma pessoa sem 2+ evidencias.\n"
                        "5. Finalize chamando osint_report com achados (minimo 5 alvo / 3 pai / 3 mae, com link), "
                        "interligacoes, inferencias e nao_encontrado.\n"
                        "PROIBIDO: responder sem tool calls, inventar dado, aceitar homonimo sem desambiguacao. Responda em portugues (pt-BR)."
                    )
                else:
                    prompt = (
                        "Resultados:\n" + "\n".join(results)
                        + f"\nArquivos:\n{workspace_mgr.list_files()}\nContinue ou finalize."
                    )
                    if agents.current == "osint" and dossie.count():
                        prompt += ("\n\nDOSSIE PARCIAL (banco do harness, cruze com os resultados, "
                                   "nao repita o que ja esta aqui):\n" + dossie.summary_compact())

            if agents.current == "osint" and dossie.count() and not _is_greeting_only(q):
                print_dossie_table()
            diff_tracker.print_pending()
            print(Colors.gray(f"  finished in {time.time() - turn_t0:.1f} sec..."))

    finally:
        try:
            agents.remember_current()
            data["current_sid"] = str(client.sid or "")
            storage.save(data)
        except Exception:
            pass
        client.close()


if __name__ == "__main__":
    main()
