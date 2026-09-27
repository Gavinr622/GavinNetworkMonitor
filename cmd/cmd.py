"""
Gavin Network Monitor - Admin Command Engine v7.3
Persistent settings, custom admin commands, and app shortcuts.
"""
from __future__ import annotations
import json, os, shlex, subprocess, sys, threading
from pathlib import Path
from typing import Callable, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "config"
DATA_DIR.mkdir(exist_ok=True)
SETTINGS_FILE = DATA_DIR / "settings.json"
CUSTOM_COMMANDS_FILE = DATA_DIR / "custom_commands.json"
APPS_FILE = DATA_DIR / "apps.json"

DEFAULT_SETTINGS = {
    "fullscreen": True,
    "auto_save": True,
    "dns_refresh_seconds": 60,
    "default_protocol": "ALL",
    "default_filter": "",
    "command_directory": str(BASE_DIR),
    "loading_screen_enabled": True,
    "loading_screen_seconds": 3.0,
    "loading_title": "GAVIN",
    "loading_subtitle": "NETWORK MONITOR",
    "loading_bg": "#171a21",
    "loading_accent": "#66c0f4",
    "loading_spinner_interval": 80,
}

ADMIN_COMMANDS = {
    "help": "Show command list",
    "pwd": "Show current command directory",
    "cd <dir>": "Change command directory",
    "dir [path]": "List files and folders",
    "ls [path]": "Alias for dir",
    "type <file>": "Display a text file",
    "cat <file>": "Alias for type",
    "echo <text>": "Print text",
    "where <program>": "Find a program on PATH",
    "whoami": "Show Windows user",
    "hostname": "Show computer name",
    "ver": "Show Windows version",
    "ipconfig": "Show network configuration",
    "getmac": "Show MAC addresses",
    "arp": "Show ARP table",
    "route": "Show routing table",
    "netstat": "Show network connections",
    "nslookup <domain>": "Resolve a domain",
    "ping <host>": "Ping a host",
    "tracert <host>": "Trace a route",
    "tasklist": "Show running processes",
    "systeminfo": "Show Windows system information",
    "python <args>": "Run Python using the current interpreter",
    "py <args>": "Run the Windows Python launcher",
    "pip <args>": "Run pip through the current Python",
    "runpy <file.py> [args]": "Run a Python file",
    "env": "Show environment variables",
    "set <NAME=VALUE>": "Set a command-session environment variable",
    "date": "Show date",
    "time": "Show time",
    "open <path>": "Open a file or folder",
    "cmd <command>": "Run a local CMD command",
    "shell <command>": "Alias for cmd",
    "settings": "Show saved settings",
    "save": "Save settings, commands and apps",
    "reload": "Reload saved settings, commands and apps",
    "custom": "List custom admin commands",
    "custom-run <name> [args]": "Run a saved custom command",
    "apps": "List saved app shortcuts",
    "app <name>": "Launch a saved app shortcut",
    "clear": "Clear the command console",
}

BLOCKED_PREFIXES = (
    "format", "del ", "erase ", "rd ", "rmdir ", "shutdown",
    "diskpart", "bcdedit", "reg delete", "reg add", "takeown",
    "icacls", "cipher /w",
)


def _read_json(path: Path, default):
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data
    except Exception:
        pass
    return default.copy() if isinstance(default, dict) else list(default)


def _write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


class AdminCommandRunner:
    def __init__(self, output: Callable[[str], None], clear_console: Optional[Callable[[], None]] = None):
        self.output = output
        self.clear_console = clear_console
        self.settings = _read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
        for key, value in DEFAULT_SETTINGS.items():
            self.settings.setdefault(key, value)
        self.custom_commands = _read_json(CUSTOM_COMMANDS_FILE, {})
        self.apps = _read_json(APPS_FILE, {})
        self.cwd = os.path.abspath(self.settings.get("command_directory") or str(BASE_DIR))
        if not os.path.isdir(self.cwd):
            self.cwd = str(BASE_DIR)
        self.env = os.environ.copy()
        self.running = False
        self.process: Optional[subprocess.Popen] = None

    def write(self, text: object) -> None:
        self.output(str(text))

    def save_all(self):
        self.settings["command_directory"] = self.cwd
        _write_json(SETTINGS_FILE, self.settings)
        _write_json(CUSTOM_COMMANDS_FILE, self.custom_commands)
        _write_json(APPS_FILE, self.apps)

    def reload_all(self):
        self.settings = _read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
        for key, value in DEFAULT_SETTINGS.items():
            self.settings.setdefault(key, value)
        self.custom_commands = _read_json(CUSTOM_COMMANDS_FILE, {})
        self.apps = _read_json(APPS_FILE, {})
        self.cwd = os.path.abspath(self.settings.get("command_directory") or str(BASE_DIR))
        if not os.path.isdir(self.cwd):
            self.cwd = str(BASE_DIR)

    def execute(self, command_line: str) -> None:
        command_line = command_line.strip()
        if not command_line:
            return
        threading.Thread(target=self._execute_thread, args=(command_line,), daemon=True).start()

    def _execute_thread(self, command_line: str) -> None:
        self.running = True
        try:
            self._execute(command_line)
        except Exception as exc:
            self.write(f"ERROR: {exc}")
        finally:
            self.process = None
            self.running = False

    def _parse(self, command_line):
        try:
            parts = shlex.split(command_line, posix=False)
        except ValueError as exc:
            self.write(f"Parse error: {exc}")
            return []
        return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in ('"', "'") else p for p in parts]

    def _execute(self, command_line: str) -> None:
        parts = self._parse(command_line)
        if not parts:
            return
        cmd, args = parts[0].lower(), parts[1:]

        # Custom commands take precedence over built-ins only when explicitly run.
        if cmd == "custom-run":
            self._custom_run(args); return
        if cmd == "app":
            self._app_run(args); return

        if cmd == "help":
            self.write("ADMIN COMMAND CENTER")
            self.write("=" * 72)
            for name, description in ADMIN_COMMANDS.items():
                self.write(f"{name:<32} {description}")
            self.write("\nCustom commands: custom-run <name> [args]")
            self.write("App shortcuts: app <name>")
            return
        if cmd in ("clear", "cls"):
            if self.clear_console: self.clear_console()
            return
        if cmd == "pwd": self.write(self.cwd); return
        if cmd == "cd": self._cd(args); return
        if cmd in ("dir", "ls"): self._dir(args); return
        if cmd in ("type", "cat"): self._type_file(args); return
        if cmd == "echo": self.write(" ".join(args)); return
        if cmd == "where": self._program("where", args); return
        if cmd == "whoami": self._program("whoami", []); return
        if cmd == "hostname": self._program("hostname", []); return
        if cmd == "ver": self._program("cmd.exe", ["/d", "/c", "ver"]); return
        if cmd in {"ipconfig","getmac","arp","route","netstat","nslookup","ping","tracert","tasklist","systeminfo"}:
            self._program(cmd, args); return
        if cmd == "python": self._run_process([sys.executable, *args]); return
        if cmd == "py": self._run_process(["py", *args]); return
        if cmd == "pip": self._run_process([sys.executable, "-m", "pip", *args]); return
        if cmd == "runpy": self._run_python_file(args); return
        if cmd == "env":
            for key in sorted(self.env): self.write(f"{key}={self.env[key]}")
            return
        if cmd == "set": self._set_env(args); return
        if cmd == "date": self._program("cmd.exe", ["/d", "/c", "date", "/t"]); return
        if cmd == "time": self._program("cmd.exe", ["/d", "/c", "time", "/t"]); return
        if cmd == "open": self._open(args); return
        if cmd in ("cmd", "shell"): self._cmd_command(" ".join(args)); return
        if cmd == "settings":
            for k, v in self.settings.items(): self.write(f"{k}={v}")
            return
        if cmd == "save":
            self.save_all(); self.write("Saved settings, custom commands and apps."); return
        if cmd == "reload":
            self.reload_all(); self.write("Reloaded saved configuration."); return
        if cmd == "custom":
            if not self.custom_commands: self.write("No custom commands saved.")
            for name, item in self.custom_commands.items(): self.write(f"{name} — {item.get('description','')}")
            return
        if cmd == "apps":
            if not self.apps: self.write("No app shortcuts saved.")
            for name, item in self.apps.items(): self.write(f"{name} — {item.get('command','')}")
            return
        self._cmd_command(command_line)

    def _cd(self, args):
        target = os.path.expandvars(args[0] if args else str(BASE_DIR)).strip('"')
        path = os.path.abspath(os.path.join(self.cwd, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not os.path.isdir(path): self.write(f"The system cannot find the path specified: {path}"); return
        self.cwd = path; self.settings["command_directory"] = path; self.write(path)

    def _dir(self, args):
        target = os.path.expandvars(args[0].strip('"')) if args else self.cwd
        path = os.path.abspath(os.path.join(self.cwd, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not os.path.exists(path): self.write(f"File not found: {path}"); return
        if os.path.isfile(path): self.write(f"{os.path.basename(path)}    {os.path.getsize(path):,} bytes"); return
        self.write(f"Directory of {path}\n")
        try:
            for item in sorted(Path(path).iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                marker = "<DIR>" if item.is_dir() else "     "
                size = "" if item.is_dir() else f"{item.stat().st_size:>12,}"
                self.write(f"{marker:5} {size:>14}  {item.name}")
        except OSError as exc: self.write(f"ERROR: {exc}")

    def _type_file(self, args):
        if not args: self.write("Usage: type <file>"); return
        target = os.path.expandvars(args[0].strip('"'))
        path = os.path.abspath(os.path.join(self.cwd, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not os.path.isfile(path): self.write(f"File not found: {path}"); return
        try: self.write(Path(path).read_text(encoding="utf-8", errors="replace"))
        except OSError as exc: self.write(f"ERROR: {exc}")

    def _program(self, program, args): self._run_process([program, *args])

    def _run_python_file(self, args):
        if not args: self.write("Usage: runpy <file.py> [args]"); return
        target = os.path.expandvars(args[0].strip('"'))
        path = os.path.abspath(os.path.join(self.cwd, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not path.lower().endswith(".py"): self.write("runpy only runs .py files."); return
        if not os.path.isfile(path): self.write(f"Python file not found: {path}"); return
        self._run_process([sys.executable, path, *args[1:]])

    def _set_env(self, args):
        if not args:
            for key in sorted(self.env): self.write(f"{key}={self.env[key]}")
            return
        assignment = " ".join(args)
        if "=" not in assignment: self.write("Usage: set NAME=VALUE"); return
        key, value = assignment.split("=", 1); key = key.strip()
        if not key: self.write("Environment variable name cannot be empty."); return
        self.env[key] = value; self.write(f"Set {key}={value}")

    def _open(self, args):
        if not args: self.write("Usage: open <path>"); return
        target = os.path.expandvars(" ".join(args).strip('"'))
        path = os.path.abspath(os.path.join(self.cwd, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not os.path.exists(path): self.write(f"Path not found: {path}"); return
        os.startfile(path); self.write(f"Opened: {path}")

    def _cmd_command(self, command_line):
        if not command_line: self.write("Usage: cmd <command>"); return
        lowered = command_line.strip().lower()
        if any(lowered == p.rstrip() or lowered.startswith(p) for p in BLOCKED_PREFIXES):
            self.write("BLOCKED: this command can make destructive system changes."); return
        self._run_process(["cmd.exe", "/d", "/s", "/c", command_line])

    def _custom_run(self, args):
        if not args: self.write("Usage: custom-run <name> [args]"); return
        name = args[0]
        item = self.custom_commands.get(name)
        if not item: self.write(f"Custom command not found: {name}"); return
        command = str(item.get("command", ""))
        extra = " ".join(args[1:])
        command = command.replace("{args}", extra).replace("{cwd}", self.cwd)
        self.write(f"Custom: {name}")
        self._cmd_command(command)

    def _app_run(self, args):
        if not args: self.write("Usage: app <name>"); return
        name = args[0]; item = self.apps.get(name)
        if not item: self.write(f"App not found: {name}"); return
        command = str(item.get("command", ""))
        extra = " ".join(args[1:])
        command = command.replace("{args}", extra).replace("{cwd}", self.cwd)
        self.write(f"Launching app: {name}")
        self._cmd_command(command)

    def _run_process(self, command):
        self.write("> " + " ".join(command))
        try:
            self.process = subprocess.Popen(command, cwd=self.cwd, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except FileNotFoundError:
            self.write(f"Command not found: {command[0]}"); return
        except OSError as exc:
            self.write(f"ERROR: {exc}"); return
        assert self.process.stdout is not None
        for line in self.process.stdout: self.write(line.rstrip("\r\n"))
        self.write(f"[exit code: {self.process.wait()}]")
