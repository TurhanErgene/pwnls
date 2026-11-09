#!/usr/bin/env python3
"""pwnls: `ls -la` with icons, a tree view, and a warning for risky files.

It flags:
  - secrets: .env files, SSH/TLS private keys, credential files (by name or by content)
  - secrets that git would commit (inside a repo and not in .gitignore)
  - world-writable files and SUID/SGID binaries (Linux/macOS)

Usage: pwnls [path] [-t] [-L DEPTH] [-a] [--no-icons] [--no-color]
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "0.1.0"

# ── icons ────────────────────────────────────────────────────────────────────

ICON_DIR = "📁"
ICON_FILE = "📄"
ICON_EXEC = "⚡"
ICON_LINK = "🔗"
ICONS_BY_NAME = {
    ".git": "🌿", ".gitignore": "🌿", ".gitattributes": "🌿",
    "dockerfile": "🐳", "docker-compose.yml": "🐳", "compose.yaml": "🐳",
    "makefile": "🛠️", "license": "⚖️", "readme.md": "📘",
    "package.json": "📦", "package-lock.json": "🔒", "yarn.lock": "🔒", "cargo.lock": "🔒", "poetry.lock": "🔒",
    "node_modules": "🗃️",
}
ICONS_BY_EXT = {
    ".py": "🐍", ".js": "🟨", ".mjs": "🟨", ".ts": "🔷", ".tsx": "🔷", ".jsx": "🟨",
    ".rs": "🦀", ".go": "🐹", ".rb": "💎", ".java": "☕", ".c": "🇨", ".h": "🇨", ".cpp": "➕",
    ".sh": "🐚", ".bash": "🐚", ".zsh": "🐚", ".ps1": "🐚",
    ".md": "📝", ".txt": "📄", ".pdf": "📕",
    ".json": "⚙️", ".yml": "⚙️", ".yaml": "⚙️", ".toml": "⚙️", ".ini": "⚙️", ".conf": "⚙️", ".cfg": "⚙️",
    ".html": "🌐", ".css": "🎨", ".svg": "🎨",
    ".png": "🖼️", ".jpg": "🖼️", ".jpeg": "🖼️", ".gif": "🖼️", ".webp": "🖼️",
    ".mp4": "🎬", ".mov": "🎬", ".mp3": "🎵", ".wav": "🎵",
    ".zip": "📦", ".tar": "📦", ".gz": "📦", ".7z": "📦", ".deb": "📦", ".rpm": "📦",
    ".db": "🗄️", ".sqlite": "🗄️", ".sql": "🗄️", ".log": "📜",
    ".pem": "🔑", ".key": "🔑", ".crt": "📜", ".p12": "🔑", ".pfx": "🔑", ".kdbx": "🔑",
}

# ── what counts as a secret ──────────────────────────────────────────────────

SECRET_NAMES = [
    ".env", ".env.*", "*.env",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.kdbx",
    "credentials", "credentials.json", "*credentials*.json", "service-account*.json",
    ".npmrc", ".pypirc", ".pgpass", ".netrc", ".git-credentials", ".htpasswd",
    "secrets.*", "*.secret", "*.secrets",
]
# example files are meant to be committed
NOT_SECRET = [".env.example", ".env.sample", ".env.template", "*.example", "*.sample", "*.pub"]
KEY_MARKERS = (b"PRIVATE KEY-----", b"BEGIN OPENSSH PRIVATE KEY")
SCAN_BYTES = 4096


@dataclass
class Entry:
    path: Path
    st: os.stat_result
    is_dir: bool
    is_link: bool
    flags: list[str] = field(default_factory=list)  # "secret", "tracked", "world", "suid"


def is_secret(path: Path, is_dir: bool) -> bool:
    if is_dir:
        return False
    name = path.name.lower()
    if any(fnmatch.fnmatch(name, p) for p in NOT_SECRET):
        return False
    if any(fnmatch.fnmatch(name, p) for p in SECRET_NAMES):
        return True
    # a private key with an innocent name
    try:
        if path.stat().st_size <= 64 * 1024:
            with open(path, "rb") as fh:
                head = fh.read(SCAN_BYTES)
            return any(m in head for m in KEY_MARKERS)
    except OSError:
        pass
    return False


def git_ignored(paths: list[Path]) -> set[str] | None:
    """Names of the `paths` (all in one folder) that git would ignore. None when not in a repo."""
    if not paths:
        return set()
    cwd = paths[0].parent
    try:
        inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=cwd, capture_output=True, text=True, timeout=5)
        if inside.stdout.strip() != "true":
            return None
        res = subprocess.run(["git", "check-ignore", "--stdin"], cwd=cwd, input="\n".join(p.name for p in paths), capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return {line.strip() for line in res.stdout.splitlines() if line.strip()}


def check(entries: list[Entry]) -> None:
    """Fill in each entry's risk flags."""
    secrets = [e for e in entries if is_secret(e.path, e.is_dir)]
    for e in secrets:
        e.flags.append("secret")
    by_dir: dict[Path, list[Entry]] = {}
    for e in secrets:
        by_dir.setdefault(e.path.parent, []).append(e)
    for group in by_dir.values():
        ignored = git_ignored([e.path for e in group])
        if ignored is None:
            continue
        for e in group:
            if e.path.name not in ignored:
                e.flags.append("tracked")
    if os.name != "nt":  # permission bits mean nothing on Windows
        for e in entries:
            mode = e.st.st_mode
            if e.is_link:
                continue
            if mode & stat.S_IWOTH and not (e.is_dir and mode & stat.S_ISVTX):
                e.flags.append("world")
            if not e.is_dir and mode & (stat.S_ISUID | stat.S_ISGID):
                e.flags.append("suid")


# ── output ───────────────────────────────────────────────────────────────────

class Style:
    def __init__(self, color: bool):
        self.on = color

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text


def icon_for(e: Entry) -> str:
    name = e.path.name.lower()
    if "secret" in e.flags:
        return "🔑" if not name.startswith(".env") else "🤫"
    if e.is_link:
        return ICON_LINK
    if name in ICONS_BY_NAME:
        return ICONS_BY_NAME[name]
    if e.is_dir:
        return ICON_DIR
    if name.startswith(".env"):
        return "⚙️"
    icon = ICONS_BY_EXT.get(e.path.suffix.lower())
    if icon:
        return icon
    if e.st.st_mode & stat.S_IXUSR and os.name != "nt":
        return ICON_EXEC
    return ICON_FILE


def human(n: int) -> str:
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


def when(t: float) -> str:
    six_months = 182 * 24 * 3600
    fmt = "%b %d %H:%M" if abs(time.time() - t) < six_months else "%b %d  %Y"
    return time.strftime(fmt, time.localtime(t))


def tags(e: Entry, s: Style) -> str:
    out = []
    if "secret" in e.flags:
        out.append(s("1;31", "SECRET"))
    if "tracked" in e.flags:
        out.append(s("1;33", "not in .gitignore!"))
    if "world" in e.flags:
        out.append(s("1;35", "world-writable"))
    if "suid" in e.flags:
        out.append(s("1;35", "SUID"))
    return ("  ← " + ", ".join(out)) if out else ""


def name_of(e: Entry, s: Style, icons: bool) -> str:
    label = e.path.name + ("/" if e.is_dir else "")
    if e.flags:
        label = s("1;31" if "secret" in e.flags else "1;35", label)
    elif e.is_dir:
        label = s("1;34", label)
    elif e.is_link:
        label = s("36", label)
    if e.is_link:
        try:
            label += s("2", " → " + os.readlink(e.path))
        except OSError:
            pass
    return (icon_for(e) + " " + label) if icons else label


def list_dir(path: Path, show_all: bool) -> list[Entry]:
    out = []
    try:
        names = sorted(os.listdir(path), key=lambda n: (not (path / n).is_dir(), n.lower()))
    except OSError as err:
        print(f"pwnls: {path}: {err.strerror}", file=sys.stderr)
        return out
    for n in names:
        if not show_all and n.startswith(".") and not is_secret(path / n, (path / n).is_dir()):
            continue  # hidden files stay hidden, unless they are a secret you should know about
        p = path / n
        try:
            st = p.lstat()
        except OSError:
            continue
        is_link = stat.S_ISLNK(st.st_mode)
        out.append(Entry(p, st, is_dir=p.is_dir() and not is_link, is_link=is_link))
    return out


def print_long(entries: list[Entry], s: Style, icons: bool) -> None:
    w = max((len(human(e.st.st_size)) for e in entries), default=1)
    for e in entries:
        perms = stat.filemode(e.st.st_mode)
        line = f"{s('2', perms)}  {human(e.st.st_size).rjust(w)}  {s('2', when(e.st.st_mtime))}  {name_of(e, s, icons)}{tags(e, s)}"
        print(line)


def walk_tree(path: Path, depth: int, show_all: bool, prefix: str, s: Style, icons: bool, found: list[Entry]) -> None:
    entries = list_dir(path, show_all)
    check(entries)
    found.extend(entries)
    for i, e in enumerate(entries):
        last = i == len(entries) - 1
        print(prefix + s("2", "└── " if last else "├── ") + name_of(e, s, icons) + tags(e, s))
        if e.is_dir and depth > 1 and e.path.name not in (".git", "node_modules"):
            walk_tree(e.path, depth - 1, show_all, prefix + ("    " if last else s("2", "│   ")), s, icons, found)


def summary(found: list[Entry], s: Style) -> str:
    risky = [e for e in found if e.flags]
    if not risky:
        return s("1;32", "✓ nothing risky here")
    parts = []
    n_secret = sum("secret" in e.flags for e in found)
    n_tracked = sum("tracked" in e.flags for e in found)
    n_world = sum("world" in e.flags for e in found)
    n_suid = sum("suid" in e.flags for e in found)
    if n_secret:
        parts.append(f"{n_secret} secret{'s' * (n_secret != 1)}")
    if n_tracked:
        parts.append(f"{n_tracked} not git-ignored")
    if n_world:
        parts.append(f"{n_world} world-writable")
    if n_suid:
        parts.append(f"{n_suid} SUID/SGID")
    return s("1;31", f"⚠ {len(risky)} risky file{'s' * (len(risky) != 1)}: " + ", ".join(parts))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pwnls", description="ls -la with icons, a tree view, and a warning for risky files.")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("-t", "--tree", action="store_true", help="show a tree instead of a list")
    ap.add_argument("-L", "--level", type=int, default=3, help="tree depth (default 3)")
    ap.add_argument("-a", "--all", action="store_true", help="show hidden files too (secrets always show)")
    ap.add_argument("--no-icons", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"pwnls {__version__}")
    args = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # emoji on Windows consoles
    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if color and os.name == "nt":
        os.system("")  # turns on ANSI colours in the Windows console
    s = Style(color)
    root = Path(args.path)
    if not root.exists():
        print(f"pwnls: {args.path}: no such file or directory", file=sys.stderr)
        return 2

    found: list[Entry] = []
    if args.tree:
        print(s("1;34", (("📁 " if not args.no_icons else "") + str(root))))
        walk_tree(root, args.level, args.all, "", s, not args.no_icons, found)
    else:
        found = list_dir(root, args.all) if root.is_dir() else []
        check(found)
        print_long(found, s, not args.no_icons)
    print()
    print(summary(found, s))
    return 1 if any("secret" in e.flags and "tracked" in e.flags for e in found) else 0


if __name__ == "__main__":
    sys.exit(main())
