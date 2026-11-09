# pwnls

`ls -la` with icons, a tree view, and a warning when a folder holds something risky.

```text
$ pwnls -t
📁 .
├── 📁 config/
│   ├── 🔑 backup.txt  ← SECRET, not in .gitignore!
│   └── ⚙️ settings.yaml
├── 📁 src/
│   ├── 📁 components/
│   │   └── 🔷 Button.tsx
│   ├── 🔷 app.ts
│   └── 🐍 db.py
├── 🤫 .env  ← SECRET, not in .gitignore!
├── 🐳 Dockerfile
├── 📦 package.json
└── 📘 README.md

⚠ 2 risky files: 2 secrets, 2 not git-ignored
```

That `backup.txt` is a private SSH key with a harmless name. `pwnls` reads the first few bytes of
small files, so a renamed key still gets caught.

## What it flags

| Flag | What it means |
|---|---|
| **SECRET** | `.env` files, SSH and TLS private keys, `credentials.json`, `.npmrc`, `.pgpass`, `.netrc` and similar, by name or by content |
| **not in .gitignore!** | a secret inside a git repo that git would commit |
| **world-writable** | anyone on the machine can change it (Linux/macOS) |
| **SUID** | runs with its owner's rights, a classic privilege-escalation spot (Linux/macOS) |

Example files like `.env.example` and public keys (`*.pub`) are not flagged.
Hidden files stay hidden without `-a`, except secrets: those always show.

## Install

One file, no dependencies, Python 3.8+.

```bash
curl -fsSL https://raw.githubusercontent.com/TurhanErgene/pwnls/main/pwnls.py -o ~/.local/bin/pwnls && chmod +x ~/.local/bin/pwnls
```

Or with pipx:

```bash
pipx install git+https://github.com/TurhanErgene/pwnls
```

On Windows, `pipx` works too, or run `python pwnls.py`.

## Use

```bash
pwnls            # long list, like ls -la
pwnls -t         # tree (3 levels deep)
pwnls -t -L 5    # deeper tree
pwnls -a         # include hidden files
pwnls --no-icons # plain names, for fonts without emoji
```

Make it your `ls`:

```bash
alias ls='pwnls'
alias lt='pwnls -t'
```

## In git hooks and CI

`pwnls` exits with code **1** when it finds a secret that git would commit, so it can stop a
commit before the key leaves your machine:

```bash
# .git/hooks/pre-commit  (make it executable)
pwnls -t -L 10 > /dev/null || { echo "pwnls: a secret is about to be committed"; exit 1; }
```

## How it works

About 300 lines of Python in [`pwnls.py`](pwnls.py):

1. **List** the folder with `os.listdir` and `lstat` (size, date, permissions, symlinks).
2. **Pick an icon** by file name first (`Dockerfile`, `package.json`), then by extension.
3. **Check for secrets** by name pattern, then by content (`-----BEGIN ... PRIVATE KEY-----`).
4. **Ask git** which of those secrets are ignored, with one `git check-ignore --stdin` call per folder.
5. **Check permission bits** for world-writable files and SUID/SGID.
6. **Print** the list or the tree, and a one-line summary.

## Tests

```bash
python -m unittest -v tests/test_pwnls.py
```

## License

MIT
