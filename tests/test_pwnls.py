import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pwnls  # noqa: E402


def run(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = pwnls.main(["--no-color", *args])
    return code, buf.getvalue()


class PwnlsTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def touch(self, name, text="x"):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def test_secrets_by_name(self):
        for n in [".env", ".env.local", "id_rsa", "server.pem", "credentials.json", ".npmrc"]:
            self.assertTrue(pwnls.is_secret(self.touch(n), False), n)
        for n in [".env.example", "id_rsa.pub", "main.py", "README.md"]:
            self.assertFalse(pwnls.is_secret(self.touch(n), False), n)

    def test_private_key_with_innocent_name(self):
        p = self.touch("backup.txt", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")
        self.assertTrue(pwnls.is_secret(p, False))

    def test_list_shows_icons_tags_and_summary(self):
        self.touch("main.py")
        self.touch(".env", "TOKEN=1")
        code, out = run(str(self.dir))
        self.assertIn("🐍 main.py", out)
        self.assertIn(".env", out)  # hidden, but secrets always show
        self.assertIn("SECRET", out)
        self.assertIn("1 risky file", out)
        self.assertEqual(code, 0)  # not in a git repo, so nothing gets committed

    def test_clean_folder(self):
        self.touch("notes.md")
        _, out = run(str(self.dir))
        self.assertIn("nothing risky", out)

    def test_tree(self):
        self.touch("src/app.ts")
        self.touch("src/keys/deploy.key")
        _, out = run("-t", str(self.dir))
        self.assertIn("├── ", out.replace("└── ", "├── "))
        self.assertIn("🔷 app.ts", out)
        self.assertIn("deploy.key", out)
        self.assertIn("SECRET", out)

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_secret_not_gitignored_fails(self):
        subprocess.run(["git", "init", "-q"], cwd=self.dir, check=True)
        self.touch(".env", "TOKEN=1")
        code, out = run(str(self.dir))
        self.assertIn("not in .gitignore", out)
        self.assertEqual(code, 1)
        self.touch(".gitignore", ".env\n")
        code, out = run(str(self.dir))
        self.assertNotIn("not in .gitignore", out)
        self.assertEqual(code, 0)

    @unittest.skipIf(os.name == "nt", "permission bits are Unix only")
    def test_world_writable_and_suid(self):
        p = self.touch("open.sh")
        os.chmod(p, 0o777)
        q = self.touch("tool")
        os.chmod(q, 0o4755)
        _, out = run(str(self.dir))
        self.assertIn("world-writable", out)
        self.assertIn("SUID", out)


if __name__ == "__main__":
    unittest.main()
