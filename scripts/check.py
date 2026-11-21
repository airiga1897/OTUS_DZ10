"""Local checks only; never authenticates or creates cloud resources."""

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(*args):
    subprocess.run([str(a) for a in args], cwd=ROOT, check=True)


def main():
    os.environ.pop("TF_PLUGIN_CACHE_DIR", None)
    expected = json.loads((ROOT / "config/lab.json").read_text())["proxmox"]["key_sha256"]
    key = ROOT / "provision/proxmox-archive-keyring.gpg"
    if hashlib.sha256(key.read_bytes()).hexdigest() != expected:
        raise ValueError("Public Proxmox repository key checksum mismatch")
    for path in (ROOT / "provision").glob("*.sh"):
        if b"\r" in path.read_bytes():
            raise ValueError(f"Bash script must use LF: {path.name}")
    for directory in ("scripts", "tests", "functions", "provision"):
        for path in (ROOT / directory).rglob("*.py"):
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    check(sys.executable, "-m", "ruff", "check", ".")
    check(sys.executable, "-m", "ruff", "format", "--check", ".")
    check(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v")
    tf = ROOT / ".tools" / ("terraform.exe" if os.name == "nt" else "terraform")
    check(tf, "fmt", "-check", "-recursive", "terraform")
    for module in ("yc", "proxmox"):
        check(
            tf,
            f"-chdir=terraform/{module}",
            "init",
            "-backend=false",
            "-input=false",
            "-lockfile=readonly",
            f"-plugin-dir={(ROOT / '.tools/provider-cache').as_posix()}",
        )
        check(tf, f"-chdir=terraform/{module}", "validate")
        check(tf, f"-chdir=terraform/{module}", "test")
    check("poetry", "check", "--lock")
    evidence = ROOT / "evidence/local-checks.json"
    evidence.parent.mkdir(exist_ok=True)
    evidence.write_text(
        json.dumps(
            {
                "python_syntax": "passed",
                "ruff": "passed",
                "ruff_format": "passed",
                "unit_tests": "passed",
                "terraform_fmt": "passed",
                "terraform_validate": "passed",
                "terraform_mock_tests": "passed",
                "poetry_lock": "passed",
                "cloud_tested": False,
            },
            indent=2,
        )
        + "\n"
    )
    print("Локальные проверки пройдены. Облачное развёртывание этим не подтверждается.")


if __name__ == "__main__":
    main()
