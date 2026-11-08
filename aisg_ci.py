#!/usr/bin/env python3
"""AISG Security Scan — GitHub Action runner script.

Runs the AISG worker on the GitHub runner (your code never leaves your CI),
sends only finding metadata to AISG, and posts the "What to do now" summary.

Security model:
  * The worker package is downloaded at run time and accepted only when the
    AISG release signature (Ed25519) and every hash match. This repository holds
    no AISG scanner code — only this wrapper and the public release key.
  * Credentials come from the AISG_WORKER secret (worker id + secret, HMAC).
    They are never printed and can be revoked in the AISG dashboard.
  * Scanner binaries are pinned by version and checked against the checksum
    file published with the same upstream release.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ed25519_verify import verify as ed25519_verify  # noqa: E402

# Public half of the AISG release key (same value as worker/release_pubkey.py).
RELEASE_PUBKEY_HEX = "b4fa13ff51424ce44ac65fbd384d13d49aaf1f381e4be0f96360554eff8c281d"
USER_AGENT = "aisg-github-action/1"
TOOLS = {
    # manifest name -> (binary, url, checksum file url, asset name in checksum file)
    "gitleaks.exe": ("gitleaks",
                     "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
                     "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt",
                     "gitleaks_8.30.1_linux_x64.tar.gz"),
    "grype.exe": ("grype",
                  "https://github.com/anchore/grype/releases/download/v0.117.0/grype_0.117.0_linux_amd64.tar.gz",
                  "https://github.com/anchore/grype/releases/download/v0.117.0/grype_0.117.0_checksums.txt",
                  "grype_0.117.0_linux_amd64.tar.gz"),
    "osv-scanner.exe": ("osv-scanner",
                        "https://github.com/google/osv-scanner/releases/download/v2.5.0/osv-scanner_linux_amd64",
                        "https://github.com/google/osv-scanner/releases/download/v2.5.0/osv-scanner_SHA256SUMS",
                        "osv-scanner_linux_amd64"),
}
GATE_ORDER = ("critical", "high", "medium", "low")


class ActionError(Exception):
    pass


def log(msg: str) -> None:
    print(f"[AISG] {msg}", flush=True)


# --------------------------------------------------------------------- HTTP
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sign_request(secret: str, ts: str, nonce: str, body: str) -> str:
    """HMAC-SHA256(sha256(secret), f"{ts}|{nonce}|{body}") — the AISG worker format."""
    key = hashlib.sha256(secret.encode()).hexdigest()
    return hmac.new(key.encode(), f"{ts}|{nonce}|{body}".encode(), hashlib.sha256).hexdigest()


def signed_body(worker_id: str, secret: str, payload: dict) -> dict:
    payload = {"worker_id": worker_id, **payload}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    ts, nonce = _now(), secrets.token_urlsafe(16)
    return {"worker_id": worker_id, "ts": ts, "nonce": nonce,
            "sig": sign_request(secret, ts, nonce, body), "body": body}


def http(url: str, data: dict | None = None, timeout: int = 120, headers: dict | None = None,
         method: str | None = None) -> bytes:
    raw = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=raw, method=method or ("POST" if raw else "GET"),
                                 headers={"User-Agent": USER_AGENT, **(headers or {}),
                                          **({"Content-Type": "application/json"} if raw else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — fixed https hosts
            return resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode("utf-8", "replace")
        raise ActionError(f"HTTP {exc.code} from {url.split('?')[0]}: {detail}") from exc


def api(cfg: dict, path: str, payload: dict, timeout: int = 120) -> dict:
    return json.loads(http(cfg["api"] + path, signed_body(cfg["wid"], cfg["secret"], payload),
                           timeout=timeout))


# ------------------------------------------------------------- package
def _sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_release(release_text: str, sig_hex: str, pubkey_hex: str | None = None) -> dict:
    try:
        sig = bytes.fromhex(sig_hex or "")
    except ValueError:
        sig = b""
    pub = bytes.fromhex(pubkey_hex or RELEASE_PUBKEY_HEX)
    if not ed25519_verify(pub, release_text.encode("utf-8"), sig):
        raise ActionError("AISG release signature is invalid — refusing to run the package")
    rel = json.loads(release_text)
    for k in ("tier", "build", "zip_sha256", "manifest_sha256"):
        if not rel.get(k):
            raise ActionError(f"release.json missing {k}")
    return rel


def safe_extract(zpath: Path, dest: Path, rel: dict) -> dict:
    """Extract only after the zip and MANIFEST match the signed release (no zip-slip)."""
    if _sha_file(zpath) != rel["zip_sha256"]:
        raise ActionError("package sha256 does not match the signed release")
    with zipfile.ZipFile(zpath) as z:
        raw = z.read("MANIFEST.json")
        if hashlib.sha256(raw).hexdigest() != rel["manifest_sha256"]:
            raise ActionError("MANIFEST.json does not match the signed release")
        man = json.loads(raw)
        files = man.get("files") or {}
        root = dest.resolve()
        for n in z.namelist():
            if n.endswith("/") or n.startswith("python/"):
                continue  # Windows embedded runtime is not used on Linux runners
            if os.name != "nt" and n.startswith("tools/") and n.lower().endswith(".exe"):
                continue  # Windows scanner binaries; the Linux ones are installed below
            target = (dest / n).resolve()
            if root not in target.parents:
                raise ActionError(f"unsafe path in package: {n}")
            data = z.read(n)
            if n in files and hashlib.sha256(data).hexdigest() != files[n]:
                raise ActionError(f"file hash mismatch: {n}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    return man


# ----------------------------------------------------------------- tools
def install_tool(name: str, bin_dir: Path, cache: Path) -> bool:
    """Install one pinned scanner binary; False (scanner reported as not run) on any doubt."""
    spec = TOOLS.get(name)
    if not spec:
        return False
    binary, url, sums_url, asset = spec
    if (bin_dir / binary).exists():
        return True
    try:
        sums = http(sums_url, timeout=60).decode()
        want = next((ln.split()[0] for ln in sums.splitlines()
                     if ln.strip().endswith(asset)), "")
        cache.mkdir(parents=True, exist_ok=True)
        dl = cache / asset
        if not dl.exists() or _sha_file(dl) != want:
            dl.write_bytes(http(url, timeout=300))
        if not want or _sha_file(dl) != want:
            log(f"{binary}: checksum mismatch — not installed (the scan will say it did not run)")
            return False
        bin_dir.mkdir(parents=True, exist_ok=True)
        if asset.endswith(".tar.gz"):
            with tarfile.open(dl) as tf:
                member = next(m for m in tf.getmembers() if Path(m.name).name == binary and m.isfile())
                (bin_dir / binary).write_bytes(tf.extractfile(member).read())
        else:
            shutil.copyfile(dl, bin_dir / binary)
        (bin_dir / binary).chmod(0o755)
        return True
    except Exception as exc:  # noqa: BLE001 — a missing tool must not hide the others
        log(f"{binary}: install failed ({type(exc).__name__}) — the scan will say it did not run")
        return False


# ------------------------------------------------------------------ GitHub
def gate_failed(counts: dict, fail_on: str) -> bool:
    fail_on = (fail_on or "none").lower()
    if fail_on not in GATE_ORDER:
        return False
    idx = GATE_ORDER.index(fail_on)
    return any(int(counts.get(k) or 0) > 0 for k in GATE_ORDER[: idx + 1])


def upsert_pr_comment(markdown: str, token: str, repo: str, pr: int,
                      api_url: str = "https://api.github.com") -> str:
    """One AISG comment per PR, updated on every run (never stacked)."""
    hdr = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    page, existing = 1, None
    while page <= 10 and existing is None:
        items = json.loads(http(f"{api_url}/repos/{repo}/issues/{pr}/comments?per_page=100&page={page}",
                                headers=hdr))
        existing = next((c for c in items if "<!-- aisg-scan -->" in (c.get("body") or "")), None)
        if len(items) < 100:
            break
        page += 1
    if existing:
        http(f"{api_url}/repos/{repo}/issues/comments/{existing['id']}", {"body": markdown},
             headers=hdr, method="PATCH")
        return "updated"
    http(f"{api_url}/repos/{repo}/issues/{pr}/comments", {"body": markdown}, headers=hdr)
    return "created"


def pr_number() -> int | None:
    try:
        ev = json.loads(Path(os.environ.get("GITHUB_EVENT_PATH", "")).read_text())
        return int((ev.get("pull_request") or {}).get("number") or 0) or None
    except Exception:  # noqa: BLE001
        return None


def is_fork_pr() -> bool:
    try:
        ev = json.loads(Path(os.environ.get("GITHUB_EVENT_PATH", "")).read_text())
        pr = ev.get("pull_request") or {}
        return bool(pr) and (pr.get("head", {}).get("repo", {}).get("full_name")
                             != pr.get("base", {}).get("repo", {}).get("full_name"))
    except Exception:  # noqa: BLE001
        return False


def write_output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


SECRET_HELP = ("Set the AISG_WORKER secret to '<worker_id>:<secret>' — the values after --id and "
               "--secret in the command shown by AISG dashboard > Worker > Connect manually "
               "(pasting that whole command also works).")


def parse_worker_secret(raw: str) -> tuple[str, str]:
    """'<id>:<secret>', with spaces, or the whole 'python -m worker enroll --id … --secret …' command."""
    raw = (raw or "").strip()
    m_id = re.search(r"--id[=\s]+(\S+)", raw)
    m_sec = re.search(r"--secret[=\s]+(\S+)", raw)
    if m_id and m_sec:
        return m_id.group(1).strip("'\""), m_sec.group(1).strip("'\"")
    wid, _, secret = raw.partition(":")
    wid, secret = wid.strip().strip("'\""), secret.strip().strip("'\"")
    if not wid or not secret or " " in wid or " " in secret:
        raise ActionError("AISG_WORKER is not in the expected format. " + SECRET_HELP)
    return wid, secret


# -------------------------------------------------------------------- main
def main() -> int:
    raw = os.environ.get("AISG_WORKER", "").strip()
    if not raw:
        if is_fork_pr():
            log("pull request from a fork: secrets are not available, scan skipped (by design)")
            return 0
        raise ActionError("AISG_WORKER secret is empty — create a worker in the AISG dashboard "
                          "(Worker > Connect manually) and store '<worker_id>:<secret>'")
    wid, secret = parse_worker_secret(raw)
    cfg = {"api": os.environ.get("AISG_API", "https://aisg.web.id").rstrip("/"),
           "wid": wid, "secret": secret}
    work = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "aisg"
    cache = Path(os.environ.get("AISG_CACHE", str(Path.home() / ".cache" / "aisg")))
    pkg = work / "pkg"
    shutil.rmtree(work, ignore_errors=True)
    pkg.mkdir(parents=True)

    log("fetching the signed AISG worker package")
    try:
        info = api(cfg, "/api/v1/worker/update/release", {"ci": True})
    except ActionError as exc:
        if "HTTP 403" in str(exc):
            raise ActionError("AISG rejected the worker credential (revoked, mistyped, or the id and "
                              "secret come from two different 'Connect manually' clicks). "
                              + SECRET_HELP) from exc
        raise
    rel = verify_release(info.get("release") or "", info.get("sig") or "")
    zpath = work / "package.zip"
    zpath.write_bytes(http(cfg["api"] + info["download"], timeout=600))
    man = safe_extract(zpath, pkg, rel)
    log(f"package verified: tier {rel['tier']}, build {rel['build']}")

    bin_dir = cache / "bin"
    if os.environ.get("AISG_TOOLS_PREINSTALLED") != "1":  # self-hosted runners may preinstall
        pip = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
        subprocess.run(pip + ["-r", str(pkg / "requirements-worker.txt")], check=True)
        if man.get("pip"):
            subprocess.run(pip + list(man["pip"]), check=False)
        for name in list(man.get("tools_bin") or []) + list(man.get("download") or []):
            if install_tool(name, bin_dir, cache / "dl"):
                # the worker looks for scanners in <package>/tools first
                binary = TOOLS[name][0]
                (pkg / "tools").mkdir(exist_ok=True)
                shutil.copyfile(bin_dir / binary, pkg / "tools" / binary)
                (pkg / "tools" / binary).chmod(0o755)
    env = dict(os.environ, AISG_AUTO_UPDATE="0", PYTHONUTF8="1",
               GRYPE_DB_CACHE_DIR=str(cache / "grype-db"),
               PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    if (bin_dir / "grype").exists() and os.environ.get("AISG_TOOLS_PREINSTALLED") != "1":
        subprocess.run([str(bin_dir / "grype"), "db", "update"], env=env, check=False)

    subprocess.run([sys.executable, "-m", "worker", "enroll", "--id", wid, "--secret", secret,
                    "--api", cfg["api"]], cwd=pkg, env=env, check=True,
                   stdout=subprocess.DEVNULL)
    job = api(cfg, "/api/v1/worker/ci/scan", {
        "repo": os.environ.get("GITHUB_REPOSITORY", ""),
        "path": os.environ.get("GITHUB_WORKSPACE", os.getcwd()),
        "sha": os.environ.get("GITHUB_SHA", ""), "ref": os.environ.get("GITHUB_REF", ""),
        "event": os.environ.get("GITHUB_EVENT_NAME", "")})
    log(f"AISG job #{job.get('job_seq')} queued — scanning {os.environ.get('GITHUB_WORKSPACE', '.')}")
    rc = subprocess.run([sys.executable, "-m", "worker", "run", "--once"], cwd=pkg, env=env).returncode
    if rc == 2:
        raise ActionError("the AISG worker reported an infrastructure error (see the log above)")

    summary = {}
    for _ in range(30):
        summary = api(cfg, "/api/v1/worker/ci/summary", {"job_id": job["job_id"]})
        if summary.get("status") == "done":
            break
        time.sleep(4)
    if summary.get("status") != "done":
        raise ActionError(f"scan did not finish (status: {summary.get('status')})")

    md = summary["markdown"]
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    report = work / "aisg-report.pdf"
    try:
        report.write_bytes(http(cfg["api"] + summary["pdf_url"], timeout=300))
        write_output("report", str(report))
    except ActionError as exc:
        log(f"PDF not downloaded: {exc}")
    pr = pr_number()
    token = os.environ.get("GITHUB_TOKEN_INPUT", "")
    if pr and token and os.environ.get("AISG_COMMENT", "true").lower() == "true":
        try:
            how = upsert_pr_comment(md, token, os.environ.get("GITHUB_REPOSITORY", ""), pr,
                                    os.environ.get("GITHUB_API_URL", "https://api.github.com"))
            log(f"pull request comment {how}")
        except ActionError as exc:
            log(f"could not comment on the pull request ({exc}) — "
                "add 'permissions: pull-requests: write' to the workflow")
    counts = summary.get("counts") or {}
    write_output("risk-level", summary.get("risk_level") or "")
    write_output("findings", str(summary.get("total") or 0))
    log(f"risk {summary.get('risk_level')} — " + ", ".join(f"{k} {counts.get(k, 0)}" for k in GATE_ORDER))
    if gate_failed(counts, os.environ.get("AISG_FAIL_ON", "none")):
        log(f"failing the check: findings at or above '{os.environ.get('AISG_FAIL_ON')}'")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ActionError as exc:
        print(f"::error title=AISG::{exc}", flush=True)
        sys.exit(2)
