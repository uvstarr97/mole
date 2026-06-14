import os
import re
import hashlib
import subprocess
from pathlib import Path

from .patterns import match_line, SKIP_EXTENSIONS, SKIP_FILES

DIFF_HEADER = re.compile(r'^diff --git a/.+ b/(.+)$')
HUNK_HEADER = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@')


def _run(cmd, cwd=None):
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            errors="replace", timeout=30,
        )
        return r.stdout
    except (subprocess.TimeoutExpired, Exception):
        return ""


def _should_skip(filepath):
    p = Path(filepath)
    return p.suffix.lower() in SKIP_EXTENSIONS or p.name in SKIP_FILES


def _parse_diff(diff_text):
    current_file = None
    current_line = 0

    for raw_line in diff_text.splitlines():
        hdr = DIFF_HEADER.match(raw_line)
        if hdr:
            current_file = hdr.group(1)
            current_line = 0
            continue

        hunk = HUNK_HEADER.match(raw_line)
        if hunk:
            current_line = int(hunk.group(1))
            continue

        if current_file and _should_skip(current_file):
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            yield current_file or "unknown", current_line, raw_line[1:]
            current_line += 1
        elif not raw_line.startswith("-") and not raw_line.startswith("\\"):
            current_line += 1


def _secret_key(finding, filepath):
    return hashlib.sha1(
        f"{finding['name']}:{finding['match'][:32]}:{filepath}".encode()
    ).hexdigest()


def scan_commits(repo_path, max_commits=None, since=None, branch=None, progress_cb=None):
    cmd = ["git", "log", "--all", "--format=%H|||%ae|||%ai|||%s"]
    if branch:
        cmd = ["git", "log", branch, "--format=%H|||%ae|||%ai|||%s"]
    if since:
        cmd += [f"--since={since}"]
    if max_commits:
        cmd += ["-n", str(max_commits)]

    raw = _run(cmd, cwd=repo_path)
    commits = []
    for line in raw.strip().splitlines():
        parts = line.split("|||", 3)
        if len(parts) == 4:
            commits.append({
                "hash":    parts[0],
                "author":  parts[1],
                "date":    parts[2][:10],
                "message": parts[3][:80],
            })

    seen_keys = set()
    findings  = []

    for i, commit in enumerate(commits):
        if progress_cb:
            progress_cb(i, len(commits), commit["hash"][:8])

        diff = _run(
            ["git", "diff-tree", "--no-commit-id", "-r", "-p", "--diff-filter=AM", commit["hash"]],
            cwd=repo_path,
        )

        for filepath, lineno, line in _parse_diff(diff):
            for match in match_line(line):
                key = _secret_key(match, filepath)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append({
                    **match,
                    "commit":      commit["hash"][:8],
                    "commit_full": commit["hash"],
                    "author":      commit["author"],
                    "date":        commit["date"],
                    "message":     commit["message"],
                    "file":        filepath,
                    "line":        lineno,
                    "context":     line.strip()[:120],
                })

    return findings, len(commits)


def scan_staged(repo_path):
    diff     = _run(["git", "diff", "--cached", "-p"], cwd=repo_path)
    findings = []
    seen     = set()
    for filepath, lineno, line in _parse_diff(diff):
        for match in match_line(line):
            key = _secret_key(match, filepath)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                **match,
                "commit":      "STAGED",
                "commit_full": "staged",
                "author":      "",
                "date":        "",
                "message":     "staged changes",
                "file":        filepath,
                "line":        lineno,
                "context":     line.strip()[:120],
            })
    return findings


def clone_repo(url, target_dir):
    name = url.rstrip("/").split("/")[-1].replace(".git", "")
    dest = os.path.join(target_dir, name)
    result = subprocess.run(
        ["git", "clone", "--depth", "5000", url, dest],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return dest


def is_git_repo(path):
    return os.path.isdir(os.path.join(path, ".git"))
