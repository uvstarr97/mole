#!/usr/bin/env python3

import os
import sys
import time
import shutil
import tempfile
import argparse

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from core.scanner import scan_commits, scan_staged, clone_repo, is_git_repo
from core.output import print_findings, print_summary, print_detail, save_json, save_html, save_txt

console = Console(highlight=False)

BANNER = """\
  _ __ ___   ___ | | ___
 | '_ ` _ \\ / _ \\| |/ _ \\
 | | | | | | (_) | |  __/
 |_| |_| |_|\\___/|_|\\___|
"""


def severity_rank(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s, 99)


def build_parser():
    p = argparse.ArgumentParser(
        prog="mole",
        description="Scan git history for secrets and credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  mole scan .                              scan full history of current repo
  mole scan . --depth 50                   last 50 commits only
  mole scan . --since 2024-01-01           commits after date
  mole scan . --staged                     staged changes only (pre-push hook)
  mole scan . -o report                    write report.html + report.json
  mole scan https://github.com/org/repo   clone and scan remote repo

  mole scrape --count 20                   scan 20 recent public repos
  mole scrape --lang python --count 10     python repos only
  mole scrape --topic security             repos tagged 'security'
  mole scrape --user torvalds              all public repos of a user
  mole scrape --org google --count 30      all public repos of an org
  mole scrape --count 15 --pick            show list, choose which to scan
  mole scrape --min-stars 100 --lang go    popular Go repos
""",
    )
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="Scan a single git repo (local or URL)")
    s.add_argument("target",                                                                    help="Path to repo or git URL")
    s.add_argument("--depth",        "-d", type=int, metavar="N",   help="Limit to last N commits")
    s.add_argument("--since",        "-s", metavar="DATE",          help="Only commits after DATE (e.g. 2024-01-01)")
    s.add_argument("--branch",       "-b", metavar="BRANCH",        help="Scan a specific branch")
    s.add_argument("--staged",             action="store_true",     help="Staged changes only")
    s.add_argument("--no-redact",          action="store_true",     help="Show full secret values")
    s.add_argument("--output",       "-o", metavar="PATH",          help="Base path for HTML+JSON (no extension)")
    s.add_argument("--json",               metavar="PATH",          help="Write JSON to PATH")
    s.add_argument("--html",               metavar="PATH",          help="Write HTML to PATH")
    s.add_argument("--detail",             action="store_true",     help="Print full detail per finding")
    s.add_argument("--min-severity",       default="LOW",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],   help="Hide findings below this severity")

    sc = sub.add_parser("scrape", help="Discover and scan public GitHub repos")
    sc.add_argument("--count",      "-n", type=int, default=10, metavar="N", help="Number of repos (default 10)")
    sc.add_argument("--lang",             metavar="LANG",                     help="Filter by language (python, go, js ...)")
    sc.add_argument("--topic",            metavar="TOPIC",                    help="Filter by topic/tag (security, api, cli ...)")
    sc.add_argument("--user",             metavar="USER",                     help="Scan all public repos of a GitHub user")
    sc.add_argument("--org",              metavar="ORG",                      help="Scan all public repos of a GitHub org")
    sc.add_argument("--sort",             default="updated",
                   choices=["updated", "stars", "forks"],                     help="Sort order (default: updated)")
    sc.add_argument("--min-stars",        type=int, metavar="N",              help="Minimum star count")
    sc.add_argument("--pick",             action="store_true",                help="Show repo list and choose which ones to scan")
    sc.add_argument("--depth",     "-d",  type=int, metavar="N",              help="Commit depth per repo")
    sc.add_argument("--output-dir","-o",  metavar="DIR",                      help="Directory to save per-repo HTML+JSON reports")
    sc.add_argument("--min-severity",     default="LOW",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],             help="Hide findings below this severity")
    sc.add_argument("--token",            metavar="TOKEN",                    help="GitHub token (or set GITHUB_TOKEN env var)")
    sc.add_argument("--no-redact",        action="store_true",                help="Show full secret values")

    return p


def _scan_repo(repo_path, target_label, depth=None, since=None, branch=None,
               staged=False, min_severity="LOW", redact=True,
               output_base=None, html_path=None, json_path=None, detail=False):
    min_rank = severity_rank(min_severity)
    start    = time.time()

    if staged:
        findings        = scan_staged(repo_path)
        commits_scanned = 0
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("  [dim]{task.description}[/dim]"),
            BarColumn(bar_width=28),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("scanning", total=None)

            def progress_cb(i, total, sha):
                prog.update(task, completed=i, total=total, description=f"scanning {sha}")

            findings, commits_scanned = scan_commits(
                repo_path, max_commits=depth, since=since, branch=branch, progress_cb=progress_cb,
            )

    elapsed  = time.time() - start
    findings = [f for f in findings if severity_rank(f["severity"]) <= min_rank]

    if detail:
        console.print()
        for f in sorted(findings, key=lambda x: severity_rank(x["severity"])):
            print_detail(f, redact=False)
    else:
        print_findings(findings, redact=False)

    print_summary(findings, commits_scanned, elapsed)

    save_txt(findings, "results.txt", target_label)
    console.print(f"  saved  [dim]results.txt[/dim]\n")

    if output_base:
        save_html(findings, output_base + ".html", target_label, elapsed, commits_scanned)
        save_json(findings, output_base + ".json", target_label)
        console.print(f"  saved  [dim]{output_base}.html[/dim]")
        console.print(f"  saved  [dim]{output_base}.json[/dim]\n")
    if html_path:
        save_html(findings, html_path, target_label, elapsed, commits_scanned)
        console.print(f"  saved  [dim]{html_path}[/dim]")
    if json_path:
        save_json(findings, json_path, target_label)
        console.print(f"  saved  [dim]{json_path}[/dim]")

    return findings, commits_scanned, elapsed


def cmd_scan(args):
    console.print(f"[bold]{BANNER}[/bold]", highlight=False)

    target    = args.target
    tmp_dir   = None
    is_remote = target.startswith("http://") or target.startswith("https://") or target.startswith("git@")

    if is_remote:
        console.print(f"  cloning [cyan]{target}[/cyan] ...")
        tmp_dir = tempfile.mkdtemp(prefix="mole_")
        try:
            repo_path = clone_repo(target, tmp_dir)
        except RuntimeError as e:
            console.print(f"  [red]error:[/red] {e}")
            sys.exit(1)
        console.print(f"  cloned  [dim]{repo_path}[/dim]\n")
    else:
        repo_path = os.path.abspath(target)

    if not is_git_repo(repo_path):
        console.print(f"  [red]error:[/red] not a git repository: {repo_path}")
        sys.exit(1)

    findings, _, _ = _scan_repo(
        repo_path,
        target_label=target,
        depth=args.depth,
        since=args.since,
        branch=args.branch,
        staged=args.staged,
        min_severity=args.min_severity,
        redact=False,
        output_base=args.output,
        html_path=args.html,
        json_path=args.json,
        detail=args.detail,
    )

    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    sys.exit(1 if any(severity_rank(f["severity"]) <= 1 for f in findings) else 0)


def _repo_table(repos, show_index=True):
    t = Table(box=box.SIMPLE_HEAVY, border_style="dim", expand=True)
    if show_index:
        t.add_column("#",           style="dim", width=4,  no_wrap=True)
    t.add_column("Repo",                         max_width=40)
    t.add_column("Lang",           style="dim",  width=13, no_wrap=True)
    t.add_column("Stars",          style="dim",  width=7,  no_wrap=True)
    t.add_column("Pushed",         style="dim",  width=11, no_wrap=True)
    t.add_column("Description",                  max_width=40)
    for i, r in enumerate(repos, 1):
        row = [r["name"], r["language"] or "", str(r["stars"]), r["pushed"], r["description"] or ""]
        if show_index:
            row = [str(i)] + row
        t.add_row(*row)
    return t


def _pick_repos(repos):
    console.print(_repo_table(repos))
    console.print()
    console.print("  [dim]enter numbers to scan  (e.g.[/dim] [bold]1,3,5-8[/bold] [dim]or[/dim] [bold]all[/bold][dim]):[/dim] ", end="")
    try:
        raw = input().strip()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return []

    if not raw or raw.lower() == "all":
        return repos

    selected = set()
    for part in raw.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                for n in range(int(a), int(b) + 1):
                    selected.add(n)
            except ValueError:
                pass
        else:
            try:
                selected.add(int(part))
            except ValueError:
                pass

    return [repos[i - 1] for i in sorted(selected) if 1 <= i <= len(repos)]


def cmd_scrape(args):
    from core.scraper import search_repos, list_user_repos, list_org_repos, RateLimitError, APIError

    console.print(f"[bold]{BANNER}[/bold]", highlight=False)

    token = args.token

    console.print("  [dim]fetching repo list ...[/dim]")
    try:
        if args.user:
            repos  = list_user_repos(args.user, count=args.count, sort=args.sort, token=token)
            source = f"user:{args.user}"
        elif args.org:
            repos  = list_org_repos(args.org, count=args.count, sort=args.sort, token=token)
            source = f"org:{args.org}"
        else:
            repos  = search_repos(
                count=args.count, lang=args.lang, topic=args.topic,
                min_stars=args.min_stars, sort=args.sort, token=token,
            )
            source = "github search"
    except RateLimitError as e:
        console.print(f"  [red]rate limit:[/red] {e}")
        sys.exit(1)
    except APIError as e:
        console.print(f"  [red]api error:[/red] {e}")
        sys.exit(1)

    if not repos:
        console.print("  [dim]no repos found.[/dim]")
        sys.exit(0)

    console.print(f"  found [bold]{len(repos)}[/bold] repos  [dim]({source})[/dim]\n")

    if args.pick:
        repos = _pick_repos(repos)
        if not repos:
            console.print("  [dim]nothing selected.[/dim]")
            sys.exit(0)
    else:
        console.print(_repo_table(repos))

    console.print()

    out_dir = None
    if args.output_dir:
        out_dir = os.path.abspath(args.output_dir)
        os.makedirs(out_dir, exist_ok=True)

    all_results = []
    tmp_root    = tempfile.mkdtemp(prefix="mole_scrape_")

    try:
        for i, repo in enumerate(repos, 1):
            name = repo["name"]
            url  = repo["url"]
            slug = name.replace("/", "__")

            console.rule(f"[dim]{i}/{len(repos)}[/dim]  [bold]{name}[/bold]", style="dim")
            console.print("  cloning ...")

            try:
                repo_path = clone_repo(url, tmp_root)
            except RuntimeError as e:
                console.print(f"  [red]clone failed:[/red] {e}\n")
                all_results.append((name, [], 0, 0.0))
                continue

            out_base = os.path.join(out_dir, slug) if out_dir else None

            findings, commits, elapsed = _scan_repo(
                repo_path,
                target_label=name,
                depth=args.depth,
                min_severity=args.min_severity,
                redact=False,
                output_base=out_base,
            )
            all_results.append((name, findings, commits, elapsed))
            shutil.rmtree(repo_path, ignore_errors=True)

    except KeyboardInterrupt:
        console.print("\n  [dim]interrupted.[/dim]")
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    if len(all_results) > 1:
        console.rule("[bold]scrape summary[/bold]", style="dim")
        console.print()

        t = Table(box=box.SIMPLE_HEAVY, border_style="dim", expand=True)
        t.add_column("Repo",    max_width=42)
        t.add_column("Commits", style="dim",      width=9, no_wrap=True)
        t.add_column("! CRIT",  style="bold red", width=7, no_wrap=True)
        t.add_column("! HIGH",  style="red",      width=7, no_wrap=True)
        t.add_column("* MED",   style="yellow",   width=7, no_wrap=True)
        t.add_column("- LOW",   style="blue",     width=7, no_wrap=True)
        t.add_column("Time",    style="dim",       width=7, no_wrap=True)

        total_findings = 0
        for name, findings, commits, elapsed in all_results:
            c = {s: sum(1 for f in findings if f["severity"] == s)
                 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            total_findings += len(findings)
            t.add_row(
                name,
                str(commits),
                str(c["CRITICAL"]) if c["CRITICAL"] else "[dim]0[/dim]",
                str(c["HIGH"])     if c["HIGH"]     else "[dim]0[/dim]",
                str(c["MEDIUM"])   if c["MEDIUM"]   else "[dim]0[/dim]",
                str(c["LOW"])      if c["LOW"]      else "[dim]0[/dim]",
                f"{elapsed:.1f}s",
            )

        console.print(t)
        console.print(f"  {len(all_results)} repos  |  [bold]{total_findings}[/bold] unique secrets total\n")

    sys.exit(0)


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.cmd == "scan":
        cmd_scan(args)
    elif args.cmd == "scrape":
        cmd_scrape(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
