import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich import box

console = Console(highlight=False)

SEV_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_COLOR  = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}
SEV_PREFIX = {"CRITICAL": "!", "HIGH": "!", "MEDIUM": "*", "LOW": "-"}


def _redact(s, show=6):
    if len(s) <= show * 2:
        return "*" * len(s)
    return s[:show] + "*" * (len(s) - show * 2) + s[-show:]


def print_findings(findings, redact=True):
    if not findings:
        console.print("\n  [dim]No secrets found.[/dim]\n")
        return

    sorted_f = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 99))

    table = Table(box=box.SIMPLE_HEAVY, border_style="dim", show_lines=False, expand=True)
    table.add_column("Sev",     style="bold", width=10, no_wrap=True)
    table.add_column("Type",    style="bold", max_width=28)
    table.add_column("File",    style="dim",  max_width=34)
    table.add_column("Commit",  style="dim",  width=9,  no_wrap=True)
    table.add_column("Match",   max_width=40)

    for f in sorted_f:
        sev   = f["severity"]
        color = SEV_COLOR.get(sev, "white")
        pre   = SEV_PREFIX.get(sev, ".")
        match = _redact(f["match"]) if redact else f["match"]
        table.add_row(
            f"[{color}]{pre} {sev}[/{color}]",
            f["name"],
            f["file"][-34:],
            f["commit"],
            match,
        )

    console.print(table)


def print_detail(f, redact=True):
    sev   = f["severity"]
    color = SEV_COLOR.get(sev, "white")
    match = _redact(f["match"]) if redact else f["match"]
    console.print(f"  [{color}]{f['severity']}[/{color}]  {f['name']}")
    console.print(f"  [dim]file:[/dim]    {f['file']}:{f['line']}")
    console.print(f"  [dim]commit:[/dim]  {f['commit']} {f['date']}  {f['author']}")
    console.print(f"  [dim]msg:[/dim]     {f['message'][:80]}")
    console.print(f"  [dim]match:[/dim]   {match}")
    console.print(f"  [dim]context:[/dim] {f['context'][:100]}")
    console.print()


def print_summary(findings, commits_scanned, elapsed):
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    parts = []
    for sev, color in SEV_COLOR.items():
        n = counts.get(sev, 0)
        if n:
            parts.append(f"[{color}]{n} {sev}[/{color}]")
    summary = "  ".join(parts) if parts else "[dim]none[/dim]"

    console.print()
    console.print(f"  commits scanned : [bold]{commits_scanned}[/bold]")
    console.print(f"  unique secrets  : [bold]{len(findings)}[/bold]")
    console.print(f"  {summary}")
    console.print(f"  time            : [dim]{elapsed:.1f}s[/dim]")
    console.print()


def save_txt(findings, path, target):
    with open(path, "w") as fp:
        fp.write(f"mole scan results\n")
        fp.write(f"target: {target}\n")
        fp.write(f"timestamp: {datetime.now().isoformat()}\n")
        fp.write(f"total: {len(findings)}\n")
        fp.write("-" * 60 + "\n\n")
        for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 99)):
            fp.write(f"[{f['severity']}] {f['name']}\n")
            fp.write(f"  file:    {f['file']}:{f['line']}\n")
            fp.write(f"  commit:  {f['commit']} {f['date']} {f['author']}\n")
            fp.write(f"  message: {f['message']}\n")
            fp.write(f"  match:   {f['match']}\n")
            fp.write(f"  context: {f['context'][:100]}\n\n")


def save_json(findings, path, target, redact=False):
    out = []
    for f in findings:
        row = dict(f)
        if redact:
            row["match"] = _redact(f["match"])
        out.append(row)
    data = {
        "tool": "mole",
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "total": len(findings),
        "findings": out,
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)


def save_html(findings, path, target, elapsed, commits):
    sev_css = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
    }
    rows = ""
    for i, f in enumerate(sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 99))):
        color = sev_css.get(f["severity"], "#6b7280")
        badge = f'<span style="background:{color};color:#fff;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700">{f["severity"]}</span>'
        redacted = _redact(f["match"])
        rows += f"""
        <tr onclick="toggle({i})" style="cursor:pointer">
          <td>{badge}</td>
          <td><strong>{f['name']}</strong></td>
          <td style="font-family:monospace;font-size:12px">{f['file'][-45:]}</td>
          <td style="font-family:monospace;font-size:12px">{f['commit']}</td>
        </tr>
        <tr id="d{i}" style="display:none;background:#1a2332">
          <td colspan="4" style="padding:14px 20px;font-size:13px;border-left:3px solid {color}">
            <div><b>type:</b> {f['name']}</div>
            <div><b>file:</b> {f['file']}:{f['line']}</div>
            <div><b>commit:</b> {f['commit_full']} — {f['date']} — {f['author']}</div>
            <div><b>message:</b> {f['message']}</div>
            <div><b>match:</b> <code style="background:#0f172a;padding:2px 6px;border-radius:4px">{redacted}</code></div>
            <div><b>context:</b> <code style="background:#0f172a;padding:2px 6px;border-radius:4px">{f['context'][:100]}</code></div>
          </td>
        </tr>"""

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    cards = "".join(
        f'<div class="card" style="border-top:3px solid {sev_css[s]}">'
        f'<div class="n" style="color:{sev_css[s]}">{counts.get(s,0)}</div>'
        f'<div class="l">{s}</div></div>'
        for s in SEV_ORDER
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>mole — {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0}}
.hdr{{padding:40px 48px;background:#1e293b;border-bottom:1px solid #334155}}
.hdr h1{{font-size:24px;font-weight:900;color:#f1f5f9;letter-spacing:-0.5px}}
.hdr .meta{{font-size:13px;color:#64748b;margin-top:6px}}
.wrap{{max-width:1200px;margin:0 auto;padding:32px 48px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:36px}}
.card{{background:#1e293b;border-radius:10px;padding:20px;text-align:center}}
.card .n{{font-size:36px;font-weight:900}}
.card .l{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}}
th{{background:#0f172a;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:12px 16px;text-align:left}}
td{{padding:13px 16px;border-bottom:1px solid #0f172a;font-size:13px;color:#cbd5e1}}
tr:hover td{{background:#243044}}
.lbl{{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:#475569;margin:32px 0 12px}}
</style></head>
<body>
<div class="hdr">
  <h1>mole</h1>
  <div class="meta">{target} &nbsp;|&nbsp; {commits} commits &nbsp;|&nbsp; {len(findings)} secrets &nbsp;|&nbsp; {elapsed:.1f}s &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
</div>
<div class="wrap">
  <div class="lbl">Summary</div>
  <div class="cards">{cards}</div>
  <div class="lbl">Findings</div>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Commit</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<script>function toggle(i){{var r=document.getElementById('d'+i);r.style.display=r.style.display==='none'?'table-row':'none'}}</script>
</body></html>"""

    with open(path, "w") as fp:
        fp.write(html)
