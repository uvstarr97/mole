# mole

Scans git history for secrets and credentials — not just what's on disk right now.

Most secret scanners check the working tree. mole digs through every commit you ever made, because that AWS key you deleted last Tuesday is still in the history. Anyone who clones your repo can see it.

## Install

```bash
pip install rich
```

No other dependencies. Uses `git` via subprocess.

## Scan a repo

```
mole scan .                          full history
mole scan . --depth 50               last 50 commits
mole scan . --since 2024-01-01       commits after date
mole scan . --staged                 staged changes only (wire into pre-push hook)
mole scan . --no-redact              show full values
mole scan . -o report                write report.html + report.json
mole scan https://github.com/org/repo  clone and scan remote repo
```

Exit code 1 if any CRITICAL or HIGH findings — wire it into CI:

```yaml
- name: secret scan
  run: python mole.py scan .
```

## Scrape GitHub repos

Discover and scan public repos in bulk.

```
mole scrape --count 20                 20 most-recently-updated public repos
mole scrape --lang python --count 10   python repos only
mole scrape --topic security           repos tagged 'security'
mole scrape --user torvalds            all public repos of a user
mole scrape --org google --count 30    all public repos of an org
mole scrape --sort stars --count 50    sorted by stars
mole scrape --min-stars 500 --lang go  popular Go repos only
mole scrape --count 15 --pick          show list, choose which ones to scan
mole scrape --count 10 -o ./reports    save per-repo HTML+JSON to ./reports/
```

Set `GITHUB_TOKEN` (or pass `--token`) to raise the rate limit from 10 to 5000 requests/min.

After all repos are scanned, mole prints an aggregate summary table showing findings per repo.

## What it finds

| Category | Examples |
|---|---|
| Cloud credentials | AWS access keys, GCP service accounts, Azure connection strings |
| VCS tokens | GitHub PATs (classic, fine-grained, OAuth, Actions), GitLab tokens |
| Payment | Stripe live keys (secret, restricted, publishable) |
| Communication | Slack bot/user tokens, webhooks, Twilio, SendGrid, Discord, Telegram |
| Google | API keys, OAuth client IDs |
| Package registries | npm tokens, PyPI tokens |
| Private keys | RSA, EC, OpenSSH, PGP, DSA, PKCS8 |
| Databases | Postgres, MySQL, MongoDB, Redis connection strings with credentials |
| Generic | Anything that looks like `password = "..."`, `api_key = "..."` |
| Entropy-based | High-entropy hex/base64 strings with no known pattern |

The entropy check is what catches custom or internal secrets — it flags strings that look statistically random even if they don't match a known format.

## Dedup

Same secret appearing in 100 commits shows up once. Findings are keyed by `(type, first-32-chars, filepath)` so you see where it was introduced, not every commit that touched the file.

## Adding a pattern

```python
# core/patterns.py
PATTERNS = [
    ...
    ("My Custom Token", re.compile(r'myco_[A-Za-z0-9]{32}'), "CRITICAL"),
]
```

## What it doesn't do

- Revoke secrets. Use your provider's dashboard for that.
- Rewrite history. Use `git filter-repo` for that.
- Scan binary files, lock files, or image assets.
