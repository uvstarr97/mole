import os
import json
import urllib.request
import urllib.parse
import urllib.error

BASE = "https://api.github.com"
UA   = "mole-secret-scanner/1.0"


def _get(path, token=None):
    url = BASE + path
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": UA,
        **({"Authorization": f"Bearer {token}"} if token else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r), r.status
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.load(e)
        except Exception:
            pass
        return body, e.code


def _token():
    return (
        os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
    )


def search_repos(count=10, lang=None, topic=None, min_stars=None,
                 sort="updated", token=None):
    """Search GitHub repos. Returns list of repo dicts."""
    tok = token or _token()

    parts = ["is:public", "fork:false"]
    if lang:
        parts.append(f"language:{lang}")
    if topic:
        parts.append(f"topic:{topic}")
    if min_stars:
        parts.append(f"stars:>={min_stars}")
    if not lang and not topic and not min_stars:
        parts.append("stars:>=5")

    q = " ".join(parts)
    sort_map = {"updated": "updated", "stars": "stars", "forks": "forks"}
    s = sort_map.get(sort, "updated")

    params = urllib.parse.urlencode({
        "q": q, "sort": s, "order": "desc",
        "per_page": min(count, 100),
    })
    data, status = _get(f"/search/repositories?{params}", tok)

    if status == 403 or status == 429:
        raise RateLimitError("GitHub rate limit hit. Set GITHUB_TOKEN env var for 30x more requests.")
    if status != 200:
        msg = data.get("message", f"HTTP {status}")
        raise APIError(f"GitHub API error: {msg}")

    items = data.get("items", [])
    return [_normalize(r) for r in items[:count]]


def list_user_repos(user, count=10, sort="pushed", token=None):
    tok = token or _token()
    params = urllib.parse.urlencode({
        "sort": sort, "direction": "desc",
        "per_page": min(count, 100), "type": "public",
    })
    data, status = _get(f"/users/{user}/repos?{params}", tok)
    if status == 404:
        raise APIError(f"User '{user}' not found.")
    if status not in (200, 206):
        raise APIError(f"GitHub API error: HTTP {status}")
    return [_normalize(r) for r in data[:count]]


def list_org_repos(org, count=10, sort="pushed", token=None):
    tok = token or _token()
    params = urllib.parse.urlencode({
        "sort": sort, "direction": "desc",
        "per_page": min(count, 100), "type": "public",
    })
    data, status = _get(f"/orgs/{org}/repos?{params}", tok)
    if status == 404:
        raise APIError(f"Org '{org}' not found.")
    if status not in (200, 206):
        raise APIError(f"GitHub API error: HTTP {status}")
    return [_normalize(r) for r in data[:count]]


def _normalize(r):
    return {
        "name":        r.get("full_name", ""),
        "url":         r.get("clone_url", ""),
        "html_url":    r.get("html_url", ""),
        "description": (r.get("description") or "")[:80],
        "language":    r.get("language") or "",
        "stars":       r.get("stargazers_count", 0),
        "forks":       r.get("forks_count", 0),
        "pushed":      (r.get("pushed_at") or "")[:10],
        "size_kb":     r.get("size", 0),
    }


class RateLimitError(Exception):
    pass

class APIError(Exception):
    pass
