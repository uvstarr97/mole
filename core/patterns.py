import re
import math
import string

PATTERNS = [
    ("AWS Access Key",          re.compile(r'AKIA[0-9A-Z]{16}'),                                                                   "CRITICAL"),
    ("AWS Secret Key",          re.compile(r'(?i)aws.{0,20}secret.{0,20}[\'"]([A-Za-z0-9/+=]{40})[\'"]'),                         "CRITICAL"),
    ("AWS Session Token",       re.compile(r'(?i)aws.{0,10}session.{0,10}[\'"]([A-Za-z0-9/+=]{100,})[\'"]'),                      "CRITICAL"),
    ("GCP Service Account",     re.compile(r'"type"\s*:\s*"service_account"'),                                                     "CRITICAL"),
    ("Azure Connection String", re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]{88}'),     "CRITICAL"),
    ("GitHub Token (classic)",  re.compile(r'ghp_[A-Za-z0-9]{36}'),                                                               "CRITICAL"),
    ("GitHub Token (fine)",     re.compile(r'github_pat_[A-Za-z0-9_]{82}'),                                                       "CRITICAL"),
    ("GitHub OAuth Token",      re.compile(r'gho_[A-Za-z0-9]{36}'),                                                               "CRITICAL"),
    ("GitHub Actions Token",    re.compile(r'ghs_[A-Za-z0-9]{36}'),                                                               "HIGH"),
    ("GitLab PAT",              re.compile(r'glpat-[A-Za-z0-9\-]{20}'),                                                           "CRITICAL"),
    ("Stripe Secret Key",       re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                                                          "CRITICAL"),
    ("Stripe Restricted Key",   re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),                                                          "CRITICAL"),
    ("Stripe Publishable Key",  re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),                                                          "HIGH"),
    ("Stripe Test Key",         re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),                                                          "MEDIUM"),
    ("Slack Bot Token",         re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),                                    "CRITICAL"),
    ("Slack User Token",        re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),                                    "CRITICAL"),
    ("Slack Webhook",           re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}'),  "HIGH"),
    ("Twilio Account SID",      re.compile(r'AC[a-f0-9]{32}'),                                                                    "HIGH"),
    ("Twilio Auth Token",       re.compile(r'(?i)twilio.{0,20}[\'"]([a-f0-9]{32})[\'"]'),                                         "CRITICAL"),
    ("SendGrid API Key",        re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),                                       "CRITICAL"),
    ("Discord Token",           re.compile(r'[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}'),                                        "CRITICAL"),
    ("Telegram Bot Token",      re.compile(r'[0-9]{8,10}:AA[0-9A-Za-z\-_]{33}'),                                                 "CRITICAL"),
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                                                            "HIGH"),
    ("Google OAuth Client ID",  re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),                            "MEDIUM"),
    ("npm Token",               re.compile(r'npm_[A-Za-z0-9]{36}'),                                                               "CRITICAL"),
    ("PyPI Token",              re.compile(r'pypi-[A-Za-z0-9_\-]{40,}'),                                                          "CRITICAL"),
    ("RSA Private Key",         re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),                                                    "CRITICAL"),
    ("EC Private Key",          re.compile(r'-----BEGIN EC PRIVATE KEY-----'),                                                     "CRITICAL"),
    ("Private Key (PKCS8)",     re.compile(r'-----BEGIN PRIVATE KEY-----'),                                                        "CRITICAL"),
    ("OpenSSH Private Key",     re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),                                                "CRITICAL"),
    ("PGP Private Key",         re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),                                              "CRITICAL"),
    ("DSA Private Key",         re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),                                                    "CRITICAL"),
    ("Credentials in URL",      re.compile(r'[a-zA-Z]{3,10}://[^/\s:@]+:[^/\s:@]+@[^/\s]+'),                                     "HIGH"),
    ("DB Connection String",    re.compile(r'(?i)(mongodb|postgres|mysql|redis|amqp)://[^:]+:[^@]+@[^\s]+'),                      "HIGH"),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),               "MEDIUM"),
    ("Generic Secret",          re.compile(r'(?i)(secret|password|passwd|pwd|api_key|apikey|auth_token|access_token)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]'), "MEDIUM"),
    ("Heroku API Key",          re.compile(r'(?i)heroku.{0,20}[\'"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'"]'), "HIGH"),
    ("Mailgun API Key",         re.compile(r'key-[0-9a-zA-Z]{32}'),                                                               "HIGH"),
    ("DigitalOcean Token",      re.compile(r'dop_v1_[a-f0-9]{64}'),                                                               "CRITICAL"),
    ("Vercel Token",            re.compile(r'(?i)vercel.{0,20}[\'"]([A-Za-z0-9]{24})[\'"]'),                                      "HIGH"),
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".tar", ".pdf",
    ".lock", ".sum", ".mod",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
    "composer.lock", "go.sum",
}

B64_CHARS = set(string.ascii_letters + string.digits + "+/=")
HEX_CHARS = set(string.hexdigits)


def _entropy(s):
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())


def _find_high_entropy(line):
    findings = []
    for m in re.finditer(r'[0-9a-fA-F]{32,}', line):
        s = m.group()
        if _entropy(s) > 3.5:
            findings.append((s, "hex"))
    for m in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', line):
        s = m.group()
        if set(s) <= B64_CHARS and _entropy(s) > 4.5:
            findings.append((s, "base64"))
    return findings


def match_line(line):
    results = []
    seen = set()

    for name, pattern, severity in PATTERNS:
        m = pattern.search(line)
        if m:
            matched = m.group()
            if matched not in seen:
                seen.add(matched)
                results.append({
                    "name": name,
                    "match": matched,
                    "severity": severity,
                    "entropy_based": False,
                })

    if not results:
        for s, charset in _find_high_entropy(line):
            key = s[:16]
            if key not in seen:
                seen.add(key)
                results.append({
                    "name": f"High-entropy string ({charset})",
                    "match": s,
                    "severity": "LOW",
                    "entropy_based": True,
                })

    return results
