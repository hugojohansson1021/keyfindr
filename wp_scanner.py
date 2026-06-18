#!/usr/bin/env python3
"""WordPress security check.

Detects common WordPress misconfigurations and exposures for
authorized penetration testing engagements:

- Configuration and backup file exposure (wp-config.php.bak etc.)
- WordPress version disclosure
- User enumeration via REST API and ?author=N
- XML-RPC accessibility
- Debug log / error log exposure
- Directory listing on standard paths
- Reflected XSS probes on the WordPress search parameter and
  user-supplied query parameters

Run only against systems you own or have written permission to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import secrets
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse, urlencode

import requests
import urllib3

USER_AGENT = "KeyFindr-WP/1.0 (authorized security testing)"
DEFAULT_TIMEOUT = 8.0
MAX_BODY_BYTES = 64 * 1024
REPORTS_DIR = Path("reports") / "wp_scanner"

GUI_EVENTS_ENABLED = False


def emit_gui_event(event_type: str, **payload) -> None:
    """Emit a single-line JSON event for the KeyFindr GUI to parse."""
    if not GUI_EVENTS_ENABLED:
        return
    payload["type"] = event_type
    print("__EVENT__ " + json.dumps(payload, default=str), flush=True)

# Paths likely to leak credentials, source, or configuration.
EXPOSURE_PATHS: tuple[str, ...] = (
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.php.save",
    "wp-config.php.swp",
    "wp-config.bak",
    "wp-config.old",
    "wp-config.txt",
    "wp-config.original.php",
    "wp-config_backup.php",
    "wp-config-backup.php",
    "wp-config-sample.php",
    "wp-config.php.dist",
    ".wp-config.php.swp",
    ".env",
    ".env.bak",
    ".env.local",
    ".env.production",
    ".env.development",
    ".htaccess.bak",
    ".htaccess~",
    ".htpasswd",
    "debug.log",
    "wp-content/debug.log",
    "wp-content/uploads/wp-config.php.bak",
    "wp-content/uploads/debug.log",
    "error_log",
    "error.log",
    "php_errorlog",
    ".git/config",
    ".git/HEAD",
    "license.txt",
    "readme.html",
    "wp-includes/version.php",
)

# Directories that should not list contents.
LISTING_PATHS: tuple[str, ...] = (
    "wp-content/uploads/",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-includes/",
    "wp-content/",
)

# Content fingerprints that confirm a file contains what we expect.
# Without these we treat 200 responses as soft 404s (common in WP themes).
SECRET_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("DB_PASSWORD", "WordPress DB password constant"),
    ("DB_USER", "WordPress DB user constant"),
    ("DB_NAME", "WordPress DB name constant"),
    ("DB_HOST", "WordPress DB host constant"),
    ("AUTH_KEY", "WordPress auth salt"),
    ("SECURE_AUTH_KEY", "WordPress secure auth salt"),
    ("NONCE_KEY", "WordPress nonce salt"),
    ("$table_prefix", "WordPress table prefix marker"),
)

ENV_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("DB_PASSWORD=", "Database password in .env"),
    ("APP_KEY=", "Laravel-style APP_KEY in .env"),
    ("AWS_SECRET_ACCESS_KEY", "AWS secret key in .env"),
    ("STRIPE_SECRET", "Stripe secret in .env"),
)

DEBUG_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    ("PHP Fatal error", "PHP fatal error in debug log"),
    ("PHP Warning", "PHP warning in debug log"),
    ("Stack trace:", "PHP stack trace in debug log"),
    ("wp-content/", "WP path leak in debug log"),
)

VERSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<meta\s+name=['\"]generator['\"]\s+content=['\"]WordPress\s+([0-9.]+)", re.IGNORECASE),
    re.compile(r"\$wp_version\s*=\s*['\"]([0-9.]+)['\"]"),
    re.compile(r"<br />\s*Version\s+([0-9.]+)", re.IGNORECASE),
)

SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    url: str | None = None
    evidence: str | None = None
    recommendation: str | None = None


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str | None = None
    is_wordpress: bool = False
    wordpress_signals: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def make_session(timeout: float, insecure: bool) -> requests.Session:
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.verify = not insecure
    session.request_timeout = timeout  # custom attr, used via helper
    return session


def _get(session: requests.Session, url: str, timeout: float,
         stream: bool = True, allow_redirects: bool = True) -> requests.Response | None:
    try:
        return session.get(
            url, timeout=timeout, allow_redirects=allow_redirects, stream=stream
        )
    except requests.RequestException:
        return None


def _read_body(response: requests.Response) -> str:
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_BODY_BYTES:
                break
    except requests.RequestException:
        pass
    finally:
        response.close()
    try:
        return b"".join(chunks).decode(
            response.encoding or "utf-8", errors="replace"
        )
    except LookupError:
        return b"".join(chunks).decode("utf-8", errors="replace")


def normalize_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else "https://" + url)
    if not parsed.netloc:
        raise argparse.ArgumentTypeError("URL has no host")
    return f"{parsed.scheme}://{parsed.netloc}/"


def fingerprint_wordpress(session: requests.Session, base: str, timeout: float,
                          result: ScanResult) -> str | None:
    """Return the homepage body if the target looks like WordPress."""
    response = _get(session, base, timeout)
    if response is None:
        result.errors.append("homepage unreachable")
        return None
    body = _read_body(response)
    lower = body.lower()

    score = 0
    signals: list[str] = []
    if 'name="generator"' in lower and "wordpress" in lower:
        score += 3
        signals.append("generator meta")
    if "/wp-content/" in body:
        score += 2
        signals.append("wp-content links")
    if "/wp-includes/" in body:
        score += 1
        signals.append("wp-includes references")
    if "/wp-json/" in body:
        score += 1
        signals.append("wp-json references")
    if "wordpress" in lower:
        score += 1
        signals.append("wordpress keyword")

    result.is_wordpress = score >= 2
    result.wordpress_signals = signals
    if result.is_wordpress:
        result.findings.append(Finding(
            check="fingerprint",
            severity="INFO",
            title="WordPress detected",
            detail=f"Signals: {', '.join(signals)}",
            url=base,
        ))
    return body if result.is_wordpress else None


def detect_version(session: requests.Session, base: str, timeout: float,
                   homepage_body: str, result: ScanResult) -> None:
    sources: list[tuple[str, str]] = [(base, homepage_body)]
    for path in ("readme.html", "wp-includes/version.php", "license.txt"):
        url = urljoin(base, path)
        response = _get(session, url, timeout)
        if response is None or response.status_code != 200:
            if response is not None:
                response.close()
            continue
        sources.append((url, _read_body(response)))

    for source_url, body in sources:
        for pattern in VERSION_PATTERNS:
            match = pattern.search(body)
            if match:
                version = match.group(1)
                result.findings.append(Finding(
                    check="version",
                    severity="LOW",
                    title=f"WordPress version disclosed: {version}",
                    detail=("Version information helps an attacker target "
                            "known CVEs. Suppress generator meta tag and "
                            "remove readme.html."),
                    url=source_url,
                    evidence=match.group(0)[:160],
                    recommendation=(
                        "Strip the generator meta tag in your theme's "
                        "functions.php (remove_action('wp_head', "
                        "'wp_generator')) and delete /readme.html."
                    ),
                ))
                return


def _body_matches(body: str, fingerprints: Iterable[tuple[str, str]]) -> list[str]:
    return [meaning for marker, meaning in fingerprints if marker in body]


def check_exposure(session: requests.Session, base: str, timeout: float,
                   threads: int, result: ScanResult) -> None:
    emit_gui_event("phase", name="exposure", total=len(EXPOSURE_PATHS))

    def probe(path: str) -> Finding | None:
        url = urljoin(base, path)
        response = _get(session, url, timeout, allow_redirects=False)
        if response is None:
            emit_gui_event("probe", group="exposure", label=path, url=url,
                           status=None, exposed=False, reachable=False)
            return None
        status = response.status_code
        if status != 200:
            response.close()
            emit_gui_event("probe", group="exposure", label=path, url=url,
                           status=status, exposed=False,
                           reachable=status not in (404, 0))
            return None
        body = _read_body(response)

        # Pick fingerprint set based on the file's expected content.
        fingerprints: tuple[tuple[str, str], ...]
        if path.startswith(".env") or "/.env" in path:
            fingerprints = ENV_FINGERPRINTS
        elif "debug.log" in path or "error_log" in path or path.endswith("error.log"):
            fingerprints = DEBUG_FINGERPRINTS
        elif path.endswith(".git/config") or path.endswith(".git/HEAD"):
            emit_gui_event("probe", group="exposure", label=path, url=url,
                           status=status, exposed=True, severity="HIGH")
            return Finding(
                check="exposure",
                severity="HIGH",
                title=f".git metadata exposed at /{path}",
                detail=("Git internals accessible over HTTP leaks full "
                        "source history."),
                url=url,
                evidence=body[:200],
                recommendation="Block /.git/ in the web server config.",
            )
        elif path in ("readme.html", "license.txt"):
            emit_gui_event("probe", group="exposure", label=path, url=url,
                           status=status, exposed=False, reachable=True,
                           note="version disclosure (handled separately)")
            return None
        else:
            fingerprints = SECRET_FINGERPRINTS

        matches = _body_matches(body, fingerprints)
        if not matches:
            # 200 but content didn't match — soft 404 in WP routing.
            emit_gui_event("probe", group="exposure", label=path, url=url,
                           status=status, exposed=False, reachable=True,
                           note="200 but content not matching (soft 404)")
            return None

        severity = "CRITICAL" if any(
            k in matches[0].lower() for k in ("password", "secret", "salt")
        ) else "HIGH"

        emit_gui_event("probe", group="exposure", label=path, url=url,
                       status=status, exposed=True, severity=severity,
                       note="; ".join(matches))
        return Finding(
            check="exposure",
            severity=severity,
            title=f"Sensitive file exposed: /{path}",
            detail="; ".join(matches),
            url=url,
            evidence=body[:240],
            recommendation=(
                "Remove the file from the web root or block via "
                "web server rules. Rotate any leaked credentials immediately."
            ),
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for finding in executor.map(probe, EXPOSURE_PATHS):
            if finding is not None:
                result.findings.append(finding)


def check_directory_listing(session: requests.Session, base: str, timeout: float,
                            result: ScanResult) -> None:
    emit_gui_event("phase", name="listing", total=len(LISTING_PATHS))
    indicators = ("<title>Index of /", "Index of /", "<h1>Index of /")
    for path in LISTING_PATHS:
        url = urljoin(base, path)
        response = _get(session, url, timeout, allow_redirects=False)
        if response is None:
            emit_gui_event("probe", group="listing", label=path, url=url,
                           status=None, exposed=False, reachable=False)
            continue
        status = response.status_code
        if status != 200:
            response.close()
            emit_gui_event("probe", group="listing", label=path, url=url,
                           status=status, exposed=False, reachable=True)
            continue
        body = _read_body(response)
        listed = any(marker in body for marker in indicators)
        emit_gui_event("probe", group="listing", label=path, url=url,
                       status=status, exposed=listed, reachable=True,
                       severity="MEDIUM" if listed else None)
        if listed:
            result.findings.append(Finding(
                check="directory_listing",
                severity="MEDIUM",
                title=f"Directory listing enabled: /{path}",
                detail=("Apache/Nginx autoindex is on. Attackers can "
                        "enumerate files in this directory."),
                url=url,
                recommendation=(
                    "Disable autoindex (Apache: 'Options -Indexes'; "
                    "Nginx: 'autoindex off;') and place an empty "
                    "index.html if needed."
                ),
            ))


def check_xmlrpc(session: requests.Session, base: str, timeout: float,
                 result: ScanResult) -> None:
    url = urljoin(base, "xmlrpc.php")
    try:
        head = session.get(url, timeout=timeout)
    except requests.RequestException:
        emit_gui_event("probe", group="xmlrpc", label="xmlrpc.php", url=url,
                       status=None, exposed=False, reachable=False)
        return
    body = (head.text or "")[:200]
    status = head.status_code
    head.close()
    enabled = status == 405 or "XML-RPC server accepts POST requests" in body
    emit_gui_event("probe", group="xmlrpc", label="xmlrpc.php", url=url,
                   status=status, exposed=enabled, reachable=True,
                   severity="MEDIUM" if enabled else None)
    if enabled:
        # Confirm with system.listMethods
        payload = (
            "<?xml version=\"1.0\"?>"
            "<methodCall><methodName>system.listMethods</methodName>"
            "<params></params></methodCall>"
        )
        try:
            response = session.post(
                url, data=payload,
                headers={"Content-Type": "text/xml"},
                timeout=timeout,
            )
        except requests.RequestException:
            response = None

        confirmed = response is not None and "methodResponse" in (response.text or "")
        result.findings.append(Finding(
            check="xmlrpc",
            severity="MEDIUM",
            title="XML-RPC endpoint is enabled",
            detail=(
                "xmlrpc.php is reachable. Useful for legacy clients but "
                "abused for brute-force amplification (system.multicall) "
                "and DDoS via pingback."
                + (" Confirmed via system.listMethods." if confirmed else "")
            ),
            url=url,
            recommendation=(
                "If not used, block POST to xmlrpc.php at the web server, "
                "or install a plugin that disables it. If used, restrict "
                "the methods exposed (filter 'xmlrpc_methods')."
            ),
        ))


def check_user_enumeration(session: requests.Session, base: str, timeout: float,
                           result: ScanResult) -> None:
    # 1) REST API
    api_url = urljoin(base, "wp-json/wp/v2/users")
    response = _get(session, api_url, timeout)
    rest_status = response.status_code if response is not None else None
    rest_exposed = False
    if response is not None and response.status_code == 200:
        body = _read_body(response)
        try:
            users = json.loads(body)
        except json.JSONDecodeError:
            users = None
        if isinstance(users, list) and users:
            rest_exposed = True
            names = [
                u.get("slug") or u.get("name") for u in users[:10]
                if isinstance(u, dict)
            ]
            result.findings.append(Finding(
                check="user_enum",
                severity="HIGH",
                title=f"User enumeration via REST API ({len(users)}+ users)",
                detail=("The /wp-json/wp/v2/users endpoint returns usernames "
                        "without authentication. Combined with login forms, "
                        "this enables targeted brute-force."),
                url=api_url,
                evidence="users: " + ", ".join(filter(None, names)),
                recommendation=(
                    "Restrict the REST users endpoint. Add to functions.php: "
                    "add_filter('rest_endpoints', function($e){ "
                    "unset($e['/wp/v2/users']); unset($e['/wp/v2/users/(?P<id>[\\d]+)']); "
                    "return $e; });"
                ),
            ))
    else:
        if response is not None:
            response.close()

    emit_gui_event("probe", group="user_enum",
                   label="REST /wp-json/wp/v2/users", url=api_url,
                   status=rest_status, exposed=rest_exposed,
                   reachable=rest_status is not None,
                   severity="HIGH" if rest_exposed else None)

    # 2) ?author=N redirect leak
    leaked: list[str] = []
    for author_id in (1, 2, 3):
        url = f"{base}?author={author_id}"
        try:
            response = session.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            emit_gui_event("probe", group="user_enum",
                           label=f"?author={author_id}", url=url,
                           status=None, exposed=False, reachable=False)
            continue
        location = response.headers.get("Location") or ""
        status = response.status_code
        response.close()
        match = re.search(r"/author/([^/?#]+)", location)
        if match:
            leaked.append(f"id {author_id} -> {match.group(1)}")
        emit_gui_event("probe", group="user_enum",
                       label=f"?author={author_id}", url=url,
                       status=status, exposed=bool(match), reachable=True,
                       severity="MEDIUM" if match else None,
                       note=f"-> {match.group(1)}" if match else None)

    if leaked:
        result.findings.append(Finding(
            check="user_enum",
            severity="MEDIUM",
            title=f"User enumeration via ?author=N redirect ({len(leaked)} users)",
            detail=("/?author=N redirects to /author/<username>/, leaking "
                    "real usernames."),
            url=urljoin(base, "?author=1"),
            evidence="; ".join(leaked),
            recommendation=(
                "Block ?author= queries at the web server, or use a security "
                "plugin (Wordfence, iThemes) to suppress the redirect."
            ),
        ))


def check_reflected_xss(session: requests.Session, base: str, timeout: float,
                        extra_params: list[str], result: ScanResult) -> None:
    marker = "kfxss" + secrets.token_hex(3)
    payload_chars = "<>\"'"
    payload = f"{marker}{payload_chars}"
    targets: list[tuple[str, str]] = [("s", "WordPress search")]
    targets.extend((p, "custom") for p in extra_params)

    for param, label in targets:
        url = f"{base}?{urlencode({param: payload})}"
        response = _get(session, url, timeout)
        if response is None:
            emit_gui_event("probe", group="xss", label=f"?{param}=", url=url,
                           status=None, exposed=False, reachable=False)
            continue
        if response.status_code != 200:
            status_code = response.status_code
            response.close()
            emit_gui_event("probe", group="xss", label=f"?{param}=", url=url,
                           status=status_code, exposed=False, reachable=True)
            continue
        body = _read_body(response)
        status_code = response.status_code

        # If even the marker isn't reflected, the param doesn't bounce back —
        # skip without flagging.
        if marker not in body:
            emit_gui_event("probe", group="xss", label=f"?{param}=", url=url,
                           status=status_code, exposed=False, reachable=True,
                           note="not reflected")
            continue

        # Check which special chars survived unescaped.
        reflected_raw = []
        for ch in payload_chars:
            if ch in body and f"{marker}{ch}" in body:
                reflected_raw.append(ch)
        if not reflected_raw:
            emit_gui_event("probe", group="xss", label=f"?{param}=", url=url,
                           status=status_code, exposed=False, reachable=True,
                           note="reflected but escaped")
            result.findings.append(Finding(
                check="xss_reflection",
                severity="INFO",
                title=f"Parameter ?{param}= reflects input (escaped)",
                detail=("Input is reflected but special characters are "
                        "encoded. No XSS observed."),
                url=url,
            ))
            continue

        # Severity: HIGH if both < and > reflect raw (script tag viable).
        critical = "<" in reflected_raw and ">" in reflected_raw
        severity = "HIGH" if critical else "MEDIUM"
        emit_gui_event("probe", group="xss", label=f"?{param}=", url=url,
                       status=status_code, exposed=True, reachable=True,
                       severity=severity,
                       note=f"raw chars: {''.join(reflected_raw)}")
        result.findings.append(Finding(
            check="xss_reflection",
            severity=severity,
            title=f"Possible reflected XSS on ?{param}= ({label})",
            detail=(
                f"Special characters ({''.join(reflected_raw)}) are "
                f"reflected into the response body without HTML encoding. "
                f"Manual confirmation recommended."
            ),
            url=url,
            evidence=_extract_context(body, marker, 80),
            recommendation=(
                "Ensure all parameter output is escaped with esc_html() / "
                "esc_attr() / wp_kses_post() depending on context. Review "
                "theme search.php and any custom shortcodes that echo "
                "$_GET / $_REQUEST values."
            ),
        ))


def _extract_context(body: str, marker: str, around: int) -> str:
    idx = body.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - around)
    end = min(len(body), idx + around)
    snippet = body[start:end]
    return snippet.replace("\n", " ").strip()


def severity_rank(finding: Finding) -> int:
    try:
        return SEVERITY_ORDER.index(finding.severity)
    except ValueError:
        return -1


def print_terminal_summary(result: ScanResult) -> None:
    print()
    print(f"Target: {result.target}")
    print(f"WordPress: {'yes' if result.is_wordpress else 'no'}"
          + (f" ({', '.join(result.wordpress_signals)})" if result.is_wordpress else ""))

    if not result.findings:
        print("No findings.")
        return

    by_sev: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in result.findings:
        by_sev.setdefault(f.severity, []).append(f)

    print()
    counts = " | ".join(
        f"{s}: {len(by_sev[s])}" for s in reversed(SEVERITY_ORDER)
        if by_sev.get(s)
    )
    print(f"Findings — {counts}")
    print()

    for sev in reversed(SEVERITY_ORDER):
        for finding in by_sev.get(sev, []):
            print(f"[{sev}] {finding.title}")
            if finding.url:
                print(f"        url: {finding.url}")
            if finding.evidence:
                short = finding.evidence.replace("\n", " ")[:160]
                print(f"        evidence: {short}")
            print(f"        {finding.detail}")
            if finding.recommendation:
                print(f"        fix: {finding.recommendation}")
            print()


def write_report(result: ScanResult, target: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-z0-9]+", "_", target.lower()).strip("_") or "target"
    ts = _now_stamp()
    path = REPORTS_DIR / f"wp_scan_{safe}_{ts}.json"
    data = asdict(result)
    data["findings"] = [asdict(f) for f in result.findings]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "WordPress security check: config exposure, version disclosure, "
            "user enumeration, XML-RPC, directory listing, reflected XSS."
        )
    )
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("--params", default="",
                        help="Comma-separated extra GET params to probe for reflected XSS "
                             "(in addition to ?s=).")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--threads", type=int, default=8,
                        help="Parallel workers for exposure probing (default: 8)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification")
    parser.add_argument("--no-xss", action="store_true",
                        help="Skip reflected XSS probes")
    parser.add_argument("--gui-events", action="store_true",
                        help="Emit __EVENT__ JSON lines for the KeyFindr GUI")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    global GUI_EVENTS_ENABLED
    GUI_EVENTS_ENABLED = bool(args.gui_events)
    base = normalize_url(args.url)
    session = make_session(args.timeout, args.insecure)
    result = ScanResult(target=base, started_at=_now_iso())

    emit_gui_event("scan_start", target=base)
    print(f"[*] Target: {base}")
    print(f"[*] Fingerprinting WordPress...")
    homepage = fingerprint_wordpress(session, base, args.timeout, result)
    if not result.is_wordpress:
        print("[!] Target does not look like WordPress. Aborting.")
        print(f"    signals: {result.wordpress_signals or 'none'}")
        result.finished_at = _now_iso()
        report_path = write_report(result, urlparse(base).netloc)
        print(f"[*] Report: {report_path}")
        return 1

    print(f"[+] WordPress confirmed ({', '.join(result.wordpress_signals)})")

    print("[*] Detecting version...")
    detect_version(session, base, args.timeout, homepage or "", result)

    print(f"[*] Probing {len(EXPOSURE_PATHS)} sensitive file paths...")
    check_exposure(session, base, args.timeout, args.threads, result)

    print(f"[*] Checking directory listings ({len(LISTING_PATHS)})...")
    check_directory_listing(session, base, args.timeout, result)

    print("[*] Checking XML-RPC...")
    check_xmlrpc(session, base, args.timeout, result)

    print("[*] Checking user enumeration...")
    check_user_enumeration(session, base, args.timeout, result)

    if not args.no_xss:
        extra = [p.strip() for p in args.params.split(",") if p.strip()]
        print(f"[*] Reflected XSS probe (?s= + {len(extra)} custom param{'s' if len(extra) != 1 else ''})...")
        check_reflected_xss(session, base, args.timeout, extra, result)

    result.finished_at = _now_iso()
    result.findings.sort(key=severity_rank, reverse=True)

    print_terminal_summary(result)
    report_path = write_report(result, urlparse(base).netloc)
    print(f"[*] Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
