"""Registry of scripts the GUI can run.

Each tool defines the CLI flags it accepts. The frontend renders a form
from `fields`; `app.py` validates submitted values against the same
schema before invoking the script as a subprocess.
"""

from __future__ import annotations

from typing import Any


TOOLS: dict[str, dict[str, Any]] = {
    "keyfinder": {
        "id": "keyfinder",
        "name": "keyFinder.py",
        "script": "keyFinder.py",
        "description": (
            "Crawls the target, scans HTML/JS/storage/source maps, and "
            "reports exposed secrets. Passive by default; --active probes "
            "additional endpoints."
        ),
        "extra_args": ["--gui-events"],
        "fields": [
            {
                "name": "url",
                "flag": "--url",
                "type": "text",
                "required": True,
                "placeholder": "https://example.com",
                "label": "Target URL",
            },
            {
                "name": "active",
                "flag": "--active",
                "type": "bool",
                "label": "Active probing (--active)",
            },
            {
                "name": "max_pages",
                "flag": "--max-pages",
                "type": "int",
                "default": 25,
                "min": 0,
                "label": "Max pages (0 = unlimited)",
            },
            {
                "name": "max_js_files",
                "flag": "--max-js-files",
                "type": "int",
                "default": 15,
                "min": 0,
                "label": "Max JS files (0 = unlimited)",
            },
        ],
    },
    "hidden_pages": {
        "id": "hidden_pages",
        "name": "find_hidden_pages.py",
        "script": "find_hidden_pages.py",
        "description": (
            "Tests a wordlist of paths against a target and reports those "
            "that return HTTP 200."
        ),
        "fields": [
            {
                "name": "url",
                "flag": "--url",
                "type": "text",
                "required": True,
                "placeholder": "https://example.com",
                "label": "Target URL",
            },
            {
                "name": "wordlist",
                "flag": "--wordlist",
                "type": "text",
                "required": True,
                "default": "common.txt",
                "label": "Wordlist path",
            },
            {
                "name": "threads",
                "flag": "--threads",
                "type": "int",
                "default": 20,
                "min": 1,
                "label": "Threads",
            },
            {
                "name": "timeout",
                "flag": "--timeout",
                "type": "int",
                "default": 5,
                "min": 1,
                "label": "Timeout (s)",
            },
            {
                "name": "output",
                "flag": "--output",
                "type": "text",
                "label": "Output CSV (optional)",
            },
        ],
    },
    "subdomain_spider": {
        "id": "subdomain_spider",
        "name": "subdomain_spider.py",
        "script": "subdomain_spider.py",
        "description": (
            "Discovers subdomains via TLS SANs, same-domain crawling, "
            "DNS records, RDAP, and crt.sh Certificate Transparency."
        ),
        "extra_args": ["--gui-events"],
        "fields": [
            {
                "name": "domain",
                "flag": "--domain",
                "type": "text",
                "required": True,
                "placeholder": "example.com",
                "label": "Domain",
            },
            {
                "name": "no_crt_sh",
                "flag": "--no-crt-sh",
                "type": "bool",
                "label": "Disable crt.sh lookup",
            },
            {
                "name": "bruteforce",
                "flag": "--bruteforce",
                "type": "bool",
                "label": "DNS bruteforce",
            },
            {
                "name": "wordlist",
                "flag": "--wordlist",
                "type": "text",
                "label": "Custom subdomain wordlist (needs bruteforce)",
            },
            {
                "name": "no_rdap",
                "flag": "--no-rdap",
                "type": "bool",
                "label": "Disable RDAP",
            },
            {
                "name": "no_http_probe",
                "flag": "--no-http-probe",
                "type": "bool",
                "label": "Disable HTTP probe",
            },
            {
                "name": "threads",
                "flag": "--threads",
                "type": "int",
                "default": 20,
                "min": 1,
                "label": "Threads",
            },
            {
                "name": "timeout",
                "flag": "--timeout",
                "type": "int",
                "default": 5,
                "min": 1,
                "label": "Timeout (s)",
            },
            {
                "name": "max_pages",
                "flag": "--max-pages",
                "type": "int",
                "default": 25,
                "min": 1,
                "label": "Max crawl pages",
            },
        ],
    },
    "wp_scanner": {
        "id": "wp_scanner",
        "name": "wp_scanner.py",
        "script": "wp_scanner.py",
        "description": (
            "WordPress-specific checks: config/backup file exposure, "
            "version disclosure, user enumeration, XML-RPC, directory "
            "listing, and reflected XSS on search + custom params."
        ),
        "extra_args": ["--gui-events"],
        "fields": [
            {
                "name": "url",
                "flag": "--url",
                "type": "text",
                "required": True,
                "placeholder": "https://example.com",
                "label": "Target URL",
            },
            {
                "name": "params",
                "flag": "--params",
                "type": "text",
                "label": "Extra XSS params (comma-separated)",
                "placeholder": "q,search,id",
            },
            {
                "name": "timeout",
                "flag": "--timeout",
                "type": "int",
                "default": 8,
                "min": 1,
                "label": "Timeout (s)",
            },
            {
                "name": "threads",
                "flag": "--threads",
                "type": "int",
                "default": 8,
                "min": 1,
                "label": "Threads",
            },
            {
                "name": "no_xss",
                "flag": "--no-xss",
                "type": "bool",
                "label": "Skip XSS probes",
            },
            {
                "name": "insecure",
                "flag": "--insecure",
                "type": "bool",
                "label": "Skip TLS verification",
            },
        ],
    },
    "api_secret_scanner": {
        "id": "api_secret_scanner",
        "name": "api_secret_scanner.py",
        "script": "api_secret_scanner.py",
        "description": (
            "Older Playwright-based scanner with dynamic interaction and "
            "network monitoring."
        ),
        "fields": [
            {
                "name": "url",
                "flag": "--url",
                "type": "text",
                "required": True,
                "placeholder": "https://example.com",
                "label": "Target URL",
            },
        ],
    },
}


def get_tool(tool_id: str) -> dict[str, Any] | None:
    return TOOLS.get(tool_id)


def build_command(tool_id: str, values: dict[str, Any]) -> list[str]:
    """Translate submitted form values into an argv list.

    Raises ValueError on unknown tool, missing required field, or
    invalid integer input.
    """
    tool = get_tool(tool_id)
    if tool is None:
        raise ValueError(f"unknown tool: {tool_id}")

    argv: list[str] = [tool["script"]]
    for field in tool["fields"]:
        raw = values.get(field["name"])
        ftype = field["type"]

        if ftype == "bool":
            if bool(raw):
                argv.append(field["flag"])
            continue

        if raw is None or raw == "":
            if field.get("required"):
                raise ValueError(f"missing required field: {field['name']}")
            continue

        if ftype == "int":
            try:
                parsed = int(raw)
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"field {field['name']} must be an integer"
                ) from error
            minimum = field.get("min")
            if minimum is not None and parsed < minimum:
                raise ValueError(
                    f"field {field['name']} must be >= {minimum}"
                )
            argv.extend([field["flag"], str(parsed)])
            continue

        argv.extend([field["flag"], str(raw)])

    for extra in tool.get("extra_args", []):
        argv.append(extra)

    return argv
