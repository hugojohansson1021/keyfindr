#!/usr/bin/env python3

"""Discover subdomains through local methods and optional Certificate Transparency."""

import argparse
import concurrent.futures
import ipaddress
import json
import random
import re
import socket
import ssl
import string
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import dns.exception
import dns.reversename
import dns.resolver
import requests
import urllib3


USER_AGENT = "SubdomainSpider/1.0 (authorized security testing)"

GUI_EVENTS_ENABLED = False


def emit_gui_event(event_type: str, **payload) -> None:
    """Emit a single-line JSON event for the GUI to parse.

    Lines are prefixed with __EVENT__ so the GUI can pick them out of
    normal stdout and route them to the visualizer without showing them
    in the terminal.
    """
    if not GUI_EVENTS_ENABLED:
        return
    payload["type"] = event_type
    print("__EVENT__ " + json.dumps(payload, default=str), flush=True)
CRT_SH_CACHE_DIRECTORY = Path("reports") / "subdomains" / "cache"
CRT_SH_CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
RDAP_CACHE_DIRECTORY = Path("reports") / "subdomains" / "cache" / "rdap"
RDAP_CACHE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)
TAKEOVER_PROVIDERS = {
    "amazonaws.com": "Amazon Web Services",
    "azurewebsites.net": "Microsoft Azure",
    "bitbucket.io": "Bitbucket",
    "cloudfront.net": "Amazon CloudFront",
    "fastly.net": "Fastly",
    "ghost.io": "Ghost",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "netlify.app": "Netlify",
    "pantheonsite.io": "Pantheon",
    "readthedocs.io": "Read the Docs",
    "shopify.com": "Shopify",
    "surge.sh": "Surge",
    "unbouncepages.com": "Unbounce",
    "vercel.app": "Vercel",
    "zendesk.com": "Zendesk",
}
TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here": "GitHub Pages",
    "No such app": "Heroku",
    "Not Found - Request ID": "Microsoft Azure",
    "The thing you were looking for is no longer here": "Heroku",
    "Project not found": "Vercel or GitLab Pages",
    "Domain not found": "Netlify or Vercel",
}
SENSITIVE_LABELS = {
    "admin",
    "auth",
    "dashboard",
    "dev",
    "development",
    "internal",
    "intranet",
    "jenkins",
    "preview",
    "prod",
    "remote",
    "stage",
    "staging",
    "test",
    "vpn",
}
RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RDAP_BOOTSTRAP_URLS = {
    "domain": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}
RDAP_BOOTSTRAP_CACHE = {}
DEFAULT_LABELS = (
    "www",
    "api",
    "app",
    "admin",
    "auth",
    "blog",
    "cdn",
    "cloud",
    "cms",
    "dashboard",
    "dev",
    "developer",
    "docs",
    "download",
    "files",
    "ftp",
    "git",
    "gitlab",
    "help",
    "internal",
    "intranet",
    "jenkins",
    "mail",
    "m",
    "mobile",
    "monitor",
    "mx",
    "ns1",
    "ns2",
    "portal",
    "preview",
    "prod",
    "remote",
    "s3",
    "shop",
    "smtp",
    "stage",
    "staging",
    "static",
    "status",
    "support",
    "test",
    "vpn",
    "web",
    "webmail",
    "wiki",
)


@dataclass
class Finding:
    hostname: str
    sources: set[str] = field(default_factory=set)
    addresses: set[str] = field(default_factory=set)
    certificate_transparency: dict | None = None
    http_probe: dict | None = None
    dns: dict | None = None
    tls: dict | None = None
    risk: dict | None = None
    rdap_networks: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "sources": sorted(self.sources),
            "addresses": sorted(self.addresses),
            "certificate_transparency": self.certificate_transparency,
            "http_probe": self.http_probe,
            "dns": self.dns,
            "tls": self.tls,
            "risk": self.risk,
            "rdap_networks": self.rdap_networks,
        }


class LinkParser(HTMLParser):
    ATTRIBUTES = {"href", "src", "action", "data-src"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        del tag
        for name, value in attrs:
            if name.lower() in self.ATTRIBUTES and value:
                self.links.append(value.strip())


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        del attrs
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.parts.append(data)

    def title(self) -> str | None:
        value = " ".join(" ".join(self.parts).split())
        return value[:300] or None


def normalize_domain(value: str) -> str:
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("domain cannot be empty")

    parsed = urlparse(value if "://" in value else f"//{value}")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise argparse.ArgumentTypeError("could not parse a hostname")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise argparse.ArgumentTypeError("an IP address is not a main domain")

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise argparse.ArgumentTypeError("domain contains invalid characters") from error

    if len(hostname) > 253 or "." not in hostname:
        raise argparse.ArgumentTypeError("enter a fully qualified domain, e.g. example.com")

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in hostname.split(".")):
        raise argparse.ArgumentTypeError("domain contains an invalid DNS label")

    return hostname


def normalize_hostname(value: str) -> str | None:
    hostname = value.strip().rstrip(".").lower()
    if hostname.startswith("*."):
        hostname = hostname[2:]
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if (
        len(hostname) > 253
        or "." not in hostname
        or any(
            not label_pattern.fullmatch(label)
            for label in hostname.split(".")
        )
    ):
        return None
    return hostname or None


def is_in_scope(hostname: str, domain: str) -> bool:
    hostname = hostname.rstrip(".").lower()
    return hostname == domain or hostname.endswith(f".{domain}")


def extract_hostnames(text: str, domain: str) -> set[str]:
    candidates = set()
    escaped_domain = re.escape(domain)
    fqdn_pattern = re.compile(
        r"(?i)(?<![a-z0-9_.-])(?:\*\.)?"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        rf"{escaped_domain}(?![a-z0-9_.-])"
    )
    for match in fqdn_pattern.finditer(text):
        hostname = normalize_hostname(match.group(0))
        if hostname and is_in_scope(hostname, domain):
            candidates.add(hostname)
    return candidates


def resolve_hostname(hostname: str) -> set[str]:
    addresses = set()
    try:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError):
        return addresses

    for family, _, _, _, sockaddr in records:
        if family in {socket.AF_INET, socket.AF_INET6}:
            addresses.add(sockaddr[0])
    return addresses


def dns_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = min(timeout, 2.0)
    resolver.lifetime = timeout
    return resolver


def query_dns_record(
    hostname: str,
    record_type: str,
    timeout: float,
) -> dict:
    resolver = dns_resolver(timeout)
    try:
        answer = resolver.resolve(
            hostname,
            record_type,
            raise_on_no_answer=False,
            search=False,
        )
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "ttl": None, "values": []}
    except dns.resolver.NoNameservers as error:
        return {
            "status": "error",
            "ttl": None,
            "values": [],
            "error": str(error),
        }
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return {"status": "timeout", "ttl": None, "values": []}
    except dns.exception.DNSException as error:
        return {
            "status": "error",
            "ttl": None,
            "values": [],
            "error": str(error),
        }

    if answer.rrset is None:
        return {"status": "no_answer", "ttl": None, "values": []}
    return {
        "status": "ok",
        "ttl": answer.rrset.ttl,
        "values": sorted({item.to_text().rstrip(".") for item in answer}),
    }


def resolve_ptr(address: str, timeout: float) -> list[str]:
    try:
        reverse_name = dns.reversename.from_address(address)
    except ValueError:
        return []
    result = query_dns_record(str(reverse_name), "PTR", timeout)
    return result.get("values", []) if result["status"] == "ok" else []


def probe_dns(hostname: str, timeout: float) -> dict:
    a_record = query_dns_record(hostname, "A", timeout)
    if a_record["status"] == "nxdomain":
        records = {
            record_type: (
                a_record
                if record_type == "A"
                else {
                    "status": "skipped_nxdomain",
                    "ttl": None,
                    "values": [],
                }
            )
            for record_type in DNS_RECORD_TYPES
        }
        return {
            "status": "nxdomain",
            "records": records,
            "addresses": [],
            "cname_chain": [],
            "final_cname_target": None,
            "final_target_addresses": [],
            "ptr": {},
        }

    records = {"A": a_record}
    records.update(
        {
            record_type: query_dns_record(hostname, record_type, timeout)
            for record_type in DNS_RECORD_TYPES
            if record_type != "A"
        }
    )
    addresses = sorted(
        {
            value
            for record_type in ("A", "AAAA")
            for value in records[record_type]["values"]
        }
    )

    cname_chain = []
    current = hostname
    seen = {hostname}
    for _ in range(10):
        cname_record = query_dns_record(current, "CNAME", timeout)
        if cname_record["status"] != "ok" or not cname_record["values"]:
            break
        target = normalize_hostname(cname_record["values"][0])
        if not target:
            break
        cname_chain.append(
            {
                "name": current,
                "target": target,
                "ttl": cname_record["ttl"],
            }
        )
        if target in seen:
            break
        seen.add(target)
        current = target

    final_target = cname_chain[-1]["target"] if cname_chain else hostname
    if cname_chain:
        final_a = query_dns_record(final_target, "A", timeout)
        final_aaaa = query_dns_record(final_target, "AAAA", timeout)
        final_target_addresses = sorted(
            set(final_a["values"]) | set(final_aaaa["values"])
        )
    else:
        final_target_addresses = addresses

    if addresses:
        status = "resolved"
    elif any(
        records[record_type]["status"] == "nxdomain"
        for record_type in ("A", "AAAA", "CNAME")
    ):
        status = "nxdomain"
    elif cname_chain and not final_target_addresses:
        status = "dangling_cname"
    else:
        status = "no_address"

    return {
        "status": status,
        "records": records,
        "addresses": addresses,
        "cname_chain": cname_chain,
        "final_cname_target": final_target if cname_chain else None,
        "final_target_addresses": final_target_addresses,
        "ptr": {
            address: resolve_ptr(address, timeout)
            for address in addresses
        },
    }


def distinguished_name_to_dict(name: tuple) -> dict:
    values = {}
    for group in name:
        for key, value in group:
            values.setdefault(key, []).append(value)
    return {
        key: items[0] if len(items) == 1 else items
        for key, items in values.items()
    }


def certificate_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(
            ssl.cert_time_to_seconds(value),
            timezone.utc,
        )
    except (ValueError, OverflowError):
        return None


def probe_tls(hostname: str, port: int, timeout: float) -> dict:
    certificate = None
    verified = True
    verification_error = None
    protocol = None
    cipher = None
    alpn = None

    def connect(context: ssl.SSLContext):
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                peer_certificate = tls_socket.getpeercert()
                if not peer_certificate:
                    peer_certificate = decode_der_certificate(
                        tls_socket.getpeercert(binary_form=True)
                    )
                return (
                    peer_certificate,
                    tls_socket.version(),
                    tls_socket.cipher(),
                    tls_socket.selected_alpn_protocol(),
                )

    try:
        certificate, protocol, cipher, alpn = connect(
            ssl.create_default_context()
        )
    except ssl.SSLCertVerificationError as error:
        verified = False
        verification_error = str(error)
        try:
            certificate, protocol, cipher, alpn = connect(
                ssl._create_unverified_context()  # noqa: SLF001
            )
        except (OSError, ssl.SSLError, ValueError) as fallback_error:
            return {
                "available": False,
                "verified": False,
                "verification_error": verification_error,
                "error": str(fallback_error),
            }
    except (OSError, ssl.SSLError, ValueError) as error:
        return {
            "available": False,
            "verified": False,
            "verification_error": None,
            "error": str(error),
        }

    not_before = certificate_datetime(certificate.get("notBefore"))
    not_after = certificate_datetime(certificate.get("notAfter"))
    days_remaining = None
    if not_after:
        days_remaining = int(
            (not_after - datetime.now(timezone.utc)).total_seconds() // 86400
        )
    subject = distinguished_name_to_dict(certificate.get("subject", ()))
    issuer = distinguished_name_to_dict(certificate.get("issuer", ()))
    sans = sorted(certificate_dns_names(certificate))
    return {
        "available": True,
        "verified": verified,
        "verification_error": verification_error,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
        "alpn": alpn,
        "subject": subject,
        "issuer": issuer,
        "subject_alt_names": sans,
        "self_signed": bool(subject and subject == issuer),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_remaining": days_remaining,
        "expired": days_remaining is not None and days_remaining < 0,
        "error": None,
    }


def decode_der_certificate(der_certificate: bytes) -> dict:
    pem_certificate = ssl.DER_cert_to_PEM_cert(der_certificate)
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as cert_file:
            cert_file.write(pem_certificate)
            path = cert_file.name
        return ssl._ssl._test_decode_cert(path)  # noqa: SLF001
    finally:
        if path:
            Path(path).unlink(missing_ok=True)


def fetch_certificate(hostname: str, port: int, timeout: float) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                return tls_socket.getpeercert()
    except ssl.SSLCertVerificationError:
        # The certificate is evidence, not a trust decision. Decode it even if
        # it is expired, self-signed, or issued for a different hostname.
        context = ssl._create_unverified_context()  # noqa: SLF001
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
                return decode_der_certificate(tls_socket.getpeercert(binary_form=True))


def certificate_dns_names(certificate: dict) -> set[str]:
    names = {
        value
        for name_type, value in certificate.get("subjectAltName", ())
        if name_type == "DNS"
    }
    if names:
        return names

    for subject_group in certificate.get("subject", ()):
        for key, value in subject_group:
            if key == "commonName":
                names.add(value)
    return names


def parse_crt_sh_records(
    certificates: list[dict],
    domain: str,
    max_hosts: int,
) -> list[dict]:
    found = {}
    for certificate in certificates:
        for raw_name in certificate.get("name_value", "").splitlines():
            hostname = normalize_hostname(raw_name)
            if (
                not hostname
                or hostname == domain
                or not is_in_scope(hostname, domain)
            ):
                continue
            found.setdefault(
                hostname,
                {
                    "hostname": hostname,
                    "issuer": certificate.get("issuer_name"),
                    "not_before": certificate.get("not_before"),
                    "not_after": certificate.get("not_after"),
                    "certificate_id": certificate.get("id"),
                },
            )

    return [
        found[hostname]
        for hostname in sorted(found)[:max_hosts]
    ]


def load_crt_sh_cache(domain: str) -> tuple[list[dict], str | None]:
    cache_path = CRT_SH_CACHE_DIRECTORY / f"crt_sh_{domain.replace('.', '_')}.json"
    try:
        with cache_path.open("r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, json.JSONDecodeError):
        return [], None

    if cached.get("domain") != domain or not isinstance(cached.get("records"), list):
        return [], None
    return cached["records"], cached.get("fetched_at")


def cache_is_fresh(fetched_at: str | None, max_age_seconds: int) -> bool:
    if not fetched_at:
        return False
    try:
        timestamp = datetime.fromisoformat(fetched_at)
    except ValueError:
        return False
    age = datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)
    return 0 <= age.total_seconds() <= max_age_seconds


def save_crt_sh_cache(domain: str, records: list[dict]) -> None:
    CRT_SH_CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    cache_path = CRT_SH_CACHE_DIRECTORY / f"crt_sh_{domain.replace('.', '_')}.json"
    temporary_path = cache_path.with_suffix(".tmp")
    with temporary_path.open("w", encoding="utf-8") as cache_file:
        json.dump(
            {
                "domain": domain,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "records": records,
            },
            cache_file,
            indent=2,
            ensure_ascii=False,
        )
    temporary_path.replace(cache_path)


def check_http(
    hostname: str,
    domain: str,
    timeout: float,
    insecure: bool,
) -> dict:
    headers = {"User-Agent": USER_AGENT}
    for scheme in ("https", "http"):
        current_url = f"{scheme}://{hostname}/"
        started = time.monotonic()
        redirect_chain = []

        for redirect_count in range(6):
            response = None
            try:
                response = requests.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    headers=headers,
                    verify=not insecure,
                    stream=True,
                )
            except requests.RequestException:
                if response is not None:
                    response.close()
                break

            status_code = response.status_code
            location = response.headers.get("Location")
            if status_code in {301, 302, 303, 307, 308} and location:
                redirect_url = urljoin(current_url, location)
                redirect = urlparse(redirect_url)
                redirect_host = normalize_hostname(redirect.hostname or "")
                redirect_chain.append(
                    {
                        "url": current_url,
                        "status": status_code,
                        "location": redirect_url,
                    }
                )
                response.close()
                if (
                    redirect.scheme not in {"http", "https"}
                    or not redirect_host
                    or not is_in_scope(redirect_host, domain)
                ):
                    return {
                        "reachable": True,
                        "http_status": status_code,
                        "https": urlparse(current_url).scheme == "https",
                        "response_ms": int(
                            (time.monotonic() - started) * 1000
                        ),
                        "final_url": current_url,
                        "redirect_count": redirect_count,
                        "redirect_chain": redirect_chain,
                        "blocked_redirect": redirect_url,
                        "title": None,
                        "server": None,
                        "powered_by": None,
                        "content_type": None,
                        "security_headers": {},
                        "missing_security_headers": [],
                        "takeover_fingerprints": [],
                    }
                current_url = redirect_url
                continue

            content_type = response.headers.get("Content-Type")
            body = b""
            if content_type and any(
                value in content_type.lower()
                for value in ("text/", "html", "json", "xml", "javascript")
            ):
                try:
                    body = response.raw.read(262_144, decode_content=True)
                except (OSError, urllib3.exceptions.HTTPError):
                    body = b""
            encoding = response.encoding or "utf-8"
            text = body.decode(encoding, errors="replace")
            response_headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }
            response.close()

            title_parser = TitleParser()
            if text:
                try:
                    title_parser.feed(text)
                except (AssertionError, ValueError):
                    pass
            security_headers = {
                header: response_headers.get(header.lower())
                for header in SECURITY_HEADERS
            }
            fingerprints = sorted(
                {
                    provider
                    for signature, provider in TAKEOVER_FINGERPRINTS.items()
                    if signature.lower() in text.lower()
                }
            )
            if status_code not in {301, 302, 303, 307, 308} or not location:
                return {
                    "reachable": True,
                    "http_status": status_code,
                    "https": urlparse(current_url).scheme == "https",
                    "response_ms": int((time.monotonic() - started) * 1000),
                    "final_url": current_url,
                    "redirect_count": redirect_count,
                    "redirect_chain": redirect_chain,
                    "title": title_parser.title(),
                    "server": response_headers.get("server"),
                    "powered_by": response_headers.get("x-powered-by"),
                    "content_type": content_type,
                    "security_headers": security_headers,
                    "missing_security_headers": [
                        header
                        for header, value in security_headers.items()
                        if not value
                    ],
                    "takeover_fingerprints": fingerprints,
                }

    return {
        "reachable": False,
        "http_status": None,
        "https": False,
        "response_ms": None,
        "final_url": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "title": None,
        "server": None,
        "powered_by": None,
        "content_type": None,
        "security_headers": {},
        "missing_security_headers": [],
        "takeover_fingerprints": [],
    }


def skipped_http_probe(reason: str) -> dict:
    return {
        "reachable": False,
        "http_status": None,
        "https": False,
        "response_ms": None,
        "final_url": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "title": None,
        "server": None,
        "powered_by": None,
        "content_type": None,
        "security_headers": {},
        "missing_security_headers": [],
        "takeover_fingerprints": [],
        "skipped_reason": reason,
    }


def cname_provider(hostname: str | None) -> str | None:
    if not hostname:
        return None
    hostname = hostname.lower().rstrip(".")
    for suffix, provider in TAKEOVER_PROVIDERS.items():
        if hostname == suffix or hostname.endswith(f".{suffix}"):
            return provider
    return None


def assess_finding_risk(finding: dict) -> dict:
    findings = []

    def add(
        risk_id: str,
        severity: str,
        title: str,
        evidence: str,
        confidence: str = "medium",
        takeover: bool = False,
    ) -> None:
        findings.append(
            {
                "id": risk_id,
                "severity": severity,
                "title": title,
                "evidence": evidence,
                "confidence": confidence,
                "potential_takeover": takeover,
            }
        )

    dns_data = finding.get("dns") or {}
    cname_target = dns_data.get("final_cname_target")
    provider = cname_provider(cname_target)
    if dns_data.get("status") == "dangling_cname":
        add(
            "dangling-cname",
            "HIGH" if provider else "MEDIUM",
            "Potential dangling CNAME",
            (
                f"CNAME points to {cname_target}, which has no A/AAAA records"
                + (f" ({provider})" if provider else "")
            ),
            "high" if provider else "medium",
            takeover=True,
        )

    probe = finding.get("http_probe") or {}
    fingerprints = probe.get("takeover_fingerprints") or []
    if fingerprints:
        add(
            "takeover-fingerprint",
            "HIGH",
            "Potential subdomain takeover fingerprint",
            f"Response matched: {', '.join(fingerprints)}",
            "high",
            takeover=True,
        )

    tls_data = finding.get("tls") or {}
    if tls_data.get("available"):
        if tls_data.get("expired"):
            add(
                "tls-expired",
                "HIGH",
                "Expired TLS certificate",
                f"Certificate expired at {tls_data.get('not_after')}",
                "high",
            )
        elif tls_data.get("days_remaining") is not None:
            days = tls_data["days_remaining"]
            if days <= 14:
                add(
                    "tls-expiring-soon",
                    "HIGH",
                    "TLS certificate expires soon",
                    f"{days} days remaining",
                    "high",
                )
            elif days <= 30:
                add(
                    "tls-expiring",
                    "MEDIUM",
                    "TLS certificate nearing expiry",
                    f"{days} days remaining",
                    "high",
                )
        if not tls_data.get("verified"):
            add(
                "tls-unverified",
                "HIGH",
                "TLS certificate verification failed",
                tls_data.get("verification_error") or "Unknown verification error",
                "high",
            )
        if tls_data.get("self_signed"):
            add(
                "tls-self-signed",
                "MEDIUM",
                "Self-signed TLS certificate",
                "Certificate subject and issuer are identical",
                "high",
            )
    elif probe.get("reachable") and probe.get("https") is False:
        add(
            "http-only",
            "MEDIUM",
            "Service reachable only over HTTP",
            f"Final URL: {probe.get('final_url')}",
            "high",
        )

    if probe.get("reachable") and probe.get("https"):
        missing = probe.get("missing_security_headers") or []
        relevant_missing = [
            header
            for header in missing
            if header in {
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
            }
        ]
        if relevant_missing:
            add(
                "missing-security-headers",
                "LOW",
                "Missing HTTP security headers",
                ", ".join(relevant_missing),
                "high",
            )

    labels = set(finding["hostname"].split("."))
    sensitive = sorted(labels & SENSITIVE_LABELS)
    if sensitive and probe.get("reachable"):
        add(
            "sensitive-environment-name",
            "MEDIUM",
            "Potentially sensitive environment is public",
            f"Hostname contains: {', '.join(sensitive)}",
            "medium",
        )

    if (
        dns_data.get("status") in {"nxdomain", "no_address"}
        and finding.get("certificate_transparency")
    ):
        add(
            "historical-ct-name",
            "INFO",
            "Historical or inactive CT hostname",
            "The name appears in Certificate Transparency but has no current address",
            "high",
        )

    highest = max(
        (item["severity"] for item in findings),
        key=lambda severity: RISK_ORDER[severity],
        default="INFO",
    )
    score = min(
        100,
        sum(
            {
                "INFO": 0,
                "LOW": 10,
                "MEDIUM": 25,
                "HIGH": 45,
                "CRITICAL": 70,
            }[item["severity"]]
            for item in findings
        ),
    )
    return {
        "level": highest,
        "score": score,
        "potential_takeover": any(
            item["potential_takeover"] for item in findings
        ),
        "findings": findings,
    }


def rdap_entity_name(entity: dict) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return entity.get("handle")
    for field in vcard[1]:
        if (
            isinstance(field, list)
            and len(field) >= 4
            and field[0] in {"fn", "org"}
        ):
            value = field[3]
            if isinstance(value, list):
                return ", ".join(str(item) for item in value)
            return str(value)
    return entity.get("handle")


def summarize_rdap_entities(entities: list[dict]) -> list[dict]:
    return [
        {
            "handle": entity.get("handle"),
            "name": rdap_entity_name(entity),
            "roles": entity.get("roles", []),
        }
        for entity in entities
    ]


def summarize_rdap_events(events: list[dict]) -> dict:
    return {
        event.get("eventAction"): event.get("eventDate")
        for event in events
        if event.get("eventAction") and event.get("eventDate")
    }


def load_rdap_bootstrap(kind: str, timeout: float) -> tuple[dict | None, str | None]:
    if kind in RDAP_BOOTSTRAP_CACHE:
        return RDAP_BOOTSTRAP_CACHE[kind], None
    try:
        response = requests.get(
            RDAP_BOOTSTRAP_URLS[kind],
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=max(timeout, 15),
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("IANA bootstrap returned non-object JSON")
    except (
        requests.RequestException,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        return None, str(error)
    RDAP_BOOTSTRAP_CACHE[kind] = data
    return data, None


def rdap_cache_path(kind: str, value: str) -> Path:
    safe_value = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value)
    return RDAP_CACHE_DIRECTORY / f"{kind}_{safe_value}.json"


def load_rdap_cache(kind: str, value: str) -> dict | None:
    path = rdap_cache_path(kind, value)
    try:
        with path.open("r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
        fetched_at = datetime.fromisoformat(cached["fetched_at"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        return None
    age = datetime.now(timezone.utc) - fetched_at.astimezone(timezone.utc)
    if age.total_seconds() > RDAP_CACHE_MAX_AGE_SECONDS:
        return None
    data = cached.get("data")
    return data if isinstance(data, dict) else None


def save_rdap_cache(kind: str, value: str, data: dict) -> None:
    RDAP_CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    path = rdap_cache_path(kind, value)
    temporary_path = path.with_suffix(".tmp")
    with temporary_path.open("w", encoding="utf-8") as cache_file:
        json.dump(
            {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "data": data,
            },
            cache_file,
            indent=2,
            ensure_ascii=False,
        )
    temporary_path.replace(path)


def rdap_service_base(
    kind: str,
    value: str,
    timeout: float,
) -> tuple[str | None, str | None]:
    bootstrap_kind = "domain"
    lookup_value = value
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as error:
            return None, str(error)
        bootstrap_kind = "ipv4" if ip.version == 4 else "ipv6"
        lookup_value = ip

    bootstrap, error = load_rdap_bootstrap(bootstrap_kind, timeout)
    if error or bootstrap is None:
        return None, error

    if kind == "domain":
        tld = value.rstrip(".").rsplit(".", 1)[-1].lower()
        for keys, urls in bootstrap.get("services", []):
            if tld in {key.lower() for key in keys} and urls:
                return urls[0], None
        return None, f"No IANA RDAP service is listed for .{tld}"

    best_match = None
    best_url = None
    for networks, urls in bootstrap.get("services", []):
        if not urls:
            continue
        for network_text in networks:
            try:
                network = ipaddress.ip_network(network_text, strict=False)
            except ValueError:
                continue
            if lookup_value in network and (
                best_match is None
                or network.prefixlen > best_match.prefixlen
            ):
                best_match = network
                best_url = urls[0]
    if best_url:
        return best_url, None
    return None, f"No IANA RDAP service is listed for {value}"


def query_rdap(kind: str, value: str, timeout: float) -> tuple[dict | None, str | None]:
    cached = load_rdap_cache(kind, value)
    if cached is not None:
        return cached, None

    base_url, service_error = rdap_service_base(kind, value, timeout)
    if service_error or not base_url:
        return None, service_error
    safe_characters = ":" if kind == "ip" else ""
    url = urljoin(
        f"{base_url.rstrip('/')}/",
        f"{kind}/{quote(value, safe=safe_characters)}",
    )
    try:
        response = requests.get(
            url,
            headers={
                "Accept": "application/rdap+json, application/json",
                "User-Agent": USER_AGENT,
            },
            timeout=min(max(timeout, 5), 8),
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("RDAP returned a non-object JSON response")
        try:
            save_rdap_cache(kind, value, data)
        except OSError:
            pass
        return data, None
    except (
        requests.RequestException,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        return None, str(error)


def summarize_domain_rdap(data: dict) -> dict:
    return {
        "handle": data.get("handle"),
        "ldh_name": data.get("ldhName"),
        "unicode_name": data.get("unicodeName"),
        "status": data.get("status", []),
        "port43": data.get("port43"),
        "nameservers": sorted(
            {
                nameserver.get("ldhName", "").lower()
                for nameserver in data.get("nameservers", [])
                if nameserver.get("ldhName")
            }
        ),
        "events": summarize_rdap_events(data.get("events", [])),
        "entities": summarize_rdap_entities(data.get("entities", [])),
        "dnssec": data.get("secureDNS", {}).get("delegationSigned"),
    }


def summarize_ip_rdap(data: dict, queried_ip: str) -> dict:
    entities = summarize_rdap_entities(data.get("entities", []))
    owner = next(
        (
            entity.get("name")
            for entity in entities
            if "registrant" in entity.get("roles", []) and entity.get("name")
        ),
        None,
    )
    return {
        "queried_ips": [queried_ip],
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "status": data.get("status", []),
        "parent_handle": data.get("parentHandle"),
        "events": summarize_rdap_events(data.get("events", [])),
        "owner": owner,
        "entities": entities,
    }


def collect_rdap(
    domain: str,
    addresses: list[str],
    timeout: float,
) -> dict:
    domain_data, domain_error = query_rdap("domain", domain, timeout)
    public_addresses = []
    skipped_addresses = []
    for address in sorted(set(addresses)):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_global:
            public_addresses.append(address)
        else:
            skipped_addresses.append(address)

    networks = {}
    errors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_ip = {
            executor.submit(query_rdap, "ip", address, timeout): address
            for address in public_addresses
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            address = future_to_ip[future]
            data, error = future.result()
            if error or data is None:
                errors.append({"ip": address, "error": error})
                continue
            network = summarize_ip_rdap(data, address)
            key = (
                network.get("handle"),
                network.get("start_address"),
                network.get("end_address"),
            )
            if key in networks:
                networks[key]["queried_ips"].append(address)
                networks[key]["queried_ips"].sort()
            else:
                networks[key] = network

    return {
        "enabled": True,
        "domain": (
            summarize_domain_rdap(domain_data)
            if domain_data is not None
            else None
        ),
        "domain_error": domain_error,
        "ip_networks": sorted(
            networks.values(),
            key=lambda item: (
                item.get("name") or "",
                item.get("start_address") or "",
            ),
        ),
        "skipped_non_global_ips": skipped_addresses,
        "errors": errors,
    }


def format_terminal_finding(finding: dict) -> str:
    probe = finding.get("http_probe")
    if probe is None:
        status = "Ej kontrollerad"
    elif probe.get("reachable"):
        status = str(probe.get("http_status") or "Svar utan statuskod")
    else:
        status = "Ej nåbar"

    addresses = finding.get("addresses") or []
    ip_addresses = ", ".join(addresses) if addresses else "Ej upplöst"
    dns_data = finding.get("dns") or {}
    cname = dns_data.get("final_cname_target") or "-"
    ptr_names = sorted(
        {
            name
            for names in (dns_data.get("ptr") or {}).values()
            for name in names
        }
    )
    ptr = ", ".join(ptr_names) if ptr_names else "-"
    title = (probe or {}).get("title") or "-"
    server = (probe or {}).get("server") or "-"
    security_headers = (probe or {}).get("security_headers") or {}
    present_headers = sum(bool(value) for value in security_headers.values())
    header_status = (
        f"{present_headers}/{len(SECURITY_HEADERS)}"
        if security_headers
        else "Ej kontrollerade"
    )

    tls_data = finding.get("tls") or {}
    if tls_data.get("available"):
        tls_status = (
            f"{tls_data.get('protocol') or 'TLS'}, "
            f"{'verifierad' if tls_data.get('verified') else 'ej verifierad'}"
        )
        if tls_data.get("days_remaining") is not None:
            tls_status += f", {tls_data['days_remaining']} dagar kvar"
    else:
        tls_status = "Ej tillgänglig"

    risk = finding.get("risk") or {}
    risk_status = risk.get("level", "INFO")
    if risk.get("potential_takeover"):
        risk_status += " (möjlig takeover)"
    risk_reasons = "; ".join(
        item["title"]
        for item in risk.get("findings", [])
        if item.get("severity") != "INFO"
    ) or "-"
    network_names = sorted(
        {
            network.get("owner") or network.get("name")
            for network in finding.get("rdap_networks", [])
            if network.get("owner") or network.get("name")
        }
    )
    networks = ", ".join(network_names) if network_names else "-"

    return "\n".join(
        (
            f"Subdomän: {finding['hostname']}",
            f"Status:   {status}",
            f"IP:       {ip_addresses}",
            f"CNAME:    {cname}",
            f"PTR:      {ptr}",
            f"Titel:    {title}",
            f"Server:   {server}",
            f"Headers:  {header_status}",
            f"TLS:      {tls_status}",
            f"Nätägare: {networks}",
            f"Risk:     {risk_status}",
            f"Orsak:    {risk_reasons}",
        )
    )


def finding_sort_key(finding: dict) -> tuple[int, int, str]:
    probe = finding.get("http_probe")
    if probe and probe.get("reachable"):
        status_code = probe.get("http_status")
        if status_code == 200:
            return (0, 200, finding["hostname"])
        if isinstance(status_code, int):
            return (1, status_code, finding["hostname"])
        return (1, 999, finding["hostname"])
    return (2, 999, finding["hostname"])


def load_wordlist(path: str | None) -> list[str]:
    if path is None:
        return list(DEFAULT_LABELS)

    labels = []
    with open(path, "r", encoding="utf-8", errors="ignore") as wordlist:
        for line in wordlist:
            label = line.split("#", 1)[0].strip().lower()
            if label:
                labels.append(label)
    return labels


def wordlist_candidate(label: str, domain: str) -> str | None:
    label = label.strip().lower().strip(".")
    if not label:
        return None
    hostname = label if is_in_scope(label, domain) else f"{label}.{domain}"
    hostname = normalize_hostname(hostname)
    if not hostname or not is_in_scope(hostname, domain):
        return None
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in hostname.split(".")
    ):
        return None
    return hostname


class SubdomainSpider:
    def __init__(
        self,
        domain: str,
        timeout: float,
        threads: int,
        tls_port: int,
        max_pages: int,
        max_cert_hosts: int,
        insecure: bool,
    ):
        self.domain = domain
        self.timeout = timeout
        self.threads = threads
        self.tls_port = tls_port
        self.max_pages = max_pages
        self.max_cert_hosts = max_cert_hosts
        self.insecure = insecure
        self.findings: dict[str, Finding] = {}
        self.wildcard_certificates = set()
        self.errors = []
        self.main_domain_dns = None

    def add_finding(
        self,
        hostname: str,
        source: str,
        addresses: set[str] | None = None,
        certificate_transparency: dict | None = None,
    ) -> None:
        hostname = normalize_hostname(hostname)
        if not hostname or not is_in_scope(hostname, self.domain):
            return
        finding = self.findings.setdefault(hostname, Finding(hostname))
        finding.sources.add(source)
        if addresses:
            finding.addresses.update(addresses)
        if certificate_transparency and finding.certificate_transparency is None:
            finding.certificate_transparency = certificate_transparency

    def discover_crt_sh(
        self,
        max_hosts: int,
        refresh: bool = False,
    ) -> dict:
        certificates = None
        last_error = None
        attempts = 0
        cached_records, cached_at = load_crt_sh_cache(self.domain)
        if (
            cached_records
            and not refresh
            and cache_is_fresh(
                cached_at,
                CRT_SH_CACHE_MAX_AGE_SECONDS,
            )
        ):
            records = cached_records[:max_hosts]
            for record in records:
                hostname = record["hostname"]
                metadata = {
                    key: value
                    for key, value in record.items()
                    if key != "hostname"
                }
                self.add_finding(
                    hostname,
                    "certificate_transparency:crt.sh_cache",
                    certificate_transparency=metadata,
                )
            return {
                "enabled": True,
                "query": f"%.{self.domain}",
                "certificate_count": None,
                "discovered_count": len(records),
                "max_hosts": max_hosts,
                "attempts": 0,
                "cache_used": True,
                "cache_fetched_at": cached_at,
                "live_error": None,
                "error": None,
            }

        max_attempts = 2
        for attempts in range(1, max_attempts + 1):
            try:
                response = requests.get(
                    "https://crt.sh/",
                    params={
                        "q": f"%.{self.domain}",
                        "output": "json",
                    },
                    headers={
                        "Accept": "application/json",
                        "User-Agent": USER_AGENT,
                    },
                    timeout=min(max(self.timeout, 10), 15),
                )
                response.raise_for_status()
                certificates = response.json()
                if not isinstance(certificates, list):
                    raise ValueError("crt.sh returned a non-list JSON response")
                break
            except (
                requests.RequestException,
                json.JSONDecodeError,
                ValueError,
            ) as error:
                last_error = error
                if attempts < max_attempts:
                    time.sleep(2 ** (attempts - 1))

        if certificates is None:
            error_message = str(last_error or "unknown crt.sh error")
            if cached_records:
                records = cached_records[:max_hosts]
                for record in records:
                    hostname = record["hostname"]
                    metadata = {
                        key: value
                        for key, value in record.items()
                        if key != "hostname"
                    }
                    self.add_finding(
                        hostname,
                        "certificate_transparency:crt.sh_cache",
                        certificate_transparency=metadata,
                    )
                return {
                    "enabled": True,
                    "query": f"%.{self.domain}",
                    "certificate_count": None,
                    "discovered_count": len(records),
                    "max_hosts": max_hosts,
                    "attempts": attempts,
                    "cache_used": True,
                    "cache_fetched_at": cached_at,
                    "live_error": error_message,
                    "error": None,
                }

            self.errors.append(
                f"crt.sh failed after {attempts} attempts: {error_message}"
            )
            return {
                "enabled": True,
                "query": f"%.{self.domain}",
                "certificate_count": 0,
                "discovered_count": 0,
                "max_hosts": max_hosts,
                "attempts": attempts,
                "cache_used": False,
                "cache_fetched_at": None,
                "live_error": error_message,
                "error": error_message,
            }

        all_records = parse_crt_sh_records(
            certificates,
            self.domain,
            1_000_000,
        )
        records = all_records[:max_hosts]
        for record in records:
            hostname = record["hostname"]
            metadata = {
                key: value
                for key, value in record.items()
                if key != "hostname"
            }
            self.add_finding(
                hostname,
                "certificate_transparency:crt.sh",
                certificate_transparency=metadata,
            )

        try:
            save_crt_sh_cache(self.domain, all_records)
        except OSError as error:
            self.errors.append(f"crt.sh cache: {error}")

        return {
            "enabled": True,
            "query": f"%.{self.domain}",
            "certificate_count": len(certificates),
            "discovered_count": len(records),
            "max_hosts": max_hosts,
            "attempts": attempts,
            "cache_used": False,
            "cache_fetched_at": None,
            "live_error": None,
            "error": None,
        }

    def inspect_certificates(
        self,
        initial_hosts: list[str],
        record_errors: bool = True,
    ) -> None:
        queue = deque(initial_hosts)
        checked = set()

        while queue and len(checked) < self.max_cert_hosts:
            hostname = queue.popleft()
            if hostname in checked or not is_in_scope(hostname, self.domain):
                continue
            checked.add(hostname)

            try:
                certificate = fetch_certificate(
                    hostname,
                    self.tls_port,
                    self.timeout,
                )
            except (OSError, ssl.SSLError, ValueError) as error:
                if record_errors:
                    self.errors.append(f"TLS {hostname}: {error}")
                continue

            self.add_finding(hostname, "tls_endpoint")
            for raw_name in certificate_dns_names(certificate):
                if raw_name.startswith("*."):
                    wildcard = normalize_hostname(raw_name)
                    if wildcard and is_in_scope(wildcard, self.domain):
                        self.wildcard_certificates.add(raw_name.lower().rstrip("."))
                    continue

                certificate_host = normalize_hostname(raw_name)
                if certificate_host and is_in_scope(certificate_host, self.domain):
                    self.add_finding(
                        certificate_host,
                        f"tls_certificate:{hostname}",
                    )
                    if certificate_host not in checked:
                        queue.append(certificate_host)

    def crawl(self, initial_hosts: list[str]) -> None:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        if self.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        seed_paths = ("/", "/robots.txt", "/sitemap.xml")
        queue = deque(
            f"https://{host}{path}"
            for host in initial_hosts
            for path in seed_paths
        )
        visited = set()

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            parsed = urlparse(url)
            hostname = normalize_hostname(parsed.hostname or "")
            if (
                parsed.scheme not in {"http", "https"}
                or not hostname
                or not is_in_scope(hostname, self.domain)
            ):
                continue
            visited.add(url)

            try:
                response = session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=not self.insecure,
                    stream=True,
                )
            except requests.RequestException as error:
                self.errors.append(f"HTTP {url}: {error}")
                if parsed.scheme == "https":
                    queue.append(url.replace("https://", "http://", 1))
                continue

            self.add_finding(hostname, "web_response")

            location = response.headers.get("Location")
            if location:
                redirect_url = urljoin(url, location)
                redirect_host = normalize_hostname(urlparse(redirect_url).hostname or "")
                if redirect_host and is_in_scope(redirect_host, self.domain):
                    self.add_finding(redirect_host, f"web_redirect:{hostname}")
                    queue.append(redirect_url)

            content_type = response.headers.get("Content-Type", "").lower()
            if not any(
                marker in content_type
                for marker in ("text/", "javascript", "json", "xml")
            ):
                response.close()
                continue

            try:
                body = response.raw.read(2_000_000, decode_content=True)
            except (
                OSError,
                requests.RequestException,
                urllib3.exceptions.HTTPError,
            ) as error:
                self.errors.append(f"HTTP body {url}: {error}")
                response.close()
                continue
            response.close()
            encoding = response.encoding or "utf-8"
            text = body.decode(encoding, errors="replace")

            for discovered_host in extract_hostnames(text, self.domain):
                self.add_finding(discovered_host, f"web_content:{hostname}")

            if "html" not in content_type:
                continue
            parser = LinkParser()
            try:
                parser.feed(text)
            except (ValueError, AssertionError):
                continue

            for link in parser.links:
                next_url = urljoin(url, link)
                next_parsed = urlparse(next_url)
                next_host = normalize_hostname(next_parsed.hostname or "")
                if (
                    next_parsed.scheme in {"http", "https"}
                    and next_host
                    and is_in_scope(next_host, self.domain)
                ):
                    self.add_finding(next_host, f"web_link:{hostname}")
                    queue.append(next_url)
        session.close()

    def detect_wildcard_dns(self) -> list[set[str]]:
        wildcard_answers = []
        for _ in range(3):
            random_label = "".join(
                random.choices(string.ascii_lowercase + string.digits, k=18)
            )
            addresses = resolve_hostname(f"{random_label}.{self.domain}")
            if addresses:
                wildcard_answers.append(addresses)
        return wildcard_answers

    def brute_force_dns(
        self,
        labels: list[str],
        include_wildcard_matches: bool,
    ) -> dict:
        candidates = sorted(
            {
                candidate
                for label in labels
                if (candidate := wordlist_candidate(label, self.domain))
                and candidate != self.domain
            }
        )
        wildcard_answers = self.detect_wildcard_dns()
        skipped_wildcard_matches = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            future_to_host = {
                executor.submit(resolve_hostname, hostname): hostname
                for hostname in candidates
            }
            for future in concurrent.futures.as_completed(future_to_host):
                hostname = future_to_host[future]
                try:
                    addresses = future.result()
                except OSError as error:
                    self.errors.append(f"DNS {hostname}: {error}")
                    continue
                if not addresses:
                    continue

                wildcard_match = any(
                    addresses == wildcard_addresses
                    for wildcard_addresses in wildcard_answers
                )
                if wildcard_match and not include_wildcard_matches:
                    skipped_wildcard_matches.append(hostname)
                    continue
                source = (
                    "dns_bruteforce:wildcard_match"
                    if wildcard_match
                    else "dns_bruteforce"
                )
                self.add_finding(hostname, source, addresses)

        return {
            "enabled": True,
            "candidate_count": len(candidates),
            "wildcard_dns_detected": bool(wildcard_answers),
            "wildcard_test_answers": [
                sorted(addresses) for addresses in wildcard_answers
            ],
            "skipped_wildcard_matches": sorted(skipped_wildcard_matches),
        }

    def resolve_findings(self) -> None:
        unresolved = [
            finding.hostname
            for finding in self.findings.values()
            if not finding.addresses
        ]
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            future_to_host = {
                executor.submit(resolve_hostname, hostname): hostname
                for hostname in unresolved
            }
            for future in concurrent.futures.as_completed(future_to_host):
                hostname = future_to_host[future]
                try:
                    self.findings[hostname].addresses.update(future.result())
                except OSError as error:
                    self.errors.append(f"DNS {hostname}: {error}")

    def enrich_dns_findings(self) -> None:
        self.main_domain_dns = probe_dns(self.domain, self.timeout)
        hostnames = sorted(
            hostname
            for hostname, finding in self.findings.items()
            if hostname != self.domain and finding.dns is None
        )
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            future_to_host = {
                executor.submit(probe_dns, hostname, self.timeout): hostname
                for hostname in hostnames
            }
            for future in concurrent.futures.as_completed(future_to_host):
                hostname = future_to_host[future]
                try:
                    dns_data = future.result()
                except dns.exception.DNSException as error:
                    self.errors.append(f"DNS enrichment {hostname}: {error}")
                    continue
                finding = self.findings[hostname]
                finding.dns = dns_data
                finding.addresses.update(dns_data.get("addresses", []))

    def probe_http_findings(self) -> None:
        for hostname, finding in self.findings.items():
            if hostname != self.domain and not finding.addresses:
                finding.http_probe = skipped_http_probe("dns_unresolved")
                emit_gui_event(
                    "host",
                    host=hostname,
                    status=None,
                    reachable=False,
                    skipped="dns_unresolved",
                    addresses=[],
                )

        hostnames = sorted(
            hostname
            for hostname, finding in self.findings.items()
            if hostname != self.domain and finding.addresses
        )
        emit_gui_event("phase", name="http_probe", total=len(hostnames))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.threads, 10)
        ) as executor:
            future_to_host = {
                executor.submit(
                    check_http,
                    hostname,
                    self.domain,
                    self.timeout,
                    self.insecure,
                ): hostname
                for hostname in hostnames
            }
            for future in concurrent.futures.as_completed(future_to_host):
                hostname = future_to_host[future]
                try:
                    probe = future.result()
                    self.findings[hostname].http_probe = probe
                    emit_gui_event(
                        "host",
                        host=hostname,
                        status=probe.get("http_status"),
                        reachable=bool(probe.get("reachable")),
                        title=probe.get("title"),
                        server=probe.get("server"),
                        final_url=probe.get("final_url"),
                        addresses=sorted(self.findings[hostname].addresses)[:3],
                    )
                except requests.RequestException as error:
                    self.errors.append(f"HTTP probe {hostname}: {error}")
                    emit_gui_event(
                        "host",
                        host=hostname,
                        status=None,
                        reachable=False,
                        error=str(error),
                    )

    def probe_tls_findings(self) -> None:
        hostnames = sorted(
            hostname
            for hostname, finding in self.findings.items()
            if hostname != self.domain and finding.addresses
        )
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(self.threads, 10)
        ) as executor:
            future_to_host = {
                executor.submit(
                    probe_tls,
                    hostname,
                    self.tls_port,
                    self.timeout,
                ): hostname
                for hostname in hostnames
            }
            for future in concurrent.futures.as_completed(future_to_host):
                hostname = future_to_host[future]
                self.findings[hostname].tls = future.result()

    def assess_risks(self) -> None:
        for hostname, finding in self.findings.items():
            if hostname != self.domain:
                finding.risk = assess_finding_risk(finding.to_dict())

    def attach_rdap_networks(self, rdap: dict) -> None:
        networks_by_ip = {}
        for network in rdap.get("ip_networks", []):
            summary = {
                key: network.get(key)
                for key in (
                    "handle",
                    "name",
                    "owner",
                    "country",
                    "start_address",
                    "end_address",
                )
            }
            for address in network.get("queried_ips", []):
                networks_by_ip[address] = summary

        for finding in self.findings.values():
            unique_networks = {}
            for address in finding.addresses:
                network = networks_by_ip.get(address)
                if not network:
                    continue
                key = (
                    network.get("handle"),
                    network.get("start_address"),
                    network.get("end_address"),
                )
                unique_networks[key] = network
            finding.rdap_networks = sorted(
                unique_networks.values(),
                key=lambda item: (
                    item.get("owner") or item.get("name") or "",
                    item.get("start_address") or "",
                ),
            )

    def report(
        self,
        methods: dict,
        dns_bruteforce: dict,
        certificate_transparency: dict,
        rdap: dict,
    ) -> dict:
        subdomains = [
            finding.to_dict()
            for hostname, finding in sorted(self.findings.items())
            if hostname != self.domain
        ]
        subdomains.sort(key=finding_sort_key)
        return {
            "target_domain": self.domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "methods": methods,
            "summary": {
                "subdomain_count": len(subdomains),
                "resolved_count": sum(
                    bool(item["addresses"]) for item in subdomains
                ),
                "wildcard_certificate_count": len(self.wildcard_certificates),
                "potential_takeover_count": sum(
                    bool(item.get("risk", {}).get("potential_takeover"))
                    for item in subdomains
                ),
                "high_risk_count": sum(
                    item.get("risk", {}).get("level") in {"HIGH", "CRITICAL"}
                    for item in subdomains
                ),
                "error_count": len(self.errors),
            },
            "main_domain_dns": self.main_domain_dns,
            "rdap": rdap,
            "wildcard_certificates": sorted(self.wildcard_certificates),
            "certificate_transparency": certificate_transparency,
            "dns_bruteforce": dns_bruteforce,
            "subdomains": subdomains,
            "errors": self.errors,
        }


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Discover subdomains through TLS certificates, same-domain web "
            "content, crt.sh Certificate Transparency logs, and optional DNS "
            "wordlist checks."
        )
    )
    parser.add_argument(
        "--domain",
        required=True,
        type=normalize_domain,
        help="Main domain or URL, e.g. example.com",
    )
    crt_group = parser.add_mutually_exclusive_group()
    crt_group.add_argument(
        "--crt-sh",
        dest="crt_sh",
        action="store_true",
        default=True,
        help="Query crt.sh Certificate Transparency logs (default)",
    )
    crt_group.add_argument(
        "--no-crt-sh",
        dest="crt_sh",
        action="store_false",
        help="Disable the external crt.sh Certificate Transparency lookup",
    )
    parser.add_argument(
        "--max-ct-hosts",
        type=positive_int,
        default=50,
        help="Maximum crt.sh hostnames to include (default: 50)",
    )
    parser.add_argument(
        "--refresh-ct",
        action="store_true",
        help="Ignore fresh crt.sh cache and fetch live CT data",
    )
    parser.add_argument(
        "--no-http-probe",
        action="store_true",
        help="Do not inspect discovered hostnames over HTTPS/HTTP",
    )
    parser.add_argument(
        "--no-rdap",
        action="store_true",
        help="Disable RDAP lookups for the main domain and public IP addresses",
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Resolve common subdomain labels through the system DNS resolver",
    )
    parser.add_argument(
        "--wordlist",
        help="Custom subdomain wordlist (requires --bruteforce)",
    )
    parser.add_argument(
        "--include-wildcard-matches",
        action="store_true",
        help="Keep DNS candidates whose answers match detected wildcard DNS",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Disable TLS certificate SAN discovery",
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Disable same-domain web crawling",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Allow invalid HTTPS certificates during web crawling",
    )
    parser.add_argument(
        "--threads",
        type=positive_int,
        default=20,
        help="Parallel DNS workers (default: 20)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=5.0,
        help="Network timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--tls-port",
        type=positive_int,
        default=443,
        help="TLS port to inspect (default: 443)",
    )
    parser.add_argument(
        "--max-pages",
        type=positive_int,
        default=25,
        help="Maximum web pages/resources to crawl (default: 25)",
    )
    parser.add_argument(
        "--max-cert-hosts",
        type=positive_int,
        default=100,
        help="Maximum discovered hosts whose certificates are inspected (default: 100)",
    )
    parser.add_argument(
        "--output",
        help="JSON report path (default: reports/subdomains/<domain>_<timestamp>.json)",
    )
    parser.add_argument(
        "--gui-events",
        action="store_true",
        help="Emit __EVENT__ JSON lines for the KeyFindr GUI visualizer",
    )
    args = parser.parse_args()
    if args.wordlist and not args.bruteforce:
        parser.error("--wordlist requires --bruteforce")
    return args


def main() -> None:
    args = parse_args()
    global GUI_EVENTS_ENABLED
    GUI_EVENTS_ENABLED = bool(args.gui_events)
    emit_gui_event("root", host=args.domain)
    spider = SubdomainSpider(
        domain=args.domain,
        timeout=args.timeout,
        threads=args.threads,
        tls_port=args.tls_port,
        max_pages=args.max_pages,
        max_cert_hosts=args.max_cert_hosts,
        insecure=args.insecure,
    )
    seed_hosts = [args.domain, f"www.{args.domain}"]
    methods = {
        "tls_certificates": not args.no_tls,
        "web_crawl": not args.no_crawl,
        "dns_bruteforce": args.bruteforce,
        "certificate_transparency_crt_sh": args.crt_sh,
        "http_probe": not args.no_http_probe,
        "dns_enrichment": True,
        "ptr_reverse_dns": True,
        "tls_enrichment": not args.no_tls,
        "risk_classification": True,
        "rdap": not args.no_rdap,
        "external_apis": args.crt_sh or not args.no_rdap,
    }

    print(f"Target: {args.domain}")
    if not args.no_tls:
        print("Inspecting TLS certificates...")
        spider.inspect_certificates(seed_hosts)

    certificate_transparency = {"enabled": False}
    if args.crt_sh:
        print("Querying crt.sh Certificate Transparency logs...")
        certificate_transparency = spider.discover_crt_sh(
            args.max_ct_hosts,
            refresh=args.refresh_ct,
        )

    if not args.no_crawl:
        print("Crawling same-domain web content...")
        spider.crawl(seed_hosts)

    dns_bruteforce = {"enabled": False}
    if args.bruteforce:
        labels = load_wordlist(args.wordlist)
        print(f"Checking {len(labels)} DNS wordlist entries...")
        dns_bruteforce = spider.brute_force_dns(
            labels,
            args.include_wildcard_matches,
        )

    print("Collecting DNS records, CNAME chains, and PTR records...")
    spider.enrich_dns_findings()

    if not args.no_tls:
        discovered_hosts = sorted(
            hostname
            for hostname, finding in spider.findings.items()
            if finding.addresses
        )
        spider.inspect_certificates(
            discovered_hosts,
            record_errors=False,
        )
        spider.enrich_dns_findings()

    if not args.no_http_probe:
        print("Inspecting HTTP status, titles, redirects, and security headers...")
        spider.probe_http_findings()

    if not args.no_tls:
        print("Inspecting TLS certificates and expiry...")
        spider.probe_tls_findings()

    print("Classifying risks and takeover indicators...")
    spider.assess_risks()

    rdap = {"enabled": False}
    if not args.no_rdap:
        print("Querying RDAP for the domain and public IP networks...")
        addresses = [
            address
            for finding in spider.findings.values()
            for address in finding.addresses
        ]
        rdap = collect_rdap(args.domain, addresses, args.timeout)
        spider.attach_rdap_networks(rdap)

    report = spider.report(
        methods,
        dns_bruteforce,
        certificate_transparency,
        rdap,
    )

    if args.output:
        output_path = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = (
            Path("reports")
            / "subdomains"
            / f"subdomains_{args.domain.replace('.', '_')}_{timestamp}.json"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)

    print(f"\nFound {report['summary']['subdomain_count']} subdomains:")
    for finding in report["subdomains"]:
        print()
        print(format_terminal_finding(finding))
    if report["wildcard_certificates"]:
        print("\nWildcard certificate names:")
        for wildcard in report["wildcard_certificates"]:
            print(f"  {wildcard}")
    print(
        "\nRisk summary: "
        f"{report['summary']['high_risk_count']} high/critical, "
        f"{report['summary']['potential_takeover_count']} potential takeovers"
    )
    if report["rdap"].get("enabled"):
        domain_rdap = report["rdap"].get("domain")
        domain_status = (
            domain_rdap.get("handle") or args.domain
            if domain_rdap
            else report["rdap"].get("domain_error") or "unavailable"
        )
        print(
            "RDAP: "
            f"domain={domain_status}, "
            f"{len(report['rdap'].get('ip_networks', []))} IP networks"
        )
    print(f"\nReport: {output_path}")
    if report["summary"]["error_count"]:
        print(
            f"Completed with {report['summary']['error_count']} network errors; "
            "see the report for details."
        )


if __name__ == "__main__":
    main()
