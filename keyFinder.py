import argparse
import base64
import json
import random
import re
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright
from tqdm import tqdm

URL = None
TARGET_HOSTNAME = None

# ---- GUI event stream -------------------------------------------------------
# When --gui-events is passed, the scanner prints "__EVENT__ <json>" lines that
# the web GUI parses to draw a live phase tree. Stdout still carries the normal
# human-readable log, so the CLI is unchanged.
GUI_EVENTS_ENABLED = False
_FINDING_SEQ = 0


def emit_gui_event(event_type: str, **payload) -> None:
    """Print a single GUI event as a tagged JSON line (no-op unless enabled)."""
    if not GUI_EVENTS_ENABLED:
        return
    payload["type"] = event_type
    print("__EVENT__ " + json.dumps(payload, default=str), flush=True)


def emit_phase(phase_id: str, label: str) -> None:
    """A top-level branch off the root: one scan phase."""
    emit_gui_event("phase", id=phase_id, parent="root", label=label)


def emit_item(item_id: str, parent_id: str, label: str) -> None:
    """A unit of work inside a phase (a crawled page, a JS file, an endpoint)."""
    emit_gui_event("item", id=item_id, parent=parent_id, label=label)


def emit_item_done(item_id: str, found: int) -> None:
    """Mark an item finished; `found` colours it (clean vs. hit)."""
    emit_gui_event("item_done", id=item_id, found=found)


def emit_finding(parent_id: str, hit: dict) -> None:
    """A leaf: a secret found under an item or phase, coloured by severity."""
    global _FINDING_SEQ
    if not GUI_EVENTS_ENABLED:
        return
    _FINDING_SEQ += 1
    raw = str(hit.get("match", hit.get("secret", "")))
    masked = raw[:4] + "***" if len(raw) > 4 else raw
    emit_gui_event(
        "finding",
        id=f"f{_FINDING_SEQ}",
        parent=parent_id,
        severity=hit.get("severity", "LOW"),
        label=masked,
        source=hit.get("filetype", ""),
        pattern=hit.get("pattern", ""),
    )


def _short_url(url: str) -> str:
    """Trim a URL to a short, tree-friendly label (path or filename)."""
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        label = path.rsplit("/", 1)[-1] or path
        return label[:28] if label else parsed.netloc
    except ValueError:
        return url[:28]


API_ENDPOINTS = [
    # Add more endpoints here if you want!
]

SECRET_PATTERNS = [
    # Google API Keys (flera varianter)
    r"AIza[0-9A-Za-z\-_]{35}",            # Google API
    r"AIzaSy[0-9A-Za-z\-_]{33}",          # Google API Key (more specific)
    r"AIza[0-9A-Za-z\-_]{39}",            # Extended Google key pattern
    r"GOOG[a-zA-Z0-9\-_]{28}",            # Google Cloud API
    r"ya29\.[0-9A-Za-z\-_]+",             # Google OAuth Access Token
    r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", # Google OAuth Client
    r"GOCSPX-[a-zA-Z0-9\-_]{28}",         # Google OAuth Client Secret
    
    # Stripe Keys (alla typer)
    r"sk_live_[0-9a-zA-Z]{24,}",          # Stripe Live Secret
    r"sk_test_[0-9a-zA-Z]{24,}",          # Stripe Test Secret
    r"pk_live_[0-9a-zA-Z]{24,}",          # Stripe Public Live
    r"pk_test_[0-9a-zA-Z]{24,}",          # Stripe Public Test
    r"rk_live_[0-9a-zA-Z]{24}",           # Stripe Restricted Key
    r"whsec_[a-zA-Z0-9+/=]{32,}",         # Stripe Webhook Secret
    
    # AWS Keys
    r"AKIA[0-9A-Z]{16}",                  # AWS Access Key ID
    r"ASIA[0-9A-Z]{16}",                  # AWS Session Token Key ID
    r"AROA[0-9A-Z]{16}",                  # AWS Role Access Key ID
    r"AIDA[0-9A-Z]{16}",                  # AWS IAM User Access Key ID
    r"AGPA[0-9A-Z]{16}",                  # AWS IAM Group Access Key ID
    r"AIPA[0-9A-Z]{16}",                  # AWS IAM Instance Profile Access Key ID
    r"ANPA[0-9A-Z]{16}",                  # AWS IAM Managed Policy Access Key ID
    r"ANVA[0-9A-Z]{16}",                  # AWS IAM Version Access Key ID
    r"APKA[0-9A-Z]{16}",                  # AWS IAM Public Key Access Key ID
    
    # GitHub Tokens (alla typer)
    r"ghp_[A-Za-z0-9]{36,}",              # GitHub Personal Access Token
    r"gho_[A-Za-z0-9]{36,}",              # GitHub OAuth Token
    r"ghu_[A-Za-z0-9]{36,}",              # GitHub User Token
    r"ghs_[A-Za-z0-9]{36,}",              # GitHub Server Token
    r"ghr_[A-Za-z0-9]{36,}",              # GitHub Refresh Token
    r"github_pat_[a-zA-Z0-9_]{82}",       # GitHub Fine-grained PAT

    # Prefix-based patterns adapted from momenbasel/keyFinder (MIT)
    # See THIRD_PARTY_NOTICES.md for attribution and license details.
    r"\bglpat-[A-Za-z0-9_-]{20,}\b",       # GitLab Personal Access Token
    r"\bglptt-[A-Za-z0-9_-]{20,}\b",       # GitLab Pipeline Token
    r"\bGR1348941[A-Za-z0-9_-]{20}\b",     # GitLab Runner Token
    r"\bsk-proj-[A-Za-z0-9_-]{40,}\b",     # OpenAI Project API Key
    r"\bsk-ant-[A-Za-z0-9_-]{90,}\b",      # Anthropic API Key
    r"\bnpm_[A-Za-z0-9]{36}\b",            # NPM Access Token
    r"\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}\b", # HashiCorp Vault Token
    r"\bshpca_[a-fA-F0-9]{32}\b",          # Shopify Custom App Token
    r"\bshppa_[a-fA-F0-9]{32}\b",          # Shopify Private App Token
    r"\bshpss_[a-fA-F0-9]{32}\b",          # Shopify Shared Secret
    r"\bsntrys_[A-Za-z0-9_]{64,}\b",       # Sentry Auth Token
    r"\bglc_[A-Za-z0-9_+/]{32,}\b",        # Grafana API Key
    r"\bglsa_[A-Za-z0-9_]{32,}_[0-9a-f]{8}\b", # Grafana Service Account Token
    
    # JWT Tokens (olika varianter)
    r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", # Standard JWT
    r"eyJ[a-zA-Z0-9\-_]+=*\.[a-zA-Z0-9\-_]+=*\.[a-zA-Z0-9\-_]+=*", # JWT med padding
    
    # Slack Tokens (alla typer)
    r"xox[baprs]-[A-Za-z0-9\-]{10,48}",   # Slack Tokens (Bot, App, User, Service)
    r"xoxe\.xox[bp]-[A-Za-z0-9\-]{10,48}", # Slack Enterprise Grid tokens
    
    # Discord
    r"discord_[a-zA-Z0-9]{68}",           # Discord Bot Token
    r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", # Discord Bot Token Alt Format
    r"mfa\.[a-z0-9_-]{84}",               # Discord MFA Token
    
    # Social Media APIs
    r"EAACEdEose0cBA[0-9A-Za-z]+",        # Facebook Access Token
    r"EAABw[0-9A-Za-z]+",                 # Facebook App Token
    r"[1-9][0-9]+-[0-9a-zA-Z]{40}",       # Facebook App Secret
    r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}", # Twitter API
    r"AAAA[A-Za-z0-9%]{80,}",             # Twitter Bearer Token
    
    # Cloud Services
    r"dapi-[a-zA-Z0-9]{32}",              # DigitalOcean API
    r"do_[a-zA-Z0-9]{64}",                # DigitalOcean Spaces
    r"v1\.[a-f0-9]{40}",                  # CircleCI Token
    r"arn:aws:iam::[0-9]{12}:role/[a-zA-Z_0-9+=,.@\-_/]+", # AWS ARN
    
    # Email Services
    r"MC[a-zA-Z0-9]{32}",                 # Mailchimp API
    r"[a-zA-Z0-9]{32}-us[0-9]{1,2}",      # Mailchimp with region
    r"key-[0-9a-zA-Z]{32}",               # Mailgun API Key
    r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",  # SendGrid API Key
    r"[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", # SendGrid alternative
    
    # Communication Services
    r"AC[a-zA-Z0-9_\-]{32}",              # Twilio Account SID
    r"SK[a-zA-Z0-9_\-]{32}",              # Twilio Auth Token
    r"AP[a-zA-Z0-9_\-]{32}",              # Twilio API Key
    
    # Payment Processors
    r"access_token\$production\$[a-z0-9]{32}",  # PayPal Access Token
    r"access_token\$sandbox\$[a-z0-9]{32}",     # PayPal Sandbox Token
    r"sq0atp-[0-9A-Za-z\-_]{22}",         # Square access token
    r"sq0csp-[0-9A-Za-z\-_]{43}",         # Square client secret
    r"sq0ids-[0-9A-Za-z\-_]{43}",         # Square application ID
    
    # Database & Storage
    r"mongodb(\+srv)?://[^\s]+",          # MongoDB Connection String
    r"postgres://[^\s]+",                 # PostgreSQL Connection String
    r"mysql://[^\s]+",                    # MySQL Connection String
    r"redis://[^\s]+",                    # Redis Connection String
    r"amqp://[^\s]+",                     # RabbitMQ Connection String
    
    # Crypto & Blockchain
    r"0x[a-fA-F0-9]{40}",                 # Ethereum Address
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",   # Bitcoin Address
    r"bc1[a-z0-9]{39,59}",                # Bitcoin Bech32 Address
    
    # API Keys (generiska patterns)
    r"(?:api[_-]?key|apikey|token|secret|nyckel)[\"':= ]+[A-Za-z0-9_\-]{8,}",  # Generisk nyckel
    r"['\"]X-RapidAPI-Key['\"]\s*:\s*['\"]([a-zA-Z0-9\-_]{32,})['\"]",  # RapidAPI key
    r"['\"]X-API-KEY['\"]\s*:\s*['\"]([a-zA-Z0-9\-_]{8,})['\"]",  # Generic X-API-KEY
    r"['\"]Authorization['\"]\s*:\s*['\"](?:Bearer |Basic |Token )?([a-zA-Z0-9\-_+/=]{20,})['\"]", # Auth headers
    
    # SSH & Crypto Keys
    r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",  # PEM private key
    r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",  # RSA private key
    r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----", # OpenSSH private key
    r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----", # EC private key
    r"-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----", # DSA private key
    r"ssh-rsa\s+[A-Za-z0-9+/=]+",         # SSH RSA public key
    r"ssh-ed25519\s+[A-Za-z0-9+/=]+",     # SSH ED25519 public key
    r"ssh-dss\s+[A-Za-z0-9+/=]+",         # SSH DSS public key
    
    # Certificates
    r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", # X.509 Certificate
    r"-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----", # Public Key
    
    # Tokens och Auth
    r"Bearer\s+[a-zA-Z0-9\-_.]+",         # Bearer token
    r"Token\s+[a-zA-Z0-9\-_.]+",          # Token auth
    r"Basic\s+[a-zA-Z0-9=:_\-+/]+",       # Basic Auth
    r"Digest\s+[a-zA-Z0-9=:_\-+/\s,=\"]+", # Digest Auth
    
    # URLs with embedded secrets
    r"https?://[^:\s]*:[^@\s]*@[^\s]+",   # URLs with credentials
    r"ftp://[^:\s]*:[^@\s]*@[^\s]+",      # FTP URLs with credentials
    
    # Configuration patterns (mer specifika)
    r"password\s*[:=]\s*['\"]([^'\"]{8,})['\"]", # Password in config
    r"secret\s*[:=]\s*['\"]([^'\"]{12,})['\"]",   # Secret in config (längre)
    r"private_key\s*[:=]\s*['\"]([^'\"]{30,})['\"]", # Private key in config (längre)
    
    # Amazon Services
    r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",  # Amazon MWS Auth Token
    r"LTAI[a-zA-Z0-9]{12,20}",            # Alibaba Cloud Access Key
    
    # Webhooks (ofta hårdkodade och känsliga)
    r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{11}/[A-Za-z0-9]{24}", # Slack Incoming Webhooks
    r"https://hooks\.slack\.com/workflows/[A-Z0-9]{10}/[A-Z0-9]{10}/[A-Za-z0-9]{18}/[A-Za-z0-9]{18}", # Slack Workflow Webhooks
    r"https://discord\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{68}", # Discord Webhooks
    r"https://discordapp\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{68}", # Discord Webhooks (old domain)
    r"https://[a-zA-Z0-9\-_]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]{36}@[a-f0-9\-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9\-]{36}", # Microsoft Teams
    r"https://outlook\.office\.com/webhook/[a-f0-9\-]{36}@[a-f0-9\-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9\-]{36}", # Microsoft Teams Outlook
    r"https://[a-zA-Z0-9\-_]+\.webhooks\.twilio\.com/v1/Accounts/[A-Za-z0-9]{34}/Flows/[A-Za-z0-9]{34}", # Twilio Studio Flow Webhooks
    r"https://api\.github\.com/repos/[a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+/hooks", # GitHub Webhooks endpoint
    r"https://[a-zA-Z0-9\-_]+\.ngrok\.io/[a-zA-Z0-9\-_/]*", # Ngrok tunnels (dev webhooks)
    r"https://[a-zA-Z0-9\-_]+\.loca\.lt", # LocalTunnel (dev webhooks)
    r"https://[a-zA-Z0-9\-_]+\.serveo\.net", # Serveo tunnels (dev webhooks)
    r"https://[a-zA-Z0-9\-_]+\.pagekite\.me", # PageKite tunnels
    r"https://webhook\.site/[a-f0-9\-]{36}", # Webhook.site URLs
    r"https://[a-zA-Z0-9\-_]+\.requestcatcher\.com", # RequestCatcher webhooks
    r"https://httpbin\.org/post", # HTTPBin (testing webhooks)
    r"https://postb\.in/[a-zA-Z0-9]{10}", # PostBin webhooks
    r"https://[a-zA-Z0-9\-_]+\.pipedream\.net", # Pipedream webhooks
    r"https://[a-zA-Z0-9\-_]+\.herokuapp\.com/[a-zA-Z0-9\-_/]*", # Heroku app webhooks
    r"https://[a-zA-Z0-9\-_]+\.vercel\.app/api/[a-zA-Z0-9\-_/]*", # Vercel API endpoints
    r"https://[a-zA-Z0-9\-_]+\.netlify\.app/\.netlify/functions/[a-zA-Z0-9\-_]+", # Netlify Functions
    r"https://[a-zA-Z0-9\-_]+\.amazonaws\.com/[a-zA-Z0-9\-_/]*", # AWS Lambda/API Gateway webhooks
    r"https://[a-z0-9\-]+\.[a-z]+\.amazonaws\.com/[a-zA-Z0-9\-_/]*", # AWS regional endpoints
    r"https://api\.stripe\.com/v1/webhook_endpoints/[a-zA-Z0-9_]+", # Stripe webhook endpoints
    r"https://[a-zA-Z0-9\-_]+\.cloudfunctions\.net/[a-zA-Z0-9\-_]+", # Google Cloud Functions
    r"https://[a-zA-Z0-9\-_]+\.azurewebsites\.net/api/[a-zA-Z0-9\-_/]*", # Azure Functions
    r"https://[a-zA-Z0-9\-_]+\.digitaloceanspaces\.com/[a-zA-Z0-9\-_/]*", # DigitalOcean Spaces
    r"https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9\-_]{35}/", # Telegram Bot Webhooks
    r"https://graph\.facebook\.com/[0-9]+/subscriptions", # Facebook Graph API Webhooks
    r"https://api\.mailgun\.net/v3/[a-zA-Z0-9\-_.]+/messages", # Mailgun Webhooks
    r"https://[a-zA-Z0-9\-_]+\.firebaseapp\.com/[a-zA-Z0-9\-_/]*", # Firebase webhooks
    r"https://us-central1-[a-zA-Z0-9\-_]+\.cloudfunctions\.net/[a-zA-Z0-9\-_]+", # Firebase Cloud Functions
    r"https://[a-zA-Z0-9\-_]+\.supabase\.co/functions/v1/[a-zA-Z0-9\-_]+", # Supabase Edge Functions
    
    # Generic webhook patterns
    r"https?://[a-zA-Z0-9\-_.]+/webhook[a-zA-Z0-9\-_/]*", # Generic webhook URLs
    r"https?://[a-zA-Z0-9\-_.]+/api/webhook[a-zA-Z0-9\-_/]*", # API webhook endpoints
    r"https?://[a-zA-Z0-9\-_.]+/hook[a-zA-Z0-9\-_/]*", # Generic hook URLs
    
    # Misc Services
    r"XJ[a-zA-Z0-9]{36}",                 # Generic UUID-like API key
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", # UUID format
    r"R_[0-9a-f]{32}",                    # Shopify private app token
    r"shpat_[a-fA-F0-9]{32}",             # Shopify access token
]


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Scan an authorized website for exposed secrets."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Authorized target URL, for example https://example.com",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active endpoint probing with GET, POST and PUT requests.",
    )
    parser.add_argument(
        "--max-pages",
        type=non_negative_int,
        default=25,
        help="Maximum number of HTML pages to crawl (default: 25, 0 = unlimited).",
    )
    parser.add_argument(
        "--max-js-files",
        type=non_negative_int,
        default=15,
        help="Maximum number of JavaScript files to scan (default: 15, 0 = unlimited).",
    )
    parser.add_argument(
        "--gui-events",
        action="store_true",
        help="Emit __EVENT__ JSON lines for the web GUI's live phase tree.",
    )
    return parser.parse_args()


def non_negative_int(value):
    try:
        parsed_value = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error

    if parsed_value < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return parsed_value


def limit_not_reached(current_count, maximum):
    """Return true when a zero/unlimited or positive limit permits more work."""
    return maximum == 0 or current_count < maximum


def configure_target(target_url):
    """Validate and store the target used by all scope checks."""
    global URL, TARGET_HOSTNAME

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target URL must include http:// or https:// and a hostname")

    normalized_path = parsed.path.rstrip("/")
    URL = urlunparse((parsed.scheme, parsed.netloc, normalized_path, "", "", ""))
    TARGET_HOSTNAME = parsed.hostname.lower().rstrip(".")
    return URL


def is_in_scope(url):
    """Allow only HTTP(S) URLs on the exact configured hostname."""
    if not TARGET_HOSTNAME:
        return False

    parsed = urlparse(url)
    hostname = parsed.hostname.lower().rstrip(".") if parsed.hostname else None
    return parsed.scheme in {"http", "https"} and hostname == TARGET_HOSTNAME


def scoped_request(method, url, max_redirects=5, **kwargs):
    """Send a request while validating every redirect against the target scope."""
    current_url = url
    current_method = method.upper()
    request_kwargs = dict(kwargs)

    for _ in range(max_redirects + 1):
        if not is_in_scope(current_url):
            print(f"Blocked out-of-scope request: {current_url}")
            return None

        response = requests.request(
            current_method,
            current_url,
            allow_redirects=False,
            **request_kwargs,
        )

        if not response.is_redirect and not response.is_permanent_redirect:
            return response

        location = response.headers.get("Location")
        if not location:
            return response

        next_url = urljoin(current_url, location)
        if not is_in_scope(next_url):
            print(f"Blocked out-of-scope redirect: {current_url} -> {next_url}")
            return None

        if response.status_code == 303 or (
            response.status_code in {301, 302} and current_method == "POST"
        ):
            current_method = "GET"
            request_kwargs.pop("data", None)
            request_kwargs.pop("json", None)

        current_url = next_url

    print(f"Stopped after {max_redirects} redirects: {url}")
    return None


def safe_request(url, max_retries=3, delay=1):
    """Perform a scoped GET request with retry logic."""
    for attempt in range(max_retries):
        try:
            time.sleep(random.uniform(0.3, 0.7))
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            resp = scoped_request("GET", url, timeout=10, headers=headers)
            return resp
        except requests.RequestException as error:
            if attempt == max_retries - 1:
                print(
                    f"Request failed after {max_retries} attempts for "
                    f"{url}: {error}"
                )
                return None
            time.sleep(delay)
    return None

def decode_and_scan(content, patterns, url):
    """Sök efter base64-kodade secrets"""
    hits = []
    base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
    
    for match in re.finditer(base64_pattern, content):
        try:
            base64_str = match.group(0)
            if re.match(r'^[a-zA-Z\s]+$', base64_str):
                continue
                
            decoded = base64.b64decode(base64_str).decode('utf-8', errors='ignore')
            decoded_hits = scan_content_regex(f"{url}#BASE64", decoded, patterns, "BASE64")
            hits.extend(decoded_hits)
        except (ValueError, UnicodeError):
            continue
    
    return hits

def extract_js_variables(js_content, url, patterns):
    """Leta efter API-nycklar i JavaScript-variabler"""
    hits = []
    
    js_patterns = [
        r"(?:const|let|var)\s+\w+\s*=\s*['\"]([A-Za-z0-9\-_+/=]{15,})['\"]",
        r"(?:apiKey|api_key|token|secret|key)\s*[:=]\s*['\"]([^'\"]{10,})['\"]",
        r"['\"]authorization['\"]\s*:\s*['\"]([^'\"]{15,})['\"]",
        r"['\"]x-api-key['\"]\s*:\s*['\"]([^'\"]{15,})['\"]",
    ]
    
    for js_pattern in js_patterns:
        for match in re.finditer(js_pattern, js_content, re.IGNORECASE):
            if len(match.groups()) >= 1:
                value = match.group(1)
                for secret_pattern in patterns:
                    if re.match(secret_pattern, value):
                        hits.append({
                            "url": url,
                            "filetype": "JS_VARIABLE",
                            "pattern": f"JS_VAR + {secret_pattern}",
                            "snippet": match.group(0),
                            "match": value,
                            "start": match.start(),
                            "end": match.end()
                        })
    return hits

def scan_content_regex(url, content, patterns, filetype="HTML"):
    """Core scanning function"""
    hits = []
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            start = max(match.start()-40, 0)
            end = min(match.end()+40, len(content))
            snippet = content[start:end].replace('\n', '')
            
            hits.append({
                "url": url,
                "filetype": filetype,
                "pattern": pattern,
                "snippet": snippet,
                "match": match.group(0),
                "start": match.start(),
                "end": match.end()
            })
    return hits

def get_js_files(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    js_files = []
    for script in soup.find_all("script", src=True):
        js_url = urljoin(base_url, script["src"])
        if is_in_scope(js_url):
            js_files.append(js_url)
    return js_files


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a_tag in soup.find_all("a", href=True):
        full_url = urljoin(base_url, a_tag["href"])
        if is_in_scope(full_url):
            parsed = urlparse(full_url)
            links.add(urlunparse(parsed._replace(fragment="")))
    return links


def restrict_browser_request(route):
    """Block Playwright requests that leave the configured hostname."""
    request_url = route.request.url
    if request_url.startswith(("about:", "blob:", "data:")) or is_in_scope(request_url):
        route.continue_()
    else:
        route.abort()


def get_rendered_html(context, url):
    """Render a page using the Playwright context owned by the main scan."""
    page = None
    try:
        page = context.new_page()
        page.goto(url, wait_until="networkidle", timeout=30000)
        if not is_in_scope(page.url):
            print(f"Blocked out-of-scope browser navigation: {page.url}")
            return None
        return page.content()
    except PlaywrightError as error:
        print(f"Playwright rendering failed for {url}: {error}")
        return None
    finally:
        if page is not None:
            page.close()

def extract_input_values(html):
    """Extract values from input fields and data attributes"""
    soup = BeautifulSoup(html, "html.parser")
    values = []
    for input_tag in soup.find_all("input", value=True):
        values.append(input_tag["value"])
    
    for element in soup.find_all(attrs={"data-key": True}):
        values.append(element["data-key"])
    for element in soup.find_all(attrs={"data-token": True}):
        values.append(element["data-token"])
    
    return values

def classify_severity(pattern, match):
    """Klassificera allvarlighetsgrad"""
    high_risk = [
        'AKIA', 'sk_live_', 'ghp_', 'xox', 'discord_', 'PRIVATE KEY',
        'hooks.slack.com', 'discord.com/api/webhooks', 'webhook.office.com',
        'glpat-', 'glptt-', 'GR1348941', 'sk-proj-', 'sk-ant-', 'npm_',
        'hvs.', 'hvb.', 'hvr.', 'shpca_', 'shppa_', 'shpss_', 'sntrys_',
        'glc_', 'glsa_'
    ]
    medium_risk = [
        'AIza', 'sk_test_', 'Bearer', 'JWT',
        'ngrok.io', 'herokuapp.com', 'vercel.app', 'netlify.app',
        'webhook', 'callback', 'api.telegram.org'
    ]
    
    pattern_str = str(pattern).lower()
    match_str = str(match).lower()
    
    for risk in high_risk:
        if risk.lower() in pattern_str or risk.lower() in match_str:
            return 'HIGH'
    
    for risk in medium_risk:
        if risk.lower() in pattern_str or risk.lower() in match_str:
            return 'MEDIUM'
    
    return 'LOW'

def categorize_source(hit):
    """Categorize the source of a secret finding"""
    source_type = hit.get('data_type', hit.get('type', hit.get('filetype', '')))
    
    if 'REQUEST' in source_type or 'RESPONSE' in source_type:
        return 'NETWORK_TRAFFIC'
    elif 'WEBSOCKET' in source_type:
        return 'WEBSOCKET'
    elif 'JS' in source_type or 'JAVASCRIPT' in source_type:
        return 'JAVASCRIPT'
    elif 'CONFIG' in source_type or 'REPO' in source_type:
        return 'CONFIGURATION'
    elif 'HTML' in source_type:
        return 'WEB_CONTENT'
    else:
        return 'OTHER'

def analyze_browser_storage(page):
    """Analyze cookies and localStorage for secrets using Playwright"""
    findings = []
    
    try:
        cookies = page.context.cookies()
        for cookie in cookies:
            cookie_data = f"{cookie['name']}={cookie['value']}"
            cookie_hits = scan_content_regex(
                page.url, 
                cookie_data, 
                SECRET_PATTERNS, 
                "COOKIE"
            )
            findings.extend(cookie_hits)
        
        local_storage = page.evaluate("""
            () => {
                const storage = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            }
        """)
        
        for key, value in local_storage.items():
            storage_data = f"{key}={value}"
            storage_hits = scan_content_regex(
                page.url,
                storage_data,
                SECRET_PATTERNS,
                "LOCAL_STORAGE"
            )
            findings.extend(storage_hits)
            
    except (KeyError, TypeError, PlaywrightError) as error:
        print(f"Browser storage analysis failed: {error}")
    
    return findings

def trigger_and_analyze_errors(base_url):
    """Trigger error pages to look for debug information with secrets"""
    findings = []
    error_triggers = [
        f"{base_url}/nonexistent-page-12345",
        f"{base_url}/api/nonexistent",
        f"{base_url}/admin/test",
        f"{base_url}/debug/test", 
        f"{base_url}/test.php",
        f"{base_url}/app/test",
        f"{base_url}/?debug=1",
        f"{base_url}/?test=1&error=1",
        f"{base_url}/api/v1/invalid",
    ]
    
    methods = ['GET', 'POST', 'PUT']
    
    for url in error_triggers:
        for method in methods:
            try:
                resp = scoped_request(method, url, timeout=5)
                if resp is None:
                    continue
                if resp.status_code in [400, 401, 403, 404, 500, 501, 502, 503]:
                    debug_indicators = [
                        'stack trace', 'traceback', 'exception', 'debug', 
                        'error details', 'server error', 'application error',
                        'database', 'connection string', 'config'
                    ]
                    
                    response_lower = resp.text.lower()
                    if any(indicator in response_lower for indicator in debug_indicators):
                        error_hits = scan_content_regex(url, resp.text, SECRET_PATTERNS, f"ERROR_PAGE_{resp.status_code}")
                        if error_hits:
                            findings.extend(error_hits)
                            print(f"🚨 Secrets found in error page: {url} (Status: {resp.status_code})")
                            
            except requests.RequestException as error:
                print(f"Active error-page request failed for {url}: {error}")
                continue
    
    return findings

def scan_social_auth_endpoints(base_url):
    """Scan social authentication endpoints for exposed client secrets"""
    findings = []
    social_endpoints = [
        f"{base_url}/auth/google",
        f"{base_url}/auth/facebook", 
        f"{base_url}/auth/twitter",
        f"{base_url}/auth/github",
        f"{base_url}/auth/linkedin",
        f"{base_url}/oauth/google",
        f"{base_url}/oauth/facebook",
        f"{base_url}/api/auth/google",
        f"{base_url}/api/oauth/callback",
        f"{base_url}/login/oauth/authorize",
        f"{base_url}/.well-known/oauth-authorization-server",
    ]
    
    for endpoint in social_endpoints:
        resp = safe_request(endpoint)
        if resp:
            oauth_hits = scan_content_regex(endpoint, resp.text, SECRET_PATTERNS, "SOCIAL_AUTH")
            findings.extend(oauth_hits)
            
            if 'location' in resp.headers:
                redirect_hits = scan_content_regex(endpoint, resp.headers['location'], SECRET_PATTERNS, "OAUTH_REDIRECT")
                findings.extend(redirect_hits)
    
    return findings

def enhanced_webhook_scan(base_url):
    """Enhanced webhook detection"""
    webhook_hits = []
    webhook_endpoints = [
        f"{base_url}/webhooks",
        f"{base_url}/api/webhooks", 
        f"{base_url}/hooks",
        f"{base_url}/callback",
        f"{base_url}/notify",
        f"{base_url}/webhook",
        f"{base_url}/api/webhook",
        f"{base_url}/api/callback",
        f"{base_url}/integration/webhook",
        f"{base_url}/integrations/webhook",
        f"{base_url}/hook/callback",
        f"{base_url}/events/webhook",
        f"{base_url}/push/webhook",
        f"{base_url}/receive/webhook",
    ]
    
    for endpoint in webhook_endpoints:
        resp = safe_request(endpoint)
        if resp:
            webhook_hits.extend(scan_content_regex(endpoint, resp.text, SECRET_PATTERNS, "WEBHOOK_ENDPOINT"))
            
            for header_name, header_value in resp.headers.items():
                if 'webhook' in header_name.lower() or 'callback' in header_name.lower():
                    webhook_hits.extend(scan_content_regex(f"{endpoint}#HEADER_{header_name}", header_value, SECRET_PATTERNS, "WEBHOOK_HEADER"))
    
    return webhook_hits

def scan_api_documentation(base_url):
    """Scan API documentation endpoints for exposed secrets"""
    findings = []
    doc_endpoints = [
        f"{base_url}/swagger-ui.html",
        f"{base_url}/swagger/index.html",
        f"{base_url}/api-docs", 
        f"{base_url}/docs",
        f"{base_url}/api/docs",
        f"{base_url}/redoc",
        f"{base_url}/api/swagger.json",
        f"{base_url}/api/openapi.json",
        f"{base_url}/v1/swagger.json",
        f"{base_url}/v2/swagger.json",
        f"{base_url}/swagger.yaml",
        f"{base_url}/openapi.yaml"
    ]
    
    for endpoint in doc_endpoints:
        resp = safe_request(endpoint)
        if resp and resp.status_code == 200:
            doc_hits = scan_content_regex(endpoint, resp.text, SECRET_PATTERNS, "API_DOCUMENTATION")
            findings.extend(doc_hits)
            if doc_hits:
                print(f"🚨 Secrets found in API documentation: {endpoint}")
    
    return findings

def scan_graphql_introspection(base_url):
    """Scan GraphQL endpoints for introspection and secrets"""
    findings = []
    graphql_endpoints = [
        f"{base_url}/graphql",
        f"{base_url}/api/graphql", 
        f"{base_url}/v1/graphql",
        f"{base_url}/query"
    ]
    
    introspection_query = {
        "query": """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }
        """
    }
    
    for endpoint in graphql_endpoints:
        try:
            resp = scoped_request(
                "POST",
                endpoint,
                json=introspection_query,
                timeout=10,
            )
            if resp is None:
                continue
            if resp.status_code == 200:
                schema_hits = scan_content_regex(endpoint, resp.text, SECRET_PATTERNS, "GRAPHQL_SCHEMA")
                findings.extend(schema_hits)
                print(f"🔍 GraphQL introspection enabled: {endpoint}")
        except requests.RequestException as error:
            print(f"GraphQL request failed for {endpoint}: {error}")
            continue
    
    return findings

def scan_source_maps(base_url, js_files):
    """Scan JavaScript source maps for secrets"""
    findings = []
    
    for js_file in js_files:
        resp = safe_request(js_file)
        if not resp:
            continue
            
        sourcemap_patterns = [
            r'//# sourceMappingURL=([^\s]+)',
            r'//@ sourceMappingURL=([^\s]+)'
        ]
        
        for pattern in sourcemap_patterns:
            matches = re.findall(pattern, resp.text)
            for match in matches:
                sourcemap_url = urljoin(js_file, match)
                if not is_in_scope(sourcemap_url):
                    print(f"Skipped out-of-scope source map: {sourcemap_url}")
                    continue
                
                sm_resp = safe_request(sourcemap_url)
                if sm_resp:
                    try:
                        sourcemap_data = sm_resp.json()
                        if 'sourcesContent' in sourcemap_data:
                            for source_content in sourcemap_data['sourcesContent']:
                                if source_content:
                                    sm_hits = scan_content_regex(sourcemap_url, source_content, SECRET_PATTERNS, "SOURCE_MAP")
                                    findings.extend(sm_hits)
                    except ValueError:
                        sm_hits = scan_content_regex(sourcemap_url, sm_resp.text, SECRET_PATTERNS, "SOURCE_MAP")
                        findings.extend(sm_hits)
    
    return findings

def generate_security_recommendations(hits):
    """Generate security recommendations based on findings"""
    recommendations = []
    
    high_severity = [hit for hit in hits if hit.get('severity') == 'HIGH']
    if high_severity:
        recommendations.append({
            'priority': 'CRITICAL',
            'title': 'Immediate Action Required - High-Risk Secrets Exposed',
            'description': f'{len(high_severity)} high-risk secrets found that could lead to immediate compromise',
            'actions': [
                'Revoke all exposed API keys immediately',
                'Rotate all authentication tokens', 
                'Review access logs for potential abuse',
                'Implement proper secret management (HashiCorp Vault, AWS Secrets Manager)',
                'Remove hardcoded credentials from source code'
            ]
        })
    
    js_hits = [hit for hit in hits if 'JS' in hit.get('filetype', '')]
    if js_hits:
        recommendations.append({
            'priority': 'HIGH',
            'title': 'Client-Side Secret Exposure',
            'description': f'{len(js_hits)} secrets found in JavaScript code',
            'actions': [
                'Move all sensitive operations to backend',
                'Use environment variables for build-time secrets only',
                'Implement proper frontend/backend API authentication',
                'Use public API keys only (never private keys in frontend)',
                'Implement code obfuscation for additional protection'
            ]
        })
    
    recommendations.append({
        'priority': 'MEDIUM',
        'title': 'General Security Improvements',
        'description': 'Proactive measures to prevent future secret exposure',
        'actions': [
            'Implement automated secret scanning in CI/CD pipeline',
            'Use tools like git-secrets, detect-secrets, or TruffleHog',
            'Regular security audits and penetration testing',
            'Implement proper logging and monitoring for API access',
            'Create incident response plan for secret exposure',
            'Train developers on secure coding practices',
            'Use secret management solutions (Vault, AWS Secrets Manager, Azure Key Vault)',
            'Implement least privilege access principles'
        ]
    })
    
    return recommendations

def generate_ultimate_report(
    all_hits,
    unique_hits,
    start_time,
    pages_crawled,
    js_files_scanned,
    active_mode,
    max_pages,
    max_js_files,
):
    """Generate comprehensive hybrid report"""
    end_time = datetime.now()
    
    severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    source_breakdown = {}
    secret_types = {}
    
    for hit in all_hits:
        if 'severity' not in hit:
            hit['severity'] = classify_severity(hit.get('pattern', ''), hit.get('match', hit.get('secret', '')))
        
        severity_count[hit['severity']] += 1
        
        source = hit.get('type', hit.get('data_type', hit.get('filetype', 'UNKNOWN')))
        source_breakdown[source] = source_breakdown.get(source, 0) + 1
        
        secret = hit.get('match', hit.get('secret', ''))
        if 'key' in secret.lower():
            secret_types['API_KEYS'] = secret_types.get('API_KEYS', 0) + 1
        elif 'token' in secret.lower():
            secret_types['TOKENS'] = secret_types.get('TOKENS', 0) + 1
        elif 'secret' in secret.lower():
            secret_types['SECRETS'] = secret_types.get('SECRETS', 0) + 1
        else:
            secret_types['OTHER'] = secret_types.get('OTHER', 0) + 1
    
    techniques = [
        'TRADITIONAL_WEB_CRAWLING',
        'PLAYWRIGHT_JS_RENDERING',
        'BASE64_DECODING',
        'JS_VARIABLE_EXTRACTION',
        'INPUT_FIELD_SCANNING',
        'SOURCE_MAP_ANALYSIS',
        'BROWSER_STORAGE_ANALYSIS',
    ]
    if active_mode:
        techniques.extend([
            'ERROR_PAGE_ANALYSIS',
            'SOCIAL_AUTH_SCANNING',
            'ENHANCED_WEBHOOK_DETECTION',
            'API_DOCUMENTATION_SCANNING',
            'GRAPHQL_INTROSPECTION',
            'SPECIALIZED_ENDPOINT_SCANNING',
        ])

    report = {
        'scan_metadata': {
            'scan_version': '3.0_HYBRID_ULTIMATE',
            'scan_type': 'ACTIVE_SECRET_ANALYSIS' if active_mode else 'PASSIVE_SECRET_ANALYSIS',
            'target_url': URL,
            'active_mode': active_mode,
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration_minutes': round((end_time - start_time).total_seconds() / 60, 2),
            'pages_analyzed': pages_crawled,
            'javascript_files_analyzed': js_files_scanned,
            'configured_limits': {
                'max_pages': max_pages,
                'max_js_files': max_js_files,
                'zero_means_unlimited': True,
            },
            'techniques_employed': techniques,
        },
        'executive_summary': {
            'total_occurrences': len(all_hits),
            'unique_findings': len(unique_hits),
            'total_secrets_found': len(unique_hits),
            'critical_findings': severity_count['HIGH'],
            'risk_level': 'CRITICAL' if severity_count['HIGH'] > 0 else 'MEDIUM' if severity_count['MEDIUM'] > 0 else 'LOW',
            'immediate_actions_required': severity_count['HIGH'] > 0,
            'severity_distribution': severity_count,
            'source_distribution': source_breakdown,
            'secret_type_distribution': secret_types
        },
        'detailed_findings': all_hits,
        'unique_findings': unique_hits,
        'security_recommendations': generate_security_recommendations(unique_hits),
        'technical_details': {
            'patterns_used': len(SECRET_PATTERNS),
            'unique_sources_scanned': len(source_breakdown),
            'scan_coverage': 'ACTIVE' if active_mode else 'PASSIVE'
        }
    }
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    parsed_target = urlparse(URL)
    target_name_parts = [parsed_target.hostname or "unknown_target"]
    if parsed_target.port:
        target_name_parts.append(str(parsed_target.port))
    if parsed_target.path.strip("/"):
        target_name_parts.append(parsed_target.path.strip("/"))

    target_name = "_".join(target_name_parts)
    target_name = re.sub(r"[^A-Za-z0-9_-]+", "_", target_name).strip("_")

    report_directory = Path("reports") / "keyfinder"
    report_directory.mkdir(parents=True, exist_ok=True)
    report_path = (
        report_directory
        / f"HYBRID_secret_scan_report_{target_name}_{timestamp}.json"
    )

    with report_path.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"📋 Hybrid Ultimate report saved: {report_path}")
    return report


def run_active_scans(base_url):
    """Run probes that must be explicitly enabled by the operator."""
    findings = []

    def _emit_active_phase(phase_id, label, hits):
        emit_phase(phase_id, label)
        for hit in hits:
            emit_finding(phase_id, hit)

    print("❌ Active phase 1: Error Page Analysis")
    error_hits = trigger_and_analyze_errors(base_url)
    findings.extend(error_hits)
    _emit_active_phase("a_errors", "Error Pages", error_hits)
    print(f"   └─ Found {len(error_hits)} secrets in error pages")

    print("👥 Active phase 2: Social Authentication Endpoints")
    social_hits = scan_social_auth_endpoints(base_url)
    findings.extend(social_hits)
    _emit_active_phase("a_social", "Social Auth", social_hits)
    print(f"   └─ Found {len(social_hits)} secrets in social auth")

    print("🔗 Active phase 3: Enhanced Webhook Detection")
    webhook_hits = enhanced_webhook_scan(base_url)
    findings.extend(webhook_hits)
    _emit_active_phase("a_webhook", "Webhooks", webhook_hits)
    print(f"   └─ Found {len(webhook_hits)} webhook secrets")

    print("📚 Active phase 4: API Documentation")
    doc_hits = scan_api_documentation(base_url)
    findings.extend(doc_hits)
    _emit_active_phase("a_apidoc", "API Docs", doc_hits)
    print(f"   └─ Found {len(doc_hits)} secrets in API docs")

    print("🔍 Active phase 5: GraphQL Analysis")
    graphql_hits = scan_graphql_introspection(base_url)
    findings.extend(graphql_hits)
    _emit_active_phase("a_graphql", "GraphQL", graphql_hits)
    print(f"   └─ Found {len(graphql_hits)} secrets in GraphQL")

    print("🎯 Active phase 6: Specialized Endpoint Scanning")
    emit_phase("a_special", "Config Endpoints")
    specialized_endpoints = [
        f"{base_url}/.env",
        f"{base_url}/config.json",
        f"{base_url}/app.json",
        f"{base_url}/package.json",
        f"{base_url}/swagger.json",
        f"{base_url}/openapi.json",
        f"{base_url}/api/config",
        f"{base_url}/api/keys",
        f"{base_url}/admin/config",
        f"{base_url}/debug",
        f"{base_url}/health",
        f"{base_url}/status",
        f"{base_url}/info",
        f"{base_url}/.well-known/security.txt",
        f"{base_url}/robots.txt",
        f"{base_url}/sitemap.xml",
        f"{base_url}/.git/config",
        f"{base_url}/.git/HEAD",
        f"{base_url}/.gitignore",
        f"{base_url}/README.md",
        f"{base_url}/composer.json",
        f"{base_url}/requirements.txt",
    ]

    endpoint_hits_count = 0
    for endpoint in specialized_endpoints:
        resp = safe_request(endpoint)
        if resp is not None and resp.status_code == 200:
            endpoint_item_id = "special:" + endpoint
            emit_item(endpoint_item_id, "a_special", _short_url(endpoint))
            endpoint_hits = scan_content_regex(
                endpoint,
                resp.text,
                SECRET_PATTERNS,
                "CONFIG_FILE",
            )
            findings.extend(endpoint_hits)
            endpoint_hits_count += len(endpoint_hits)
            for hit in endpoint_hits:
                emit_finding(endpoint_item_id, hit)
            emit_item_done(endpoint_item_id, len(endpoint_hits))
            if endpoint_hits:
                print(f"✅ Secrets found in: {endpoint}")

    print(f"   └─ Found {endpoint_hits_count} secrets in specialized endpoints")

    if API_ENDPOINTS:
        print("🌐 Active phase 7: Custom API Endpoints")
        for api_url in API_ENDPOINTS:
            if not is_in_scope(api_url):
                print(f"Skipped out-of-scope custom API endpoint: {api_url}")
                continue
            api_resp = safe_request(api_url)
            if api_resp is not None:
                findings.extend(
                    scan_content_regex(
                        api_url,
                        api_resp.text,
                        SECRET_PATTERNS,
                        filetype="API",
                    )
                )

    return findings


def hybrid_ultimate_main(active_mode=False, max_pages=25, max_js_files=15):
    """THE ULTIMATE HYBRID SECRET SCANNER - Best of Both Worlds"""
    start_time = datetime.now()
    print("🚀 Starting HYBRID ULTIMATE Secret Scanner...")
    print(f"🎯 Target: {URL}")
    print(f"🔧 Mode: {'ACTIVE' if active_mode else 'PASSIVE'}")
    print(
        "📏 Limits: "
        f"pages={'unlimited' if max_pages == 0 else max_pages}, "
        f"JS files={'unlimited' if max_js_files == 0 else max_js_files}"
    )
    print("=" * 60)

    emit_gui_event("root", label=URL)

    all_hits = []
    js_files_found = []

    print("🕷️ Passive phase 1: Scoped Web Crawling")
    emit_phase("p_crawl", "Web Crawling")

    url_queue = deque([URL])
    visited_pages = set()
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        context.route("**/*", restrict_browser_request)
        
        while url_queue and limit_not_reached(len(visited_pages), max_pages):
            url = url_queue.popleft()
            if url in visited_pages or not is_in_scope(url):
                continue
            visited_pages.add(url)

            print(f"   🔍 Crawling: {url}")
            crawl_item_id = "crawl:" + url
            emit_item(crawl_item_id, "p_crawl", _short_url(url))
            crawl_hits_start = len(all_hits)

            # Standard HTTP request
            resp = safe_request(url)
            if resp is not None:
                content = resp.text
                
                # TRADITIONAL SCANNING (from Original)
                hits = scan_content_regex(url, content, SECRET_PATTERNS, filetype="HTML")
                all_hits.extend(hits)
                
                # INPUT FIELD SCANNING (from Original)
                input_hits = []
                input_values = extract_input_values(content)
                for val in input_values:
                    input_hits.extend(
                        scan_content_regex(
                            url,
                            val,
                            SECRET_PATTERNS,
                            filetype="InputField",
                        )
                    )
                all_hits.extend(input_hits)

                # BASE64 SCANNING (from Original)
                base64_hits = decode_and_scan(content, SECRET_PATTERNS, url)
                all_hits.extend(base64_hits)
                
                # PLAYWRIGHT BACKUP IF NO HITS (from Original)
                if not hits and not input_hits and not base64_hits:
                    print(f"   └─ No secrets in static content, trying Playwright rendering...")
                    rendered_html = get_rendered_html(context, url)
                    if rendered_html:
                        rendered_hits = scan_content_regex(url, rendered_html, SECRET_PATTERNS, filetype="HTML_RENDERED")
                        all_hits.extend(rendered_hits)
                        
                        # Re-scan input fields on rendered content
                        rendered_input_values = extract_input_values(rendered_html)
                        for val in rendered_input_values:
                            rendered_input_hits = scan_content_regex(url, val, SECRET_PATTERNS, filetype="InputField_RENDERED")
                            all_hits.extend(rendered_input_hits)
                        
                        # Re-scan base64 on rendered content
                        rendered_base64_hits = decode_and_scan(rendered_html, SECRET_PATTERNS, url)
                        all_hits.extend(rendered_base64_hits)
                
                # Get JS files for later analysis
                page_js_files = get_js_files(content, url)
                js_files_found.extend(page_js_files)
                
                # Extract new links
                new_links = extract_links(content, resp.url)
                print(f"   └─ Found {len(new_links)} links on {url}")
                
                for link in sorted(new_links):
                    if link not in visited_pages:
                        url_queue.append(link)
            
            # BROWSER STORAGE ANALYSIS (from Ultimate)
            try:
                page = context.new_page()
                page.goto(url, wait_until='networkidle', timeout=30000)
                if is_in_scope(page.url):
                    storage_hits = analyze_browser_storage(page)
                    all_hits.extend(storage_hits)
                else:
                    print(f"Blocked out-of-scope browser navigation: {page.url}")
                page.close()
            except PlaywrightError as error:
                print(f"   └─ ⚠️ Browser analysis failed for {url}: {error}")

            for hit in all_hits[crawl_hits_start:]:
                emit_finding(crawl_item_id, hit)
            emit_item_done(crawl_item_id, len(all_hits) - crawl_hits_start)

        browser.close()
    
    print(f"   └─ Crawled {len(visited_pages)} pages")
    
    print("⚡ Passive phase 2: JavaScript Analysis")
    emit_phase("p_js", "JavaScript Analysis")
    js_secret_count = 0
    unique_js_files = list(dict.fromkeys(js_files_found))
    selected_js_files = (
        unique_js_files
        if max_js_files == 0
        else unique_js_files[:max_js_files]
    )
    processed_js_files = []

    for js_url in tqdm(selected_js_files, desc="Analyzing JS files"):

        js_item_id = "js:" + js_url
        emit_item(js_item_id, "p_js", _short_url(js_url))
        js_resp = safe_request(js_url)
        if js_resp is not None:
            # STANDARD JS SCANNING
            js_hits = scan_content_regex(js_url, js_resp.text, SECRET_PATTERNS, filetype="JS")
            all_hits.extend(js_hits)

            # JAVASCRIPT VARIABLE EXTRACTION (from Original)
            js_var_hits = extract_js_variables(js_resp.text, js_url, SECRET_PATTERNS)
            all_hits.extend(js_var_hits)

            # BASE64 SCANNING IN JS (from Original)
            js_base64_hits = decode_and_scan(js_resp.text, SECRET_PATTERNS, js_url)
            all_hits.extend(js_base64_hits)

            js_secret_count += len(js_hits) + len(js_var_hits) + len(js_base64_hits)
            processed_js_files.append(js_url)

            js_file_hits = js_hits + js_var_hits + js_base64_hits
            for hit in js_file_hits:
                emit_finding(js_item_id, hit)
            emit_item_done(js_item_id, len(js_file_hits))
        else:
            emit_item_done(js_item_id, 0)

    print(
        f"   └─ Analyzed {len(processed_js_files)} JS files, "
        f"found {js_secret_count} secrets"
    )

    print("🗺️ Passive phase 3: Source Map Analysis")
    emit_phase("p_sourcemap", "Source Maps")
    sourcemap_hits = scan_source_maps(URL, processed_js_files)
    all_hits.extend(sourcemap_hits)
    for hit in sourcemap_hits:
        emit_finding("p_sourcemap", hit)
    print(f"   └─ Found {len(sourcemap_hits)} secrets in source maps")

    if active_mode:
        print("\n" + "=" * 60)
        print("ACTIVE PROBING ENABLED")
        print("=" * 60)
        all_hits.extend(run_active_scans(URL))
    
    # FINAL REPORT GENERATION
    print("\n" + "=" * 60)
    print("📊 HYBRID SCAN COMPLETE - Generating Report")
    print("=" * 60)
    
    if all_hits:
        # Remove duplicates
        unique_hits = []
        seen = set()
        for hit in all_hits:
            hit_signature = (hit.get('match', hit.get('secret', '')), hit.get('url', ''))
            if hit_signature not in seen:
                seen.add(hit_signature)
                unique_hits.append(hit)
        
        print(f"🎯 Total findings: {len(all_hits)} ({len(unique_hits)} unique)")
        
        # Generate comprehensive report
        report = generate_ultimate_report(
            all_hits,
            unique_hits,
            start_time,
            len(visited_pages),
            len(processed_js_files),
            active_mode,
            max_pages,
            max_js_files,
        )
        
        # DETAILED OUTPUT (from Original)
        print("\n--- 🔑 HYBRID SCAN RESULTS ---\n")
        
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_hits = sorted(unique_hits, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 2))
        
        unique_keys = set()
        for hit in sorted_hits:
            severity_emoji = {'HIGH': '🚨', 'MEDIUM': '⚠️', 'LOW': '💡'}.get(hit.get('severity', 'LOW'), '💡')
            
            print(f"{severity_emoji} [{hit.get('severity', 'LOW')}] Source: {hit['filetype']} | URL: {hit['url']}")
            print(f"Pattern: {hit['pattern']}")
            print(f"Match (pos {hit['start']}–{hit['end']}): {hit['match']}")
            print(f"Context: ...{hit['snippet']}...\n")
            unique_keys.add((hit['filetype'], hit['url'], hit['match']))
        
        print("🔑 Summary - Potential secrets found:")
        for filetype, url, match_str in unique_keys:
            masked = match_str[:8] + "*" * (len(match_str) - 12) + match_str[-4:] if len(match_str) > 12 else match_str[:4] + "*" * (len(match_str) - 4)
            print(f"{filetype} | {url} | {masked}")
        
        # Print summary by severity
        severity_summary = {}
        for hit in unique_hits:
            severity = hit.get('severity', 'LOW')
            severity_summary[severity] = severity_summary.get(severity, 0) + 1
        
        print(f"\n📊 Final Statistics:")
        print(f"🚨 Critical: {severity_summary.get('HIGH', 0)}")
        print(f"⚠️ Medium: {severity_summary.get('MEDIUM', 0)}")
        print(f"💡 Low: {severity_summary.get('LOW', 0)}")
        print(f"🌐 Total pages crawled: {len(visited_pages)}")
        print(f"📜 Total occurrences: {len(all_hits)}")
        print(f"🔑 Total unique secrets: {len(unique_keys)}")

        emit_gui_event("done", findings=len(all_hits), unique=len(unique_keys))
        return all_hits
    else:
        print("✅ No secrets found - this is good!")
        emit_gui_event("done", findings=0, unique=0)
        # Generate report even when no secrets are found
        generate_ultimate_report(
            [],
            [],
            start_time,
            len(visited_pages),
            len(processed_js_files),
            active_mode,
            max_pages,
            max_js_files,
        )
        return []

# Run the hybrid ultimate scanner
if __name__ == "__main__":
    args = parse_arguments()
    GUI_EVENTS_ENABLED = bool(args.gui_events)
    try:
        configure_target(args.url)
    except ValueError as error:
        raise SystemExit(f"Invalid target: {error}") from error
    hybrid_ultimate_main(
        active_mode=args.active,
        max_pages=args.max_pages,
        max_js_files=args.max_js_files,
    )
