import requests
from bs4 import BeautifulSoup
import re
from tqdm import tqdm
from collections import deque
from playwright.sync_api import sync_playwright
import base64
import time
import random
import json
from datetime import datetime

URL = "https://www.cronsoc.com/"


API_ENDPOINTS = [
    # Lägg till fler här om du vill!
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
    
    # Generic webhook patterns (brett men användbart)
    r"https?://[a-zA-Z0-9\-_.]+/webhook[a-zA-Z0-9\-_/]*", # Generic webhook URLs
    r"https?://[a-zA-Z0-9\-_.]+/api/webhook[a-zA-Z0-9\-_/]*", # API webhook endpoints
    r"https?://[a-zA-Z0-9\-_.]+/hook[a-zA-Z0-9\-_/]*", # Generic hook URLs
    # Misc Services
    r"XJ[a-zA-Z0-9]{36}",                 # Generic UUID-like API key
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", # UUID format
    r"R_[0-9a-f]{32}",                    # Shopify private app token
    r"shpat_[a-fA-F0-9]{32}",             # Shopify access token
]


def safe_request(url, max_retries=3, delay=1):
    """Säker HTTP-förfrågan med retry-logik"""
    for attempt in range(max_retries):
        try:
            # Lägg till en liten delay och bättre headers
            time.sleep(random.uniform(0.3, 0.7))
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            resp = requests.get(url, timeout=10, headers=headers)
            return resp
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Misslyckades efter {max_retries} försök för {url}: {e}")
                return None
            time.sleep(delay)
    return None

def decode_and_scan(content, patterns, url):
    """Sök efter base64-kodade secrets"""
    hits = []
    # Leta efter base64-kodade strängar
    base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
    
    for match in re.finditer(base64_pattern, content):
        try:
            base64_str = match.group(0)
            # Skippa om det ser ut som vanlig text
            if re.match(r'^[a-zA-Z\s]+$', base64_str):
                continue
                
            decoded = base64.b64decode(base64_str).decode('utf-8', errors='ignore')
            # Skanna det avkodade innehållet
            decoded_hits = scan_content_regex(f"{url}#BASE64", decoded, patterns, "BASE64")
            hits.extend(decoded_hits)
        except:
            continue
    
    return hits

def extract_js_variables(js_content, url, patterns):
    """Leta efter API-nycklar i JavaScript-variabler"""
    hits = []
    
    # Patterns för JavaScript-variabler
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
                # Testa om värdet matchar någon av våra secret patterns
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
    """Originalfunktionen - INGEN validering som kan blockera"""
    hits = []
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            start = max(match.start()-40, 0)
            end = min(match.end()+40, len(content))
            snippet = content[start:end].replace('\n', '')
            
            # Hitta hela raden där matchen sker
            match_start = match.start()
            match_end = match.end()
            line_start = content.rfind('\n', 0, match_start)
            if line_start == -1:
                line_start = 0
            else:
                line_start += 1
            line_end = content.find('\n', match_end)
            if line_end == -1:
                line_end = len(content)
            line = content[line_start:line_end]
            
            # Spara ALLT - ingen filtrering! (utan line-parameter)
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
        src = script['src']
        if src.startswith("http"):
            js_files.append(src)
        else:
            js_files.append(requests.compat.urljoin(base_url, src))
    return js_files

def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if href.startswith("http"):
            full_url = href
        else:
            full_url = requests.compat.urljoin(base_url, href)
        if full_url.startswith(base_url):
            links.add(full_url.split("#")[0])
    return links

def get_rendered_html(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            html = page.content()
            browser.close()
            return html
    except Exception as e:
        print(f"Playwright-rendering misslyckades för {url}: {e}")
        return None

def extract_input_values(html):
    soup = BeautifulSoup(html, "html.parser")
    values = []
    for input_tag in soup.find_all("input", value=True):
        values.append(input_tag["value"])
    
    # Lägg till även data-attribut
    for element in soup.find_all(attrs={"data-key": True}):
        values.append(element["data-key"])
    for element in soup.find_all(attrs={"data-token": True}):
        values.append(element["data-token"])
    
    return values

def classify_severity(pattern, match):
    """Klassificera allvarlighetsgrad"""
    high_risk = [
        'AKIA', 'sk_live_', 'ghp_', 'xox', 'discord_', 'PRIVATE KEY',
        'hooks.slack.com', 'discord.com/api/webhooks', 'webhook.office.com'  # Kritiska webhooks
    ]
    medium_risk = [
        'AIza', 'sk_test_', 'Bearer', 'JWT',
        'ngrok.io', 'herokuapp.com', 'vercel.app', 'netlify.app',  # Dev/staging webhooks
        'webhook', 'callback', 'api.telegram.org'  # Generella webhooks
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

def generate_report(hits, start_time, total_pages_crawled):
    """Generera JSON-rapport"""
    end_time = datetime.now()
    
    # Lägg till severity till alla hits
    for hit in hits:
        hit['severity'] = classify_severity(hit['pattern'], hit['match'])
    
    unique_keys = set(hit['match'] for hit in hits)
    severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for hit in hits:
        severity_count[hit['severity']] += 1
    
    report = {
        'scan_info': {
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': (end_time - start_time).total_seconds(),
            'total_pages_crawled': total_pages_crawled,
            'total_hits': len(hits),
            'unique_keys': len(unique_keys),
            'severity_breakdown': severity_count
        },
        'findings': hits
    }
    
    # Spara rapporten
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'secret_scan_report_{timestamp}.json'
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n📊 Detaljerad rapport sparad som: {filename}")
    return report

def main():
    start_time = datetime.now()
    print("🚀 Startar API Secret Scanner...")
    print(f"🎯 Målwebbplats: {URL}")
    
    start_url = URL
    url_queue = deque([start_url])
    visited_urls = set()
    all_hits = []

    while url_queue:
        url = url_queue.popleft()
        if url in visited_urls:
            continue
        visited_urls.add(url)

        print(f"Hämtar: {url}")
        resp = safe_request(url)
        if not resp:
            continue

        content = resp.text
        print("Svar mottaget!")

        print("Söker efter kända API-nycklar/secrets i HTML...")
        hits = scan_content_regex(url, content, SECRET_PATTERNS, filetype="HTML")
        
        # Skanna input-värden
        input_values = extract_input_values(content)
        for val in input_values:
            hits.extend(scan_content_regex(url, val, SECRET_PATTERNS, filetype="InputField"))

        # Base64-scanning
        base64_hits = decode_and_scan(content, SECRET_PATTERNS, url)
        hits.extend(base64_hits)

        # Om inga hits, försök med Playwright
        if not hits:
            print("Försöker med Playwright för att få renderat HTML...")
            rendered_html = get_rendered_html(url)
            if rendered_html:
                hits = scan_content_regex(url, rendered_html, SECRET_PATTERNS, filetype="HTML (Rendered)")
                input_values = extract_input_values(rendered_html)
                for val in input_values:
                    hits.extend(scan_content_regex(url, val, SECRET_PATTERNS, filetype="InputField (Rendered)"))
                
                # Base64-scanning på renderat innehåll
                base64_hits = decode_and_scan(rendered_html, SECRET_PATTERNS, url)
                hits.extend(base64_hits)

        all_hits.extend(hits)

        # Extrahera nya länkar
        new_links = extract_links(content, start_url)
        for link in new_links:
            if link not in visited_urls:
                url_queue.append(link)

        # Skanna JavaScript-filer
        js_files = get_js_files(content, url)
        for js_url in tqdm(js_files, desc="Scanning JS-filer"):
            if js_url in visited_urls:
                continue
            
            print(f"Hämtar JS: {js_url}")
            js_resp = safe_request(js_url)
            if js_resp:
                # Vanlig regex-scanning
                js_hits = scan_content_regex(js_url, js_resp.text, SECRET_PATTERNS, filetype="JS")
                all_hits.extend(js_hits)
                
                # JavaScript-variabel-scanning
                js_var_hits = extract_js_variables(js_resp.text, js_url, SECRET_PATTERNS)
                all_hits.extend(js_var_hits)
                
                # Base64-scanning i JS
                base64_hits = decode_and_scan(js_resp.text, SECRET_PATTERNS, js_url)
                all_hits.extend(base64_hits)
                
                visited_urls.add(js_url)

    # Skanna API-endpoints
    for api_url in API_ENDPOINTS:
        print(f"Hämtar API-endpoint: {api_url}")
        api_resp = safe_request(api_url)
        if api_resp:
            api_hits = scan_content_regex(api_url, api_resp.text, SECRET_PATTERNS, filetype="API")
            all_hits.extend(api_hits)

    # Generera rapport
    if all_hits:
        report = generate_report(all_hits, start_time, len(visited_urls))
        
        print("\n--- Möjliga API-nycklar och secrets hittade! ---\n")
        
        # Sortera efter allvarlighetsgrad
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_hits = sorted(all_hits, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 2))
        
        unique_keys = set()
        for hit in sorted_hits:
            severity_emoji = {'HIGH': '🚨', 'MEDIUM': '⚠️', 'LOW': '💡'}.get(hit.get('severity', 'LOW'), '💡')
            
            print(f"{severity_emoji} [{hit.get('severity', 'LOW')}] Filtyp: {hit['filetype']} | URL: {hit['url']}")
            print(f"Regex: {hit['pattern']}")
            print(f"Träff (pos {hit['start']}–{hit['end']}): {hit['match']}")
            print(f"Kontext: ...{hit['snippet']}...\n")
            unique_keys.add((hit['filetype'], hit['url'], hit['match']))
        
        print("🔑 Sammanfattning - Potentiella nycklar/secrets funna:")
        for filetype, url, match_str in unique_keys:
            # Maskera nyckeln för säkerhets skull
            masked = match_str[:8] + "*" * (len(match_str) - 12) + match_str[-4:] if len(match_str) > 12 else match_str[:4] + "*" * (len(match_str) - 4)
            print(f"{filetype} | {url} | {masked}")
        
        # Statistik
        severity_count = report['scan_info']['severity_breakdown']
        print(f"\n📊 Statistik:")
        print(f"🚨 Högrisk: {severity_count['HIGH']}")
        print(f"⚠️  Mediumrisk: {severity_count['MEDIUM']}")
        print(f"💡 Lågrisk: {severity_count['LOW']}")
        print(f"🌐 Totalt sidor crawlade: {report['scan_info']['total_pages_crawled']}")
        print(f"🔑 Totalt unika nycklar: {len(unique_keys)}")
        
    else:
        print("✅ Inga API-nycklar eller secrets hittade.")

if __name__ == "__main__":
    main()
