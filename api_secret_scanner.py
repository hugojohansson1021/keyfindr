import argparse
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

# Importera patterns från separat fil
from secret_patterns import SECRET_PATTERNS


API_ENDPOINTS = [
    # Lägg till fler här om du vill!
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
            
            # Lista för att spara alla network requests
            network_requests = []
            
            # Fånga ALLA HTTP-requests (XHR, Fetch, etc)
            def handle_request(request):
                network_requests.append({
                    'url': request.url,
                    'method': request.method,
                    'headers': request.headers,
                    'post_data': request.post_data
                })
            
            def handle_response(response):
                try:
                    network_requests.append({
                        'url': response.url,
                        'status': response.status,
                        'headers': response.headers,
                        'response_body': response.text() if response.status == 200 else None
                    })
                except:
                    pass
            
            page.on('request', handle_request)
            page.on('response', handle_response)
            
            # Ladda sidan
            page.goto(url, wait_until="networkidle", timeout=30000)
            time.sleep(2)  # Vänta på lazy-loading
            
            # Interagera med sidan för att trigga fler requests
            interact_with_page(page)
            
            html = page.content()
            browser.close()
            
            return html, network_requests
    except Exception as e:
        print(f"Playwright-rendering misslyckades för {url}: {e}")
        return None, []

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

def interact_with_page(page):
    """Interagera med sidan för att trigga dynamiska API-anrop"""
    print("  🤖 Interagerar med sidan...")
    
    try:
        # 1. SCROLLA nedåt för lazy-loading
        print("  📜 Scrollar för lazy-loading...")
        for _ in range(3):
            page.evaluate("window.scrollBy(0, window.innerHeight)")
            time.sleep(1)
        
        # Scrolla tillbaka upp
        page.evaluate("window.scrollTo(0, 0)")
        time.sleep(1)
        
        # 2. KLICKA på vanliga knappar (Sök, Visa mer, Ladda mer, etc)
        button_selectors = [
            'button[type="submit"]',
            'button:has-text("Search")',
            'button:has-text("Sök")',
            'button:has-text("Load more")',
            'button:has-text("Ladda mer")',
            'button:has-text("Show more")',
            'button:has-text("Visa mer")',
            'input[type="submit"]',
            '.search-button',
            '#search-button',
            '.load-more',
            '.show-more'
        ]
        
        for selector in button_selectors:
            try:
                buttons = page.query_selector_all(selector)
                for button in buttons[:3]:  # Max 3 knappar per typ
                    if button.is_visible():
                        print(f"  🖱️  Klickar på: {selector}")
                        button.click()
                        time.sleep(2)
                        break
            except:
                pass
        
        # 3. FYLL I och SKICKA sökformulär
        print("  🔍 Testar sökformulär...")
        search_inputs = [
            'input[type="search"]',
            'input[name="search"]',
            'input[name="q"]',
            'input[placeholder*="Search"]',
            'input[placeholder*="Sök"]',
            '.search-input',
            '#search-input',
            '#search'
        ]
        
        for selector in search_inputs:
            try:
                search_input = page.query_selector(selector)
                if search_input and search_input.is_visible():
                    print(f"  ⌨️  Fyller i sökfält: {selector}")
                    search_input.fill("test")
                    time.sleep(1)
                    
                    # Tryck Enter eller hitta submit-knapp
                    search_input.press("Enter")
                    time.sleep(3)
                    break
            except:
                pass
        
        # 4. KLICKA på tabs/flikar
        print("  🗂️  Testar tabs/flikar...")
        tab_selectors = [
            '[role="tab"]',
            '.tab',
            '.nav-tab',
            'button.tab-button'
        ]
        
        for selector in tab_selectors:
            try:
                tabs = page.query_selector_all(selector)
                for tab in tabs[:3]:  # Max 3 tabs
                    if tab.is_visible():
                        tab.click()
                        time.sleep(1)
            except:
                pass
        
        # 5. ÖPPNA dropdowns/select
        print("  📋 Testar dropdowns...")
        try:
            selects = page.query_selector_all('select')
            for select in selects[:3]:
                if select.is_visible():
                    options = select.query_selector_all('option')
                    if len(options) > 1:
                        select.select_option(index=1)
                        time.sleep(1)
        except:
            pass
        
        # 6. KLICKA på modaler/popups (stäng och öppna)
        modal_triggers = [
            'button:has-text("Login")',
            'button:has-text("Sign in")',
            'button:has-text("Logga in")',
            '.modal-trigger',
            '.popup-trigger'
        ]
        
        for selector in modal_triggers:
            try:
                trigger = page.query_selector(selector)
                if trigger and trigger.is_visible():
                    print(f"  🔓 Klickar på modal: {selector}")
                    trigger.click()
                    time.sleep(2)
                    
                    # Stäng modal
                    close_btn = page.query_selector('[aria-label="Close"], .close, .modal-close')
                    if close_btn:
                        close_btn.click()
                        time.sleep(1)
                    break
            except:
                pass
        
        # 7. HOVER över element (kan trigga lazy-loading)
        print("  👆 Testar hover-interaktioner...")
        try:
            hoverable = page.query_selector_all('a, button, [data-tooltip]')
            for element in hoverable[:5]:
                if element.is_visible():
                    element.hover()
                    time.sleep(0.5)
        except:
            pass
        
        print("  ✅ Interaktion klar!")
        
    except Exception as e:
        print(f"  ⚠️  Fel vid interaktion: {e}")

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

def scan_network_requests(network_requests, patterns, base_url):
    """Skanna alla nätverksförfrågningar efter API-nycklar"""
    print("🌐 Skannar network requests...")
    hits = []
    
    for req in network_requests:
        try:
            # Skanna URL
            if 'url' in req:
                url_hits = scan_content_regex(
                    f"{base_url}#NETWORK",
                    str(req['url']),
                    patterns,
                    filetype="NETWORK_URL"
                )
                hits.extend(url_hits)
            
            # Skanna headers
            if 'headers' in req:
                headers_str = json.dumps(req['headers'])
                header_hits = scan_content_regex(
                    f"{base_url}#NETWORK",
                    headers_str,
                    patterns,
                    filetype="NETWORK_HEADERS"
                )
                hits.extend(header_hits)
            
            # Skanna POST data
            if 'post_data' in req and req['post_data']:
                post_hits = scan_content_regex(
                    f"{base_url}#NETWORK",
                    str(req['post_data']),
                    patterns,
                    filetype="NETWORK_POST"
                )
                hits.extend(post_hits)
            
            # Skanna response body
            if 'response_body' in req and req['response_body']:
                response_hits = scan_content_regex(
                    f"{base_url}#NETWORK",
                    str(req['response_body']),
                    patterns,
                    filetype="NETWORK_RESPONSE"
                )
                hits.extend(response_hits)
                
        except Exception as e:
            continue
    
    print(f"  ✅ Hittade {len(hits)} potentiella nycklar i network traffic!")
    return hits

def generate_report(hits, start_time, total_pages_crawled, target_url):
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
            'target_url': target_url,
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
    
    # Skapa ett säkert filnamn från URL:en
    # Ta bort protokoll och specialtecken
    safe_url = re.sub(r'https?://', '', target_url)
    safe_url = re.sub(r'[^\w\-.]', '_', safe_url)
    safe_url = safe_url.strip('_')
    
    # Spara rapporten med URL och datum
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'secret_scan_{safe_url}_{timestamp}.json'
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n📊 Detaljerad rapport sparad som: {filename}")
    return report

def parse_args():
    parser = argparse.ArgumentParser(
        description="Crawl a target and scan for exposed secrets (Playwright-based)."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Authorized target URL, e.g. https://example.com",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target_url = args.url
    start_time = datetime.now()
    print("🚀 Startar API Secret Scanner...")
    print(f"🎯 Målwebbplats: {target_url}")
    print("🔍 Ny funktion: Dynamisk interaktion + Network monitoring aktiverad!\n")

    start_url = target_url
    url_queue = deque([start_url])
    visited_urls = set()
    all_hits = []
    all_network_requests = []

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

        # ALLTID använd Playwright för dynamisk interaktion och network monitoring
        print("🎭 Startar Playwright för dynamisk scanning...")
        rendered_result = get_rendered_html(url)
        
        if rendered_result and rendered_result[0]:  # Kolla om vi fick HTML tillbaka
            rendered_html, network_requests = rendered_result
            
            # Spara network requests för senare analys
            all_network_requests.extend(network_requests)
            
            # Skanna renderat HTML
            rendered_hits = scan_content_regex(url, rendered_html, SECRET_PATTERNS, filetype="HTML (Rendered)")
            hits.extend(rendered_hits)
            
            # Skanna input-värden i renderat HTML
            input_values = extract_input_values(rendered_html)
            for val in input_values:
                hits.extend(scan_content_regex(url, val, SECRET_PATTERNS, filetype="InputField (Rendered)"))
            
            # Base64-scanning på renderat innehåll
            base64_hits = decode_and_scan(rendered_html, SECRET_PATTERNS, url)
            hits.extend(base64_hits)
            
            # Skanna alla network requests
            network_hits = scan_network_requests(network_requests, SECRET_PATTERNS, url)
            hits.extend(network_hits)

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
        report = generate_report(all_hits, start_time, len(visited_urls), target_url)
        
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
        print(f"🔗 Totalt network requests: {len(all_network_requests)}")
        print(f"🔑 Totalt unika nycklar: {len(unique_keys)}")
        
    else:
        print("✅ Inga API-nycklar eller secrets hittade.")

if __name__ == "__main__":
    main()
