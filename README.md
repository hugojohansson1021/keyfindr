# KeyFindr - Cyber Security Testing Tools for webbapps

![KeyFindr](public/Sk%C3%A4rmavbild%202026-06-16%20kl.%2018.06.41.png)

Python tools for authorized web security testing. The project contains utilities for discovering hidden paths, crawling public web assets, and finding accidentally exposed API keys, tokens, webhooks, credentials, and similar secrets.

A local web GUI ties the scripts together so you can run everything from the browser and watch the output live in a built-in terminal.

Use these scripts only against systems you own or have explicit permission to test.

## Quick start

Four steps from clone to running app:

```bash
git clone <repo-url> keyfindr
cd keyfindr
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py

```

Then open `http://127.0.0.1:5000` in your browser.

> The Playwright-based scanners (`keyFinder.py`, `api_secret_scanner.py`)
> need a browser binary the first time they run. The GUI offers a
> one-click `playwright install chromium` action when needed, so it is
> not part of the base setup.

Deactivate the environment when done:

```bash
deactivate
```


## Snabbkommandon

### Hitta subdomäner

Komplett standardsökning via TLS-certifikat, webbcrawling och publika
Certificate Transparency-loggar från `crt.sh`:

```bash
python subdomain_spider.py --domain https://emaxmedia.se/
```

Sök även med den inbyggda DNS-ordlistan:

```bash
python subdomain_spider.py --domain example.com --bruteforce
```

Sök med en egen ordlista:

```bash
python subdomain_spider.py \
  --domain example.com \
  --bruteforce \
  --wordlist subdomains.txt
```


### Hitta dolda sidor

```bash
python find_hidden_pages.py \
  --url https://example.com \
  --wordlist common.txt
```


### Skanna efter exponerade hemligheter

Passiv skanning:

```bash
python keyFinder.py --url 

```

Aktiv skanning:

```bash
python keyFinder.py --url https://example.com --active
```

## Verktyg

### Subdomain Spider: `subdomain_spider.py`

Discovers subdomains connected to a main domain. Certificate Transparency
lookup through `crt.sh` is enabled by default.

Default methods:

- Reads DNS names from TLS certificate SAN fields on the main domain, `www`,
  and newly discovered hosts.
- Crawls same-domain HTML, JavaScript, JSON, XML, links, and redirects for
  referenced hostnames.
- Collects `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`, and `SOA` records
  with TTL values.
- Builds CNAME chains and checks whether their final targets still resolve.
- Performs PTR/reverse-DNS lookups for every resolved IP address.
- Queries public Certificate Transparency logs through `crt.sh` and records
  certificate issuer, validity dates, and certificate ID.
- Collects HTTP status, title, redirects, response time, server headers,
  content type, and common security headers.
- Collects TLS protocol, cipher, issuer, SAN names, verification status,
  self-signed status, expiry date, and remaining days.
- Classifies risk indicators such as dangling CNAME records, possible
  subdomain takeover, expired TLS, HTTP-only services, exposed staging/admin
  environments, and missing security headers.
- Uses RDAP for the main domain and unique public IP networks.
- Blocks redirects that leave the requested main domain.

#### Kommandon

```bash
python subdomain_spider.py --domain example.com
```

```bash
python subdomain_spider.py --domain example.com --no-crt-sh
```

Disable RDAP:

```bash
python subdomain_spider.py --domain example.com --no-rdap
```

Disable HTTP inspection:

```bash
python subdomain_spider.py --domain example.com --no-http-probe
```

```bash
python subdomain_spider.py --domain example.com --bruteforce
```

```bash
python subdomain_spider.py \
  --domain example.com \
  --bruteforce \
  --wordlist subdomains.txt
```

The DNS method tests random names first and filters candidates that exactly
match detected wildcard-DNS answers. Use `--include-wildcard-matches` only when
you want those uncertain results included.

The standard command uses the external public service `crt.sh`. It only finds
names that have appeared in public TLS certificates. Disable it with
`--no-crt-sh`. Limit the number of imported names with `--max-ct-hosts`; the
default is `50`. Disable HTTP verification with `--no-http-probe`.
Temporary crt.sh errors are retried up to four times with increasing delays.
Successful CT results are cached under `reports/subdomains/cache/` and reused
for 24 hours, which makes repeated scans much faster. Use `--refresh-ct` to
force a live refresh.

RDAP lookups use IANA's official bootstrap registries and query the
authoritative domain registry or regional IP registry directly. Disable them
with `--no-rdap`. RDAP applies to the registered domain and IP networks, not
to individual subdomains as separate registrations. Some TLDs do not publish
an RDAP service; this is reported explicitly.

Takeover results are indicators, not confirmation. Manually verify service
ownership and provider-specific behavior before reporting a vulnerability.

Output:

- `reports/subdomains/subdomains_<domain>_<timestamp>.json`

Terminalresultatet visas som ett block per fynd:

```text
Subdomän: api.example.com
Status:   200
IP:       192.0.2.10
CNAME:    service.example-provider.net
PTR:      host-192-0-2-10.provider.net
Titel:    API Dashboard
Server:   nginx
Headers:  4/6
TLS:      TLSv1.3, verifierad, 48 dagar kvar
Nätägare: Example Hosting AB
Risk:     MEDIUM
Orsak:    Potentially sensitive environment is public
```

Resultaten sorteras med status `200` först, andra nåbara HTTP-statusar
därefter och ej nåbara fynd längst ned.

Only run the tool for domains you own or have explicit permission to test.

### Hidden Page Finder: `find_hidden_pages.py`

Discovers hidden or forgotten paths by testing a wordlist against a target domain.

What it does:

- Reads paths from a wordlist such as `common.txt`.
- Sends parallel HTTP requests to `BASE_URL/path`.
- Reports paths that return HTTP `200`.
- Writes results to a CSV file.

Example:

```bash
python find_hidden_pages.py \
  --url https://example.com \
  --wordlist common.txt \
  --threads 20 \
  --timeout 5
```

Optional output file:

```bash
python find_hidden_pages.py \
  --url https://example.com \
  --wordlist common.txt \
  --output results.csv
```

Output:

- Default output is named from the target domain, for example `doldasidor_example_com.csv`.
- CSV columns: `URL`, `Status`, `Length`.

### Hybrid Secret Scanner: `keyFinder.py`

The newer and broader hybrid secret scanner.

What it does:

- Crawls same-site links.
- Scans HTML, JavaScript, input values, and base64-decoded content.
- Uses Playwright for JavaScript-rendered pages and browser storage checks.
- Checks cookies and `localStorage`.
- Looks for exposed secrets in source maps.
- Tests common sensitive locations such as `.env`, `.git/config`, `robots.txt`, `sitemap.xml`, `config.json`, and API config paths.
- Checks API documentation endpoints such as Swagger/OpenAPI paths.
- Tests GraphQL introspection endpoints.
- Checks common OAuth/social-auth and webhook endpoints.
- Produces a detailed hybrid JSON report with severity and recommendations.

Recent changes:

- Fixed the `input_hits` bug.
- Confirmed that there are no duplicate function definitions.
- Replaced broad `except:` handlers with specific exceptions.
- Added strict hostname scope validation.
- Blocks out-of-scope redirects, links, JavaScript files, and Playwright requests.
- Passive scanning is the default.
- Active probing must be explicitly enabled with `--active`.
- Removed local cloud metadata scanning.
- The target URL is no longer hardcoded.

#### Passive scanning

Passive mode follows pages and resources that the target website exposes
through normal navigation. It:

- Crawls links on the exact target hostname.
- Scans HTML, discovered JavaScript files, input values, and base64 content.
- Renders discovered pages with Playwright.
- Scans cookies, `localStorage`, and discovered source maps.
- Does not guess sensitive paths or send GraphQL, POST, or PUT probes.

Use passive mode first because it has lower impact and is less likely to alter
application state or trigger security alerts.

```bash
python keyFinder.py --url https://example.com
```

The crawl limits are configurable:

```bash
python keyFinder.py \
  --url https://example.com \
  --max-pages 100 \
  --max-js-files 50
```

- `--max-pages` limits the number of HTML pages. Default: `25`.
- `--max-js-files` limits JavaScript and source map analysis. Default: `15`.
- Use `0` for an unlimited value, for example `--max-pages 0`.

#### Active scanning

Active mode includes everything from passive mode and additionally probes
common endpoints that were not necessarily linked from the website. It:

- Triggers error pages using GET, POST, and PUT requests.
- Checks OAuth, social authentication, and webhook endpoints.
- Checks Swagger/OpenAPI documentation paths.
- Sends GraphQL introspection queries.
- Tests sensitive paths such as `.env`, `.git/config`, and configuration files.
- Scans custom entries from `API_ENDPOINTS`.

Active mode generates more traffic and may trigger WAF, SOC, rate-limit, or
monitoring alerts. It can also interact with application routes that change
state, so use it only when active probing is explicitly included in the
customer-approved scope.

```bash
python keyFinder.py --url https://heddy.emaxmedia.se/ --active
```

Output:

- `reports/keyfinder/HYBRID_secret_scan_report_<target>_<timestamp>.json`
- The `reports/keyfinder` directory is created automatically on the first run.

Notes:

- Both modes enforce the exact target hostname.
- Redirects and resources outside the configured hostname are blocked.
- Subdomains are not included automatically.
- The JSON report keeps every occurrence in `detailed_findings`.
- A deduplicated list is stored in `unique_findings` and used for the terminal
  summary.

### WordPress Scanner: `wp_scanner.py`

WordPress-specific security check for authorized engagements.

What it does:

- Fingerprints the target as WordPress (aborts if not WP).
- Detects the WordPress version via generator meta tag, `readme.html`, and `wp-includes/version.php`.
- Probes ~35 sensitive paths for exposed backups and configuration:
  `wp-config.php.bak`, `.env`, `debug.log`, `.git/config`, editor swap
  files, etc. Each hit is content-verified to avoid soft 404s.
- Detects directory listing on `wp-content/uploads/`, `plugins/`, `themes/`.
- Checks if XML-RPC is enabled (and confirms via `system.listMethods`).
- Tests user enumeration via the REST API (`/wp-json/wp/v2/users`) and via
  the classic `?author=N` redirect.
- Probes the WordPress search parameter (`?s=`) plus any custom params you
  pass for reflected XSS — flags **HIGH** when `<` and `>` reflect raw.
- Sorts findings by severity (CRITICAL → INFO) and writes a JSON report.

Usage:

```bash
python wp_scanner.py --url https://customer.example.com
```

Also probe `?q=` and `?id=` for reflected XSS:

```bash
python wp_scanner.py --url https://customer.example.com --params q,id
```

Skip XSS probes (passive mode):

```bash
python wp_scanner.py --url https://customer.example.com --no-xss
```

Output:

- `reports/wp_scanner/wp_scan_<host>_<timestamp>.json`
- Terminal: grouped findings with severity, URL, evidence, and a remediation
  suggestion per finding.

Notes:

- XSS detection here is reflection-based — it confirms that special
  characters survive unencoded in the response body. Always manually verify
  before reporting as an exploit.
- The script aborts if the target does not look like WordPress, to avoid
  noisy false positives on non-WP sites.

### `api_secret_scanner.py`

A focused secret scanner that combines crawling, JavaScript rendering, and network request analysis.

What it does:

- Crawls pages from a hardcoded target URL.
- Scans static HTML for secrets.
- Scans rendered HTML with Playwright.
- Interacts with pages to trigger dynamic requests.
- Captures and scans network requests, response bodies, headers, and POST data.
- Scans JavaScript files.
- Scans base64-decoded content.
- Uses patterns from `secret_patterns.py`.

Run with a target URL:

```bash
python api_secret_scanner.py --url https://example.com
```

Output:

- `secret_scan_<target>_<timestamp>.json`

### `keyFinderOG.py`

The original/legacy version of the key finder.

What it does:

- Crawls same-site links from a hardcoded target URL.
- Scans HTML for secrets.
- Scans JavaScript files.
- Scans input values and selected data attributes.
- Scans base64-decoded strings.
- Uses Playwright as a fallback when static content does not produce findings.
- Writes a simpler JSON report.

Before running, edit the hardcoded target at the top of the file:

```python
URL = "https://example.com/"
```

Then run:

```bash
python keyFinderOG.py
```

Output:

- `secret_scan_report_<timestamp>.json`

Use this when you want a lighter, less broad version of the scanner.

### `secret_patterns.py`

Shared pattern library used by `api_secret_scanner.py`.

It contains regular expressions for detecting common exposed secrets, including:

- Google API keys and OAuth tokens
- Stripe keys
- AWS access key IDs
- GitHub tokens
- JWTs
- Slack and Discord tokens/webhooks
- Database connection strings
- Private keys and certificates
- Bearer/basic auth tokens
- Webhook URLs
- Cloud function/API endpoints

### `common.txt`

Wordlist used by `find_hidden_pages.py`.

It contains common hidden paths and files such as:

- admin paths
- dotfiles
- `.git` paths
- config files
- backup paths
- common framework and server files

## Typical Workflow

1. Discover exposed paths:

```bash
python find_hidden_pages.py --url https://example.com --wordlist common.txt
```

2. Review interesting paths from the CSV output.

3. Run a secret scanner against the authorized target:

```bash
python keyFinder.py --url https://example.com
```

4. Review the generated JSON report.

5. Rotate/revoke any real exposed credentials found during testing.

## Configuration

The command-line tools accept arguments:

```bash
python find_hidden_pages.py --help
python keyFinder.py --help
```

`keyFinder.py` requires `--url` and supports `--active`, `--max-pages`, and
`--max-js-files`. `api_secret_scanner.py` requires `--url`. `keyFinderOG.py`
still uses a hardcoded `URL` value at the top of the file.

Custom API endpoints can be added in each scanner's `API_ENDPOINTS` list.

## Output Files

Generated output files are intentionally not required for the code to run. They can be deleted or ignored after review.

Common generated files:

- `doldasidor_<domain>.csv`
- `reports/subdomains/subdomains_<domain>_<timestamp>.json`
- `secret_scan_<target>_<timestamp>.json`
- `secret_scan_report_<timestamp>.json`
- `reports/keyfinder/HYBRID_secret_scan_report_<target>_<timestamp>.json`

## Git Hygiene

Recommended files/directories to avoid committing:

- `venv/`
- `__pycache__/`
- `.DS_Store`
- generated `.csv` reports
- generated `.json` scan reports
- local notes containing secrets

Before pushing, scan the repo itself for credentials and remove or rotate anything real.

## Dependencies

Main runtime dependencies:

- `requests`
- `dnspython`
- `beautifulsoup4`
- `playwright`
- `tqdm`
- `colorama`

Install all pinned dependencies with:

```bash
pip install -r requirements.txt
```

## Legal Notice

These tools are intended for defensive security testing, internal audits, and authorized penetration testing. Do not run them against third-party systems without written permission.

## License

Released under the [MIT License](LICENSE). The software is provided "as is",
without warranty of any kind, and the authors accept no liability for how it is
used. You are solely responsible for ensuring you have permission to test any
system you point these tools at.
