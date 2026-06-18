"""
API Secret Patterns
===================
Denna fil innehåller alla regex-patterns för att detektera API-nycklar,
tokens, webhooks och andra känsliga secrets.
"""

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
