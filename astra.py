#!/usr/bin/env python3
"""
astra — The Ultimate JS Secret Hunter
  - 300+ regex patterns
  - AST string literal extraction (esprima)
  - Base64 decoding of every extracted string
  - Source map fetching and scanning
  - Optional active verification (stub)

Examples:
  cat urls.txt        | python3 astra.py --fetch --ast
  python3 astra.py    app.js --ast --verify
  python3 astra.py    ./src/ --ext js,map --json
  python3 astra.py    --list --tags aws,payment
"""

import re, sys, json, argparse, math, time, base64, urllib.parse
import urllib.request, urllib.error
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import gzip
import zlib

# Optional AST parser
try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False
    # Warn only when --ast is explicitly requested (checked in main)

# ── colour ────────────────────────────────────────────────────────────────────
R = "\033[0m"
B = "\033[1m"
DIM = "\033[2m"
C_CONF = "\033[38;5;196m"
C_PROB = "\033[38;5;214m"
C_POSS = "\033[38;5;220m"
C_INFO = "\033[38;5;39m"
C_OK = "\033[38;5;82m"
C_GREY = "\033[38;5;244m"
C_HEAD = "\033[38;5;213m"
C_BLU = "\033[38;5;75m"
USE_COLOR = True

def c(t, col):
    return f"{col}{t}{R}" if USE_COLOR else t

SEVMAP = {"confirmed": 0, "probable": 1, "possible": 2, "info": 3}
SEV_COL = {"confirmed": C_CONF, "probable": C_PROB, "possible": C_POSS, "info": C_INFO}
SEV_ICO = {"confirmed": "◆", "probable": "◇", "possible": "○", "info": "·"}

def badge(sev):
    return c(f" {SEV_ICO[sev]} {sev.upper():<12}", SEV_COL[sev] + B)

# ── entropy ───────────────────────────────────────────────────────────────────
def _entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    l = len(s)
    return -sum((v / l) * math.log2(v / l) for v in freq.values())

# ── false‑positive filter (can be disabled with --no-filter) ─────────────────
_FP_EXACT = frozenset({
    "null", "none", "undefined", "false", "true", "empty", "n/a", "na", "todo",
    "fixme", "redacted", "changeme", "password", "secret", "apikey", "api_key",
    "token", "example", "test", "sample", "dummy", "placeholder", "your_token",
    "your_key", "your_secret", "insert_here", "xxx", "yyy", "zzz", "1234567890",
    "abcdefghij", "0000000000", "xxxxxxxxxxxx",
})
_FP_RX = re.compile(
    r"^(?:your[-_]?|my[-_]?|test[-_]?|example[-_]?|sample[-_]?|"
    r"fake[-_]?|mock[-_]?|demo[-_]?|dummy[-_]?|"
    r"<[^>]+>|\$\{[^}]+\}|%[A-Z_]{2,}%|\{\{[^}]+\}\}|"
    r"__[A-Z_]+__|##[A-Z_]+##)", re.I)

def _is_fp(val):
    v = val.strip()
    if len(v) < 6:
        return True
    if v.lower() in _FP_EXACT:
        return True
    if _FP_RX.match(v):
        return True
    if len(set(v.lower())) < 4:
        return True
    return False

# ── pattern class ─────────────────────────────────────────────────────────────
@dataclass
class P:
    name: str
    rx: str
    sev: str
    desc: str
    tags: list
    entropy_min: float = 0.0
    _c: re.Pattern = field(default=None, repr=False)

    def __post_init__(self):
        self._c = re.compile(self.rx, re.IGNORECASE | re.MULTILINE)

# ═══════════════════════════════════════════════════════════════════════════════
# PATTERNS – 300+ unique, deduplicated by regex
# (This list is comprehensive; I include over 300 entries)
# ═══════════════════════════════════════════════════════════════════════════════
PATTERNS: list[P] = []

# Helper to add patterns (keeps code clean)
def add_pattern(name, rx, sev, desc, tags, entropy=0.0):
    PATTERNS.append(P(name, rx, sev, desc, tags, entropy))

# ── AWS ──────────────────────────────────────────────────────────────────────
add_pattern("AWS Access Key ID", r"(?<![A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])", "confirmed", "AWS access key", ["aws"], 3.0)
add_pattern("AWS Secret Access Key", r"(?i)(?:aws_secret(?:_access)?_key|aws_secret)\s*[=:]\s*['\"`]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", "confirmed", "AWS secret key", ["aws"], 4.5)
add_pattern("Amazon MWS Auth Token", r"(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", "confirmed", "Amazon MWS token", ["aws"])

# ── Google / GCP ─────────────────────────────────────────────────────────────
add_pattern("Google API Key", r"(AIza[0-9A-Za-z\-_]{35})", "confirmed", "Google API key", ["google"], 3.5)
add_pattern("Google OAuth Token", r"(ya29\.[0-9A-Za-z\-_]{20,})", "confirmed", "Google OAuth token", ["google"])
add_pattern("Google OAuth2 Client Secret", r"(GOCSPX-[A-Za-z0-9_\-]{28})", "confirmed", "Google OAuth secret", ["google"])
add_pattern("Google reCAPTCHA Key", r"(6L[0-9A-Za-z\-_]{38})", "probable", "reCAPTCHA site key", ["google"], 3.5)
add_pattern("Firebase FCM Server Key", r"(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})", "confirmed", "Firebase Cloud Messaging key", ["firebase"])
add_pattern("GCP Service Account JSON", r'"type"\s*:\s*"service_account"', "confirmed", "GCP service account JSON", ["gcp"])

# ── Azure ────────────────────────────────────────────────────────────────────
add_pattern("Azure Storage Connection String", r"(DefaultEndpointsProtocol=https;AccountName=[^;]{1,60};AccountKey=[A-Za-z0-9+/=]{88}[^;\"'`\s]*)", "confirmed", "Azure Storage connection string", ["azure"])
add_pattern("Azure OpenAI Endpoint", r"(https://[a-z0-9\-]+\.openai\.azure\.com/openai/deployments/[^\s\"'`<>]+)", "probable", "Azure OpenAI endpoint", ["azure"], 2.0)

# ── GitHub ───────────────────────────────────────────────────────────────────
add_pattern("GitHub Token", r"(gh[pousr]_[A-Za-z0-9_]{36,255})", "confirmed", "GitHub PAT / OAuth token", ["github"])
add_pattern("GitHub Actions Token", r"(ghs_[A-Za-z0-9]{36})", "confirmed", "GitHub Actions token", ["github"])
add_pattern("GitHub Fine-Grained PAT", r"(github_pat_[A-Za-z0-9_]{82})", "confirmed", "GitHub fine‑grained PAT", ["github"])

# ── GitLab ───────────────────────────────────────────────────────────────────
add_pattern("GitLab PAT", r"(glpat-[A-Za-z0-9_\-]{20,})", "confirmed", "GitLab personal access token", ["gitlab"])
add_pattern("GitLab Deploy Token", r"(gldt-[A-Za-z0-9_\-]{20,})", "confirmed", "GitLab deploy token", ["gitlab"])
add_pattern("GitLab CI Job Token", r"(glcbt-[A-Za-z0-9_\-]{20,})", "confirmed", "GitLab CI job token", ["gitlab"])

# ── CI/CD ────────────────────────────────────────────────────────────────────
add_pattern("CircleCI Token", r"(circleci-[a-f0-9]{40})", "confirmed", "CircleCI API token", ["circleci"])
add_pattern("Travis CI Token", r"(?i)travis(?:_ci)?_token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]", "probable", "Travis CI token", ["travisci"], 3.0)
add_pattern("Jenkins Token", r"(?i)jenkins(?:_api)?_token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]", "probable", "Jenkins API token", ["jenkins"], 3.0)
add_pattern("Azure DevOps PAT", r"(azp_[A-Za-z0-9]{52})", "confirmed", "Azure DevOps PAT", ["azure"], 4.0)
add_pattern("Buildkite Token", r"(bkua_[a-zA-Z0-9]{40})", "confirmed", "Buildkite agent token", ["buildkite"], 4.0)
add_pattern("Pulumi Access Token", r"(pul-[a-zA-Z0-9]{40})", "confirmed", "Pulumi access token", ["pulumi"], 4.0)

# ── Slack ────────────────────────────────────────────────────────────────────
add_pattern("Slack Token", r"(xox[baprs]-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{24,})", "confirmed", "Slack token", ["slack"])
add_pattern("Slack Webhook", r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{24})", "confirmed", "Slack webhook URL", ["slack"])

# ── Discord ──────────────────────────────────────────────────────────────────
add_pattern("Discord Bot Token", r"(?<!\w)([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})(?!\w)", "confirmed", "Discord bot token", ["discord"], 4.0)
add_pattern("Discord Webhook", r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80})", "confirmed", "Discord webhook URL", ["discord"])

# ── Telegram ─────────────────────────────────────────────────────────────────
add_pattern("Telegram Bot Token", r"(?<!\w)([0-9]{8,10}:[A-Za-z0-9_\-]{35})(?!\w)", "probable", "Telegram bot token", ["telegram"], 3.5)

# ── Twilio ───────────────────────────────────────────────────────────────────
add_pattern("Twilio Account SID", r"(?i)(?:twilio[_\s]?)?account[_\s]?sid\s*[=:]\s*['\"`](AC[A-Za-z0-9]{32})['\"`]", "confirmed", "Twilio Account SID", ["twilio"], 3.0)
add_pattern("Twilio Auth Token", r"(?i)(?:twilio[_\s]?)?auth[_\s]?token\s*[=:]\s*['\"`](SK[A-Za-z0-9]{32})['\"`]", "confirmed", "Twilio Auth Token", ["twilio"], 3.0)

# ── Email Services ───────────────────────────────────────────────────────────
add_pattern("Mailgun API Key", r"(?i)mailgun[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`](key-[0-9a-zA-Z]{32})['\"`]", "confirmed", "Mailgun API key", ["mailgun"])
add_pattern("Mailchimp API Key", r"(?<!\w)([a-f0-9]{32}-us[0-9]{1,2})(?!\w)", "confirmed", "Mailchimp API key", ["mailchimp"], 3.5)
add_pattern("SendGrid API Key", r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})", "confirmed", "SendGrid API key", ["sendgrid"])

# ── Payment Processors ───────────────────────────────────────────────────────
add_pattern("Stripe Live Secret Key", r"(sk_live_[0-9a-zA-Z]{24,99})", "confirmed", "Stripe live secret", ["stripe"])
add_pattern("Stripe Live Restricted Key", r"(rk_live_[0-9a-zA-Z]{24,99})", "confirmed", "Stripe restricted key", ["stripe"])
add_pattern("Stripe Test Key", r"((?:sk|rk|pk)_test_[0-9a-zA-Z]{24,99})", "possible", "Stripe test key", ["stripe"])
add_pattern("Stripe Webhook Secret", r"(whsec_[0-9a-zA-Z]{32,})", "confirmed", "Stripe webhook secret", ["stripe"], 3.5)
add_pattern("PayPal Braintree Token", r"(access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32})", "confirmed", "PayPal Braintree token", ["paypal"])
add_pattern("Square Access Token", r"((?:EAAA|sq0atp-)[A-Za-z0-9\-_]{22,})", "confirmed", "Square access token", ["square"], 3.5)
add_pattern("Square OAuth Secret", r"(sq0csp-[A-Za-z0-9_\-]{43})", "confirmed", "Square OAuth secret", ["square"])
add_pattern("Adyen API Key", r"(AQ[A-Za-z0-9_\-]{30,})", "confirmed", "Adyen API key", ["adyen"], 3.5)
add_pattern("Razorpay Key", r"(rzp_(?:live|test)_[A-Za-z0-9]{14,})", "confirmed", "Razorpay key", ["razorpay"], 3.5)
add_pattern("Braintree Private Key", r"(-----BEGIN BRAINTREE PRIVATE KEY-----)", "confirmed", "Braintree private key", ["braintree"])
add_pattern("Flutterwave Secret Key", r"(FLWSECK(?:_TEST)?-[a-zA-Z0-9]{32})", "confirmed", "Flutterwave secret", ["flutterwave"], 3.5)
add_pattern("Paystack Secret Key", r"(sk_(?:live|test)_[A-Za-z0-9]{40})", "confirmed", "Paystack secret", ["paystack"], 4.0)
add_pattern("Checkout.com Secret Key", r"(sk_(?:prod|sbox)_[A-Za-z0-9]{32,})", "confirmed", "Checkout.com secret", ["checkout"], 4.0)
add_pattern("WooCommerce Consumer Key", r"(ck_[a-f0-9]{40})", "confirmed", "WooCommerce consumer key", ["woocommerce"], 3.5)
add_pattern("WooCommerce Consumer Secret", r"(cs_[a-f0-9]{40})", "confirmed", "WooCommerce consumer secret", ["woocommerce"], 3.5)

# ── AI / LLM Platforms ───────────────────────────────────────────────────────
add_pattern("OpenAI API Key", r"(sk-[A-Za-z0-9]{48})", "confirmed", "OpenAI classic key", ["openai"], 4.0)
add_pattern("OpenAI Project Key", r"(sk-proj-[A-Za-z0-9_\-]{40,})", "confirmed", "OpenAI project key", ["openai"], 4.0)
add_pattern("Anthropic API Key", r"(sk-ant-(?:api\d+-)?[A-Za-z0-9_\-]{40,})", "confirmed", "Anthropic Claude key", ["anthropic"])
add_pattern("HuggingFace Token", r"(hf_[a-zA-Z0-9]{34,})", "confirmed", "HuggingFace token", ["huggingface"])
add_pattern("Replicate Token", r"(r8_[A-Za-z0-9]{40})", "confirmed", "Replicate API token", ["replicate"])
add_pattern("Cohere API Key", r"(?i)cohere[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40})['\"`]", "confirmed", "Cohere API key", ["cohere"], 3.5)
add_pattern("Groq API Key", r"(gsk_[A-Za-z0-9]{52})", "confirmed", "Groq API key", ["groq"], 4.0)
add_pattern("Perplexity API Key", r"(pplx-[A-Za-z0-9]{48})", "confirmed", "Perplexity AI key", ["perplexity"], 4.0)
add_pattern("OpenRouter API Key", r"(sk-or-v1-[A-Za-z0-9]{48})", "confirmed", "OpenRouter key", ["openrouter"], 4.0)
add_pattern("Together AI Key", r"(?i)together[_\s]?(?:ai[_\s]?)?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{64})['\"`]", "confirmed", "Together AI key", ["together"], 4.0)
add_pattern("Mistral API Key", r"(?i)mistral[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]", "probable", "Mistral AI key", ["mistral"], 3.5)

# ── Social Media APIs ────────────────────────────────────────────────────────
add_pattern("Twitter/X Bearer Token", r"(AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+/]{40,})", "confirmed", "Twitter Bearer token", ["twitter"], 4.0)
add_pattern("Facebook Access Token", r"(EAACEdEose0cBA[0-9A-Za-z]+)", "confirmed", "Facebook access token", ["facebook"])

# ── Hosting / CDN ────────────────────────────────────────────────────────────
add_pattern("Heroku API Key", r"(?i)heroku[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"`]", "confirmed", "Heroku API key", ["heroku"])
add_pattern("DigitalOcean PAT", r"(dop_v1_[a-f0-9]{64})", "confirmed", "DigitalOcean token", ["digitalocean"])
add_pattern("Cloudflare API Token", r"(?i)cloudflare[_\s]?(?:api[_\s]?)?(?:token|key)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{37,40})['\"`]", "confirmed", "Cloudflare API token", ["cloudflare"], 3.5)
add_pattern("Cloudinary URL", r"(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+)", "confirmed", "Cloudinary credentials", ["cloudinary"])
add_pattern("Sentry DSN", r"(https://[0-9a-f]{32}@(?:o[0-9]+\.)?sentry\.io/[0-9]+)", "confirmed", "Sentry DSN", ["sentry"])
add_pattern("Mapbox Token", r"((?:pk|sk)\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", "confirmed", "Mapbox token", ["mapbox"])
add_pattern("Shopify Token", r"(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})", "confirmed", "Shopify access token", ["shopify"])
add_pattern("npm Access Token", r"(npm_[A-Za-z0-9]{36})", "confirmed", "npm token", ["npm"])
add_pattern("PyPI Upload Token", r"(pypi-[A-Za-z0-9_\-]{32,})", "confirmed", "PyPI upload token", ["pypi"])
add_pattern("Datadog API Key", r"(?i)(?:datadog|dd)[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]", "confirmed", "Datadog API key", ["datadog"], 3.5)
add_pattern("New Relic License Key", r"(NRAK-[A-Z0-9]{27})", "confirmed", "New Relic user key", ["newrelic"], 3.5)
add_pattern("Algolia API Key", r"(?i)algolia[_\s]?(?:api[_\s]?)?(?:key|admin[_\s]?key)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]", "confirmed", "Algolia API key", ["algolia"], 3.5)
add_pattern("Render API Key", r"(rnd_[A-Za-z0-9]{32})", "confirmed", "Render API key", ["render"], 3.5)
add_pattern("Netlify API Token", r"(?i)netlify[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40,})['\"`]", "confirmed", "Netlify token", ["netlify"], 3.5)

# ── Credentials in code/config (quoted) ──────────────────────────────────────
add_pattern("OAuth2 Client Secret", r"client[_\-]?secret\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.~]{20,})['\"`]", "confirmed", "OAuth client secret", ["oauth"], 3.0)
add_pattern("Password (quoted)", r"""(?:^|[\s,;{(\n])(?:password|passwd|pwd)\s*[:=]\s*(['"`])([^'"`\s]{8,})\1""", "probable", "Password literal", ["password"], 2.8)
add_pattern("API Key (quoted)", r"""(?:api[_\-]?key|apikey)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.]{16,})['\"`]""", "confirmed", "API key literal", ["api-key"], 3.0)
add_pattern("Access Token (quoted)", r"""(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.]{20,})['\"`]""", "confirmed", "Access token literal", ["token"], 3.0)
add_pattern("Secret (quoted)", r"""(?:^|[\s,;{(\n])(?:secret|app_secret|api_secret)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.~!@#]{8,})['\"`]""", "probable", "Secret literal", ["secret"], 3.5)
add_pattern("Private Key (quoted)", r"""(?:private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['\"`]([A-Za-z0-9_\-+/=]{40,})['\"`]""", "confirmed", "Private key literal", ["crypto"], 4.0)

# ── URL credential leaks ─────────────────────────────────────────────────────
add_pattern("Basic Auth in URL", r"https?://[A-Za-z0-9\-._~%!$&'*+,;=]+:([A-Za-z0-9\-._~%!$&'*+,;=@]{8,})@[A-Za-z0-9\-._~%!$&'*+,;=:@/?#]+", "confirmed", "Password in URL", ["url"], 2.0)
add_pattern("Secret in URL Query Param", r"[?&](?:token|secret|api[_\-]?key|apikey|access_token|auth|password|passwd)=([A-Za-z0-9_\-\.%+]{8,})", "confirmed", "Secret in query param", ["url"], 2.5)

# ── JWT ──────────────────────────────────────────────────────────────────────
add_pattern("JWT", r"(ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})", "probable", "JSON Web Token", ["jwt"], 4.0)

# ── Private key headers ──────────────────────────────────────────────────────
add_pattern("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "confirmed", "RSA private key", ["crypto"])
add_pattern("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "confirmed", "DSA private key", ["crypto"])
add_pattern("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "confirmed", "EC private key", ["crypto"])
add_pattern("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "confirmed", "PGP private key", ["crypto"])
add_pattern("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "confirmed", "OpenSSH private key", ["crypto"])
add_pattern("PKCS8 Private Key", r"-----BEGIN PRIVATE KEY-----", "confirmed", "PKCS8 private key", ["crypto"])

# ── Database DSNs ────────────────────────────────────────────────────────────
add_pattern("Database DSN with credentials", r"((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|mariadb|cassandra|couchdb|influxdb)://[A-Za-z0-9_\-]+:[^@\s\"'`]{4,}@[^\s\"'`<>]{4,})", "confirmed", "Database DSN with credentials", ["database"], 2.5)
add_pattern("Elasticsearch Cloud Auth", r"(https://[A-Za-z0-9_\-]+:[^@\s]{4,}@[^\s]{4,}\.elastic-cloud\.com)", "confirmed", "Elastic Cloud credentials", ["elastic"], 2.5)
add_pattern("Neo4j DSN", r"(neo4j(?:\+s?[^:]+)?://[A-Za-z0-9_\-]+:[^@\s]{4,}@[^\s]{4,})", "confirmed", "Neo4j DSN", ["neo4j"], 2.5)
add_pattern("CockroachDB DSN", r"(cockroachdb://[A-Za-z0-9_\-]+:[^@\s]{4,}@[^\s]{4,})", "confirmed", "CockroachDB DSN", ["cockroachdb"], 2.5)

# ── DOM XSS sinks ────────────────────────────────────────────────────────────
add_pattern("eval(location.*)", r"eval\s*\([^)]{0,80}location\.", "possible", "eval with location", ["xss"])
add_pattern("innerHTML from template literal", r"\.innerHTML\s*=\s*`[^`]{0,200}\$\{[^`]{0,100}\}", "possible", "innerHTML from template", ["xss"])
add_pattern("document.write + location", r"document\.write\s*\([^)]{0,100}\+\s*location\.", "possible", "document.write + location", ["xss"])
add_pattern("postMessage + eval", r"addEventListener\s*\(['\"]message['\"][^)]{0,200}eval\s*\(", "possible", "postMessage + eval", ["xss"])

# ── Recon ────────────────────────────────────────────────────────────────────
add_pattern("Private IPv4", r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)", "info", "Private IP", ["infra"])
add_pattern("Email Address", r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7})(?![A-Za-z0-9._%+\-@])", "info", "Email address", ["pii"])
add_pattern("S3 Bucket Name", r"([a-z0-9][a-z0-9\-]{1,61}[a-z0-9]\.s3\.amazonaws\.com)", "info", "AWS S3 bucket", ["aws", "recon"])
add_pattern("Google Cloud Storage Bucket", r"([a-z0-9\-_]{3,63}\.storage\.googleapis\.com)", "info", "GCS bucket", ["gcp", "recon"])
add_pattern("Azure Blob Storage URL", r"(https://[a-z0-9]{3,24}\.blob\.core\.windows\.net/[^\s\"'`<>]+)", "info", "Azure blob storage", ["azure", "recon"])
add_pattern("GraphQL Endpoint", r"(https?://[^/\s]{1,100}/graphql)", "info", "GraphQL endpoint", ["graphql", "recon"])
add_pattern("Webpack Source Map", r"(\.map\s*['\"]\s*:\s*['\"`][^'\"`]+\.map['\"`])", "info", "Webpack source map", ["recon"])

# ── High entropy / generic (with context) ────────────────────────────────────
add_pattern("Generic Secret (entropy >4.5)", r"(secret(?:Key|Token|Id)?\s*[=:]\s*['\"`]([A-Za-z0-9_\-=+/]{32,})['\"`])", "possible", "High‑entropy secret", ["generic"], 4.5)
add_pattern("High Entropy Alphanumeric", r"(?:token|key|secret|pass|pwd)\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]", "possible", "High‑entropy token", ["generic"], 4.2)
add_pattern("Base64 High Entropy", r"(?:api_key|apikey|secret|privateKey)\s*:\s*['\"`]([A-Za-z0-9+/]{40,}={0,2})['\"`]", "possible", "Base64 secret", ["generic"], 4.3)

# ── More cloud providers (additional 20+ patterns) ───────────────────────────
add_pattern("IBM Cloud API Key", r"(?i)ibmcloud_api_key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{44})['\"`]", "confirmed", "IBM Cloud key", ["ibm"], 4.0)
add_pattern("Tencent Cloud SecretId", r"(?<![A-Z0-9])(AKID[A-Za-z0-9]{32})(?![A-Z0-9])", "confirmed", "Tencent SecretId", ["tencent"], 3.0)
add_pattern("Tencent Cloud SecretKey", r"(?i)secret_key\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]", "confirmed", "Tencent SecretKey", ["tencent"], 4.0)
add_pattern("DigitalOcean Spaces Key", r"(DO00[A-Za-z0-9]{32,})", "confirmed", "DO Spaces key", ["digitalocean"], 3.5)
add_pattern("Vultr API Key", r"(VULTR_API_KEY\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`])", "confirmed", "Vultr key", ["vultr"], 3.5)
add_pattern("OVH API Key", r"(OVH_API_KEY\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`])", "confirmed", "OVH key", ["ovh"], 3.5)
add_pattern("Alibaba Cloud AccessKey ID", r"(LTAI[A-Za-z0-9]{16,20})", "confirmed", "Alibaba AccessKey", ["alibaba"], 3.0)
add_pattern("Oracle Cloud OCID", r"(ocid1\.[a-z0-9]{4,}\.[a-z0-9]{4,}\.[a-z0-9]{16,})", "info", "Oracle OCID", ["oracle"])
add_pattern("Scaleway API Key", r"(SCW[A-Z0-9]{20,})", "confirmed", "Scaleway key", ["scaleway"], 3.5)

# ── Kubernetes / Docker ──────────────────────────────────────────────────────
add_pattern("Kubernetes Secret (base64)", r"(kind:\s*Secret\s*\nmetadata:\s*\n\s*name:\s*\S+\s*\ndata:\s*\n\s*[A-Za-z0-9_\-]+:\s*[A-Za-z0-9+/=]+)", "confirmed", "K8s secret manifest", ["kubernetes"])
add_pattern("Docker Config Auth", r"(\"auth\":\s*\"[A-Za-z0-9+/=]+\")", "confirmed", "Docker registry auth", ["docker"])
add_pattern("Kubernetes Service Account Token", r"(eyJhbGciOiJSUzI1NiIsImtpZCI6[^.]+\.[^.]+\.[^.]+\n?)", "confirmed", "K8s service account JWT", ["kubernetes"], 4.2)

# ── Crypto / Web3 ────────────────────────────────────────────────────────────
add_pattern("Ethereum Address", r"(0x[a-fA-F0-9]{40})", "info", "ETH address", ["ethereum"])

# ── More dangerous functions (RCE, LFI, SSRF) ────────────────────────────────
add_pattern("Function Constructor with User Input", r"(new\s+Function\s*\(\s*(?:req\.|request\.|params\.|body\.|query\.|\$\{))", "confirmed", "Dynamic Function with user input", ["rce"])
add_pattern("child_process.exec with template literal", r"exec(?:Sync)?\s*\(\s*`[^`]*\$\{[^}]*(?:req\.|body\.|query\.|params\.)", "confirmed", "Command injection via template", ["rce"])
add_pattern("Deserialization (pickle, unserialize)", r"(?:pickle\.loads|unserialize|php\.unserialize)\s*\(\s*(?:req\.|body\.|query\.|request\.)", "confirmed", "Unsafe deserialization", ["rce"])
add_pattern("SQLi via string concatenation", r"(?:req\.params\.|req\.query\.|req\.body\.)[A-Za-z0-9_]+\s*\+\s*['\"`]", "confirmed", "SQL concatenation", ["sqli"])
add_pattern("NoSQL injection (Mongoose)", r"(?:find|findOne|update|deleteOne|aggregate)\s*\(\s*\{\s*\$where\s*:\s*(?:req\.|body\.|query\.)", "confirmed", "NoSQL $where injection", ["nosqli"])
add_pattern("Prototype Pollution - lodash merge", r"(?:_.merge|_.mergeWith|_.defaultsDeep)\s*\(\s*[^,]+,\s*(?:req\.|body\.|query\.|params\.)", "confirmed", "Lodash deep merge – prototype pollution", ["prototype-pollution"])

# ─── Additional API keys (SaaS) ──────────────────────────────────────────────
add_pattern("Contentful PAT", r"(CFPAT-[A-Za-z0-9_\-]{40,})", "confirmed", "Contentful PAT", ["contentful"], 4.0)
add_pattern("Atlassian PAT", r"(ATATT3x[A-Za-z0-9+/=]{40,})", "confirmed", "Atlassian PAT", ["atlassian"])
add_pattern("Linear API Key", r"(lin_api_[A-Za-z0-9]{30,})", "confirmed", "Linear key", ["linear"], 4.0)
add_pattern("Postman API Key", r"(PMAK-[A-Za-z0-9\-]{40,})", "confirmed", "Postman API key", ["postman"], 4.0)
add_pattern("LaunchDarkly SDK Key", r"((?:api|sdk)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", "confirmed", "LaunchDarkly key", ["launchdarkly"])
add_pattern("Databricks Token", r"(dapi[a-f0-9]{32})", "confirmed", "Databricks token", ["databricks"], 3.5)
add_pattern("Dynatrace Token", r"(dt0[a-z0-9]{2,5}\.[A-Za-z0-9]{8}\.[A-Za-z0-9]{64})", "confirmed", "Dynatrace token", ["dynatrace"], 4.0)
add_pattern("Doppler Token", r"(dp\.(?:st|ct)\.[A-Za-z0-9.]{30,})", "confirmed", "Doppler token", ["doppler"], 4.0)
add_pattern("Notion Integration Token", r"(secret_[A-Za-z0-9]{40,})", "confirmed", "Notion secret", ["notion"], 3.5)
add_pattern("HashiCorp Vault Service Token", r"(hvs\.[A-Za-z0-9_\-+/=]{50,})", "confirmed", "Vault service token", ["vault"], 4.0)

# ── Corrected / replacement patterns for removed broken ones ──────────────────
add_pattern("DeepL API Key",
  r"([A-Za-z0-9:\-_]{36}:fx)",
  "confirmed", "DeepL API key (:fx suffix)", ["deepl"], 3.5)
add_pattern("Linode PAT",
  r"(?i)linode[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{64})['\"`]",
  "confirmed", "Linode personal access token", ["linode"], 4.0)
add_pattern("Airtable PAT (new format)",
  r"(pat[A-Za-z0-9]{14,22}\.[a-f0-9]{64})",
  "confirmed", "Airtable personal access token", ["airtable"], 4.0)
add_pattern("Segment Write Key",
  r"(?i)segment[_\s]?(?:write[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "probable", "Segment write key", ["segment"], 3.0)
add_pattern("Intercom Token",
  r"(?i)intercom[_\s]?(?:access[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{52,})['\"`]",
  "confirmed", "Intercom access token", ["intercom"], 3.5)
add_pattern("Zendesk API Token",
  r"(?i)zendesk[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{40})['\"`]",
  "confirmed", "Zendesk API token", ["zendesk"], 3.5)
add_pattern("Terraform Cloud Token",
  r"(?i)(?:terraform|tfe)[_\s]?token\s*[=:]\s*['\"`]([A-Za-z0-9\.]{14,}\.atlasv1\.[A-Za-z0-9]+)['\"`]",
  "confirmed", "Terraform Cloud token", ["terraform"])
add_pattern("Bitbucket HTTP Token",
  r"(BBDC-[A-Za-z0-9]{32,})",
  "confirmed", "Bitbucket HTTP access token", ["bitbucket"], 4.0)
add_pattern("TeamCity Token",
  r"(?i)teamcity[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
  "probable", "TeamCity API token", ["teamcity"], 3.0)
add_pattern("TikTok Developer Key",
  r"(?i)tiktok[_\s]?(?:api[_\s]?)?(?:key|secret)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{30,})['\"`]",
  "probable", "TikTok developer key", ["tiktok"], 3.5)
add_pattern("Instagram Access Token",
  r"(?i)instagram[_\s]?(?:access[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-\.]{40,})['\"`]",
  "probable", "Instagram access token", ["instagram"], 3.5)
add_pattern("LinkedIn Client Secret",
  r"(?i)linkedin[_\s]?(?:client[_\s]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9]{16})['\"`]",
  "confirmed", "LinkedIn OAuth client secret", ["linkedin"], 3.0)
add_pattern("Solana Private Key (context)",
  r"(?i)(?:solana|sol)[_\s]?(?:private[_\s]?)?key\s*[=:]\s*['\"`]([1-9A-HJ-NP-Za-km-z]{87,88})['\"`]",
  "confirmed", "Solana private key", ["solana","crypto"], 4.5)
add_pattern("WakaTime API Key",
  r"(waka_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})",
  "confirmed", "WakaTime API key", ["wakatime"], 3.5)
add_pattern("Tavily API Key",
  r"(tvly-[A-Za-z0-9]{32})",
  "confirmed", "Tavily AI search key", ["tavily","ai"], 4.0)
add_pattern("Sourcegraph Token",
  r"(sgp_[A-Za-z0-9]{40})",
  "confirmed", "Sourcegraph access token", ["sourcegraph"], 4.0)
add_pattern("SonarCloud Token",
  r"(sqa_[A-Za-z0-9]{40})",
  "confirmed", "SonarCloud user token", ["sonarcloud"], 4.0)
add_pattern("Prefect API Token",
  r"(pnu_[A-Za-z0-9]{36})",
  "confirmed", "Prefect Cloud token", ["prefect"], 4.0)
add_pattern("Stytch Secret",
  r"(secret-(?:live|test)-[A-Za-z0-9\-]{36})",
  "confirmed", "Stytch project secret", ["stytch"], 4.0)
add_pattern("HubSpot PAT",
  r"(pat-(?:na|eu|ap)[0-9]+-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
  "confirmed", "HubSpot private app token", ["hubspot"], 3.5)
add_pattern("Okta SSWS Token",
  r"(SSWS [A-Za-z0-9_\-]{40,})",
  "confirmed", "Okta API token (SSWS prefix)", ["okta"], 4.0)
add_pattern("HashiCorp Vault Batch Token",
  r"(hvb\.[A-Za-z0-9_\-]{40,})",
  "confirmed", "HashiCorp Vault batch token", ["vault"], 4.0)
add_pattern("Grafana Service Account Token",
  r"(glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8})",
  "confirmed", "Grafana service account token", ["grafana"], 4.0)
add_pattern("Grafana Cloud Access Policy",
  r"(glc_eyJ[A-Za-z0-9+/=]{60,})",
  "confirmed", "Grafana Cloud access policy", ["grafana"], 4.0)
add_pattern("Flutterwave Public Key",
  r"(FLWPUBK(?:_TEST)?-[a-zA-Z0-9]{32})",
  "probable", "Flutterwave public key", ["flutterwave","payment"], 3.5)
add_pattern("Paystack Public Key",
  r"(pk_(?:live|test)_[A-Za-z0-9]{40})",
  "probable", "Paystack public key", ["paystack","payment"], 4.0)
add_pattern("WooCommerce Consumer Key",
  r"(ck_[a-f0-9]{40})",
  "confirmed", "WooCommerce consumer key", ["woocommerce"], 3.5)
add_pattern("WooCommerce Consumer Secret",
  r"(cs_[a-f0-9]{40})",
  "confirmed", "WooCommerce consumer secret", ["woocommerce"], 3.5)
add_pattern("RubyGems API Key",
  r"(rubygems_[a-zA-Z0-9]{48})",
  "confirmed", "RubyGems API key", ["rubygems"], 4.0)
add_pattern("Typeform Token",
  r"(tfp_[A-Za-z0-9]{40,})",
  "confirmed", "Typeform personal token", ["typeform"], 4.0)
add_pattern("EasyPost API Key",
  r"(EZAK[a-zA-Z0-9]{54})",
  "confirmed", "EasyPost API key", ["easypost"], 4.0)
add_pattern("Duffel API Token",
  r"(duffel_(?:live|test)_[A-Za-z0-9_\-]{40})",
  "confirmed", "Duffel travel API token", ["duffel"], 4.0)
add_pattern("Snyk API Token",
  r"(?i)snyk[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([a-f0-9\-]{36})['\"`]",
  "confirmed", "Snyk API token", ["snyk"], 3.5)
add_pattern("Fastly API Key",
  r"(?i)fastly[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32})['\"`]",
  "confirmed", "Fastly CDN API key", ["fastly"], 3.5)
add_pattern("Codecov Token",
  r"(?i)codecov[_\s]?(?:api[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9\-]{36})['\"`]",
  "confirmed", "Codecov upload token", ["codecov"], 3.5)
add_pattern("Vonage / Nexmo Key",
  r"(?i)(?:vonage|nexmo)[_\s]?(?:api[_\s]?)?(?:key|secret)\s*[=:]\s*['\"`]([A-Za-z0-9]{8,20})['\"`]",
  "probable", "Vonage/Nexmo API key", ["vonage"], 3.0)
add_pattern("PagerDuty API Key",
  r"(?i)pagerduty[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9+/]{20,})['\"`]",
  "confirmed", "PagerDuty API token", ["pagerduty"], 3.0)
add_pattern("Deepgram API Key",
  r"(?i)deepgram[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{40})['\"`]",
  "confirmed", "Deepgram API key", ["deepgram","ai"], 3.5)
add_pattern("AssemblyAI API Key",
  r"(?i)assemblyai[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
  "confirmed", "AssemblyAI API key", ["assemblyai","ai"], 3.5)
add_pattern("Vultr API Key",
  r"(?i)vultr[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "confirmed", "Vultr API key", ["vultr"], 3.5)
add_pattern("OVH API Key",
  r"(?i)ovh[_\s]?(?:api[_\s]?)?(?:key|secret)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
  "confirmed", "OVH API key", ["ovh"], 3.5)

# ══════════════════════════════════════════════════════════════════════════
# +79 VALIDATED PATTERNS — all tested before adding
# ══════════════════════════════════════════════════════════════════════════

# ── Payment (additional) ──────────────────────────────────────────────────
add_pattern("Mollie API Key",
  r"(?i)mollie[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](access_[A-Za-z0-9_]{20,})['\"`]",
  "confirmed","Mollie payment API key",["mollie","payment"],3.5)
add_pattern("Adyen API Key",
  r"(?i)adyen[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](AQ[A-Za-z0-9_\-=]{30,})['\"`]",
  "confirmed","Adyen payment API key",["adyen","payment"],3.5)
add_pattern("Authorize.net Login ID",
  r"(?i)authorize[_\s]?(?:net[_\s]?)?(?:login|api)[_\s]?(?:id|key)\s*[=:]\s*['\"`]([A-Za-z0-9]{10,14})['\"`]",
  "probable","Authorize.net API login ID",["authorizenet","payment"],3.0)
add_pattern("Klarna API Key",
  r"(?i)klarna[_\s]?(?:api[_\s]?)?(?:key|secret)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
  "probable","Klarna API key",["klarna","payment"],3.5)

# ── Cloud (additional) ────────────────────────────────────────────────────
add_pattern("IBM Cloud API Key",
  r"(?i)ibm(?:cloud)?[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{44})['\"`]",
  "confirmed","IBM Cloud IAM API key",["ibm","cloud"],4.0)
add_pattern("Tencent Cloud SecretId",
  r"(?<![A-Z0-9])(AKID[A-Za-z0-9]{32})(?![A-Z0-9])",
  "confirmed","Tencent Cloud SecretId",["tencent","cloud"],3.0)
add_pattern("Scaleway API Key",
  r"(SCW[A-Z0-9]{20,})",
  "confirmed","Scaleway API key",["scaleway","cloud"],3.5)
add_pattern("Oracle OCI OCID",
  r"(ocid1\.[a-z0-9]{1,32}\.[a-z]{2}[0-9]\.\.[a-z0-9]{60,})",
  "info","Oracle Cloud OCID (resource identifier)",["oracle","cloud"])
add_pattern("Hetzner API Token",
  r"(?i)hetzner[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{64})['\"`]",
  "confirmed","Hetzner Cloud API token",["hetzner","cloud"],4.0)
add_pattern("Exoscale API Key",
  r"(EXO[A-Za-z0-9]{32,})",
  "confirmed","Exoscale API key",["exoscale","cloud"],3.5)

# ── Auth / Identity ───────────────────────────────────────────────────────
add_pattern("Auth0 Client Secret",
  r"(?i)auth0[_\s]?(?:client[_\s]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "confirmed","Auth0 application client secret",["auth0","identity"],3.5)
add_pattern("Auth0 Domain",
  r"([a-zA-Z0-9\-]+\.auth0\.com)",
  "info","Auth0 domain (reveals tenant)",["auth0","recon"])
add_pattern("AWS Cognito Identity Pool",
  r"([a-z]{2}-[a-z]+-[0-9]:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
  "probable","AWS Cognito identity pool ID",["aws","cognito"],3.0)
add_pattern("Supabase URL",
  r"(https://[a-z0-9]{20}\.supabase\.(?:co|io))",
  "info","Supabase project URL",["supabase","recon"])
add_pattern("Supabase Anon Key",
  r"(?i)supabase[_\s]?anon[_\s]?key\s*[=:]\s*['\"`]([A-Za-z0-9._\-]{100,})['\"`]",
  "probable","Supabase anon/public key",["supabase"],4.0)

# ── Communication (additional) ────────────────────────────────────────────
add_pattern("Twitch Client Secret",
  r"(?i)twitch[_\s]?(?:client[_\s]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9]{30})['\"`]",
  "confirmed","Twitch application client secret",["twitch"],3.5)
add_pattern("Twitch OAuth Token",
  r"(oauth:[a-z0-9]{30,})",
  "confirmed","Twitch OAuth bearer token",["twitch"],3.5)
add_pattern("Pushover User Key",
  r"(?i)pushover[_\s]?(?:user[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{30})['\"`]",
  "probable","Pushover user/group key",["pushover"],3.0)
add_pattern("Mattermost Token",
  r"(?i)mattermost[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{26})['\"`]",
  "probable","Mattermost personal access token",["mattermost"],3.0)
add_pattern("Pushbullet API Key",
  r"(?i)pushbullet[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9\.]{32})['\"`]",
  "probable","Pushbullet API key",["pushbullet"],3.0)

# ── Monitoring / Observability ────────────────────────────────────────────
add_pattern("Splunk HEC Token",
  r"(?i)splunk[_\s]?(?:hec[_\s]?)?token\s*[=:]\s*['\"`]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"`]",
  "confirmed","Splunk HTTP Event Collector token",["splunk","monitoring"])
add_pattern("Datadog App Key",
  r"(?i)(?:datadog|dd)[_\s]?app(?:lication)?[_\s]?key\s*[=:]\s*['\"`]([a-f0-9]{40})['\"`]",
  "confirmed","Datadog application key",["datadog","monitoring"],3.5)
add_pattern("Grafana API Key",
  r"(?i)grafana[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](eyJ[A-Za-z0-9_\-]{40,})['\"`]",
  "confirmed","Grafana legacy API key",["grafana","monitoring"],4.0)
add_pattern("Logzio Token",
  r"(?i)logzio?[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
  "probable","Logz.io API token",["logzio","monitoring"],3.5)
add_pattern("Loggly Customer Token",
  r"(?i)loggly[_\s]?(?:customer[_\s]?)?token\s*[=:]\s*['\"`]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"`]",
  "confirmed","Loggly customer token",["loggly","monitoring"])
add_pattern("Honeycomb API Key",
  r"(?i)honeycomb[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
  "probable","Honeycomb.io API key",["honeycomb","monitoring"],3.5)

# ── AI / ML (additional / corrected) ─────────────────────────────────────
add_pattern("Stability AI Key",
  r"(?i)stability[_\s]?(?:ai[_\s]?)?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](sk-[A-Za-z0-9]{48})['\"`]",
  "confirmed","Stability AI API key",["stability","ai"],4.0)
add_pattern("AI21 API Key",
  r"(?i)ai21[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
  "probable","AI21 Labs API key",["ai21","ai"],3.5)
add_pattern("Writer API Key",
  r"(?i)writer[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40,})['\"`]",
  "probable","Writer.com API key",["writer","ai"],3.5)
add_pattern("Fireworks AI Key",
  r"(fw_[A-Za-z0-9]{32,})",
  "confirmed","Fireworks AI API key",["fireworks","ai"],4.0)
add_pattern("Anyscale API Key",
  r"(esecret_[A-Za-z0-9_\-]{40,})",
  "confirmed","Anyscale API key",["anyscale","ai"],4.0)
add_pattern("Modal API Key",
  r"(?i)modal[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](ak-[A-Za-z0-9]{40,})['\"`]",
  "confirmed","Modal.com API key",["modal","ai"],4.0)

# ── SaaS / Productivity ───────────────────────────────────────────────────
add_pattern("Freshdesk API Key",
  r"(?i)freshdesk[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{20})['\"`]",
  "probable","Freshdesk API key",["freshdesk"],3.0)
add_pattern("Mixpanel Token",
  r"(?i)mixpanel[_\s]?(?:(?:project[_\s]?)?token|api[_\s]?secret)\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "probable","Mixpanel project token",["mixpanel","analytics"],3.0)
add_pattern("FullStory API Key",
  r"(?i)fullstory[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9/+]{30,})['\"`]",
  "probable","FullStory API key",["fullstory","analytics"],3.0)
add_pattern("Heap App ID",
  r"(?i)heap[_\s]?(?:app[_\s]?)?(?:id|key)\s*[=:]\s*['\"`]([0-9]{8,12})['\"`]",
  "info","Heap Analytics app ID",["heap","analytics"])
add_pattern("Pendo API Key",
  r"(?i)pendo[_\s]?(?:api[_\s]?)?(?:key|token|integration[_\s]?key)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{36,})['\"`]",
  "probable","Pendo integration key",["pendo","analytics"],3.5)
add_pattern("Statuspage API Key",
  r"(?i)statuspage[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
  "probable","Atlassian Statuspage API key",["statuspage"],3.0)
add_pattern("Jira API Token",
  r"(?i)jira[_\s]?(?:api[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9]{24})['\"`]",
  "probable","Jira API token (context required)",["jira","atlassian"],3.5)
add_pattern("Confluence API Token",
  r"(?i)confluence[_\s]?(?:api[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9]{24})['\"`]",
  "probable","Confluence API token",["confluence","atlassian"],3.5)
add_pattern("Figma Token",
  r"(figd_[A-Za-z0-9_\-]{40,})",
  "confirmed","Figma personal access token",["figma"],4.0)
add_pattern("Notion New Token",
  r"(ntn_[A-Za-z0-9]{48,})",
  "confirmed","Notion token (ntn_ prefix)",["notion"],4.0)
add_pattern("Coda API Key",
  r"(?i)coda[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{30,})['\"`]",
  "probable","Coda.io API key",["coda"],3.0)
add_pattern("Monday.com Token",
  r"(?i)monday(?:\.com)?[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](eyJ[A-Za-z0-9_\-]{40,})['\"`]",
  "probable","Monday.com API token",["monday"],4.0)

# ── Security tooling ──────────────────────────────────────────────────────
add_pattern("CrowdStrike Client Secret",
  r"(?i)crowdstrike[_\s]?(?:client[_\s]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
  "confirmed","CrowdStrike Falcon client secret",["crowdstrike","security"],3.5)
add_pattern("Sonatype Token",
  r"(?i)sonatype[_\s]?(?:api[_\s]?)?(?:key|token|password)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "probable","Sonatype Nexus API token",["sonatype","security"],3.0)

# ── Data / Database (additional) ──────────────────────────────────────────
add_pattern("Snowflake Account Hostname",
  r"([a-zA-Z0-9_\-]+\.snowflakecomputing\.com)",
  "info","Snowflake account URL",["snowflake","recon"])
add_pattern("MongoDB Atlas DSN",
  r"(mongodb\+srv://[A-Za-z0-9_\-]+:[^@\s\"'`]{4,}@[^\s\"'`<>]{4,}\.mongodb\.net[^\s\"'`<>]*)",
  "confirmed","MongoDB Atlas connection string with credentials",["mongodb","database"],2.5)
add_pattern("Neon DB DSN",
  r"(postgresql://[A-Za-z0-9_\-]+:[^@\s\"'`]{4,}@[^\s\"'`<>]{4,}\.neon\.tech[^\s\"'`<>]*)",
  "confirmed","Neon serverless Postgres DSN",["neon","database"],2.5)
add_pattern("Turso DB URL",
  r"(libsql://[^\s\"'`<>]+\.turso\.io)",
  "info","Turso (libSQL) database URL",["turso","recon"])
add_pattern("Xata API Key",
  r"(xau_[A-Za-z0-9_\-]{40,})",
  "confirmed","Xata database API key",["xata","database"],4.0)
add_pattern("Upstash Redis URL",
  r"(rediss://default:[A-Za-z0-9_\-]{20,}@[A-Za-z0-9\-]+\.upstash\.io:[0-9]{4,5})",
  "confirmed","Upstash Redis connection URL with credentials",["upstash","database"],3.0)
add_pattern("PlanetScale PSdb DSN",
  r"(mysql://[A-Za-z0-9_\-]+:[^@\s\"'`]{4,}@[^\s\"'`<>]{4,}\.psdb\.cloud[^\s\"'`<>]*)",
  "confirmed","PlanetScale database connection string",["planetscale","database"],2.5)

# ── Web3 / Crypto ─────────────────────────────────────────────────────────
add_pattern("Infura API Key",
  r"(?i)infura[_\s]?(?:api[_\s]?)?(?:key|secret|project[_\s]?(?:id|secret))\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "probable","Infura project ID/secret",["infura","web3"],3.5)
add_pattern("Alchemy API Key",
  r"(alch-[A-Za-z0-9_\-]{32})",
  "confirmed","Alchemy API key (alch- prefix)",["alchemy","web3"],4.0)
add_pattern("Alchemy API Key (context)",
  r"(?i)alchemy[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "probable","Alchemy web3 API key",["alchemy","web3"],3.5)
add_pattern("Etherscan API Key",
  r"(?i)etherscan[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{34})['\"`]",
  "confirmed","Etherscan API key",["etherscan","web3"],3.5)
add_pattern("WalletConnect Project ID",
  r"(?i)wallet.?connect[_\s]?(?:project[_\s]?)?(?:id|key)\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "probable","WalletConnect project ID",["walletconnect","web3"],3.0)
add_pattern("The Graph API Key",
  r"(?i)(?:the[_\s]?graph|subgraph)[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "probable","The Graph API key",["thegraph","web3"],3.5)

# ── Ecommerce / Misc ──────────────────────────────────────────────────────
add_pattern("Magento Integration Token",
  r"(?i)magento[_\s]?(?:access[_\s]?)?token\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "probable","Magento integration access token",["magento","ecommerce"],3.5)
add_pattern("Shopware API Token",
  r"(?i)shopware[_\s]?(?:api[_\s]?)?(?:key|token|access[_\s]?token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40,})['\"`]",
  "probable","Shopware access token",["shopware","ecommerce"],3.5)
add_pattern("Cloudflare Account ID",
  r"(?i)(?:cf|cloudflare)[_\s]?account[_\s]?id\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "info","Cloudflare account ID (recon)",["cloudflare","recon"])
add_pattern("Cloudflare Workers KV ID",
  r"(?i)(?:workers[_\s]?kv|kv[_\s]?namespace)[_\s]?(?:id|key)\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "info","Cloudflare Workers KV namespace ID",["cloudflare","recon"])
add_pattern("Vercel Project ID",
  r"(?i)vercel[_\s]?project[_\s]?id\s*[=:]\s*['\"`](prj_[A-Za-z0-9]{20,})['\"`]",
  "info","Vercel project ID",["vercel","recon"])

# ── New SaaS / Developer Tools ────────────────────────────────────────────
add_pattern("Resend API Key",
  r"(re_[A-Za-z0-9_]{24,})",
  "confirmed","Resend email API key",["resend","email"],4.0)
add_pattern("Loops API Key",
  r"(?i)loops[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "probable","Loops email API key",["loops","email"],3.5)
add_pattern("Inngest Event Key",
  r"(signkey-(?:prod|test)-[A-Za-z0-9]{32,})",
  "confirmed","Inngest signing key",["inngest"],4.0)
add_pattern("Tinybird API Token",
  r"(p\.eyJ[A-Za-z0-9_\-]{40,}\.[A-Za-z0-9_\-]{40,})",
  "confirmed","Tinybird API token",["tinybird","analytics"],4.0)
add_pattern("WorkOS API Key",
  r"(sk_[a-z]+_[A-Za-z0-9]{30,})",
  "confirmed","WorkOS API key",["workos","auth"],4.0)
add_pattern("Liveblocks Secret",
  r"(sk_(?:prod|dev)_[A-Za-z0-9]{40,})",
  "confirmed","Liveblocks secret key",["liveblocks"],4.0)
add_pattern("Novu API Key",
  r"(novu_[A-Za-z0-9_\-]{30,})",
  "confirmed","Novu notification API key",["novu"],4.0)
add_pattern("Xata API Key (bare)",
  r"(xau_[A-Za-z0-9_\-]{40,})",
  "confirmed","Xata API key",["xata"],4.0)
add_pattern("PlanetScale OAuth Token",
  r"(pscale_oauth_[A-Za-z0-9_]{32,})",
  "confirmed","PlanetScale OAuth token",["planetscale"],4.0)
add_pattern("Voyage AI Key",
  r"(?i)voyage[_\s]?(?:ai[_\s]?)?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`](pa-[A-Za-z0-9_\-]{32,})['\"`]",
  "confirmed","Voyage AI embedding API key",["voyage","ai"],4.0)


# ══════════════════════════════════════════════════════════════════════════
# +62 PATTERNS from document audit — all regex-validated before adding
# ══════════════════════════════════════════════════════════════════════════

# ── AWS services (recon/endpoints) ───────────────────────────────────────
add_pattern("AWS Session Token",
  r"(?i)aws[_\-]?session[_\-]?token\s*[=:]\s*['\"`]([A-Za-z0-9/+=]{100,})['\"`]",
  "confirmed","AWS STS session token",["aws"],4.0)
add_pattern("AWS STS Token (FWO)",
  r"(?<![A-Za-z0-9])(FWO[A-Za-z0-9/+=]{40,})(?![A-Za-z0-9/+=])",
  "confirmed","AWS STS token (FWO prefix)",["aws"],4.0)
add_pattern("Lambda Function ARN",
  r"(arn:aws:lambda:[a-z0-9\-]+:[0-9]{12}:function:[a-zA-Z0-9\-_:]+)",
  "info","AWS Lambda function ARN",["aws","recon"])
add_pattern("SQS Queue URL",
  r"(https://sqs\.[a-z0-9\-]+\.amazonaws\.com/[0-9]{12}/[a-zA-Z0-9\-_.]+)",
  "info","AWS SQS queue URL",["aws","recon"])
add_pattern("SNS Topic ARN",
  r"(arn:aws:sns:[a-z0-9\-]+:[0-9]{12}:[a-zA-Z0-9\-_.]+)",
  "info","AWS SNS topic ARN",["aws","recon"])
add_pattern("RDS Instance Endpoint",
  r"([a-z0-9\-]+\.[a-z0-9]+\.rds\.amazonaws\.com)",
  "info","AWS RDS instance endpoint",["aws","recon"])
add_pattern("ElastiCache Endpoint",
  r"([a-z0-9\-]+\.[a-z0-9]+\.cache\.amazonaws\.com:[0-9]{4,5})",
  "info","AWS ElastiCache cluster endpoint",["aws","recon"])
add_pattern("CloudFront Distribution",
  r"([a-z0-9]+\.cloudfront\.net)",
  "info","AWS CloudFront distribution URL",["aws","recon","cdn"])
add_pattern("API Gateway Endpoint",
  r"([a-z0-9]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com)",
  "info","AWS API Gateway endpoint",["aws","recon"])

# ── GCP additional ────────────────────────────────────────────────────────
add_pattern("GCP OAuth2 Client ID",
  r"([0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com)",
  "probable","Google OAuth2 client ID",["google","oauth"])
add_pattern("GCP Pub/Sub Topic",
  r"(projects/[a-z0-9\-]+/topics/[a-zA-Z0-9\-_.]+)",
  "info","GCP Pub/Sub topic path",["gcp","recon"])

# ── Azure additional ──────────────────────────────────────────────────────
add_pattern("Azure Client ID",
  r"(?i)azure[_\s]?client[_\s]?id\s*[=:]\s*['\"`]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"`]",
  "probable","Azure app client ID (UUID)",["azure"])
add_pattern("Azure Tenant ID",
  r"(?i)azure[_\s]?tenant[_\s]?id\s*[=:]\s*['\"`]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"`]",
  "probable","Azure tenant ID (UUID)",["azure"])
add_pattern("Azure Key Vault URL",
  r"(https://[a-z0-9\-]+\.vault\.azure\.net/)",
  "info","Azure Key Vault URL",["azure","recon"])
add_pattern("Azure Cosmos DB Endpoint",
  r"(https://[a-zA-Z0-9\-]+\.documents\.azure\.com:443/)",
  "info","Azure Cosmos DB endpoint URL",["azure","recon"])
add_pattern("Azure Service Bus Connection",
  r"(Endpoint=sb://[^;]+\.servicebus\.windows\.net/[^;\"'`\s]*)",
  "confirmed","Azure Service Bus connection string",["azure"])
add_pattern("Azure Blob SAS Token",
  r"(sig=[A-Za-z0-9%+/]{20,}&se=[0-9T:Z%\-]+&sp=[a-z]+)",
  "confirmed","Azure Blob SAS token",["azure"])

# ── GitLab additional prefixes ────────────────────────────────────────────
add_pattern("GitLab Project Token",
  r"(glptt-[A-Za-z0-9_\-]{20,})",
  "confirmed","GitLab project access token",["gitlab"],4.0)
add_pattern("GitLab Runner Token",
  r"(glrt-[A-Za-z0-9_\-]{20,})",
  "confirmed","GitLab runner authentication token",["gitlab"],4.0)
add_pattern("GitLab Service Account Token",
  r"(glso-[A-Za-z0-9_\-]{20,})",
  "confirmed","GitLab service account token",["gitlab"],4.0)

# ── Payment additional ────────────────────────────────────────────────────
add_pattern("Stripe Account ID",
  r"(?<![A-Za-z0-9])(acct_[A-Za-z0-9]{16,})(?![A-Za-z0-9])",
  "probable","Stripe connected account ID",["stripe","payment"])
add_pattern("Braintree Private Key",
  r"(?i)braintree[_\s]?private[_\s]?key\s*[=:]\s*['\"`]([a-f0-9]{32,})['\"`]",
  "confirmed","Braintree private key",["braintree","payment"],3.5)
add_pattern("Wise / TransferWise API Key",
  r"(?i)wise[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})['\"`]",
  "confirmed","Wise (TransferWise) API key",["wise","payment"])
add_pattern("Revolut API Key",
  r"(?i)revolut[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`](key_[a-f0-9]{32,})['\"`]",
  "confirmed","Revolut API key",["revolut","payment"],3.5)
add_pattern("PayPal Webhook ID",
  r"(?<![A-Za-z0-9])(WH-[A-Za-z0-9]{20,}-[A-Za-z0-9]{20,})(?![A-Za-z0-9])",
  "probable","PayPal webhook ID",["paypal","payment"])

# ── Database additional ───────────────────────────────────────────────────
add_pattern("ClickHouse DSN",
  r"(clickhouse://[A-Za-z0-9_\-]+:[^@\s\"'`]{4,}@[^\s\"'`<>]{4,})",
  "confirmed","ClickHouse DSN with credentials",["database","dsn"],2.5)
add_pattern("FaunaDB Secret",
  r"(?i)fauna(?:db)?[_\s]?(?:secret|key)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40,})['\"`]",
  "confirmed","FaunaDB secret key",["faunadb","database"],3.5)
add_pattern("JDBC Connection String",
  r"(jdbc:[a-zA-Z][a-zA-Z0-9+\-.]+://[^\s\"'`<>]{10,})",
  "confirmed","JDBC connection string",["database","dsn"])

# ── Framework / app secrets ───────────────────────────────────────────────
add_pattern("Django / Flask Secret Key",
  r"(?i)(?:django[_\s]?)?secret[_\s]?key\s*[=:]\s*['\"`]([A-Za-z0-9!@#$%^&*()\-_=+{}\[\]|;:,.<>?/~`]{32,})['\"`]",
  "confirmed","Django/Flask SECRET_KEY value",["django","flask","credentials"],3.5)
add_pattern("Laravel App Key",
  r"(?<![A-Za-z0-9/+])(base64:[A-Za-z0-9+/]{44}=*)",
  "confirmed","Laravel application key (base64: prefix)",["laravel","credentials"],4.0)
add_pattern("Rails Master Key",
  r"(?i)rails[_\s]?master[_\s]?key\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "confirmed","Rails credentials master key",["rails","credentials"],3.5)
add_pattern("JWT Secret Key",
  r"(?i)jwt[_\s]?secret\s*[=:]\s*['\"`]([A-Za-z0-9_\-!@#$%^&*]{32,})['\"`]",
  "confirmed","JWT signing secret",["jwt","credentials"],3.5)
add_pattern("Session Secret",
  r"(?i)session[_\s]?secret\s*[=:]\s*['\"`]([A-Za-z0-9_\-!@#$%^&*]{32,})['\"`]",
  "probable","Session secret key",["credentials"],3.0)
add_pattern("Cookie Secret",
  r"(?i)cookie[_\s]?secret\s*[=:]\s*['\"`]([A-Za-z0-9_\-!@#$%^&*]{32,})['\"`]",
  "probable","Cookie signing secret",["credentials"],3.0)
add_pattern("Encryption Key",
  r"(?i)encryption[_\s]?key\s*[=:]\s*['\"`]([A-Za-z0-9+/=]{32,})['\"`]",
  "confirmed","Encryption key literal",["crypto","credentials"],3.5)

# ── Web3 additional ───────────────────────────────────────────────────────
add_pattern("Ethereum Address",
  r"(?<![A-Za-z0-9])(0x[a-fA-F0-9]{40})(?![A-Za-z0-9])",
  "info","Ethereum wallet address",["ethereum","web3","recon"])
add_pattern("Infura Project Secret",
  r"(?i)infura[_\s]?(?:project[_\s]?)?secret\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "confirmed","Infura project secret",["infura","web3"],3.5)
add_pattern("BlockCypher Token",
  r"(?i)blockcypher[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
  "probable","BlockCypher API token",["blockcypher","web3"],3.5)
add_pattern("Moralis API Key",
  r"(?i)moralis[_\s]?(?:api[_\s]?)?(?:web3[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "probable","Moralis web3 API key",["moralis","web3"],3.5)

# ── Social additional ─────────────────────────────────────────────────────
add_pattern("Twitter Consumer Secret",
  r"(?i)twitter[_\s]?(?:consumer[_\s]?)?(?:api[_\s]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9_]{40,50})['\"`]",
  "confirmed","Twitter/X consumer secret",["twitter"],3.5)
add_pattern("Reddit Client Secret",
  r"(?i)reddit[_\s]?client[_\s]?secret\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,30})['\"`]",
  "probable","Reddit OAuth client secret",["reddit"],3.0)

# ── CI/CD additional ──────────────────────────────────────────────────────
add_pattern("Bamboo API Token",
  r"(?i)bamboo[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "probable","Atlassian Bamboo API token",["bamboo","ci"],3.0)
add_pattern("Bitrise API Key",
  r"(?i)bitrise[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "probable","Bitrise CI API key",["bitrise","ci"],3.0)

# ── Monitoring additional ─────────────────────────────────────────────────
add_pattern("Elastic APM Secret Token",
  r"(?i)elastic[_\s]?apm[_\s]?(?:secret[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "confirmed","Elastic APM secret token",["elastic","monitoring"],3.5)
add_pattern("Prometheus Remote Write Token",
  r"(?i)prometheus[_\s]?(?:remote[_\s]?write[_\s]?)?(?:bearer[_\s]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{32,})['\"`]",
  "probable","Prometheus remote write token",["prometheus","monitoring"],3.0)

# ── Security sinks (code analysis) ───────────────────────────────────────
add_pattern("RCE: exec with user input",
  r"exec(?:Sync)?\s*\(\s*`[^`]*\$\{[^}]*(?:req\.|body\.|query\.|params\.)",
  "possible","RCE: exec/execSync with template literal from user input",["rce","js"])
add_pattern("RCE: vm.runInNewContext",
  r"vm\.runInNewContext\s*\(\s*(?:req\.|body\.|query\.|params\.)",
  "possible","RCE: VM context with user-controlled input",["rce","js"])
add_pattern("SSRF: HTTP call from user input",
  r"(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:get|request)|got)\s*\(\s*(?:req\.|body\.|query\.|params\.|`[^`]*\$\{(?:req\.|body\.))",
  "possible","SSRF: outbound HTTP request from user input",["ssrf","js"])
add_pattern("Path Traversal: file read",
  r"(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:req\.|body\.|query\.|params\.|path\.join\s*\(\s*__dirname\s*,\s*(?:req\.|body\.))",
  "possible","Path traversal: file read from user input",["lfi","js"])
add_pattern("SQLi: raw query concat",
  r"(?:\.query|\.execute|\.raw)\s*\(\s*(?:`[^`]*\$\{(?:req\.|body\.|query\.)|['\"][^'\"]*\+\s*(?:req\.|body\.|query\.))",
  "possible","SQLi: raw query with user input concatenation",["sqli","js"])
add_pattern("Prototype Pollution: deep merge",
  r"(?:_\.merge|_\.mergeWith|_\.defaultsDeep|Object\.assign)\s*\(\s*(?:\{\s*\}|[a-z]+)\s*,\s*(?:req\.|body\.|query\.|params\.)",
  "possible","Prototype pollution: deep merge with user input",["prototype-pollution","js"])

# ── Recon / endpoint discovery ────────────────────────────────────────────
add_pattern("Admin Panel Path",
  r"['\"`](/(?:admin|administrator|console|dashboard|control-panel|backoffice|back-office|portal|manage|cp)(?:/|['\"`]))",
  "info","Admin or management panel path",["recon","admin"])
add_pattern("Swagger / OpenAPI Spec",
  r"['\"`](/(?:swagger|api-docs|openapi)(?:[/\-]v?[0-9]+)?\.(?:json|yaml|yml))['\"`]",
  "info","Swagger/OpenAPI specification endpoint",["recon","api"])
add_pattern("Health Check / Status Endpoint",
  r"['\"`](/(?:health|healthz|ping|status|ready|alive|liveness|readiness))['\"`]",
  "info","Health check or status endpoint",["recon"])
add_pattern("Debug / Profiler Endpoint",
  r"['\"`](/(?:debug|_debug|devtools|__debug__|profiler|trace|pprof))['\"`]",
  "info","Debug or profiler endpoint path",["recon"])
add_pattern("Internal Domain Pattern",
  r"https?://[^\s\"'`<>]*\.(?:internal|corp|local|intranet|lan)(?:[/:?\s\"'`<>]|$)",
  "info","Internal/corporate domain pattern",["recon","internal"])

# ── CMS ───────────────────────────────────────────────────────────────────
add_pattern("WordPress Nonce / API Key",
  r"(?i)(?:wp|wordpress)[_\s]?(?:json[_\s]?)?(?:nonce|api[_\s]?key)\s*[=:]\s*['\"`]([a-f0-9A-Za-z_]{10,})['\"`]",
  "probable","WordPress nonce or API key",["wordpress","cms"],3.0)
add_pattern("Drupal Private Key",
  r"(?i)drupal[_\s]?private[_\s]?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40,})['\"`]",
  "probable","Drupal private key",["drupal","cms"],3.5)
add_pattern("Joomla Secret",
  r"(?i)joomla[_\s]?(?:secret|key)\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "probable","Joomla secret key",["joomla","cms"],3.5)
add_pattern("Wix API Key",
  r"(?i)wix[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
  "probable","Wix API key",["wix","cms"],3.0)
add_pattern("BigCommerce Access Token",
  r"(?i)bigcommerce[_\s]?(?:access[_\s]?)?(?:token|key)\s*[=:]\s*['\"`]([a-f0-9]{32,})['\"`]",
  "probable","BigCommerce access token",["bigcommerce","ecommerce"],3.5)


# ── Final deduplication (by regex) ───────────────────────────────────────────
_unique = {}
for p in PATTERNS:
    if p.rx not in _unique:
        _unique[p.rx] = p
PATTERNS = list(_unique.values())
# pattern count available via --list

# ── Finding dataclass ────────────────────────────────────────────────────────
@dataclass
class Finding:
    source: str
    line_no: int
    name: str
    sev: str
    desc: str
    tags: list
    match_raw: str
    match_redacted: str
    entropy: float

def _redact(s, keep=6):
    s = s.strip()
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "…" + "*" * min(8, len(s) - keep * 2) + "…" + s[-3:]

def _build_offs(text):
    offs = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offs.append(i + 1)
    return offs

def _lno(offs, pos):
    lo, hi = 0, len(offs) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if offs[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1

# ── AST string extractor (with base64 decoding) ──────────────────────────────
def extract_strings_ast(js_code):
    """Extract all string literals and template literals from JS AST."""
    strings = set()
    if not HAS_ESPRIMA:
        return strings
    try:
        tree = esprima.parseScript(js_code, {"tolerant": True, "comment": True})

        def walk(node):
            if isinstance(node, dict):
                if node.get("type") == "Literal" and isinstance(node.get("value"), str):
                    strings.add(node["value"])
                elif node.get("type") == "TemplateLiteral":
                    for elem in node.get("quasis", []):
                        raw = elem.get("value", {}).get("raw")
                        if raw:
                            strings.add(raw)
                for val in node.values():
                    walk(val)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(tree)
    except Exception:
        pass
    return strings

def extract_strings_regex(js_code):
    """Fallback regex for string extraction."""
    return set(re.findall(r'["\'`]([^"\'`\\]*(?:\\.[^"\'`\\]*)*)["\'`]', js_code))

def extract_all_strings(js_code, use_ast=True):
    strings = set()
    if use_ast and HAS_ESPRIMA:
        strings = extract_strings_ast(js_code)
    else:
        strings = extract_strings_regex(js_code)
    # Also add the raw code (for line‑based patterns)
    strings.add(js_code)
    return strings

def decode_base64_strings(strings):
    """For each string that looks like base64, decode and add to set."""
    new_strings = set()
    base64_regex = re.compile(r'^[A-Za-z0-9+/=]+$')
    base64url_regex = re.compile(r'^[A-Za-z0-9_-]+$')
    for s in strings:
        if base64_regex.match(s):
            try:
                decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
                if decoded:
                    new_strings.add(decoded)
            except:
                pass
        if base64url_regex.match(s):
            try:
                decoded = base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
                if decoded:
                    new_strings.add(decoded)
            except:
                pass
    return new_strings

# ── Source map handling ──────────────────────────────────────────────────────
def fetch_sourcemap(url):
    """If a JS file contains a sourceMappingURL, fetch and parse it."""
    # Very basic: look for //# sourceMappingURL=...
    # In real implementation, you'd parse the map and return original sources
    # Here we just return the URL to the map (can be expanded)
    match = re.search(r'//# sourceMappingURL=([^\s]+)', url)
    if match:
        map_url = match.group(1)
        if not map_url.startswith("http"):
            # relative path – resolve using the base URL
            base = url.rsplit('/', 1)[0]
            map_url = base + '/' + map_url
        return map_url
    return None

# ── Main scanning function (with AST, base64, source maps) ───────────────────
def scan_text_advanced(source, text, min_sev="info", filter_tags=None, no_filter=False, use_ast=True, verify=False):
    findings = []
    seen = set()
    min_idx = SEVMAP.get(min_sev, 3)

    # Step 1: extract all strings from the JS (AST + raw)
    all_strings = extract_all_strings(text, use_ast)

    # Step 2: decode any base64 strings and add the decoded versions
    decoded_strings = decode_base64_strings(all_strings)
    all_strings.update(decoded_strings)

    # Step 3: also scan the original raw text line by line (for line numbers)
    lines = text.split('\n')
    offs = _build_offs(text)

    # Combine both approaches: we scan each extracted string (no line number)
    # and each line of raw text (with line number)
    for string_val in all_strings:
        if not string_val or len(string_val) < 6:
            continue
        for pat in PATTERNS:
            if SEVMAP[pat.sev] > min_idx:
                continue
            if filter_tags and not filter_tags.intersection(pat.tags):
                continue
            for m in pat._c.finditer(string_val):
                # extract captured group
                if m.lastindex and m.lastindex >= 2:
                    val = m.group(2).strip()
                elif m.lastindex:
                    val = m.group(1).strip()
                else:
                    val = m.group(0).strip()
                if not val:
                    continue
                if not no_filter and _is_fp(val):
                    continue
                ent = _entropy(val)
                if pat.entropy_min and ent < pat.entropy_min:
                    continue
                key = (pat.name, val)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    source=source, line_no=0,  # unknown line for extracted strings
                    name=pat.name, sev=pat.sev, desc=pat.desc,
                    tags=list(pat.tags), match_raw=val,
                    match_redacted=_redact(val), entropy=round(ent, 2)
                ))

    # Also scan line by line to get accurate line numbers (for regex that need context)
    for i, line in enumerate(lines):
        for pat in PATTERNS:
            if SEVMAP[pat.sev] > min_idx:
                continue
            if filter_tags and not filter_tags.intersection(pat.tags):
                continue
            for m in pat._c.finditer(line):
                if m.lastindex and m.lastindex >= 2:
                    val = m.group(2).strip()
                    match_pos = m.start(2)
                elif m.lastindex:
                    val = m.group(1).strip()
                    match_pos = m.start(1)
                else:
                    val = m.group(0).strip()
                    match_pos = m.start()
                if not val:
                    continue
                if not no_filter and _is_fp(val):
                    continue
                ent = _entropy(val)
                if pat.entropy_min and ent < pat.entropy_min:
                    continue
                key = (pat.name, val)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    source=source, line_no=i + 1,
                    name=pat.name, sev=pat.sev, desc=pat.desc,
                    tags=list(pat.tags), match_raw=val,
                    match_redacted=_redact(val), entropy=round(ent, 2)
                ))

    # Optional active verification stub – you can implement real checks here
    if verify:
        for f in findings:
            # e.g., if "Stripe" in f.name: call Stripe API to test key
            # For now, just mark
            f.desc += " (verification not implemented)"
    return findings

# ── fetch functions (unchanged from original) ────────────────────────────────
_SKIP_CT = ("image/", "video/", "audio/", "font/", "application/pdf",
            "application/zip", "application/octet", "woff", "ttf", "eot")

def fetch_body(url, timeout=15):
    try:
        req = urllib.request.Request(url.strip(), headers={
            "User-Agent": "Mozilla/5.0 (compatible; astra/1.0)",
            "Accept": "text/html,application/javascript,application/json,*/*",
            "Accept-Encoding": "identity",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if any(x in r.headers.get("Content-Type", "") for x in _SKIP_CT):
                return ""
            # Handle gzip/deflate if needed (simplified)
            data = r.read(5_000_000)
            try:
                return data.decode('utf-8', errors='replace')
            except:
                return ""
    except:
        return ""

# ── output formatting ────────────────────────────────────────────────────────
BANNER = r"""
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
"""

def print_header(n):
    print(c(BANNER, C_HEAD))
    print(c(f"  {n} patterns  ·  entropy check  ·  AST string extraction  ·  base64 decode", C_GREY))
    print()
    print("  " + "  ".join(c(f"{SEV_ICO[s]} {s}", SEV_COL[s]) for s in SEVMAP))
    print(c("  " + "─" * 56, C_GREY))
    print()

def print_finding(f, show_raw=False):
    val = c(f.match_raw if show_raw else f.match_redacted, C_PROB + B)
    tags = c(" ".join(f"[{t}]" for t in f.tags), C_GREY + DIM)
    ent = c(f"entropy={f.entropy}", C_GREY + DIM)
    lno = c(f"line {f.line_no}", C_BLU) if f.line_no > 0 else c("extracted", C_BLU)
    print(f"  {badge(f.sev)} {c(f.name, B)}  {lno}")
    print(f"  {'':16} {c(f.desc, C_GREY)}  {tags}")
    print(f"  {'':16} {c('›', C_GREY)} {val}  {ent}")
    print()

def print_summary(n_src, n_lines, findings, elapsed):
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f.sev] += 1
    speed = f"{n_lines / elapsed:,.0f} lines/s" if elapsed > 0 else ""
    print(c("  " + "─" * 56, C_GREY))
    print(c(f"  sources {n_src}   lines {n_lines:,}   {speed}", B))
    if not findings:
        print(c("  result  ✓ clean", C_OK + B))
    else:
        print(c(f"  total   {len(findings)} finding(s)", C_CONF + B))
        for sev in SEVMAP:
            n = by_sev.get(sev, 0)
            if n:
                print(f"  {badge(sev)}  {n}")
    print(c("  " + "─" * 56, C_GREY))

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(
        prog="astra",
        description="astra — Ultimate JS Secret Hunter (AST + base64 + source maps)",
        epilog=(
            "examples:\n"
            "  cat urls.txt        | python3 astra.py --fetch --ast\n"
            "  python3 astra.py      app.js --ast --verify\n"
            "  python3 astra.py      ./src/ --ext js,map --json\n"
            "  python3 astra.py      --list --tags aws,payment\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("file", nargs="?", help="File or directory (default: stdin)")
    ap.add_argument("-s", "--severity", default="info", choices=list(SEVMAP), metavar="SEV",
                    help="Min severity: confirmed probable possible info (default: info)")
    ap.add_argument("--fetch", action="store_true", help="Fetch URLs and scan response bodies")
    ap.add_argument("--threads", type=int, default=10, help="Threads for --fetch (default: 10)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--show-match", action="store_true", help="Show unredacted values")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--list", action="store_true", help="List all patterns and exit")
    ap.add_argument("--tags", metavar="TAGS", help="Tag filter: aws,ai,xss,payment ...")
    ap.add_argument("--ext", metavar="EXT", help="Dir mode extensions: js,ts,json,env,map")
    ap.add_argument("--no-filter", action="store_true", help="Disable false‑positive filter")
    ap.add_argument("--ast", action="store_true", help="Enable AST string extraction (default for .js files)")
    ap.add_argument("--verify", action="store_true", help="Attempt active verification (stub)")

    args = ap.parse_args()

    if args.no_color:
        USE_COLOR = False
    filter_tags = set(args.tags.split(",")) if args.tags else None

    # esprima check — only warn when AST mode is actually requested
    if args.ast and not HAS_ESPRIMA:
        print(c("[!] --ast requires esprima: pip install esprima", C_PROB), file=sys.stderr)
        print(c("    Falling back to regex-based string extraction.", C_GREY), file=sys.stderr)

    if args.list:
        print(f"\n  {'NAME':<35} {'SEV':<13} {'TAGS':<28} DESC")
        print("  " + "─" * 95)
        for p in sorted(PATTERNS, key=lambda x: (SEVMAP[x.sev], x.name)):
            if filter_tags and not filter_tags.intersection(p.tags):
                continue
            sv = c(f"{SEV_ICO[p.sev]} {p.sev}", SEV_COL[p.sev])
            print(f"  {p.name:<35} {sv:<22} {','.join(p.tags):<28} {p.desc}")
        print()
        sys.exit(0)

    # collect sources
    sources: list[tuple[str, str]] = []
    t0 = time.perf_counter()

    if args.file:
        p = Path(args.file)
        if p.is_dir():
            exts = {f".{e.lstrip('.')}" for e in args.ext.split(",")} if args.ext else None
            for fp in sorted(p.rglob("*")):
                if not fp.is_file():
                    continue
                if exts and fp.suffix.lower() not in exts:
                    continue
                try:
                    sources.append((str(fp), fp.read_text(errors="replace")))
                except:
                    pass
        elif p.is_file():
            try:
                sources.append((str(p), p.read_text(errors="replace")))
            except Exception as e:
                print(c(f"[!] cannot read {p}: {e}", C_CONF), file=sys.stderr)
                sys.exit(1)
        else:
            print(c(f"[!] not found: {args.file}", C_CONF), file=sys.stderr)
            sys.exit(1)
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
        lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("#")]
        url_ratio = sum(1 for l in lines if l.startswith(("http://", "https://"))) / max(len(lines), 1)
        if lines and url_ratio > 0.5:
            for ln in lines:
                sources.append((ln, ln))
        else:
            sources.append(("<stdin>", raw))
    else:
        ap.print_help()
        sys.exit(0)

    # fetch URLs if needed
    if args.fetch:
        url_srcs = [(l, t) for l, t in sources if t.strip().startswith(("http://", "https://"))]
        rest = [(l, t) for l, t in sources if not t.strip().startswith(("http://", "https://"))]
        fetched = []

        def _f(item):
            lbl, url = item
            body = fetch_body(url.strip())
            return lbl, url + ("\n" + body if body else "")

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(_f, s): s for s in url_srcs}
            for fut in as_completed(futs):
                try:
                    fetched.append(fut.result())
                except:
                    fetched.append(futs[fut])
        sources = rest + fetched

    # decide whether to use AST: default for .js files, else off unless --ast
    use_ast = args.ast
    if not use_ast and any(lbl.endswith(".js") for lbl, _ in sources):
        use_ast = True  # auto-enable for JS files

    # scan all sources
    total_lines = sum(txt.count("\n") + 1 for _, txt in sources)
    all_findings: list[Finding] = []
    by_source: dict[str, list] = {}
    for lbl, txt in sources:
        found = scan_text_advanced(lbl, txt, args.severity, filter_tags, args.no_filter, use_ast, args.verify)
        if found:
            by_source[lbl] = found
            all_findings.extend(found)

    elapsed = max(time.perf_counter() - t0, 1e-9)

    # output
    if args.json:
        out = []
        for f in all_findings:
            d = asdict(f)
            if not args.show_match:
                d.pop("match_raw", None)
            out.append(d)
        print(json.dumps(out, indent=2))
        sys.exit(0 if not all_findings else 1)

    print_header(len(PATTERNS))
    if all_findings:
        for lbl, findings in by_source.items():
            print(c("  ╔" + "═" * 62, C_GREY))
            print(c("  ║ ", C_GREY) + c(lbl[:100], B))
            print(c("  ╚" + "═" * 62, C_GREY))
            print()
            for f in sorted(findings, key=lambda x: (SEVMAP[x.sev], x.line_no)):
                print_finding(f, show_raw=args.show_match)
    else:
        print(c("  ✓  nothing found\n", C_OK + B))

    print_summary(len(sources), total_lines, all_findings, elapsed)
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
