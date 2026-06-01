#!/usr/bin/env python3
"""
astra — secret & credential scanner
  cat urls.txt        | python3 astra.py
  cat bundle.min.js   | python3 astra.py
  python3 astra.py    app.js
  python3 astra.py    ./src/ --ext js,ts,json,env
  python3 astra.py    urls.txt --fetch
  python3 astra.py    app.js --json
  python3 astra.py    --list
"""

import re, sys, json, argparse, math, time
import urllib.request, urllib.error
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── colour ────────────────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; DIM="\033[2m"
C_CONF="\033[38;5;196m"; C_PROB="\033[38;5;214m"
C_POSS="\033[38;5;220m"; C_INFO="\033[38;5;39m"
C_OK  ="\033[38;5;82m";  C_GREY="\033[38;5;244m"
C_HEAD="\033[38;5;213m"; C_BLU ="\033[38;5;75m"
USE_COLOR = True
def c(t, col): return f"{col}{t}{R}" if USE_COLOR else t

SEVMAP  = {"confirmed":0,"probable":1,"possible":2,"info":3}
SEV_COL = {"confirmed":C_CONF,"probable":C_PROB,"possible":C_POSS,"info":C_INFO}
SEV_ICO = {"confirmed":"◆","probable":"◇","possible":"○","info":"·"}
def badge(sev): return c(f" {SEV_ICO[sev]} {sev.upper():<12}", SEV_COL[sev]+B)

# ── entropy ───────────────────────────────────────────────────────────────────
def _entropy(s):
    if not s: return 0.0
    freq = defaultdict(int)
    for ch in s: freq[ch] += 1
    l = len(s)
    return -sum((v/l)*math.log2(v/l) for v in freq.values())

# ── false-positive filter ─────────────────────────────────────────────────────
_FP_EXACT = frozenset({
    "null","none","undefined","false","true","empty","n/a","na","todo",
    "fixme","redacted","changeme","password","secret","apikey","api_key",
    "token","example","test","sample","dummy","placeholder","your_token",
    "your_key","your_secret","insert_here","xxx","yyy","zzz","1234567890",
    "abcdefghij","0000000000","xxxxxxxxxxxx",
})
_FP_RX = re.compile(
    r"^(?:your[-_]?|my[-_]?|test[-_]?|example[-_]?|sample[-_]?|"
    r"fake[-_]?|mock[-_]?|demo[-_]?|dummy[-_]?|"
    r"<[^>]+>|\$\{[^}]+\}|%[A-Z_]{2,}%|\{\{[^}]+\}\}|"
    r"__[A-Z_]+__|##[A-Z_]+##)", re.I)

def _is_fp(val):
    v = val.strip()
    if len(v) < 8:             return True
    if v.lower() in _FP_EXACT: return True
    if _FP_RX.match(v):        return True
    if len(set(v.lower())) < 5: return True
    return False

# ── pattern ───────────────────────────────────────────────────────────────────
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
        self._c = re.compile(self.rx, re.IGNORECASE|re.MULTILINE)

# ════════════════════════════════════════════════════════════════════════════
# PATTERNS — design contract:
#   • Self-contained unique prefixes (AKIA, sk_live_, glpat-) → no context needed
#   • Generic KV patterns (api_key=, password=) → MUST have quoted value
#   • Standalone short prefixes (AC, SK, 00) → REMOVED; require assignment context
#   • entropy_min tuned per character-space of real tokens
# ════════════════════════════════════════════════════════════════════════════
PATTERNS: list[P] = [

    # ── AWS ───────────────────────────────────────────────────────────────────
    P("AWS Access Key ID",
      r"(?<![A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])",
      "confirmed","AWS access key ID",["aws","cloud"],3.0),
    P("AWS Secret Access Key",
      r"(?i)(?:aws_secret(?:_access)?_key|aws_secret)\s*[=:]\s*['\"`]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
      "confirmed","AWS secret access key",["aws","cloud"],4.5),
    P("Amazon MWS Auth Token",
      r"(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
      "confirmed","Amazon MWS auth token",["aws","cloud"]),

    # ── Google / GCP ──────────────────────────────────────────────────────────
    P("Google API Key",
      r"(AIza[0-9A-Za-z\-_]{35})",
      "confirmed","Google API key (Maps, Gemini, etc.)",["google","cloud","ai"]),
    P("Google OAuth Token",
      r"(ya29\.[0-9A-Za-z\-_]{20,})",
      "confirmed","Google OAuth 2.0 access token",["google","cloud"]),
    P("Google OAuth2 Client Secret",
      r"(GOCSPX-[A-Za-z0-9_\-]{28})",
      "confirmed","Google OAuth2 client secret",["google","cloud"]),
    P("Google reCAPTCHA Key",
      r"(6L[0-9A-Za-z\-_]{38})",
      "probable","Google reCAPTCHA key",["google"],3.5),
    P("Firebase FCM Server Key",
      r"(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})",
      "confirmed","Firebase Cloud Messaging server key",["firebase","google"]),
    P("GCP Service Account JSON",
      r'"type"\s*:\s*"service_account"',
      "confirmed","GCP service account credential block",["gcp","google","cloud"]),

    # ── Azure ─────────────────────────────────────────────────────────────────
    P("Azure Storage Connection String",
      r"(DefaultEndpointsProtocol=https;AccountName=[^;]{1,60};AccountKey=[A-Za-z0-9+/=]{88}[^;\"'`\s]*)",
      "confirmed","Azure Storage connection string",["azure","cloud"]),
    P("Azure OpenAI Endpoint",
      r"(https://[a-z0-9\-]+\.openai\.azure\.com/openai/deployments/[^\s\"'`<>]+)",
      "probable","Azure OpenAI deployment endpoint (may expose resource name)",["azure","cloud","ai"]),

    # ── GitHub ────────────────────────────────────────────────────────────────
    P("GitHub Token",
      r"(gh[pousr]_[A-Za-z0-9_]{36,255})",
      "confirmed","GitHub PAT / OAuth / refresh token",["github"]),
    P("GitHub Actions Token",
      r"(ghs_[A-Za-z0-9]{36})",
      "confirmed","GitHub Actions server-to-server token",["github"]),
    P("GitHub Fine-Grained PAT",
      r"(github_pat_[A-Za-z0-9_]{82})",
      "confirmed","GitHub fine-grained personal access token",["github"]),

    # ── GitLab ────────────────────────────────────────────────────────────────
    P("GitLab PAT",
      r"(glpat-[A-Za-z0-9_\-]{20,})",
      "confirmed","GitLab personal access token",["gitlab"]),
    P("GitLab Deploy Token",
      r"(gldt-[A-Za-z0-9_\-]{20,})",
      "confirmed","GitLab deploy token",["gitlab"]),

    # ── CI/CD ─────────────────────────────────────────────────────────────────
    P("CircleCI Token",
      r"(circleci-[a-f0-9]{40})",
      "confirmed","CircleCI personal API token",["circleci","ci"]),
    P("Travis CI Token",
      r"(?i)travis(?:_ci)?_token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
      "probable","Travis CI token",["travisci","ci"],3.0),
    P("Jenkins Token",
      r"(?i)jenkins(?:_api)?_token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
      "probable","Jenkins API token",["jenkins","ci"],3.0),

    # ── Slack ─────────────────────────────────────────────────────────────────
    P("Slack Token",
      r"(xox[baprs]-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{24,})",
      "confirmed","Slack API/bot/user token",["slack"]),
    P("Slack Webhook",
      r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{24})",
      "confirmed","Slack incoming webhook URL",["slack"]),

    # ── Discord ───────────────────────────────────────────────────────────────
    P("Discord Bot Token",
      r"(?<!\w)([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})(?!\w)",
      "confirmed","Discord bot token",["discord"],4.0),
    P("Discord Webhook",
      r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80})",
      "confirmed","Discord webhook URL",["discord"]),

    # ── Telegram ──────────────────────────────────────────────────────────────
    P("Telegram Bot Token",
      r"(?<!\w)([0-9]{8,10}:[A-Za-z0-9_\-]{35})(?!\w)",
      "probable","Telegram bot API token",["telegram"],3.5),

    # ── Twilio (require assignment context — AC/SK prefix alone is too broad) ─
    P("Twilio Account SID",
      r"(?i)(?:twilio[_\s]?)?account[_\s]?sid\s*[=:]\s*['\"`](AC[A-Za-z0-9]{32})['\"`]",
      "confirmed","Twilio account SID",["twilio"],3.0),
    P("Twilio Auth Token",
      r"(?i)(?:twilio[_\s]?)?auth[_\s]?token\s*[=:]\s*['\"`](SK[A-Za-z0-9]{32})['\"`]",
      "confirmed","Twilio auth token",["twilio"],3.0),

    # ── Email ─────────────────────────────────────────────────────────────────
    P("Mailgun API Key",
      r"(?i)mailgun[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`](key-[0-9a-zA-Z]{32})['\"`]",
      "confirmed","Mailgun API key",["mailgun","email"]),
    P("Mailchimp API Key",
      r"(?<!\w)([a-f0-9]{32}-us[0-9]{1,2})(?!\w)",
      "confirmed","Mailchimp API key",["mailchimp","email"],3.5),
    P("SendGrid API Key",
      r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})",
      "confirmed","SendGrid API key",["sendgrid","email"]),

    # ── Payment ───────────────────────────────────────────────────────────────
    P("Stripe Live Secret Key",
      r"(sk_live_[0-9a-zA-Z]{24,99})",
      "confirmed","Stripe live secret key",["stripe","payment"]),
    P("Stripe Live Restricted Key",
      r"(rk_live_[0-9a-zA-Z]{24,99})",
      "confirmed","Stripe live restricted key",["stripe","payment"]),
    P("Stripe Test Key",
      r"((?:sk|rk|pk)_test_[0-9a-zA-Z]{24,99})",
      "possible","Stripe test key (verify not used in production)",["stripe","payment"]),
    P("Stripe Webhook Secret",
      r"(whsec_[0-9a-zA-Z]{32,})",
      "confirmed","Stripe webhook signing secret",["stripe","payment"],3.5),
    P("PayPal Braintree Token",
      r"(access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32})",
      "confirmed","PayPal/Braintree production access token",["paypal","payment"]),
    P("Square Access Token",
      r"((?:EAAA|sq0atp-)[A-Za-z0-9\-_]{22,})",
      "confirmed","Square payment access token",["square","payment"],3.5),
    P("Square OAuth Secret",
      r"(sq0csp-[A-Za-z0-9_\-]{43})",
      "confirmed","Square OAuth secret",["square","payment"]),

    # ── Social ────────────────────────────────────────────────────────────────
    P("Facebook Access Token",
      r"(EAACEdEose0cBA[0-9A-Za-z]+)",
      "confirmed","Facebook/Meta OAuth access token",["facebook","meta"]),

    # ══════════════════════════════════════════════════════════════════════════
    # AI / LLM PLATFORMS
    # ══════════════════════════════════════════════════════════════════════════

    # OpenAI — classic sk-[48] AND new sk-proj- format
    P("OpenAI API Key",
      r"(sk-[A-Za-z0-9]{48})",
      "confirmed","OpenAI API key (classic format)",["openai","ai"],4.0),
    P("OpenAI Project Key",
      r"(sk-proj-[A-Za-z0-9_\-]{40,})",
      "confirmed","OpenAI project-scoped API key",["openai","ai"],4.0),

    # Anthropic
    P("Anthropic API Key",
      r"(sk-ant-(?:api\d+-)?[A-Za-z0-9_\-]{40,})",
      "confirmed","Anthropic Claude API key",["anthropic","ai"]),

    # Google Gemini — same AIza prefix as Google API key, tagged separately
    P("Google Gemini Key",
      r"(AIza[0-9A-Za-z\-_]{35})",
      "confirmed","Google Gemini / PaLM API key (AIza prefix)",["gemini","google","ai"]),

    # HuggingFace
    P("HuggingFace Token",
      r"(hf_[a-zA-Z0-9]{34,})",
      "confirmed","HuggingFace API token",["huggingface","ai"]),

    # Replicate
    P("Replicate Token",
      r"(r8_[A-Za-z0-9]{40})",
      "confirmed","Replicate API token",["replicate","ai"]),

    # Cohere
    P("Cohere API Key",
      r"(?i)cohere[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40})['\"`]",
      "confirmed","Cohere API key",["cohere","ai"],3.5),

    # Groq  (gsk_ prefix, publicly documented)
    P("Groq API Key",
      r"(gsk_[A-Za-z0-9]{52})",
      "confirmed","Groq API key",["groq","ai"],4.0),

    # Perplexity AI
    P("Perplexity API Key",
      r"(pplx-[A-Za-z0-9]{48})",
      "confirmed","Perplexity AI API key",["perplexity","ai"],4.0),

    # OpenRouter
    P("OpenRouter API Key",
      r"(sk-or-v1-[A-Za-z0-9]{48})",
      "confirmed","OpenRouter API key",["openrouter","ai"],4.0),

    # Together AI
    P("Together AI Key",
      r"(?i)together[_\s]?(?:ai[_\s]?)?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{64})['\"`]",
      "confirmed","Together AI API key",["together","ai"],4.0),

    # Mistral AI
    P("Mistral API Key",
      r"(?i)mistral[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
      "probable","Mistral AI API key",["mistral","ai"],3.5),

    # Stability AI
    P("Stability AI Key",
      r"(sk-[A-Za-z0-9]{48})",   # same prefix as OpenAI — covered above, but tagged
      "confirmed","Stability AI API key (sk- prefix)",["stability","ai"],4.0),

    # ElevenLabs
    P("ElevenLabs API Key",
      r"(?i)elevenlabs[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
      "confirmed","ElevenLabs API key",["elevenlabs","ai"],3.5),

    # Pinecone
    P("Pinecone API Key",
      r"(?i)pinecone[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{36,})['\"`]",
      "confirmed","Pinecone vector DB API key",["pinecone","ai"],3.5),

    # Weaviate
    P("Weaviate API Key",
      r"(?i)weaviate[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{36,})['\"`]",
      "probable","Weaviate API key",["weaviate","ai"],3.5),

    # ── Hosting / CDN ─────────────────────────────────────────────────────────
    P("Heroku API Key",
      r"(?i)heroku[_\s]?(?:api[_\s]?)?(?:key|token)\s*[=:]\s*['\"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"`]",
      "confirmed","Heroku API key",["heroku"]),
    P("DigitalOcean PAT",
      r"(dop_v1_[a-f0-9]{64})",
      "confirmed","DigitalOcean personal access token",["digitalocean","cloud"]),
    P("Cloudflare API Token",
      r"(?i)cloudflare[_\s]?(?:api[_\s]?)?(?:token|key)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{37,40})['\"`]",
      "confirmed","Cloudflare API token",["cloudflare"],3.5),
    P("Cloudinary URL",
      r"(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+)",
      "confirmed","Cloudinary credentials URL",["cloudinary"]),
    P("Sentry DSN",
      r"(https://[0-9a-f]{32}@(?:o[0-9]+\.)?sentry\.io/[0-9]+)",
      "confirmed","Sentry DSN",["sentry"]),
    P("Mapbox Token",
      r"((?:pk|sk)\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",
      "confirmed","Mapbox public/secret token",["mapbox"]),
    P("Shopify Token",
      r"(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})",
      "confirmed","Shopify access token",["shopify"]),
    P("npm Access Token",
      r"(npm_[A-Za-z0-9]{36})",
      "confirmed","npm access token",["npm"]),
    P("PyPI Upload Token",
      r"(pypi-[A-Za-z0-9_\-]{32,})",
      "confirmed","PyPI upload token",["pypi"]),
    P("Datadog API Key",
      r"(?i)(?:datadog|dd)[_\s]?(?:api[_\s]?)?key\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
      "confirmed","Datadog API key",["datadog"],3.5),
    P("New Relic License Key",
      # NRAK- prefix for New Relic user keys (publicly documented format)
      r"(NRAK-[A-Z0-9]{27})",
      "confirmed","New Relic user API key",["newrelic"],3.5),
    P("Algolia API Key",
      r"(?i)algolia[_\s]?(?:api[_\s]?)?(?:key|admin[_\s]?key)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
      "confirmed","Algolia API/admin key",["algolia"],3.5),

    # ── Credentials in code/config (QUOTED VALUES ONLY) ───────────────────────
    P("OAuth2 Client Secret",
      r"client[_\-]?secret\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.~]{20,})['\"`]",
      "confirmed","OAuth2 client_secret value",["oauth","credentials"],3.0),
    P("Password (quoted)",
      r"""(?:^|[\s,;{(\n])(?:password|passwd|pwd)\s*[:=]\s*(['"`])([^'"`\s]{8,})\1""",
      "probable","Password literal in config/code",["password","credentials"],2.8),
    P("API Key (quoted)",
      r"""(?:api[_\-]?key|apikey)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.]{16,})['\"`]""",
      "confirmed","API key literal assignment",["api-key","credentials"],3.0),
    P("Access Token (quoted)",
      r"""(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.]{20,})['\"`]""",
      "confirmed","Access/auth token literal",["token","credentials"],3.0),
    P("Secret (quoted)",
      r"""(?:^|[\s,;{(\n])(?:secret|app_secret|api_secret)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.~!@#]{8,})['\"`]""",
      "probable","Secret literal in config/code",["secret","credentials"],3.5),
    P("Private Key (quoted)",
      r"""(?:private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['\"`]([A-Za-z0-9_\-+/=]{40,})['\"`]""",
      "confirmed","Private key literal in code",["crypto","credentials"],4.0),

    # ── URL credential leaks ──────────────────────────────────────────────────
    P("Basic Auth in URL",
      r"https?://[A-Za-z0-9\-._~%!$&'*+,;=]+:([A-Za-z0-9\-._~%!$&'*+,;=@]{8,})@[A-Za-z0-9\-._~%!$&'*+,;=:@/?#]+",
      "confirmed","Password embedded in URL",["url","credentials"],2.0),
    P("Secret in URL Query Param",
      r"[?&](?:token|secret|api[_\-]?key|apikey|access_token|auth|password|passwd)=([A-Za-z0-9_\-\.%+]{8,})",
      "confirmed","Secret/credential in URL query parameter",["url","credentials"],2.5),

    # ── JWT ───────────────────────────────────────────────────────────────────
    P("JWT",
      r"(ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})",
      "probable","JSON Web Token",["jwt","token"],4.0),

    # ── Private key headers ───────────────────────────────────────────────────
    P("RSA Private Key",     r"-----BEGIN RSA PRIVATE KEY-----",
      "confirmed","RSA private key",["crypto"]),
    P("DSA Private Key",     r"-----BEGIN DSA PRIVATE KEY-----",
      "confirmed","DSA private key",["crypto"]),
    P("EC Private Key",      r"-----BEGIN EC PRIVATE KEY-----",
      "confirmed","EC private key",["crypto"]),
    P("PGP Private Key",     r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
      "confirmed","PGP private key block",["crypto"]),
    P("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----",
      "confirmed","OpenSSH private key",["crypto"]),
    P("PKCS8 Private Key",   r"-----BEGIN PRIVATE KEY-----",
      "confirmed","PKCS8 private key",["crypto"]),

    # ── Database DSNs (credentials required) ─────────────────────────────────
    P("Database DSN with credentials",
      r"((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|mariadb)://[A-Za-z0-9_\-]+:[^@\s\"'`]{4,}@[^\s\"'`<>]{4,})",
      "confirmed","Database DSN with embedded credentials",["database","dsn"],2.5),

    # ── DOM XSS sinks ─────────────────────────────────────────────────────────
    P("eval(location.*)",
      r"eval\s*\([^)]{0,80}location\.",
      "possible","DOM XSS: eval() with location object",["xss","js"]),
    P("innerHTML from template literal",
      r"\.innerHTML\s*=\s*`[^`]{0,200}\$\{[^`]{0,100}\}",
      "possible","DOM XSS: innerHTML assigned from template literal",["xss","js"]),
    P("document.write + location",
      r"document\.write\s*\([^)]{0,100}\+\s*location\.",
      "possible","DOM XSS: document.write() + location",["xss","js"]),
    P("postMessage + eval",
      r"addEventListener\s*\(['\"]message['\"][^)]{0,200}eval\s*\(",
      "possible","DOM XSS: postMessage handler calls eval()",["xss","js"]),

    # ── Recon ─────────────────────────────────────────────────────────────────
    P("Private IPv4",
      r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)",
      "info","RFC-1918 private IPv4 address",["infra","recon"]),
    P("Email Address",
      r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7})(?![A-Za-z0-9._%+\-@])",
      "info","Email address",["pii","recon"]),
]

# deduplicate by name (e.g. Google API Key and Gemini Key share same regex)
_seen: set = set()
_DEDUP: list[P] = []
for _p in PATTERNS:
    # for exact same regex, keep first only
    if _p.rx not in _seen:
        _seen.add(_p.rx)
        _DEDUP.append(_p)
    # but if name differs and regex differs, keep both
PATTERNS = _DEDUP

# ── finding ───────────────────────────────────────────────────────────────────
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
    if len(s) <= keep*2: return "*"*len(s)
    return s[:keep]+"…"+"*"*min(8,len(s)-keep*2)+"…"+s[-3:]

def _build_offs(text):
    offs = [0]
    for i,ch in enumerate(text):
        if ch=="\n": offs.append(i+1)
    return offs

def _lno(offs, pos):
    lo,hi = 0,len(offs)-1
    while lo<hi:
        mid=(lo+hi+1)//2
        if offs[mid]<=pos: lo=mid
        else: hi=mid-1
    return lo+1

def scan_text(source, text, min_sev="info", filter_tags=None):
    out, seen = [], set()
    min_idx = SEVMAP.get(min_sev, 3)
    offs = _build_offs(text)
    for pat in PATTERNS:
        if SEVMAP[pat.sev] > min_idx: continue
        if filter_tags and not filter_tags.intersection(pat.tags): continue
        for m in pat._c.finditer(text):
            # group 2 if present (KV patterns with quote-char in g1, value in g2)
            if m.lastindex and m.lastindex >= 2:
                val = m.group(2).strip()
            elif m.lastindex:
                val = m.group(1).strip()
            else:
                val = m.group(0).strip()
            if not val or _is_fp(val): continue
            ent = _entropy(val)
            if pat.entropy_min and ent < pat.entropy_min: continue
            key = (pat.name, val)
            if key in seen: continue
            seen.add(key)
            out.append(Finding(
                source=source, line_no=_lno(offs, m.start()),
                name=pat.name, sev=pat.sev, desc=pat.desc,
                tags=list(pat.tags), match_raw=val,
                match_redacted=_redact(val), entropy=round(ent,2),
            ))
    return out

# ── fetch ─────────────────────────────────────────────────────────────────────
_SKIP_CT = ("image/","video/","audio/","font/","application/pdf",
            "application/zip","application/octet","woff","ttf","eot")
def fetch_body(url, timeout=15):
    try:
        req = urllib.request.Request(url.strip(), headers={
            "User-Agent":"Mozilla/5.0 (compatible; astra/1.0)",
            "Accept":"text/html,application/javascript,application/json,*/*",
            "Accept-Encoding":"identity",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if any(x in r.headers.get("Content-Type","") for x in _SKIP_CT): return ""
            return r.read(5_000_000).decode("utf-8", errors="replace")
    except: return ""

# ── output ────────────────────────────────────────────────────────────────────
BANNER = r"""
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
"""

def print_header(n):
    print(c(BANNER, C_HEAD))
    print(c(f"  {n} patterns  ·  entropy check  ·  quoted-value enforcement", C_GREY))
    print()
    print("  "+"  ".join(c(f"{SEV_ICO[s]} {s}",SEV_COL[s]) for s in SEVMAP))
    print(c("  "+"─"*56, C_GREY)); print()

def print_finding(f, show_raw=False):
    val  = c(f.match_raw if show_raw else f.match_redacted, C_PROB+B)
    tags = c(" ".join(f"[{t}]" for t in f.tags), C_GREY+DIM)
    ent  = c(f"entropy={f.entropy}", C_GREY+DIM)
    lno  = c(f"line {f.line_no}", C_BLU)
    print(f"  {badge(f.sev)} {c(f.name,B)}  {lno}")
    print(f"  {'':16} {c(f.desc,C_GREY)}  {tags}")
    print(f"  {'':16} {c('›',C_GREY)} {val}  {ent}")
    print()

def print_summary(n_src, n_lines, findings, elapsed):
    by_sev = defaultdict(int)
    for f in findings: by_sev[f.sev]+=1
    speed = f"{n_lines/elapsed:,.0f} lines/s" if elapsed>0 else ""
    print(c("  "+"─"*56, C_GREY))
    print(c(f"  sources {n_src}   lines {n_lines:,}   {speed}", B))
    if not findings:
        print(c("  result  ✓ clean", C_OK+B))
    else:
        print(c(f"  total   {len(findings)} finding(s)", C_CONF+B))
        for sev in SEVMAP:
            n=by_sev.get(sev,0)
            if n: print(f"  {badge(sev)}  {n}")
    print(c("  "+"─"*56, C_GREY))

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(
        prog="astra",
        description="astra — secret & credential scanner",
        epilog=(
            "examples:\n"
            "  cat urls.txt        | python3 astra.py\n"
            "  cat bundle.min.js   | python3 astra.py\n"
            "  python3 astra.py      app.js\n"
            "  python3 astra.py      ./src/ --ext js,ts,json,env\n"
            "  python3 astra.py      urls.txt --fetch --threads 20\n"
            "  python3 astra.py      app.js --json\n"
            "  python3 astra.py      --list --tags ai\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("file",           nargs="?", help="File or directory (default: stdin)")
    ap.add_argument("-s","--severity",default="info",choices=list(SEVMAP),metavar="SEV",
                    help="Min severity: confirmed probable possible info  (default: info)")
    ap.add_argument("--fetch",        action="store_true", help="Fetch URLs and scan response bodies")
    ap.add_argument("--threads",      type=int,default=10, help="Threads for --fetch (default: 10)")
    ap.add_argument("--json",         action="store_true", help="JSON output")
    ap.add_argument("--show-match",   action="store_true", help="Show unredacted values")
    ap.add_argument("--no-color",     action="store_true", help="Disable ANSI colors")
    ap.add_argument("--list",         action="store_true", help="List all patterns and exit")
    ap.add_argument("--tags",         metavar="TAGS",      help="Tag filter: aws,ai,xss,payment ...")
    ap.add_argument("--ext",          metavar="EXT",       help="Dir mode extensions: js,ts,json,env")
    args = ap.parse_args()

    if args.no_color: USE_COLOR = False
    filter_tags = set(args.tags.split(",")) if args.tags else None

    if args.list:
        print(f"\n  {'NAME':<35} {'SEV':<13} {'TAGS':<28} DESC")
        print("  "+"─"*95)
        for p in sorted(PATTERNS, key=lambda x:(SEVMAP[x.sev],x.name)):
            if filter_tags and not filter_tags.intersection(p.tags): continue
            sv = c(f"{SEV_ICO[p.sev]} {p.sev}", SEV_COL[p.sev])
            print(f"  {p.name:<35} {sv:<22} {','.join(p.tags):<28} {p.desc}")
        print(); sys.exit(0)

    # collect sources
    sources: list[tuple[str,str]] = []
    t0 = time.perf_counter()

    if args.file:
        p = Path(args.file)
        if p.is_dir():
            exts = {f".{e.lstrip('.')}" for e in args.ext.split(",")} if args.ext else None
            for fp in sorted(p.rglob("*")):
                if not fp.is_file(): continue
                if exts and fp.suffix.lower() not in exts: continue
                try: sources.append((str(fp), fp.read_text(errors="replace")))
                except: pass
        elif p.is_file():
            try: sources.append((str(p), p.read_text(errors="replace")))
            except Exception as e:
                print(c(f"[!] cannot read {p}: {e}", C_CONF), file=sys.stderr); sys.exit(1)
        else:
            print(c(f"[!] not found: {args.file}", C_CONF), file=sys.stderr); sys.exit(1)
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
        lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith("#")]
        url_ratio = sum(1 for l in lines if l.startswith(("http://","https://"))) / max(len(lines),1)
        if lines and url_ratio > 0.5:
            for ln in lines: sources.append((ln, ln))
        else:
            sources.append(("<stdin>", raw))
    else:
        ap.print_help(); sys.exit(0)

    # fetch
    if args.fetch:
        url_srcs = [(l,t) for l,t in sources if t.strip().startswith(("http://","https://"))]
        rest     = [(l,t) for l,t in sources if not t.strip().startswith(("http://","https://"))]
        fetched  = []
        def _f(item):
            lbl,url=item; body=fetch_body(url.strip())
            return lbl, url+("\n"+body if body else "")
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs={ex.submit(_f,s):s for s in url_srcs}
            for fut in as_completed(futs):
                try: fetched.append(fut.result())
                except: fetched.append(futs[fut])
        sources = rest+fetched

    # scan
    total_lines = sum(txt.count("\n")+1 for _,txt in sources)
    all_findings: list[Finding] = []
    by_source: dict[str,list] = {}
    for lbl,txt in sources:
        found = scan_text(lbl, txt, args.severity, filter_tags)
        if found:
            by_source[lbl] = found
            all_findings.extend(found)

    elapsed = max(time.perf_counter()-t0, 1e-9)

    # JSON output
    if args.json:
        out=[]
        for f in all_findings:
            d=asdict(f)
            if not args.show_match: del d["match_raw"]
            out.append(d)
        print(json.dumps(out, indent=2))
        sys.exit(0 if not all_findings else 1)

    # human output
    print_header(len(PATTERNS))
    if all_findings:
        for lbl,findings in by_source.items():
            print(c("  ╔"+"═"*62, C_GREY))
            print(c("  ║ ",C_GREY)+c(lbl[:100],B))
            print(c("  ╚"+"═"*62, C_GREY))
            print()
            for f in sorted(findings, key=lambda x:(SEVMAP[x.sev],x.line_no)):
                print_finding(f, show_raw=args.show_match)
    else:
        print(c("  ✓  nothing found\n", C_OK+B))

    print_summary(len(sources), total_lines, all_findings, elapsed)
    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
