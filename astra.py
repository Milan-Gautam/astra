#!/usr/bin/env python3
"""
astra — fast, low-false-positive secret & credential scanner
for JS files, URL lists, config files, and HTTP responses.

Usage:
  cat urls.txt          | python3 astra.py
  cat bundle.min.js     | python3 astra.py
  python3 astra.py      app.js
  python3 astra.py      ./src/ --ext js,ts,json,env
  python3 astra.py      urls.txt --fetch --threads 25
  python3 astra.py      app.js --json | jq '.[]|select(.sev=="confirmed")'
  python3 astra.py      --list --tags aws
"""

import re, sys, json, argparse, math, time, os
import urllib.request, urllib.error
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── ANSI ─────────────────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; DIM="\033[2m"
C_CONF="\033[38;5;196m"; C_PROB="\033[38;5;214m"
C_POSS="\033[38;5;220m"; C_INFO="\033[38;5;39m"
C_OK  ="\033[38;5;82m";  C_GREY="\033[38;5;244m"
C_HEAD="\033[38;5;213m"; C_BLU ="\033[38;5;75m"
USE_COLOR = True
def c(t, col): return f"{col}{t}{R}" if USE_COLOR else t

# ── severity ──────────────────────────────────────────────────────────────────
# Labels designed for researchers — no "critical/high" to imply exploitability
SEVMAP  = {"confirmed": 0, "probable": 1, "possible": 2, "info": 3}
SEV_COL = {"confirmed": C_CONF, "probable": C_PROB,
           "possible":  C_POSS, "info":     C_INFO}
SEV_ICO = {"confirmed": "◆", "probable": "◇",
           "possible":  "○", "info":     "·"}

def badge(sev):
    return c(f" {SEV_ICO[sev]} {sev.upper():<12}", SEV_COL[sev]+B)

# ── helpers ───────────────────────────────────────────────────────────────────
def _entropy(s: str) -> float:
    if not s: return 0.0
    freq = defaultdict(int)
    for ch in s: freq[ch] += 1
    l = len(s)
    return -sum((v/l)*math.log2(v/l) for v in freq.values())

# Placeholder / template values that are never real secrets
_FP_EXACT = {
    "null","none","undefined","false","true","empty","n/a","na",
    "todo","fixme","redacted","changeme","password","secret","apikey",
    "api_key","token","example","test","sample","dummy","placeholder",
    "your_token","your_key","your_secret","insert_here","xxx","yyy","zzz",
    "1234567890","abcdefghij","0000000000",
}
_FP_RX = re.compile(
    r"^(?:"
    r"your[_\-]?|my[_\-]?|test[_\-]?|example[_\-]?|sample[_\-]?|"
    r"dummy[_\-]?|fake[_\-]?|mock[_\-]?|demo[_\-]?|"
    r"<[^>]+>|\$\{[^}]+\}|%[A-Z_]{2,}%|\{\{[^}]+\}\}|"
    r"__[A-Z_]+__|##[A-Z_]+##|@@[A-Z_]+@@"
    r")",
    re.IGNORECASE,
)

def _is_fp(val: str) -> bool:
    v = val.strip()
    if len(v) < 6:                   return True
    if v.lower() in _FP_EXACT:       return True
    if _FP_RX.match(v):              return True
    if len(set(v.lower())) < 5:      return True  # low diversity
    # all same repeated chunk (e.g. "abcabcabcabc")
    for chunk in range(1, len(v)//2 + 1):
        if v == v[:chunk] * (len(v)//chunk) and len(v) % chunk == 0:
            return True
    return False

# ── pattern dataclass ─────────────────────────────────────────────────────────
@dataclass
class P:
    name: str
    rx: str
    sev: str
    desc: str
    tags: list
    entropy_min: float = 0.0   # 0 = no entropy check
    _c: re.Pattern = field(default=None, repr=False)
    def __post_init__(self):
        self._c = re.compile(self.rx, re.IGNORECASE | re.MULTILINE)

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN LIBRARY
# Each pattern captures the *secret value* in group 1 (or full match if no
# groups). Specificity first — broad fallbacks at the bottom.
# ══════════════════════════════════════════════════════════════════════════════
PATTERNS: list[P] = [

    # ── AWS ───────────────────────────────────────────────────────────────────
    P("AWS Access Key ID",
      r"(?<![A-Z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])",
      "confirmed", "AWS access key ID", ["aws","cloud"], 3.0),
    P("AWS Secret Access Key",
      r"(?i)(?:aws_secret(?:_access)?_key|aws_secret)\s*[=:]\s*['\"`]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
      "confirmed", "AWS secret access key", ["aws","cloud"], 4.5),
    P("Amazon MWS Auth Token",
      r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
      "confirmed", "Amazon MWS auth token", ["aws","mws"]),

    # ── Google / GCP ──────────────────────────────────────────────────────────
    P("Google API Key",
      r"(AIza[0-9A-Za-z\-_]{35})",
      "confirmed", "Google API key", ["google","api-key"]),
    P("Google OAuth Access Token",
      r"(ya29\.[0-9A-Za-z\-_]{20,})",
      "confirmed", "Google OAuth 2.0 access token", ["google","oauth"]),
    P("Google OAuth2 Client Secret",
      r"(GOCSPX-[A-Za-z0-9_\-]{28})",
      "confirmed", "Google OAuth2 client secret", ["google","oauth"]),
    P("Google reCAPTCHA Key",
      r"(6L[0-9A-Za-z\-_]{38})",
      "probable", "Google reCAPTCHA key", ["google","recaptcha"]),
    P("Firebase / FCM Server Key",
      r"(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})",
      "confirmed", "Firebase Cloud Messaging server key", ["firebase","google"]),
    P("GCP Service Account JSON",
      r'"type"\s*:\s*"service_account"',
      "confirmed", "GCP service account JSON credential block", ["gcp","google"]),

    # ── Azure ─────────────────────────────────────────────────────────────────
    P("Azure Storage Connection String",
      r"(DefaultEndpointsProtocol=https;AccountName=[^;]{1,60};AccountKey=[A-Za-z0-9+/=]{88}[^;]*)",
      "confirmed", "Azure Storage connection string", ["azure","cloud"]),
    P("Azure SAS Token",
      r"(?:sig=)([A-Za-z0-9%+/]{30,}?)(?:&|$|[\"'\s])",
      "probable", "Azure Shared Access Signature token", ["azure","cloud"], 3.5),
    P("Azure AD Client Secret",
      r"(?i)(?:azure|aad)[_\-\s.]?(?:client[_\-\s.]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9_\-~.]{30,})['\"`]",
      "confirmed", "Azure AD / App Registration client secret", ["azure","cloud"], 3.5),

    # ── GitHub / GitLab / Bitbucket ───────────────────────────────────────────
    P("GitHub Token",
      r"(gh[pousr]_[A-Za-z0-9_]{36,255})",
      "confirmed", "GitHub personal access / OAuth / refresh token", ["github","token"]),
    P("GitHub Actions Token",
      r"(ghs_[A-Za-z0-9]{36})",
      "confirmed", "GitHub Actions server-to-server token", ["github","token"]),
    P("GitHub Fine-Grained Token",
      r"(github_pat_[A-Za-z0-9_]{82})",
      "confirmed", "GitHub fine-grained personal access token", ["github","token"]),
    P("GitLab PAT",
      r"(glpat-[A-Za-z0-9_\-]{20,})",
      "confirmed", "GitLab personal access token", ["gitlab","token"]),
    P("GitLab Deploy Token",
      r"(gldt-[A-Za-z0-9_\-]{20,})",
      "confirmed", "GitLab deploy token", ["gitlab","token"]),
    P("Bitbucket App Password",
      r"(?i)bitbucket[_\-\s.]?(?:app[_\-\s.]?)?(?:password|token)\s*[=:]\s*['\"`]([A-Za-z0-9+/]{20,})['\"`]",
      "confirmed", "Bitbucket app password", ["bitbucket","token"], 3.0),

    # ── CI / CD ───────────────────────────────────────────────────────────────
    P("CircleCI Token",
      r"(circleci-[a-f0-9]{40})",
      "confirmed", "CircleCI personal API token", ["circleci","ci"]),
    P("Travis CI Token",
      r"(?i)travis[_\-\s.]?(?:ci[_\-\s.]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
      "probable", "Travis CI token", ["travisci","ci"], 3.0),
    P("Jenkins Token",
      r"(?i)jenkins[_\-\s.]?(?:api[_\-\s.]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{20,})['\"`]",
      "probable", "Jenkins API token", ["jenkins","ci"], 3.0),
    P("GitHub Actions Workflow Secret",
      r"\$\{\{\s*secrets\.[A-Z_]{3,}\s*\}\}",
      "info", "GitHub Actions secret reference (may indicate secret exists)", ["github","ci"]),

    # ── Slack / Discord / Telegram ────────────────────────────────────────────
    P("Slack Bot/User Token",
      r"(xox[baprs]-(?:[0-9]{9,13}-){2,3}[a-zA-Z0-9]{20,})",
      "confirmed", "Slack API / bot / user token", ["slack","token"]),
    P("Slack Webhook URL",
      r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,12}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{24})",
      "confirmed", "Slack incoming webhook URL", ["slack","webhook"]),
    P("Discord Bot Token",
      r"(?<![A-Za-z0-9])([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})(?![A-Za-z0-9_\-])",
      "confirmed", "Discord bot token", ["discord","token"], 4.0),
    P("Discord Webhook URL",
      r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,80})",
      "confirmed", "Discord webhook URL", ["discord","webhook"]),
    P("Telegram Bot Token",
      r"(?<![A-Za-z0-9])([0-9]{8,10}:[A-Za-z0-9_\-]{35})(?![A-Za-z0-9_\-])",
      "probable", "Telegram bot API token", ["telegram","token"], 3.5),

    # ── Email providers ───────────────────────────────────────────────────────
    P("Mailgun API Key",
      r"(key-[0-9a-zA-Z]{32})",
      "probable", "Mailgun API key", ["mailgun","email"], 3.5),
    P("Mailchimp API Key",
      r"([a-f0-9]{32}-us[0-9]{1,2})",
      "confirmed", "Mailchimp API key", ["mailchimp","email"], 3.5),
    P("SendGrid API Key",
      r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})",
      "confirmed", "SendGrid API key", ["sendgrid","email"]),
    P("Postmark Server Token",
      r"(?i)postmark[_\-\s.]?(?:server[_\-\s.]?)?(?:api[_\-\s.]?)?token\s*[=:]\s*['\"`]([a-f0-9\-]{36})['\"`]",
      "confirmed", "Postmark server API token", ["postmark","email"]),
    P("Sparkpost API Key",
      r"(?i)sparkpost[_\-\s.]?(?:api[_\-\s.]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{40})['\"`]",
      "confirmed", "SparkPost API key", ["sparkpost","email"], 3.5),

    # ── Twilio ────────────────────────────────────────────────────────────────
    P("Twilio Auth Token",
      r"(?<![A-Za-z0-9])(SK[0-9a-fA-F]{32})(?![A-Za-z0-9])",
      "probable", "Twilio auth token", ["twilio"]),
    P("Twilio Account SID",
      r"(?<![A-Za-z0-9])(AC[a-zA-Z0-9_\-]{32})(?![A-Za-z0-9_\-])",
      "probable", "Twilio account SID", ["twilio"]),

    # ── Payment ───────────────────────────────────────────────────────────────
    P("Stripe Live Secret Key",
      r"(sk_live_[0-9a-zA-Z]{24,99})",
      "confirmed", "Stripe live secret key", ["stripe","payment"]),
    P("Stripe Live Restricted Key",
      r"(rk_live_[0-9a-zA-Z]{24,99})",
      "confirmed", "Stripe live restricted key", ["stripe","payment"]),
    P("Stripe Test Key",
      r"((?:sk|rk|pk)_test_[0-9a-zA-Z]{24,99})",
      "possible", "Stripe test key (check if used in production)", ["stripe","payment"]),
    P("Stripe Webhook Secret",
      r"(whsec_[0-9a-zA-Z]{32,})",
      "probable", "Stripe webhook signing secret", ["stripe","payment"], 3.5),
    P("PayPal Braintree Token",
      r"(access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32})",
      "confirmed", "PayPal/Braintree production access token", ["paypal","payment"]),
    P("Square Access Token",
      r"((?:EAAA|sq0atp-)[A-Za-z0-9\-_]{22,})",
      "confirmed", "Square payment access token", ["square","payment"], 3.5),
    P("Square OAuth Secret",
      r"(sq0csp-[A-Za-z0-9_\-]{43})",
      "confirmed", "Square OAuth secret", ["square","payment"]),

    # ── Social / Identity ─────────────────────────────────────────────────────
    P("Facebook Access Token",
      r"(EAACEdEose0cBA[0-9A-Za-z]+)",
      "confirmed", "Facebook/Meta OAuth access token", ["facebook","meta"]),
    P("Facebook App Secret",
      r"(?i)facebook[_\-\s.]?(?:app[_\-\s.]?)?secret\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
      "confirmed", "Facebook app secret", ["facebook","meta"], 3.5),
    P("Twitter Bearer Token",
      r"(AAAA[A-Za-z0-9%]{80,})",
      "probable", "Twitter/X Bearer token", ["twitter","oauth"], 4.0),
    P("Twitter OAuth Credentials",
      r"(?i)twitter[_\-\s.]?(?:api[_\-\s.]?)?(?:secret|consumer[_\-\s.]?secret)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{35,})['\"`]",
      "probable", "Twitter/X OAuth consumer secret", ["twitter","oauth"], 3.5),
    P("LinkedIn Client Secret",
      r"(?i)linkedin[_\-\s.]?(?:client[_\-\s.]?)?secret\s*[=:]\s*['\"`]([A-Za-z0-9]{16})['\"`]",
      "confirmed", "LinkedIn OAuth client secret", ["linkedin","oauth"], 3.0),

    # ── AI / ML ───────────────────────────────────────────────────────────────
    P("OpenAI API Key",
      r"(sk-[A-Za-z0-9]{48})",
      "confirmed", "OpenAI API key", ["openai","ai"]),
    P("OpenAI Organization",
      r"(org-[A-Za-z0-9]{24})",
      "probable", "OpenAI organization ID", ["openai","ai"], 3.0),
    P("Anthropic API Key",
      r"(sk-ant-(?:api\d+-)?[A-Za-z0-9_\-]{40,})",
      "confirmed", "Anthropic Claude API key", ["anthropic","ai"]),
    P("HuggingFace Token",
      r"(hf_[a-zA-Z0-9]{34,})",
      "confirmed", "HuggingFace API token", ["huggingface","ai"]),
    P("Replicate API Token",
      r"(r8_[A-Za-z0-9]{40})",
      "confirmed", "Replicate API token", ["replicate","ai"]),
    P("Cohere API Key",
      r"(?i)cohere[_\-\s.]?(?:api[_\-\s.]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40})['\"`]",
      "confirmed", "Cohere API key", ["cohere","ai"], 3.5),

    # ── Hosting / CDN ─────────────────────────────────────────────────────────
    P("Heroku API Key",
      r"(?i)heroku[_\-\s.]?(?:api[_\-\s.]?)?(?:key|token)\s*[=:]\s*['\"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"`]",
      "confirmed", "Heroku API key", ["heroku","hosting"]),
    P("DigitalOcean PAT",
      r"(dop_v1_[a-f0-9]{64})",
      "confirmed", "DigitalOcean personal access token", ["digitalocean","cloud"]),
    P("Cloudflare API Token",
      r"(?i)(?:cf_|cloudflare[_\-\s.]?)(?:api[_\-\s.]?)?(?:token|key)\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{37,40})['\"`]",
      "confirmed", "Cloudflare API token/key", ["cloudflare","cdn"], 3.5),
    P("Cloudinary URL",
      r"(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+)",
      "confirmed", "Cloudinary credentials URL", ["cloudinary","media"]),
    P("Netlify Token",
      r"(?i)netlify[_\-\s.]?(?:api[_\-\s.]?)?(?:key|token)\s*[=:]\s*['\"`]([a-zA-Z0-9_\-]{40,})['\"`]",
      "confirmed", "Netlify access token", ["netlify","hosting"], 3.5),
    P("Vercel Token",
      r"(?i)vercel[_\-\s.]?(?:api[_\-\s.]?)?(?:key|token)\s*[=:]\s*['\"`]([a-zA-Z0-9_\-]{24,})['\"`]",
      "confirmed", "Vercel API token", ["vercel","hosting"], 3.0),

    # ── Dev tools / package registries ────────────────────────────────────────
    P("npm Access Token",
      r"(npm_[A-Za-z0-9]{36})",
      "confirmed", "npm access token", ["npm","devtools"]),
    P("PyPI Upload Token",
      r"(pypi-[A-Za-z0-9_\-]{32,})",
      "confirmed", "PyPI upload token", ["pypi","devtools"]),
    P("Docker Hub Credential",
      r"(?i)docker(?:hub)?[_\-\s.]?(?:password|token)\s*[=:]\s*['\"`]([A-Za-z0-9_\-!@#$%^&*]{8,})['\"`]",
      "probable", "Docker Hub credential", ["docker","devtools"], 3.0),
    P("Terraform Cloud Token",
      r"(?i)terraform[_\-\s.]?(?:cloud[_\-\s.]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]+)['\"`]",
      "confirmed", "Terraform Cloud API token", ["terraform","devtools"]),

    # ── Monitoring / analytics ────────────────────────────────────────────────
    P("Sentry DSN",
      r"(https://[0-9a-f]{32}@(?:o[0-9]+\.)?sentry\.io/[0-9]+)",
      "confirmed", "Sentry DSN (contains auth key)", ["sentry","monitoring"]),
    P("Datadog API Key",
      r"(?i)datadog[_\-\s.]?(?:api[_\-\s.]?)?key\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
      "confirmed", "Datadog API key", ["datadog","monitoring"], 3.5),
    P("New Relic License Key",
      r"(?i)new.?relic[_\-\s.]?(?:license[_\-\s.]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{40})['\"`]",
      "confirmed", "New Relic license key", ["newrelic","monitoring"], 3.5),
    P("Algolia API Key",
      r"(?i)algolia[_\-\s.]?(?:api[_\-\s.]?)?(?:key|admin)\s*[=:]\s*['\"`]([A-Za-z0-9]{32})['\"`]",
      "confirmed", "Algolia API/admin key", ["algolia","search"], 3.5),
    P("Mixpanel Token",
      r"(?i)mixpanel[_\-\s.]?token\s*[=:]\s*['\"`]([a-f0-9]{32})['\"`]",
      "probable", "Mixpanel project token", ["mixpanel","analytics"], 3.0),
    P("Segment Write Key",
      r"(?i)segment[_\-\s.]?(?:write[_\-\s.]?)?key\s*[=:]\s*['\"`]([A-Za-z0-9]{32,})['\"`]",
      "probable", "Segment write key", ["segment","analytics"], 3.0),

    # ── Maps / geolocation ────────────────────────────────────────────────────
    P("Mapbox Token",
      r"(pk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",
      "confirmed", "Mapbox public token", ["mapbox","maps"]),
    P("Mapbox Secret Token",
      r"(sk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",
      "confirmed", "Mapbox secret token", ["mapbox","maps"]),
    P("Google Maps API Key",
      r"(AIza[0-9A-Za-z\-_]{35})",  # same prefix as google api key — matched above
      "confirmed", "Google Maps API key", ["google","maps"]),

    # ── Ecommerce / identity ──────────────────────────────────────────────────
    P("Shopify Token",
      r"(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})",
      "confirmed", "Shopify access token", ["shopify","ecommerce"]),
    P("Okta API Token",
      r"(00[A-Za-z0-9_\-]{40})",
      "probable", "Okta API token", ["okta","identity"], 3.5),
    P("Atlassian API Token",
      r"(?i)atlassian[_\-\s.]?(?:api[_\-\s.]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9+/]{24,}={0,2})['\"`]",
      "probable", "Atlassian/Jira API token", ["atlassian","jira"], 3.0),
    P("Zendesk API Token",
      r"(?i)zendesk[_\-\s.]?(?:api[_\-\s.]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{40})['\"`]",
      "confirmed", "Zendesk API token", ["zendesk","support"], 3.5),
    P("Intercom Access Token",
      r"(?i)intercom[_\-\s.]?(?:access[_\-\s.]?)?token\s*[=:]\s*['\"`]([A-Za-z0-9_\-]{52,})['\"`]",
      "confirmed", "Intercom access token", ["intercom","support"], 3.5),
    P("Airtable API Key",
      r"(key[A-Za-z0-9]{14})",
      "probable", "Airtable API key", ["airtable"], 3.0),

    # ── Credentials in code / config ──────────────────────────────────────────
    P("OAuth2 Client Secret",
      r"(?:client[_\-]?secret)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.~]{20,})['\"`]",
      "confirmed", "OAuth2 client_secret assignment", ["oauth","credentials"], 3.0),
    P("Password in KV",
      r"""(?:^|[\s,;{(\n])(?:password|passwd|pwd)\s*[:=]\s*['\"`]([^'\"`\s]{6,})['\"`]""",
      "probable", "Password value in config/code", ["password","credentials"], 2.8),
    P("Secret in KV",
      r"""(?:^|[\s,;{(\n])(?:secret|api_secret|app_secret)\s*[:=]\s*['\"`]([^'\"`\s]{8,})['\"`]""",
      "probable", "Secret value in config/code", ["secret","credentials"], 3.2),
    P("API Key Assignment (strict)",
      r"""(?:api[_\-]?key|apikey|access[_\-]?key)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.]{16,})['\"`]""",
      "confirmed", "API key assignment in code/config", ["api-key","credentials"], 3.0),
    P("Access Token Assignment",
      r"""(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"`]([A-Za-z0-9_\-\.]{20,})['\"`]""",
      "confirmed", "Access/auth token assignment in code", ["token","credentials"], 3.0),
    P("Private Key Assignment",
      r"""(?:private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['\"`]([A-Za-z0-9_\-+/=]{40,})['\"`]""",
      "confirmed", "Private key value in code/config", ["crypto","credentials"], 4.0),

    # ── URL-based credential leaks ────────────────────────────────────────────
    P("Credentials in URL (Basic Auth)",
      r"https?://(?:[A-Za-z0-9\-._~%!$&'*+,;=]+):([^@\s:]{4,50})@[A-Za-z0-9\-._~%!$&'*+,;=:@/?#]+",
      "confirmed", "Password embedded in URL", ["url","credentials"]),
    P("Sensitive Parameter in URL",
      r"https?://[^\s\"'`<>]*[?&](?:token|key|secret|auth|api[_\-]?key|password|passwd|access_token|apikey)=([^\s\"'`<>&]{6,})",
      "confirmed", "Secret/credential in URL query parameter", ["url","credentials"], 2.5),
    P("Internal / Dev URL",
      r"https?://[^\s\"'`<>]*(?:staging\.|devapi\.|dev\.|internal\.|corp\.|\.internal|\.corp|\.local|test\.)[^\s\"'`<>]*",
      "possible", "Non-production / internal URL exposed", ["url","recon"]),

    # ── HTTP auth headers ─────────────────────────────────────────────────────
    P("HTTP Authorization Basic",
      r"(?i)Authorization\s*[=:]\s*['\"`]?Basic\s+([A-Za-z0-9+/=]{16,})",
      "confirmed", "HTTP Basic Auth header (base64 credentials)", ["http","credentials"]),
    P("HTTP Authorization Bearer",
      r"(?i)Authorization\s*[=:]\s*['\"`]?Bearer\s+([A-Za-z0-9_\-\.=+/]{20,})",
      "probable", "HTTP Bearer token", ["http","token"], 3.0),

    # ── JWT ───────────────────────────────────────────────────────────────────
    P("JSON Web Token",
      r"(ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})",
      "probable", "JSON Web Token (3-part)", ["jwt","token"], 4.0),

    # ── Private keys ──────────────────────────────────────────────────────────
    P("RSA Private Key",       r"-----BEGIN RSA PRIVATE KEY-----",
      "confirmed", "RSA private key block", ["crypto","private-key"]),
    P("DSA Private Key",       r"-----BEGIN DSA PRIVATE KEY-----",
      "confirmed", "DSA private key block", ["crypto","private-key"]),
    P("EC Private Key",        r"-----BEGIN EC PRIVATE KEY-----",
      "confirmed", "Elliptic-curve private key", ["crypto","private-key"]),
    P("PGP Private Key",       r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
      "confirmed", "PGP/GPG private key block", ["crypto","private-key"]),
    P("OpenSSH Private Key",   r"-----BEGIN OPENSSH PRIVATE KEY-----",
      "confirmed", "OpenSSH private key", ["crypto","private-key"]),
    P("PKCS8 Private Key",     r"-----BEGIN PRIVATE KEY-----",
      "confirmed", "PKCS#8 private key block", ["crypto","private-key"]),

    # ── Database DSNs ─────────────────────────────────────────────────────────
    P("Database Connection String",
      r"((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|oracle|mariadb|cassandra|couchdb|elasticsearch)://[^\s\"'`<>]{8,})",
      "confirmed", "Database connection string", ["database","dsn"], 3.0),
    P("JDBC Connection String",
      r"(jdbc:[a-z0-9]+://[^\s\"'`<>]{8,})",
      "confirmed", "JDBC connection string", ["database","dsn"]),

    # ── XSS / DOM sinks (JS-specific) ────────────────────────────────────────
    P("eval(location.*)",
      r"eval\s*\([^)]{0,80}location\.",
      "possible", "DOM XSS sink: eval() with location object", ["xss","js"]),
    P("innerHTML from template literal",
      r"\.innerHTML\s*=\s*`[^`]{0,200}\$\{[^`]{0,100}\}",
      "possible", "DOM XSS sink: innerHTML assigned from template literal", ["xss","js"]),
    P("document.write + location",
      r"document\.write\s*\([^)]{0,100}\+\s*location\.",
      "possible", "DOM XSS sink: document.write() + location", ["xss","js"]),
    P("postMessage + eval",
      r"""addEventListener\s*\(['\"]message['\"],[^)]{0,200}eval\s*\(""",
      "possible", "DOM XSS sink: postMessage handler calls eval()", ["xss","js"]),
    P("innerHTML = location.*",
      r"\.innerHTML\s*=\s*(?:window\.)?location\.",
      "possible", "DOM XSS sink: innerHTML directly from location", ["xss","js"]),
    P("Open Redirect Sink",
      r"(?:window\.location|location\.href|location\.replace)\s*=\s*(?:location\.|window\.location\.|['\"`][^'\"`]{0,5}\+)",
      "possible", "Possible open redirect: location assigned from input", ["redirect","js"]),

    # ── Infrastructure / recon ────────────────────────────────────────────────
    P("Private IPv4 Address",
      r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)",
      "info", "RFC-1918 private IPv4 address", ["infra","recon"]),
    P("Email Address",
      r"(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7})(?![A-Za-z0-9._%+\-@])",
      "info", "Email address (PII)", ["pii","recon"]),
    P("UUID",
      r"(?<![A-Za-z0-9\-])([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9\-])",
      "info", "UUID (possible resource ID or secret)", ["recon"]),

    # ── High-entropy generic fallback ─────────────────────────────────────────
    P("High-Entropy Assignment",
      r"""(?:secret|password|token|key|auth|apikey|credential)\s*[:=]\s*['\"`]([A-Za-z0-9+/\-_=!@#$%^&*]{32,})['\"`]""",
      "possible", "High-entropy secret-like assignment (verify manually)", ["generic"], 4.5),
]

# deduplicate patterns with identical names (e.g. Google API Key / Maps)
_seen_names = {}
_DEDUP_PATTERNS: list[P] = []
for _p in PATTERNS:
    if _p.name not in _seen_names:
        _seen_names[_p.name] = True
        _DEDUP_PATTERNS.append(_p)
PATTERNS = _DEDUP_PATTERNS

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

def _redact(s: str, keep=6) -> str:
    s = s.strip()
    if len(s) <= keep * 2: return "*" * len(s)
    return s[:keep] + "…" + "*" * min(8, len(s) - keep*2) + "…" + s[-3:]

# precompute line-start offsets for fast lineno lookup
def _build_offsets(text: str) -> list[int]:
    offs = [0]
    for i, ch in enumerate(text):
        if ch == "\n": offs.append(i+1)
    return offs

def _lineno(offs: list[int], pos: int) -> int:
    lo, hi = 0, len(offs) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if offs[mid] <= pos: lo = mid
        else: hi = mid - 1
    return lo + 1

def scan_text(source: str, text: str,
              min_sev="info", filter_tags=None) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()
    min_idx = SEVMAP.get(min_sev, 3)
    offsets = _build_offsets(text)

    for pat in PATTERNS:
        if SEVMAP[pat.sev] > min_idx: continue
        if filter_tags and not filter_tags.intersection(pat.tags): continue
        for m in pat._c.finditer(text):
            val = (m.group(1) if m.lastindex else m.group(0)).strip()
            if not val: continue
            if _is_fp(val): continue
            ent = _entropy(val)
            if pat.entropy_min and ent < pat.entropy_min: continue
            key = (pat.name, val)
            if key in seen: continue
            seen.add(key)
            out.append(Finding(
                source=source,
                line_no=_lineno(offsets, m.start()),
                name=pat.name, sev=pat.sev,
                desc=pat.desc, tags=list(pat.tags),
                match_raw=val, match_redacted=_redact(val),
                entropy=round(ent, 2),
            ))
    return out

# ── URL fetching ──────────────────────────────────────────────────────────────
_SKIP_CT = ("image/","video/","audio/","font/","application/pdf",
            "application/zip","application/octet","woff","ttf","eot")

def fetch_body(url: str, timeout=15) -> str:
    try:
        req = urllib.request.Request(url.strip(), headers={
            "User-Agent": "Mozilla/5.0 (astra/1.0; security-scanner)",
            "Accept": "text/html,application/javascript,application/json,*/*;q=0.9",
            "Accept-Encoding": "identity",
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type","")
            if any(x in ct for x in _SKIP_CT): return ""
            return r.read(5_000_000).decode("utf-8", errors="replace")
    except Exception:
        return ""

# ── output ────────────────────────────────────────────────────────────────────
BANNER = r"""
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
"""

def print_header(n_patterns: int):
    print(c(BANNER, C_HEAD))
    info = f"  {n_patterns} patterns  ·  entropy filtering  ·  placeholder suppression"
    print(c(info, C_GREY))
    legend = "  " + "  ".join(
        c(f"{SEV_ICO[s]} {s}", SEV_COL[s]) for s in SEVMAP)
    print(); print(legend)
    print(c("  " + "─"*58, C_GREY)); print()

def print_finding(f: Finding, show_raw=False):
    val  = c(f.match_raw if show_raw else f.match_redacted, C_PROB+B)
    tags = c(" ".join(f"[{t}]" for t in f.tags), C_GREY+DIM)
    ent  = c(f"entropy={f.entropy}", C_GREY+DIM)
    lno  = c(f"line {f.line_no}", C_BLU)
    print(f"  {badge(f.sev)} {c(f.name, B)}  {lno}")
    print(f"  {'':16} {c(f.desc, C_GREY)}  {tags}")
    print(f"  {'':16} {c('›', C_GREY)} {val}  {ent}")
    print()

def print_summary(n_sources, n_lines, findings, elapsed):
    by_sev = defaultdict(int)
    for f in findings: by_sev[f.sev] += 1
    speed = f"{n_lines/elapsed:,.0f} lines/s" if elapsed > 0 else ""
    print(c("  " + "─"*58, C_GREY))
    print(c(f"  sources {n_sources}   lines {n_lines:,}   {speed}", B))
    if not findings:
        print(c("  result  ✓ clean — no secrets detected", C_OK+B))
    else:
        print(c(f"  total   {len(findings)} finding(s)", C_CONF+B))
        for sev in SEVMAP:
            n = by_sev.get(sev, 0)
            if n: print(f"  {badge(sev)}  {n}")
    print(c("  " + "─"*58, C_GREY))

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(
        prog="astra",
        description="astra — fast, low-FP secret & credential scanner",
        epilog=(
            "examples:\n"
            "  cat urls.txt            | python3 astra.py\n"
            "  cat bundle.min.js       | python3 astra.py\n"
            "  python3 astra.py          app.js\n"
            "  python3 astra.py          ./src/ --ext js,ts,json,env\n"
            "  python3 astra.py          urls.txt --fetch --threads 25\n"
            "  python3 astra.py          app.js -s confirmed --json\n"
            "  python3 astra.py          --list --tags aws,payment\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("file",             nargs="?",
                    help="File or directory to scan (default: stdin)")
    ap.add_argument("-s","--severity",  default="info",
                    choices=list(SEVMAP), metavar="SEV",
                    help="Min severity: confirmed probable possible info  (default: info)")
    ap.add_argument("--fetch",          action="store_true",
                    help="Fetch URL lines and scan HTTP response bodies")
    ap.add_argument("--threads",        type=int, default=10,
                    help="Worker threads for --fetch (default: 10)")
    ap.add_argument("--json",           action="store_true",
                    help="Output findings as JSON array")
    ap.add_argument("--show-match",     action="store_true",
                    help="Show unredacted match values")
    ap.add_argument("--no-color",       action="store_true",
                    help="Disable ANSI colours")
    ap.add_argument("--list",           action="store_true",
                    help="List all patterns and exit")
    ap.add_argument("--tags",           metavar="TAGS",
                    help="Comma-separated tag filter e.g. aws,payment,xss")
    ap.add_argument("--ext",            metavar="EXT",
                    help="Directory mode: file extensions to scan e.g. js,ts,json")
    args = ap.parse_args()

    if args.no_color:
        USE_COLOR = False

    filter_tags = set(args.tags.split(",")) if args.tags else None

    if args.list:
        print(f"\n  {'NAME':<35} {'SEV':<13} {'TAGS':<28} DESC")
        print("  " + "─"*95)
        for p in sorted(PATTERNS, key=lambda x: (SEVMAP[x.sev], x.name)):
            if filter_tags and not filter_tags.intersection(p.tags): continue
            sv = c(f"{SEV_ICO[p.sev]} {p.sev}", SEV_COL[p.sev])
            print(f"  {p.name:<35} {sv:<22} {','.join(p.tags):<28} {p.desc}")
        print()
        sys.exit(0)

    # ── collect (label, text) sources ────────────────────────────────────────
    sources: list[tuple[str, str]] = []
    t0 = time.perf_counter()

    if args.file:
        p = Path(args.file)
        if p.is_dir():
            exts = {f".{e.lstrip('.')}" for e in args.ext.split(",")} if args.ext else None
            for fp in sorted(p.rglob("*")):
                if not fp.is_file(): continue
                if exts and fp.suffix.lower() not in exts: continue
                try:
                    sources.append((str(fp), fp.read_text(errors="replace")))
                except Exception:
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
        lines = [l.strip() for l in raw.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        # heuristic: URL list vs blob
        is_line_list = (
            len(lines) > 1
            and all(len(l) < 4096 for l in lines)
            and sum(1 for l in lines if l.startswith(("http://","https://"))) > len(lines) * 0.3
        )
        if is_line_list:
            for ln in lines:
                sources.append((ln, ln))
        else:
            sources.append(("<stdin>", raw))
    else:
        ap.print_help(); sys.exit(0)

    # ── optional URL fetch ────────────────────────────────────────────────────
    if args.fetch:
        url_srcs  = [(lbl, txt) for lbl, txt in sources
                     if txt.strip().startswith(("http://","https://"))]
        rest      = [(lbl, txt) for lbl, txt in sources
                     if not txt.strip().startswith(("http://","https://"))]
        fetched   = []
        def _fetch(item):
            lbl, url = item
            body = fetch_body(url.strip())
            return lbl, (url + "\n" + body) if body else (lbl, url)
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(_fetch, s): s for s in url_srcs}
            for fut in as_completed(futs):
                try:    fetched.append(fut.result())
                except: fetched.append(futs[fut])
        sources = rest + fetched

    # ── scan ─────────────────────────────────────────────────────────────────
    total_lines = sum(txt.count("\n") + 1 for _, txt in sources)
    all_findings: list[Finding] = []
    by_source: dict[str, list] = {}

    for lbl, txt in sources:
        found = scan_text(lbl, txt, args.severity, filter_tags)
        if found:
            by_source[lbl] = found
            all_findings.extend(found)

    elapsed = max(time.perf_counter() - t0, 1e-9)

    # ── JSON ──────────────────────────────────────────────────────────────────
    if args.json:
        out = []
        for f in all_findings:
            d = asdict(f)
            if not args.show_match: del d["match_raw"]
            out.append(d)
        print(json.dumps(out, indent=2))
        sys.exit(0 if not all_findings else 1)

    # ── human ─────────────────────────────────────────────────────────────────
    print_header(len(PATTERNS))

    if all_findings:
        for lbl, findings in by_source.items():
            print(c("  ╔" + "═"*64, C_GREY))
            print(c("  ║ ", C_GREY) + c(lbl[:100], B))
            print(c("  ╚" + "═"*64, C_GREY))
            print()
            for f in sorted(findings, key=lambda x: (SEVMAP[x.sev], x.line_no)):
                print_finding(f, show_raw=args.show_match)
    else:
        print(c("  ✓  nothing found — clean input\n", C_OK+B))

    print_summary(len(sources), total_lines, all_findings, elapsed)
    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
