#!/usr/bin/env python3
"""
astra — JavaScript Secret Hunter
Version: 2.0 (Tested & Working)
Features:
  - 150+ unique regex patterns
  - Sequential file scanning (one by one)
  - Line-by-line pattern matching
  - Proper error handling (404, etc.)
  - Color-coded output
  - JSON export
  - Tag filtering
  - Severity levels
  - Entropy checking
  - False positive filtering
"""

import sys
import re
import json
import argparse
import math
from pathlib import Path
from collections import defaultdict
from typing import List, Tuple, Dict, Any

# ── ANSI Colors ─────────────────────────────────────────────────────────
class C:
    R = '\033[91m'  # Red
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    B = '\033[94m'  # Blue
    M = '\033[95m'  # Magenta
    C = '\033[96m'  # Cyan
    W = '\033[97m'  # White
    X = '\033[90m'  # Gray
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RST = '\033[0m'

# ── Entropy ─────────────────────────────────────────────────────────────
def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    l = len(s)
    return -sum((v/l) * math.log2(v/l) for v in freq.values())

# ── False Positive Check ────────────────────────────────────────────────
_FP_SET = {
    'null','undefined','true','false','none','example','test','sample',
    'dummy','placeholder','your_key','your_token','insert_here','changeme',
    'todo','fixme','password','secret','api_key','apikey','token','redacted',
    'n/a','na','empty','1234567890','abcdefghij','0000000000','xxxxxxxxxxxx',
    'xxxxx','yyyyy','zzzzz','abcdef','123456','qwerty','asdfgh',
}

def is_fp(val: str) -> bool:
    v = val.strip()
    if len(v) < 6: return True
    if v.lower() in _FP_SET: return True
    if len(set(v.lower())) < 4: return True
    if v.count('x') > len(v) * 0.5: return True
    if v.count('*') > len(v) * 0.3: return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
# 150+ UNIQUE PATTERNS - Each tested for compilation
# ═══════════════════════════════════════════════════════════════════════════

def build_patterns() -> List[Tuple[str, str, str, List[str], float]]:
    """Returns list of (regex, name, severity, tags, entropy_min)"""
    patterns = []
    
    def add(rx, name, sev, tags, ent=0.0):
        patterns.append((rx, name, sev, tags, ent))
    
    # AWS (8 patterns)
    add(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', ['aws'], 3.0)
    add(r'(?i)aws_secret_access_key\s*[=:]\s*[\'"]([A-Za-z0-9/+=]{40})[\'"]', 'AWS Secret Key', 'confirmed', ['aws'], 4.5)
    add(r'(?i)aws_session_token\s*[=:]\s*[\'"]([A-Za-z0-9/+=]{100,})[\'"]', 'AWS Session Token', 'confirmed', ['aws'], 4.0)
    add(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Token', 'confirmed', ['aws'])
    add(r'(?<![A-Za-z0-9])(FWO[A-Za-z0-9/+=]{40,})(?![A-Za-z0-9/+=])', 'AWS STS FWO Token', 'confirmed', ['aws'], 4.0)
    
    # Google Cloud / Firebase (7 patterns)
    add(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', ['google'], 3.5)
    add(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth Token', 'confirmed', ['google'])
    add(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Secret', 'confirmed', ['google'])
    add(r'(6L[0-9A-Za-z\-_]{38})', 'Google reCAPTCHA', 'probable', ['google'], 3.5)
    add(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'Firebase FCM Key', 'confirmed', ['firebase'])
    add(r'"type"\s*:\s*"service_account"', 'GCP Service Account', 'confirmed', ['gcp'])
    add(r'([0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com)', 'Google OAuth Client ID', 'probable', ['google'])
    
    # GitHub (3 patterns)
    add(r'(ghp_[A-Za-z0-9]{36})', 'GitHub PAT', 'confirmed', ['github'])
    add(r'(ghs_[A-Za-z0-9]{36})', 'GitHub Actions Token', 'confirmed', ['github'])
    add(r'(github_pat_[A-Za-z0-9_]{82})', 'GitHub Fine PAT', 'confirmed', ['github'])
    
    # GitLab (6 patterns)
    add(r'(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab PAT', 'confirmed', ['gitlab'])
    add(r'(gldt-[A-Za-z0-9_\-]{20,})', 'GitLab Deploy Token', 'confirmed', ['gitlab'])
    add(r'(glcbt-[A-Za-z0-9_\-]{20,})', 'GitLab CI Token', 'confirmed', ['gitlab'])
    add(r'(glptt-[A-Za-z0-9_\-]{20,})', 'GitLab Project Token', 'confirmed', ['gitlab'])
    add(r'(glrt-[A-Za-z0-9_\-]{20,})', 'GitLab Runner Token', 'confirmed', ['gitlab'])
    add(r'(glso-[A-Za-z0-9_\-]{20,})', 'GitLab Service Token', 'confirmed', ['gitlab'])
    
    # Azure (7 patterns)
    add(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88})', 'Azure Storage Key', 'confirmed', ['azure'])
    add(r'(Endpoint=sb://[^;]+\.servicebus\.windows\.net/[^;"\'\s]*)', 'Azure Service Bus', 'confirmed', ['azure'])
    add(r'(sig=[A-Za-z0-9%+/]{20,}&se=[0-9T:Z%\-]+&sp=[a-z]+)', 'Azure SAS Token', 'confirmed', ['azure'])
    add(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps PAT', 'confirmed', ['azure'], 4.0)
    add(r'(?i)azure_client_id\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Client ID', 'probable', ['azure'])
    add(r'(?i)azure_tenant_id\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Tenant ID', 'probable', ['azure'])
    add(r'https://[a-z0-9\-]+\.blob\.core\.windows\.net/', 'Azure Blob URL', 'info', ['azure'])
    
    # Stripe (4 patterns)
    add(r'(sk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Key', 'confirmed', ['stripe'])
    add(r'(rk_live_[0-9a-zA-Z]{24,99})', 'Stripe Restricted Key', 'confirmed', ['stripe'])
    add(r'(sk_test_[0-9a-zA-Z]{24,99})', 'Stripe Test Key', 'possible', ['stripe'])
    add(r'(whsec_[0-9a-zA-Z]{32,})', 'Stripe Webhook Secret', 'confirmed', ['stripe'], 3.5)
    
    # OpenAI / AI (9 patterns)
    add(r'(sk-[A-Za-z0-9]{48})', 'OpenAI API Key', 'confirmed', ['openai'], 4.0)
    add(r'(sk-proj-[A-Za-z0-9_\-]{40,})', 'OpenAI Project Key', 'confirmed', ['openai'], 4.0)
    add(r'(sk-ant-api\d+-[A-Za-z0-9_\-]{40,})', 'Anthropic API Key', 'confirmed', ['anthropic'])
    add(r'(hf_[a-zA-Z0-9]{34,})', 'HuggingFace Token', 'confirmed', ['huggingface'])
    add(r'(gsk_[A-Za-z0-9]{52})', 'Groq API Key', 'confirmed', ['groq'], 4.0)
    add(r'(pplx-[A-Za-z0-9]{48})', 'Perplexity Key', 'confirmed', ['perplexity'], 4.0)
    add(r'(sk-or-v1-[A-Za-z0-9]{48})', 'OpenRouter Key', 'confirmed', ['openrouter'], 4.0)
    add(r'(r8_[A-Za-z0-9]{40})', 'Replicate Token', 'confirmed', ['replicate'])
    add(r'(tvly-[A-Za-z0-9]{32})', 'Tavily AI Key', 'confirmed', ['tavily'], 4.0)
    
    # Slack / Discord (4 patterns)
    add(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})', 'Slack Token', 'confirmed', ['slack'])
    add(r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+', 'Slack Webhook', 'confirmed', ['slack'])
    add(r'(M[A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})', 'Discord Bot Token', 'confirmed', ['discord'], 4.0)
    add(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', 'Discord Webhook', 'confirmed', ['discord'])
    
    # Private Keys (7 patterns)
    add(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'confirmed', ['crypto'])
    add(r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key', 'confirmed', ['crypto'])
    add(r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 'confirmed', ['crypto'])
    add(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'confirmed', ['crypto'])
    add(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Key', 'confirmed', ['crypto'])
    add(r'-----BEGIN PRIVATE KEY-----', 'PKCS8 Key', 'confirmed', ['crypto'])
    add(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Encrypted Key', 'confirmed', ['crypto'])
    
    # Database DSNs (8 patterns)
    add(r'mongodb\+srv://[^:]+:[^@]+@[^\s"\'<>]+', 'MongoDB Atlas DSN', 'confirmed', ['database'], 2.5)
    add(r'postgresql://[^:]+:[^@]+@[^\s"\'<>]+', 'PostgreSQL DSN', 'confirmed', ['database'], 2.5)
    add(r'mysql://[^:]+:[^@]+@[^\s"\'<>]+', 'MySQL DSN', 'confirmed', ['database'], 2.5)
    add(r'redis://[^:]+:[^@]+@[^\s"\'<>]+', 'Redis DSN', 'confirmed', ['database'], 2.5)
    add(r'clickhouse://[^:]+:[^@]+@[^\s"\'<>]+', 'ClickHouse DSN', 'confirmed', ['database'], 2.5)
    add(r'jdbc:[a-zA-Z]+://[^\s"\'<>]+', 'JDBC String', 'confirmed', ['database'])
    add(r'rediss://default:[^@]+@[^\s]+\.upstash\.io:\d+', 'Upstash Redis', 'confirmed', ['database'], 3.0)
    add(r'postgresql://[^:]+:[^@]+@[^\s]+\.neon\.tech', 'Neon DSN', 'confirmed', ['database'], 2.5)
    
    # Payment (10 patterns)
    add(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'PayPal Braintree', 'confirmed', ['paypal'])
    add(r'EAAA[A-Za-z0-9\-_]{22,}', 'Square Access Token', 'confirmed', ['square'], 3.5)
    add(r'sq0atp-[A-Za-z0-9\-_]{22,}', 'Square OAuth Token', 'confirmed', ['square'], 3.5)
    add(r'sq0csp-[A-Za-z0-9_\-]{43}', 'Square OAuth Secret', 'confirmed', ['square'])
    add(r'AQ[A-Za-z0-9_\-]{30,}', 'Adyen API Key', 'confirmed', ['adyen'], 3.5)
    add(r'rzp_live_[A-Za-z0-9]{14,}', 'Razorpay Live', 'confirmed', ['razorpay'], 3.5)
    add(r'rzp_test_[A-Za-z0-9]{14,}', 'Razorpay Test', 'possible', ['razorpay'], 3.5)
    add(r'FLWSECK-[a-zA-Z0-9]{32}', 'Flutterwave Secret', 'confirmed', ['flutterwave'], 3.5)
    add(r'sk_live_[A-Za-z0-9]{40}', 'Paystack Live', 'confirmed', ['paystack'], 4.0)
    add(r'sk_test_[A-Za-z0-9]{40}', 'Paystack Test', 'possible', ['paystack'], 4.0)
    
    # Email Services (5 patterns)
    add(r'key-[0-9a-zA-Z]{32}', 'Mailgun Key', 'confirmed', ['mailgun'])
    add(r'[a-f0-9]{32}-us[0-9]{1,2}', 'Mailchimp Key', 'confirmed', ['mailchimp'], 3.5)
    add(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', 'SendGrid Key', 'confirmed', ['sendgrid'])
    add(r're_[A-Za-z0-9_]{24,}', 'Resend Key', 'confirmed', ['resend'], 4.0)
    add(r'(?i)sendgrid_api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'SendGrid (Context)', 'confirmed', ['sendgrid'], 3.5)
    
    # CI/CD (6 patterns)
    add(r'circleci-[a-f0-9]{40}', 'CircleCI Token', 'confirmed', ['circleci'])
    add(r'bkua_[a-zA-Z0-9]{40}', 'Buildkite Token', 'confirmed', ['buildkite'], 4.0)
    add(r'pul-[a-zA-Z0-9]{40}', 'Pulumi Token', 'confirmed', ['pulumi'], 4.0)
    add(r'(?i)jenkins_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{20,})[\'"]', 'Jenkins Token', 'probable', ['jenkins'], 3.0)
    add(r'(?i)travis_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{20,})[\'"]', 'Travis Token', 'probable', ['travis'], 3.0)
    add(r'(?i)bitrise_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Bitrise Token', 'probable', ['bitrise'], 3.0)
    
    # Social Media (5 patterns)
    add(r'AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+/]{40,}', 'Twitter Bearer', 'confirmed', ['twitter'], 4.0)
    add(r'EAACEdEose0cBA[0-9A-Za-z]+', 'Facebook Token', 'confirmed', ['facebook'])
    add(r'oauth:[a-z0-9]{30,}', 'Twitch OAuth', 'confirmed', ['twitch'], 3.5)
    add(r'(?i)twitch_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{30})[\'"]', 'Twitch Secret', 'confirmed', ['twitch'], 3.5)
    add(r'(?i)linkedin_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{16})[\'"]', 'LinkedIn Secret', 'confirmed', ['linkedin'], 3.0)
    
    # Cloud Services (10 patterns)
    add(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean PAT', 'confirmed', ['digitalocean'])
    add(r'DO00[A-Za-z0-9]{32,}', 'DO Spaces Key', 'confirmed', ['digitalocean'], 3.5)
    add(r'rnd_[A-Za-z0-9]{32}', 'Render Key', 'confirmed', ['render'], 3.5)
    add(r'SCW[A-Z0-9]{20,}', 'Scaleway Key', 'confirmed', ['scaleway'], 3.5)
    add(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Key', 'confirmed', ['alibaba'], 3.0)
    add(r'(?i)heroku_api_key\s*[=:]\s*[\'"]([0-9a-f-]{36})[\'"]', 'Heroku Key', 'confirmed', ['heroku'])
    add(r'(?i)cloudflare_api_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{37,40})[\'"]', 'Cloudflare Token', 'confirmed', ['cloudflare'], 3.5)
    add(r'(?i)netlify_access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'Netlify Token', 'confirmed', ['netlify'], 3.5)
    add(r'(?i)vercel_token\s*[=:]\s*[\'"]([A-Za-z0-9]{24})[\'"]', 'Vercel Token', 'probable', ['vercel'], 3.0)
    add(r'(?i)ibmcloud_api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{44})[\'"]', 'IBM Cloud Key', 'confirmed', ['ibm'], 4.0)
    
    # Monitoring (7 patterns)
    add(r'https://[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+', 'Sentry DSN', 'confirmed', ['sentry'])
    add(r'NRAK-[A-Z0-9]{27}', 'New Relic Key', 'confirmed', ['newrelic'], 3.5)
    add(r'(?i)datadog_api_key\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Datadog API Key', 'confirmed', ['datadog'], 3.5)
    add(r'(?i)datadog_app_key\s*[=:]\s*[\'"]([a-f0-9]{40})[\'"]', 'Datadog App Key', 'confirmed', ['datadog'], 3.5)
    add(r'glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}', 'Grafana SA Token', 'confirmed', ['grafana'], 4.0)
    add(r'glc_eyJ[A-Za-z0-9+/=]{60,}', 'Grafana Cloud Policy', 'confirmed', ['grafana'], 4.0)
    add(r'dt0[a-z0-9]{2,5}\.[A-Za-z0-9]{8}\.[A-Za-z0-9]{64}', 'Dynatrace Token', 'confirmed', ['dynatrace'], 4.0)
    
    # Security / Auth (6 patterns)
    add(r'SSWS [A-Za-z0-9_\-]{40,}', 'Okta Token', 'confirmed', ['okta'], 4.0)
    add(r'(?i)auth0_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Auth0 Secret', 'confirmed', ['auth0'], 3.5)
    add(r'sk_[a-z]+_[A-Za-z0-9]{30,}', 'WorkOS Key', 'confirmed', ['workos'], 4.0)
    add(r'sk_prod_[A-Za-z0-9]{40,}', 'Liveblocks Prod', 'confirmed', ['liveblocks'], 4.0)
    add(r'sk_dev_[A-Za-z0-9]{40,}', 'Liveblocks Dev', 'possible', ['liveblocks'], 4.0)
    add(r'secret-live-[A-Za-z0-9\-]{36}', 'Stytch Live', 'confirmed', ['stytch'], 4.0)
    
    # SaaS (10 patterns)
    add(r'CFPAT-[A-Za-z0-9_\-]{40,}', 'Contentful PAT', 'confirmed', ['contentful'], 4.0)
    add(r'PMAK-[A-Za-z0-9\-]{40,}', 'Postman Key', 'confirmed', ['postman'], 4.0)
    add(r'secret_[A-Za-z0-9]{40,}', 'Notion Token', 'confirmed', ['notion'], 3.5)
    add(r'ntn_[A-Za-z0-9]{48,}', 'Notion New Token', 'confirmed', ['notion'], 4.0)
    add(r'figd_[A-Za-z0-9_\-]{40,}', 'Figma Token', 'confirmed', ['figma'], 4.0)
    add(r'dapi[a-f0-9]{32}', 'Databricks Token', 'confirmed', ['databricks'], 3.5)
    add(r'lin_api_[A-Za-z0-9]{30,}', 'Linear Key', 'confirmed', ['linear'], 4.0)
    add(r'tfp_[A-Za-z0-9]{40,}', 'Typeform Token', 'confirmed', ['typeform'], 4.0)
    add(r'EZAK[a-zA-Z0-9]{54}', 'EasyPost Key', 'confirmed', ['easypost'], 4.0)
    add(r'duffel_live_[A-Za-z0-9_\-]{40}', 'Duffel Live', 'confirmed', ['duffel'], 4.0)
    
    # Crypto / Web3 (7 patterns)
    add(r'0x[a-fA-F0-9]{40}', 'Ethereum Address', 'info', ['ethereum'])
    add(r'alch-[A-Za-z0-9_\-]{32}', 'Alchemy Key', 'confirmed', ['alchemy'], 4.0)
    add(r'(?i)etherscan_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{34})[\'"]', 'Etherscan Key', 'confirmed', ['etherscan'], 3.5)
    add(r'(?i)infura_project_secret\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Infura Secret', 'confirmed', ['infura'], 3.5)
    add(r'(?i)solana_private_key\s*[=:]\s*[\'"]([1-9A-HJ-NP-Za-km-z]{87,88})[\'"]', 'Solana Key', 'confirmed', ['solana'], 4.5)
    add(r'(?i)alchemy_api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Alchemy (Context)', 'probable', ['alchemy'], 3.5)
    add(r'(?i)moralis_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Moralis Key', 'probable', ['moralis'], 3.5)
    
    # Generic Secrets (10 patterns)
    add(r'(?i)client_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.~]{20,})[\'"]', 'OAuth Client Secret', 'confirmed', ['oauth'], 3.0)
    add(r'(?i)api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{16,})[\'"]', 'API Key (Generic)', 'confirmed', ['api-key'], 3.0)
    add(r'(?i)access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Access Token', 'confirmed', ['token'], 3.0)
    add(r'(?i)private_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-+/=]{40,})[\'"]', 'Private Key Value', 'confirmed', ['crypto'], 4.0)
    add(r'(?i)secret_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Secret Key', 'probable', ['secret'], 3.5)
    add(r'(?i)password\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]', 'Password', 'probable', ['password'], 2.8)
    add(r'(?i)api_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.~!@#]{8,})[\'"]', 'API Secret', 'probable', ['secret'], 3.5)
    add(r'(?i)auth_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Auth Token', 'probable', ['token'], 3.0)
    add(r'(?i)encryption_key\s*[=:]\s*[\'"]([A-Za-z0-9+/=]{32,})[\'"]', 'Encryption Key', 'confirmed', ['crypto'], 3.5)
    add(r'(?i)session_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Session Secret', 'probable', ['credentials'], 3.0)
    
    # JWT / Tokens (3 patterns)
    add(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 'JWT Token', 'probable', ['jwt'], 4.0)
    add(r'(?i)bearer\s+([A-Za-z0-9\-\._~+/]{20,}=*)', 'Bearer Token', 'probable', ['token'], 3.5)
    add(r'(?i)Basic\s+([A-Za-z0-9+/=]{20,})', 'Basic Auth', 'probable', ['auth'], 3.0)
    
    # URL Credentials (3 patterns)
    add(r'https?://[^:]+:([^@]{8,})@[^\s]+', 'Basic Auth URL', 'confirmed', ['url'], 2.0)
    add(r'[?&](?:token|api_key|apikey|access_token)=([A-Za-z0-9_\-\.%+]{8,})', 'Secret in URL', 'confirmed', ['url'], 2.5)
    add(r'[?&](?:secret|password|passwd)=([A-Za-z0-9_\-\.%+]{8,})', 'Password in URL', 'confirmed', ['url'], 2.5)
    
    # Framework Secrets (5 patterns)
    add(r'(?i)django_secret_key\s*[=:]\s*[\'"]([^\'"]{32,})[\'"]', 'Django Key', 'confirmed', ['django'], 3.5)
    add(r'base64:[A-Za-z0-9+/]{44}=', 'Laravel Key', 'confirmed', ['laravel'], 4.0)
    add(r'(?i)rails_master_key\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Rails Key', 'confirmed', ['rails'], 3.5)
    add(r'(?i)jwt_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'JWT Secret', 'confirmed', ['jwt'], 3.5)
    add(r'(?i)cookie_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Cookie Secret', 'probable', ['credentials'], 3.0)
    
    # Package Managers (3 patterns)
    add(r'npm_[A-Za-z0-9]{36}', 'npm Token', 'confirmed', ['npm'])
    add(r'pypi-[A-Za-z0-9_\-]{32,}', 'PyPI Token', 'confirmed', ['pypi'])
    add(r'rubygems_[a-zA-Z0-9]{48}', 'RubyGems Key', 'confirmed', ['rubygems'], 4.0)
    
    # Security Tools (4 patterns)
    add(r'sgp_[A-Za-z0-9]{40}', 'Sourcegraph Token', 'confirmed', ['sourcegraph'], 4.0)
    add(r'sqa_[A-Za-z0-9]{40}', 'SonarCloud Token', 'confirmed', ['sonarcloud'], 4.0)
    add(r'(?i)snyk_api_token\s*[=:]\s*[\'"]([a-f0-9\-]{36})[\'"]', 'Snyk Token', 'confirmed', ['snyk'], 3.5)
    add(r'(?i)codecov_token\s*[=:]\s*[\'"]([A-Za-z0-9\-]{36})[\'"]', 'Codecov Token', 'confirmed', ['codecov'], 3.5)
    
    # Additional SaaS (8 patterns)
    add(r'pat-[a-zA-Z0-9]{14,22}\.[a-f0-9]{64}', 'Airtable PAT', 'confirmed', ['airtable'], 4.0)
    add(r'BBDC-[A-Za-z0-9]{32,}', 'Bitbucket Token', 'confirmed', ['bitbucket'], 4.0)
    add(r'hvs\.[A-Za-z0-9_\-+/=]{50,}', 'Vault Token', 'confirmed', ['vault'], 4.0)
    add(r'hvb\.[A-Za-z0-9_\-]{40,}', 'Vault Batch', 'confirmed', ['vault'], 4.0)
    add(r'pnu_[A-Za-z0-9]{36}', 'Prefect Token', 'confirmed', ['prefect'], 4.0)
    add(r'fw_[A-Za-z0-9]{32,}', 'Fireworks Key', 'confirmed', ['fireworks'], 4.0)
    add(r'esecret_[A-Za-z0-9_\-]{40,}', 'Anyscale Key', 'confirmed', ['anyscale'], 4.0)
    add(r'novu_[A-Za-z0-9_\-]{30,}', 'Novu Key', 'confirmed', ['novu'], 4.0)
    
    # Database Services (4 patterns)
    add(r'xau_[A-Za-z0-9_\-]{40,}', 'Xata Key', 'confirmed', ['xata'], 4.0)
    add(r'pscale_oauth_[A-Za-z0-9_]{32,}', 'PlanetScale OAuth', 'confirmed', ['planetscale'], 4.0)
    add(r'mysql://[^:]+:[^@]+@[^\s]+\.psdb\.cloud', 'PlanetScale DSN', 'confirmed', ['planetscale'], 2.5)
    add(r'libsql://[^\s]+\.turso\.io', 'Turso DB URL', 'info', ['turso'])
    
    # Mapbox / Shopify / Cloudinary (4 patterns)
    add(r'(?:pk|sk)\.eyJ1[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', 'Mapbox Token', 'confirmed', ['mapbox'])
    add(r'shpat_[a-fA-F0-9]{32}', 'Shopify Admin', 'confirmed', ['shopify'])
    add(r'shpca_[a-fA-F0-9]{32}', 'Shopify Custom', 'confirmed', ['shopify'])
    add(r'cloudinary://\d+:[A-Za-z0-9_\-]+@', 'Cloudinary URL', 'confirmed', ['cloudinary'])
    
    # Communication (3 patterns)
    add(r'\d{8,10}:[A-Za-z0-9_\-]{35}', 'Telegram Bot', 'probable', ['telegram'], 3.5)
    add(r'(?i)vonage_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{8,20})[\'"]', 'Vonage Key', 'probable', ['vonage'], 3.0)
    add(r'(?i)pushover_user_key\s*[=:]\s*[\'"]([A-Za-z0-9]{30})[\'"]', 'Pushover Key', 'probable', ['pushover'], 3.0)
    
    # CMS (4 patterns)
    add(r'(?i)wordpress_nonce\s*[=:]\s*[\'"]([a-f0-9A-Za-z_]{10,})[\'"]', 'WordPress Nonce', 'probable', ['wordpress'], 3.0)
    add(r'(?i)drupal_private_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'Drupal Key', 'probable', ['drupal'], 3.5)
    add(r'(?i)joomla_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Joomla Secret', 'probable', ['joomla'], 3.5)
    add(r'(?i)bigcommerce_token\s*[=:]\s*[\'"]([a-f0-9]{32,})[\'"]', 'BigCommerce Token', 'probable', ['bigcommerce'], 3.5)
    
    # Security Issues (6 patterns)
    add(r'(?i)eval\s*\([^)]*location\.', 'eval(location) XSS', 'possible', ['xss'])
    add(r'(?i)\.innerHTML\s*=\s*`[^`]*\$\{', 'innerHTML XSS', 'possible', ['xss'])
    add(r'(?i)document\.write\s*\([^)]*location\.', 'doc.write XSS', 'possible', ['xss'])
    add(r'(?i)exec\s*\(\s*`[^`]*\$\{[^}]*req\.', 'Command Injection', 'confirmed', ['rce'])
    add(r'(?i)pickle\.loads\s*\(', 'Pickle RCE', 'confirmed', ['rce'])
    add(r'(?i)vm\.runInNewContext\s*\([^)]*req\.', 'VM Sandbox Escape', 'possible', ['rce'])
    
    # Recon (4 patterns)
    add(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Private IP A', 'info', ['infra'])
    add(r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'Private IP B', 'info', ['infra'])
    add(r'192\.168\.\d{1,3}\.\d{1,3}', 'Private IP C', 'info', ['infra'])
    add(r'[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', 'Email Address', 'info', ['pii'])
    
    # Shopify / E-commerce (4 patterns)
    add(r'ck_[a-f0-9]{40}', 'WooCommerce CK', 'confirmed', ['woocommerce'], 3.5)
    add(r'cs_[a-f0-9]{40}', 'WooCommerce CS', 'confirmed', ['woocommerce'], 3.5)
    add(r'FLWPUBK-[a-zA-Z0-9]{32}', 'Flutterwave Public', 'probable', ['flutterwave'], 3.5)
    add(r'pk_live_[A-Za-z0-9]{40}', 'Paystack Public', 'probable', ['paystack'], 4.0)
    
    # Additional (2 patterns)
    add(r'waka_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}', 'WakaTime Key', 'confirmed', ['wakatime'], 3.5)
    add(r'signkey-(?:prod|test)-[A-Za-z0-9]{32,}', 'Inngest Key', 'confirmed', ['inngest'], 4.0)
    
    # Remove duplicates
    seen = set()
    unique = []
    for p in patterns:
        if p[0] not in seen:
            seen.add(p[0])
            unique.append(p)
    
    return unique

# Build patterns ONCE
PATTERNS = build_patterns()

# ═══════════════════════════════════════════════════════════════════════════
# SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════

class SecretScanner:
    def __init__(self, severity='possible', show_raw=False, verbose=False,
                 json_output=False, filter_tags=None):
        self.severity = severity
        self.show_raw = show_raw
        self.verbose = verbose
        self.json_output = json_output
        self.filter_tags = set(filter_tags.split(',')) if filter_tags else None
        
        self.files_scanned = 0
        self.files_with_secrets = 0
        self.total_findings = 0
        
        self.compiled = self._compile()
    
    def _compile(self):
        sev_levels = {'confirmed': 0, 'probable': 1, 'possible': 2, 'info': 3}
        min_level = sev_levels.get(self.severity, 3)
        
        compiled = []
        for rx, name, sev, tags, ent_min in PATTERNS:
            if sev_levels.get(sev, 3) > min_level:
                continue
            if self.filter_tags and not self.filter_tags.intersection(tags):
                continue
            try:
                compiled.append((re.compile(rx, re.IGNORECASE | re.MULTILINE), 
                               name, sev, tags, ent_min))
            except:
                if self.verbose:
                    print(f"{C.Y}[!] Bad pattern: {name}{C.RST}", file=sys.stderr)
        return compiled
    
    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a file line by line. Returns list of findings."""
        p = Path(filepath)
        
        # Check exists
        if not p.exists():
            if self.verbose:
                print(f"{C.R}[✗] 404: {filepath}{C.RST}", file=sys.stderr)
            return []
        
        # Check extension
        exts = {'.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.env', '.conf', '.config'}
        if p.suffix.lower() not in exts:
            if self.verbose:
                print(f"{C.Y}[!] Skip: {filepath}{C.RST}", file=sys.stderr)
            return []
        
        # Read file
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            if self.verbose:
                print(f"{C.R}[✗] Read error: {filepath} - {e}{C.RST}", file=sys.stderr)
            return []
        
        findings = []
        
        # Check each line against each pattern
        for line_num, line in enumerate(lines, 1):
            for pattern, name, sev, tags, ent_min in self.compiled:
                for match in pattern.finditer(line):
                    val = match.group(1) if match.lastindex else match.group(0)
                    val = val.strip()
                    
                    if is_fp(val):
                        continue
                    
                    if ent_min > 0:
                        if entropy(val) < ent_min:
                            continue
                    
                    findings.append({
                        'file': filepath,
                        'line': line_num,
                        'pattern': name,
                        'severity': sev,
                        'tags': list(tags),
                        'value': val if self.show_raw else self._redact(val),
                        'entropy': round(entropy(val), 2)
                    })
        
        return findings
    
    def _redact(self, val: str) -> str:
        if len(val) <= 6:
            return '*' * len(val)
        return val[:3] + '*' * (len(val) - 6) + val[-3:]
    
    def scan_all(self, files: List[str]):
        """Main method - scan all files sequentially."""
        if not files:
            print(f"{C.R}[✗] No files provided{C.RST}")
            return
        
        if not self.json_output:
            self._print_banner()
        
        all_findings = []
        
        for idx, fp in enumerate(files, 1):
            if self.verbose and not self.json_output:
                print(f"{C.X}[{idx}/{len(files)}] Scanning: {fp}{C.RST}")
            
            findings = self.scan_file(fp)
            self.files_scanned += 1
            
            if findings:
                self.files_with_secrets += 1
                self.total_findings += len(findings)
                all_findings.extend(findings)
                
                if not self.json_output:
                    self._show_findings(fp, findings, idx, len(files))
            else:
                if not self.json_output:
                    print(f"{C.G}[{idx}/{len(files)}] ✓ Clean: {fp}{C.RST}")
        
        if not self.json_output:
            self._show_summary(all_findings)
        else:
            print(json.dumps(all_findings, indent=2))
    
    def _print_banner(self):
        print(f"\n{C.BOLD}{C.C}╔══════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.C}║   ASTRA - JS Secret Hunter v2.0              ║{C.RST}")
        print(f"{C.BOLD}{C.C}║   {len(PATTERNS)} Unique Patterns                      ║{C.RST}")
        print(f"{C.BOLD}{C.C}╚══════════════════════════════════════════════╝{C.RST}")
        print(f"{C.W}  Severity: {self.severity.upper()}{C.RST}")
        if self.filter_tags:
            print(f"{C.W}  Tags: {', '.join(sorted(self.filter_tags))}{C.RST}")
        print(f"{C.X}{'─' * 50}{C.RST}\n")
    
    def _show_findings(self, fp, findings, idx, total):
        sev_c = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
        
        print(f"\n{C.BOLD}{C.G}┌─ [{idx}/{total}] {fp}{C.RST}")
        print(f"{C.BOLD}{C.G}├─ {len(findings)} finding(s){C.RST}")
        
        for f in findings:
            c = sev_c.get(f['severity'], C.W)
            tags = f"[{','.join(f['tags'])}]" if f['tags'] else ""
            ent = f" ent={f['entropy']}" if f['entropy'] > 0 else ""
            print(f"{c}│  [{f['severity'].upper():10}] L{f['line']:4} | "
                  f"{f['pattern']:35} | {f['value']}{ent} {C.X}{tags}{C.RST}")
        
        print(f"{C.BOLD}{C.G}└{'─' * 50}{C.RST}")
    
    def _show_summary(self, findings):
        print(f"\n{C.BOLD}{C.M}╔══════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.M}║   SCAN SUMMARY                               ║{C.RST}")
        print(f"{C.BOLD}{C.M}╚══════════════════════════════════════════════╝{C.RST}")
        print(f"  Files scanned:    {self.files_scanned}")
        print(f"  With secrets:     {self.files_with_secrets}")
        print(f"  Total findings:   {self.total_findings}")
        
        if not findings:
            print(f"\n{C.G}  ✓ CLEAN - No secrets found{C.RST}")
        else:
            print(f"\n{C.R}  ⚠ FOUND {self.total_findings} POTENTIAL SECRETS{C.RST}")
            
            sev_count = defaultdict(int)
            for f in findings:
                sev_count[f['severity']] += 1
            
            colors = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
            for s in ['confirmed', 'probable', 'possible', 'info']:
                if sev_count[s]:
                    print(f"  {colors[s]}[{s.upper():10}] {sev_count[s]}{C.RST}")
        
        print(f"{C.BOLD}{C.M}{'═' * 50}{C.RST}\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='astra - JS Secret Hunter (150+ patterns)',
        epilog="""
Examples:
  python astra.py app.js bundle.js
  python astra.py *.js -s confirmed
  python astra.py src/*.js -r -v
  python astra.py bundle.js -j
  python astra.py *.js -t aws,payment
  python astra.py -l  (list all patterns)
        """
    )
    parser.add_argument('files', nargs='*', help='Files to scan')
    parser.add_argument('-s', '--severity', default='possible',
                       choices=['confirmed','probable','possible','info'])
    parser.add_argument('-r', '--show-raw', action='store_true', help='Show raw secrets')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-j', '--json', action='store_true', help='JSON output')
    parser.add_argument('-t', '--tags', help='Filter by tags (comma-separated)')
    parser.add_argument('-l', '--list', action='store_true', help='List all patterns')
    
    args = parser.parse_args()
    
    # List patterns
    if args.list:
        print(f"\n{C.BOLD}Total unique patterns: {len(PATTERNS)}{C.RST}\n")
        print(f"{'NAME':<40} {'SEV':<12} {'TAGS':<30} {'ENTROPY':<8}")
        print('─' * 95)
        for rx, name, sev, tags, ent in sorted(PATTERNS, key=lambda x: x[2]):
            e = f'{ent:.1f}' if ent > 0 else 'N/A'
            print(f'{name:<40} {sev:<12} {",".join(tags):<30} {e:<8}')
        print()
        sys.exit(0)
    
    # Need files
    if not args.files:
        parser.print_help()
        sys.exit(1)
    
    scanner = SecretScanner(
        severity=args.severity,
        show_raw=args.show_raw,
        verbose=args.verbose,
        json_output=args.json,
        filter_tags=args.tags
    )
    
    scanner.scan_all(args.files)
    
    # Exit code: 1 if secrets found
    sys.exit(1 if scanner.total_findings > 0 else 0)

if __name__ == '__main__':
    main()
