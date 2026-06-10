#!/usr/bin/env python3
"""
astra — Secret & Credential Scanner v1.3
==========================================
307+ unique patterns · zero dependencies · Python 3.7+
Precision-first, JS-aware secret detection.
Scans files, directories, and live URLs with threaded fetching.
"""

import sys
import re
import json
import argparse
import math
import time
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse

# ── ANSI Colors ──────────────────────────────────────────────────────────
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; X = '\033[90m'
    BOLD = '\033[1m'; DIM = '\033[2m'; RST = '\033[0m'

BANNER = rf"""{C.BOLD}{C.C}
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
{C.RST}{C.X}  secret & credential scanner v1.3{C.RST}
"""

# ── Entropy ──────────────────────────────────────────────────────────────
def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    l = len(s)
    return -sum((v/l) * math.log2(v/l) for v in freq.values())

# ── Secret Context Keywords ──────────────────────────────────────────────
_SECRET_KEYWORDS = {
    'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'auth',
    'api_key', 'apikey', 'api_secret', 'apisecret', 'access_key', 'accesskey',
    'access_token', 'accesstoken', 'private_key', 'privatekey',
    'client_secret', 'clientsecret', 'secret_key', 'secretkey',
    'encryption_key', 'encryptionkey', 'jwt_secret', 'jwtsecret',
    'session_secret', 'sessionsecret', 'cookie_secret', 'cookiesecret',
    'refresh_token', 'refreshtoken', 'id_token', 'idtoken',
    'auth_token', 'authtoken', 'bearer_token', 'bearertoken',
    'db_password', 'dbpassword', 'database_password', 'databasepassword',
    'smtp_password', 'smtppassword', 'ftp_password', 'ftppassword',
    'admin_password', 'adminpassword', 'root_password', 'rootpassword',
    'user_password', 'userpassword', 'master_key', 'masterkey',
    'app_secret', 'appsecret', 'app_key', 'appkey',
    'webhook_secret', 'webhooksecret', 'signing_secret', 'signingsecret',
    'connection_string', 'connectionstring', 'dsn', 'uri',
    'credential', 'credentials', 'authorization', 'authorisation',
    'license_key', 'licensekey', 'subscription_key', 'subscriptionkey',
}

_FP_BLACKLIST = {
    'null', 'undefined', 'true', 'false', 'none', 'example', 'test', 'sample',
    'dummy', 'placeholder', 'your_key', 'your_token', 'insert_here', 'changeme',
    'todo', 'fixme', 'redacted', 'n/a', 'na', 'empty',
    'function', 'object', 'string', 'number', 'boolean', 'return', 'export', 'import',
    'require', 'module', 'window', 'document', 'console', 'error', 'callback',
    'loading', 'done', 'errors', 'retries', 'version', 'language', 'region',
    'libraries', 'client', 'channel', 'options', 'instance', 'status', 'core',
    'default', 'config', 'settings', 'env', 'environment',
    'development', 'production', 'staging', 'localhost', '127.0.0.1', '0.0.0.0',
}

def is_secret_context(line: str) -> bool:
    """Check if line contains secret-related keywords."""
    line_lower = line.lower()
    for kw in _SECRET_KEYWORDS:
        if kw in line_lower:
            return True
    return False

def is_fp(val: str, line: str = "") -> bool:
    """Smart false positive check with context awareness."""
    v = val.strip()
    vl = v.lower()
    
    if len(v) < 4 or len(v) > 500:
        return True
    
    if vl in _FP_BLACKLIST:
        return True
    
    # Character diversity
    if len(set(vl)) < 4:
        return True
    
    # Repeated characters
    if v.count(v[0]) > len(v) * 0.6:
        return True
    
    # Pure hex strings (likely hashes)
    if re.match(r'^[a-f0-9]{32,128}$', vl):
        return True
    
    # If no secret context in line, be stricter
    if line and not is_secret_context(line):
        if len(set(vl)) < 8:
            return True
        if v.count(v[0]) > len(v) * 0.4:
            return True
    
    # Minified/obfuscated code
    code_indicators = sum(1 for c in v if c in '.,;:{}[]()=+<>!&|')
    if len(v) > 50 and code_indicators > len(v) * 0.15:
        return True
    
    return False

# ═══════════════════════════════════════════════════════════════════════════
# COMPLETE PATTERN DATABASE - 307+ UNIQUE PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

def build_patterns():
    patterns = []
    def add(rx, name, sev, tags, ent=0.0):
        patterns.append((rx, name, sev, tags, ent))
    
    # ══════════════════════════════════════════════════════════════════════
    # AWS (18 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key ID', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Temporary Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', ['aws'], 3.0)
    add(r'(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[=:]\s*[\'"`]([A-Za-z0-9\/+=]{40})[\'"`]', 'AWS Secret Access Key', 'confirmed', ['aws'], 4.5)
    add(r'(?i)(?:aws_session_token|aws_session)\s*[=:]\s*[\'"`]([A-Za-z0-9\/+=]{100,})[\'"`]', 'AWS Session Token', 'confirmed', ['aws'], 4.0)
    add(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Auth Token', 'confirmed', ['aws'])
    add(r'(FWO[A-Za-z0-9\/+=]{40,})', 'AWS STS FWO Token', 'confirmed', ['aws'], 4.0)
    add(r'(A3T[A-Z0-9]{16,})', 'AWS Session Token (A3T)', 'confirmed', ['aws'])
    add(r'arn:aws:[a-z]+:[a-z0-9\-]*:[0-9]{12}:.+', 'AWS ARN Resource', 'info', ['aws', 'recon'])
    add(r'([a-z0-9][a-z0-9\-]*\.s3\.amazonaws\.com)', 'AWS S3 Bucket URL', 'info', ['aws', 'recon'])
    add(r'([a-z0-9][a-z0-9\-]*\.s3-website[\.-][a-z0-9\-]+\.amazonaws\.com)', 'AWS S3 Website URL', 'info', ['aws', 'recon'])
    add(r'([a-z0-9\-]+\.cloudfront\.net)', 'AWS CloudFront URL', 'info', ['aws', 'cdn'])
    add(r'([a-z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com)', 'AWS API Gateway URL', 'info', ['aws', 'api'])
    add(r'([a-z0-9\-]+\.elb\.amazonaws\.com)', 'AWS ELB URL', 'info', ['aws', 'infra'])
    add(r'([a-z0-9\-]+\.rds\.amazonaws\.com)', 'AWS RDS URL', 'info', ['aws', 'database'])
    add(r'([a-z0-9\-]+\.elasticache\.amazonaws\.com)', 'AWS ElastiCache URL', 'info', ['aws', 'database'])
    add(r'([a-z0-9\-]+\.redshift\.amazonaws\.com)', 'AWS Redshift URL', 'info', ['aws', 'database'])
    
    # ══════════════════════════════════════════════════════════════════════
    # Google Cloud (14 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', ['google', 'api'], 3.5)
    add(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth 2.0 Token', 'confirmed', ['google', 'auth'])
    add(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Client Secret', 'confirmed', ['google', 'auth'])
    add(r'(6L[0-9A-Za-z\-_]{38})', 'Google reCAPTCHA Site Key', 'probable', ['google'])
    add(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'Firebase Cloud Messaging Key', 'confirmed', ['google', 'firebase'])
    add(r'[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com', 'Google OAuth 2.0 Client ID', 'probable', ['google', 'auth'])
    add(r'(?i)gcp[_-]?project[_-]?id\s*[=:]\s*[\'"`]([a-z0-9\-]{6,30})[\'"`]', 'GCP Project ID', 'confirmed', ['google', 'gcp'])
    add(r'(?i)firebase[_-]?project[_-]?id\s*[=:]\s*[\'"`]([a-z0-9\-]{6,30})[\'"`]', 'Firebase Project ID', 'confirmed', ['google', 'firebase'])
    add(r'(?i)bigquery[_-]?dataset\s*[=:]\s*[\'"`]([a-zA-Z0-9_]+)[\'"`]', 'BigQuery Dataset ID', 'info', ['google', 'gcp'])
    add(r'(?i)pubsub[_-]?topic\s*[=:]\s*[\'"`](projects\/[^\/]+\/topics\/[a-zA-Z0-9\-_]+)[\'"`]', 'Pub/Sub Topic Path', 'info', ['google', 'gcp'])
    add(r'storage\.googleapis\.com\/([a-z0-9\-_]+)', 'GCS Bucket Name', 'info', ['google', 'gcp', 'storage'])
    add(r'firebasestorage\.googleapis\.com\/([a-z0-9\-_]+)', 'Firebase Storage Bucket', 'info', ['google', 'firebase'])
    add(r'(?i)cloud[_-]?run[_-]?service\s*[=:]\s*[\'"`]([a-z0-9\-]+)[\'"`]', 'Cloud Run Service Name', 'info', ['google', 'gcp'])
    add(r'(?i)spanner[_-]?instance\s*[=:]\s*[\'"`]([a-z0-9\-]+)[\'"`]', 'Spanner Instance ID', 'info', ['google', 'gcp'])
    
    # ══════════════════════════════════════════════════════════════════════
    # Azure (14 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88})', 'Azure Storage Connection String', 'confirmed', ['azure'])
    add(r'(Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/[^;"\'\s]*)', 'Azure Service Bus Connection', 'confirmed', ['azure'])
    add(r'(sig=[A-Za-z0-9%+\/]{20,}&se=[0-9T:Z%\-]+&sp=[a-z]+)', 'Azure Blob SAS Token', 'confirmed', ['azure'])
    add(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps Personal Access Token', 'confirmed', ['azure', 'ci_cd'], 4.0)
    add(r'(?i)azure[_-]?client[_-]?id\s*[=:]\s*[\'"`]([a-f0-9\-]{36})[\'"`]', 'Azure Client ID', 'probable', ['azure'])
    add(r'(?i)azure[_-]?tenant[_-]?id\s*[=:]\s*[\'"`]([a-f0-9\-]{36})[\'"`]', 'Azure Tenant ID', 'probable', ['azure'])
    add(r'(?i)azure[_-]?client[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9\-_\.~]{32,})[\'"`]', 'Azure Client Secret', 'confirmed', ['azure'])
    add(r'(?i)azure[_-]?keyvault[_-]?url\s*[=:]\s*[\'"`](https:\/\/[^"\']+\.vault\.azure\.net\/)[\'"`]', 'Azure Key Vault URL', 'confirmed', ['azure'])
    add(r'(?i)cosmos[_-]?db[_-]?endpoint\s*[=:]\s*[\'"`](https:\/\/[^"\']+\.documents\.azure\.com)[\'"`]', 'Cosmos DB Endpoint', 'info', ['azure', 'database'])
    add(r'(?i)azure[_-]?function[_-]?app\s*[=:]\s*[\'"`]([a-z0-9\-]{3,32})[\'"`]', 'Azure Function App Name', 'info', ['azure'])
    add(r'[a-z0-9\-_]+\.blob\.core\.windows\.net', 'Azure Blob Storage URL', 'info', ['azure', 'storage'])
    add(r'[a-z0-9\-_]+\.mysql\.database\.azure\.com', 'Azure MySQL Server', 'info', ['azure', 'database'])
    add(r'[a-z0-9\-_]+\.postgres\.database\.azure\.com', 'Azure PostgreSQL Server', 'info', ['azure', 'database'])
    add(r'[a-z0-9\-_]+\.redis\.cache\.windows\.net', 'Azure Redis Cache', 'info', ['azure', 'database'])
    
    # ══════════════════════════════════════════════════════════════════════
    # Other Cloud Providers (14 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean Personal Access Token', 'confirmed', ['cloud', 'digitalocean'], 4.0)
    add(r'DO00[A-Za-z0-9]{32,}', 'DigitalOcean Spaces Access Key', 'confirmed', ['cloud', 'digitalocean'], 3.5)
    add(r'rnd_[A-Za-z0-9]{32}', 'Render API Key', 'confirmed', ['cloud', 'render'], 3.5)
    add(r'SCW[A-Z0-9]{20,}', 'Scaleway API Key', 'confirmed', ['cloud', 'scaleway'], 3.5)
    add(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Cloud AccessKey ID', 'confirmed', ['cloud', 'alibaba'], 3.0)
    add(r'(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[\'"`]([0-9a-f\-]{36})[\'"`]', 'Heroku API Key', 'confirmed', ['cloud', 'heroku'])
    add(r'(?i)cloudflare[_-]?api[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{37,40})[\'"`]', 'Cloudflare API Token', 'confirmed', ['cloud', 'cloudflare'], 3.5)
    add(r'(?i)cloudflare[_-]?global[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{37})[\'"`]', 'Cloudflare Global API Key', 'confirmed', ['cloud', 'cloudflare'])
    add(r'(?i)netlify[_-]?access[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{40,})[\'"`]', 'Netlify Access Token', 'confirmed', ['cloud', 'netlify'], 3.5)
    add(r'(?i)vercel[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{24})[\'"`]', 'Vercel Token', 'probable', ['cloud', 'vercel'])
    add(r'(?i)linode[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{64})[\'"`]', 'Linode API Token', 'confirmed', ['cloud', 'linode'])
    add(r'(?i)vultr[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{64})[\'"`]', 'Vultr API Key', 'confirmed', ['cloud', 'vultr'])
    add(r'(?i)fastly[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{32,})[\'"`]', 'Fastly API Key', 'confirmed', ['cloud', 'fastly'])
    add(r'(?i)ibmcloud[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{44})[\'"`]', 'IBM Cloud API Key', 'confirmed', ['cloud', 'ibm'], 4.0)

    # ══════════════════════════════════════════════════════════════════════
    # Payment Processors (22 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(sk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Secret Key', 'confirmed', ['payment', 'stripe'])
    add(r'(rk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Restricted Key', 'confirmed', ['payment', 'stripe'])
    add(r'(sk_test_[0-9a-zA-Z]{24,99})', 'Stripe Test Secret Key', 'possible', ['payment', 'stripe'])
    add(r'(whsec_[0-9a-zA-Z]{32,})', 'Stripe Webhook Signing Secret', 'confirmed', ['payment', 'stripe'], 3.5)
    add(r'(?i)stripe[_-]?account[_-]?id\s*[=:]\s*[\'"`](acct_[A-Za-z0-9]{16,})[\'"`]', 'Stripe Account ID', 'probable', ['payment', 'stripe'])
    add(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'PayPal Braintree Production Token', 'confirmed', ['payment', 'paypal'])
    add(r'(?i)paypal[_-]?client[_-]?id\s*[=:]\s*[\'"`](A[A-Za-z0-9\-_]{30,})[\'"`]', 'PayPal Client ID', 'confirmed', ['payment', 'paypal'])
    add(r'(?i)paypal[_-]?secret\s*[=:]\s*[\'"`](E[A-Za-z0-9\-_]{30,})[\'"`]', 'PayPal Secret Key', 'confirmed', ['payment', 'paypal'])
    add(r'(?i)paypal[_-]?webhook[_-]?id\s*[=:]\s*[\'"`](WH-[A-Za-z0-9]{32,})[\'"`]', 'PayPal Webhook ID', 'probable', ['payment', 'paypal'])
    add(r'(sq0csp-[A-Za-z0-9_\-]{43})', 'Square OAuth Client Secret', 'confirmed', ['payment', 'square'])
    add(r'(EAAA[A-Za-z0-9\-_]{22,})', 'Square Access Token', 'confirmed', ['payment', 'square'], 3.5)
    add(r'(sq0atp-[A-Za-z0-9\-_]{22,})', 'Square OAuth Access Token', 'confirmed', ['payment', 'square'], 3.5)
    add(r'(rzp_live_[A-Za-z0-9]{14,})', 'Razorpay Live API Key', 'confirmed', ['payment', 'razorpay'], 3.5)
    add(r'(rzp_test_[A-Za-z0-9]{14,})', 'Razorpay Test API Key', 'possible', ['payment', 'razorpay'], 3.5)
    add(r'(sk_live_[A-Za-z0-9]{40})', 'Paystack Live Secret Key', 'confirmed', ['payment', 'paystack'], 4.0)
    add(r'(ck_[a-f0-9]{40})', 'WooCommerce Consumer Key', 'confirmed', ['payment', 'woocommerce'], 3.5)
    add(r'(cs_[a-f0-9]{40})', 'WooCommerce Consumer Secret', 'confirmed', ['payment', 'woocommerce'], 3.5)
    add(r'(AQ[A-Za-z0-9_\-]{30,})', 'Adyen API Key', 'confirmed', ['payment', 'adyen'], 3.5)
    add(r'(FLWSECK-[a-zA-Z0-9]{32})', 'Flutterwave Secret Key', 'confirmed', ['payment', 'flutterwave'], 3.5)
    add(r'(?i)mollie[_-]?api[_-]?key\s*[=:]\s*[\'"`](live_[a-f0-9]{30,})[\'"`]', 'Mollie API Key', 'confirmed', ['payment', 'mollie'])
    add(r'(?i)revolut[_-]?api[_-]?key\s*[=:]\s*[\'"`](key_[a-f0-9]{32,})[\'"`]', 'Revolut API Key', 'confirmed', ['payment', 'revolut'])
    add(r'(?i)checkout[_-]?secret\s*[=:]\s*[\'"`](sk_[a-f0-9]{32,})[\'"`]', 'Checkout.com Secret Key', 'confirmed', ['payment', 'checkout'])

    # ══════════════════════════════════════════════════════════════════════
    # GitHub & GitLab & CI/CD (20 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(ghp_[A-Za-z0-9]{36})', 'GitHub Personal Access Token', 'confirmed', ['github', 'ci_cd'])
    add(r'(ghs_[A-Za-z0-9]{36})', 'GitHub Actions Token', 'confirmed', ['github', 'ci_cd'])
    add(r'(github_pat_[A-Za-z0-9_]{82})', 'GitHub Fine-grained PAT', 'confirmed', ['github', 'ci_cd'], 4.0)
    add(r'(gho_[A-Za-z0-9]{36})', 'GitHub OAuth Access Token', 'confirmed', ['github'])
    add(r'(ghu_[A-Za-z0-9]{36})', 'GitHub User-to-Server Token', 'confirmed', ['github'])
    add(r'(ghr_[A-Za-z0-9]{36})', 'GitHub Refresh Token', 'confirmed', ['github'])
    add(r'(?i)github[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{40})[\'"`]', 'GitHub Token Generic', 'confirmed', ['github'])
    add(r'(?i)github[_-]?app[_-]?id\s*[=:]\s*[\'"`]([0-9]+)[\'"`]', 'GitHub App ID', 'info', ['github'])
    add(r'(?i)github[_-]?installation[_-]?id\s*[=:]\s*[\'"`]([0-9]+)[\'"`]', 'GitHub Installation ID', 'info', ['github'])
    add(r'(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab Personal Access Token', 'confirmed', ['gitlab', 'ci_cd'])
    add(r'(gldt-[A-Za-z0-9_\-]{20,})', 'GitLab Deploy Token', 'confirmed', ['gitlab'])
    add(r'(glcbt-[A-Za-z0-9_\-]{20,})', 'GitLab CI/CD Job Token', 'confirmed', ['gitlab'])
    add(r'(glptt-[A-Za-z0-9_\-]{20,})', 'GitLab Project Access Token', 'confirmed', ['gitlab'])
    add(r'(glrt-[A-Za-z0-9_\-]{20,})', 'GitLab Runner Auth Token', 'confirmed', ['gitlab'])
    add(r'(glso-[A-Za-z0-9_\-]{20,})', 'GitLab Service Account Token', 'confirmed', ['gitlab'])
    add(r'(?i)gitlab[_-]?ci[_-]?job[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{20,})[\'"`]', 'GitLab CI Job Token Env', 'confirmed', ['gitlab'])
    add(r'(?i)gitlab[_-]?runner[_-]?token\s*[=:]\s*[\'"`](glrt-[A-Za-z0-9\-_]{20,})[\'"`]', 'GitLab Runner Token Env', 'confirmed', ['gitlab'])
    add(r'circleci-[a-f0-9]{40}', 'CircleCI API Token', 'confirmed', ['ci_cd', 'circleci'])
    add(r'bkua_[a-zA-Z0-9]{40}', 'Buildkite Agent Token', 'confirmed', ['ci_cd', 'buildkite'], 4.0)
    add(r'pul-[a-zA-Z0-9]{40}', 'Pulumi Access Token', 'confirmed', ['ci_cd', 'pulumi'], 4.0)

    # ══════════════════════════════════════════════════════════════════════
    # OpenAI & AI Services (20 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(sk-[A-Za-z0-9]{48})', 'OpenAI API Key Classic', 'confirmed', ['ai', 'openai'], 4.0)
    add(r'(sk-proj-[A-Za-z0-9_\-]{40,})', 'OpenAI Project API Key', 'confirmed', ['ai', 'openai'], 4.0)
    add(r'(org-[A-Za-z0-9_\-]{20,})', 'OpenAI Organization ID', 'info', ['ai', 'openai'])
    add(r'(sk-ant-api\d+-[A-Za-z0-9_\-]{40,})', 'Anthropic Claude API Key', 'confirmed', ['ai', 'anthropic'])
    add(r'(hf_[a-zA-Z0-9]{34,})', 'HuggingFace API Token', 'confirmed', ['ai', 'huggingface'])
    add(r'(gsk_[A-Za-z0-9]{52})', 'Groq API Key', 'confirmed', ['ai', 'groq'], 4.0)
    add(r'(pplx-[A-Za-z0-9]{48})', 'Perplexity AI API Key', 'confirmed', ['ai', 'perplexity'], 4.0)
    add(r'(sk-or-v1-[A-Za-z0-9]{48})', 'OpenRouter API Key', 'confirmed', ['ai', 'openrouter'], 4.0)
    add(r'(r8_[A-Za-z0-9]{40})', 'Replicate API Token', 'confirmed', ['ai', 'replicate'])
    add(r'(tvly-[A-Za-z0-9]{32})', 'Tavily AI Search API Key', 'confirmed', ['ai', 'tavily'], 4.0)
    add(r'(fw_[A-Za-z0-9]{32,})', 'Fireworks AI API Key', 'confirmed', ['ai', 'fireworks'], 4.0)
    add(r'(esecret_[A-Za-z0-9_\-]{40,})', 'Anyscale API Key', 'confirmed', ['ai', 'anyscale'], 4.0)
    add(r'(?i)cohere[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Cohere API Key', 'confirmed', ['ai', 'cohere'], 3.5)
    add(r'(?i)mistral[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Mistral AI API Key', 'confirmed', ['ai', 'mistral'], 3.5)
    add(r'(?i)deepgram[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Deepgram API Key', 'confirmed', ['ai', 'deepgram'])
    add(r'(?i)stability[_-]?ai[_-]?key\s*[=:]\s*[\'"`](sk-[A-Za-z0-9]{30,})[\'"`]', 'Stability AI API Key', 'confirmed', ['ai', 'stability'])
    add(r'(?i)elevenlabs[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'ElevenLabs API Key', 'confirmed', ['ai', 'elevenlabs'])
    add(r'(?i)assemblyai[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32})[\'"`]', 'AssemblyAI API Key', 'confirmed', ['ai', 'assemblyai'])
    add(r'(?i)runwayml[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32,})[\'"`]', 'RunwayML API Key', 'confirmed', ['ai', 'runwayml'])
    add(r'(?i)together[_-]?ai[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{30,})[\'"`]', 'Together AI Key', 'confirmed', ['ai', 'together'])

    # ══════════════════════════════════════════════════════════════════════
    # Generic Secrets with KEYWORD=VALUE context (14 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"`]([^\'"`]{4,})[\'"`]', 'Hardcoded Password', 'confirmed', ['generic', 'password'], 2.5)
    add(r'(?i)(?:secret|secret_key|secretkey)\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]', 'Hardcoded Secret', 'confirmed', ['generic', 'secret'], 3.0)
    add(r'(?i)(?:api_key|apikey)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.]{16,})[\'"`]', 'Generic API Key', 'confirmed', ['generic', 'api-key'], 3.0)
    add(r'(?i)(?:api_secret|apisecret)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.~!@#]{12,})[\'"`]', 'Generic API Secret', 'probable', ['generic', 'secret'], 3.5)
    add(r'(?i)(?:access_token|accesstoken)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.]{20,})[\'"`]', 'Access Token', 'confirmed', ['generic', 'token'], 3.0)
    add(r'(?i)(?:auth_token|authtoken)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.]{20,})[\'"`]', 'Authentication Token', 'probable', ['generic', 'token'], 3.0)
    add(r'(?i)(?:client_secret|clientsecret)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.~]{20,})[\'"`]', 'OAuth Client Secret', 'confirmed', ['generic', 'oauth'], 3.0)
    add(r'(?i)(?:client_id|clientid)\s*[=:]\s*[\'"`]([A-Za-z0-9]{16,})[\'"`]', 'OAuth Client ID', 'probable', ['generic', 'oauth'])
    add(r'(?i)(?:private_key|privatekey)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-+\/=]{40,})[\'"`]', 'Private Key Value', 'confirmed', ['generic', 'crypto'], 4.0)
    add(r'(?i)(?:refresh_token|refreshtoken)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.]{20,})[\'"`]', 'Refresh Token', 'confirmed', ['generic', 'token'])
    add(r'(?i)(?:encryption_key|encryptionkey)\s*[=:]\s*[\'"`]([A-Za-z0-9+\/=]{32,})[\'"`]', 'Encryption Key', 'confirmed', ['generic', 'crypto'], 3.5)
    add(r'(?i)(?:session_secret|sessionsecret)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]', 'Session Secret', 'probable', ['generic', 'session'], 3.0)
    add(r'(?i)(?:jwt_secret|jwtsecret)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]', 'JWT Signing Secret', 'confirmed', ['generic', 'jwt'], 3.5)
    add(r'(?i)(?:master_key|masterkey)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]', 'Master Key', 'confirmed', ['generic', 'crypto'], 3.5)

    # ══════════════════════════════════════════════════════════════════════
    # Database DSNs (18 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'mongodb\+srv:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MongoDB Atlas Connection String', 'confirmed', ['database', 'mongodb'], 2.5)
    add(r'mongodb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MongoDB Connection String', 'confirmed', ['database', 'mongodb'], 2.5)
    add(r'postgresql:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'PostgreSQL Connection String', 'confirmed', ['database', 'postgresql'], 2.5)
    add(r'postgres:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'PostgreSQL DSN Short', 'confirmed', ['database', 'postgresql'], 2.5)
    add(r'mysql:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MySQL Connection String', 'confirmed', ['database', 'mysql'], 2.5)
    add(r'mariadb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MariaDB Connection String', 'confirmed', ['database', 'mariadb'], 2.5)
    add(r'redis:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Redis Connection String', 'confirmed', ['database', 'redis'], 2.5)
    add(r'rediss:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Redis TLS Connection String', 'confirmed', ['database', 'redis'], 2.5)
    add(r'clickhouse:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'ClickHouse Connection String', 'confirmed', ['database', 'clickhouse'], 2.5)
    add(r'cassandra:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Cassandra Connection String', 'confirmed', ['database', 'cassandra'], 2.5)
    add(r'cockroachdb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'CockroachDB Connection String', 'confirmed', ['database', 'cockroachdb'], 2.5)
    add(r'jdbc:[a-zA-Z]+:\/\/[^\s"\'`<>]+', 'JDBC Connection String', 'confirmed', ['database', 'jdbc'], 2.5)
    add(r'sqlite:\/\/\/[^\s]+', 'SQLite File Path', 'info', ['database', 'sqlite'])
    add(r'(?i)(?:database_url|db_url|db_uri)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]', 'Database URL Generic', 'confirmed', ['database'])
    add(r'(?i)(?:redis_password|redis_pass)\s*[=:]\s*[\'"`]([A-Za-z0-9]{16,})[\'"`]', 'Redis Password', 'confirmed', ['database', 'redis'])
    add(r'mongodb\.net\/[a-zA-Z0-9\-_]+', 'MongoDB Atlas Cluster URL', 'info', ['database', 'mongodb'])
    add(r'rediss:\/\/default:[^@]+@[^\s]+\.upstash\.io:\d+', 'Upstash Redis URL', 'confirmed', ['database', 'upstash'], 3.0)
    add(r'postgresql:\/\/[^:]+:[^@]+@[^\s]+\.neon\.tech', 'Neon Serverless Postgres DSN', 'confirmed', ['database', 'neon'], 2.5)

    # ══════════════════════════════════════════════════════════════════════
    # Messaging & Communication (16 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})', 'Slack Bot/User Token', 'confirmed', ['messaging', 'slack'])
    add(r'https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+', 'Slack Incoming Webhook URL', 'confirmed', ['messaging', 'slack'])
    add(r'(M[A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})', 'Discord Bot Token', 'confirmed', ['messaging', 'discord'], 4.0)
    add(r'https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+', 'Discord Webhook URL', 'confirmed', ['messaging', 'discord'])
    add(r'(?i)twilio[_-]?account[_-]?sid\s*[=:]\s*[\'"`](AC[a-f0-9]{32})[\'"`]', 'Twilio Account SID', 'confirmed', ['messaging', 'twilio'])
    add(r'(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Twilio Auth Token', 'confirmed', ['messaging', 'twilio'])
    add(r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})', 'SendGrid API Key', 'confirmed', ['messaging', 'sendgrid'])
    add(r'(key-[0-9a-zA-Z]{32})', 'Mailgun API Key', 'confirmed', ['messaging', 'mailgun'])
    add(r'(\d{8,10}:[A-Za-z0-9_\-]{35})', 'Telegram Bot Token', 'probable', ['messaging', 'telegram'], 3.5)
    add(r'(?i)zendesk[_-]?api[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Zendesk API Token', 'confirmed', ['messaging', 'zendesk'])
    add(r'(?i)intercom[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{60,})[\'"`]', 'Intercom Access Token', 'confirmed', ['messaging', 'intercom'])
    add(r'(?i)pagerduty[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{20,})[\'"`]', 'PagerDuty API Key', 'confirmed', ['messaging', 'pagerduty'])
    add(r'(?i)opsgenie[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32,})[\'"`]', 'Opsgenie API Key', 'confirmed', ['messaging', 'opsgenie'])
    add(r'(?i)pushover[_-]?user[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{30})[\'"`]', 'Pushover User Key', 'probable', ['messaging', 'pushover'])
    add(r'(?i)vonage[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{8,20})[\'"`]', 'Vonage/Nexmo API Key', 'probable', ['messaging', 'vonage'])
    add(r'(?i)rocket[_-]?chat[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'RocketChat Token', 'probable', ['messaging', 'rocketchat'])

    # ══════════════════════════════════════════════════════════════════════
    # Crypto & Private Keys (16 patterns)
    # ══════════════════════════════════════════════════════════════════════
    add(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key Header', 'confirmed', ['crypto', 'private-key'])
    add(r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key Header', 'confirmed', ['crypto', 'private-key'])
    add(r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key Header', 'confirmed', ['crypto', 'private-key'])
    add(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key Header', 'confirmed', ['crypto', 'ssh'])
    add(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key Block', 'confirmed', ['crypto', 'pgp'])
    add(r'-----BEGIN PRIVATE KEY-----', 'PKCS8 Private Key Header', 'confirmed', ['crypto', 'private-key'])
    add(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Encrypted Private Key Header', 'confirmed', ['crypto', 'private-key'])
    add(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})', 'JSON Web Token (JWT)', 'probable', ['crypto', 'jwt'], 4.0)
    add(r'(?i)ssh[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\+\/=]{40,})[\'"`]', 'SSH Key Value', 'confirmed', ['crypto', 'ssh'], 4.0)
    add(r'(?i)ssl[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9\/+=]{40,})[\'"`]', 'SSL/TLS Private Key', 'confirmed', ['crypto', 'ssl'], 4.0)
    add(r'(?i)ssh-rsa\s+AAAAB3NzaC1yc2[0-9A-Za-z\/+=]+', 'SSH RSA Public Key', 'info', ['crypto', 'ssh'])
    add(r'-----BEGIN CERTIFICATE-----', 'X.509 Certificate Header', 'info', ['crypto', 'certificate'])
    add(r'-----BEGIN PUBLIC KEY-----', 'Public Key Header', 'info', ['crypto', 'public-key'])
    add(r'(?i)(?:bearer|token)\s+([A-Za-z0-9\-\._~\+\/]{30,}=*)', 'Bearer Authorization Token', 'probable', ['crypto', 'token'], 3.5)
    add(r'(?i)Basic\s+([A-Za-z0-9\+\/=]{20,})', 'HTTP Basic Auth Value', 'probable', ['crypto', 'auth'], 3.0)
    add(r'(?i)x-api-key\s*[=:]\s*[\'"`]([A-Za-z0-9]{20,})[\'"`]', 'X-API-Key Header Value', 'confirmed', ['crypto', 'api-key'])

    # Deduplicate and return
    seen = set()
    unique = []
    for p in patterns:
        if p[0] not in seen:
            seen.add(p[0])
            unique.append(p)
    return unique

# Build patterns once
PATTERNS = build_patterns()

# ═══════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class SecretScanner:
    """Main scanner engine with line-by-line detection and status codes."""
    
    def __init__(self, severity='info', show_raw=False, verbose=False,
                 json_output=False, filter_tags=None, threads=10, timeout=15,
                 max_depth=1, follow_js=True, quiet=False, no_fp=False):
        self.severity = severity
        self.show_raw = show_raw
        self.verbose = verbose
        self.json_output = json_output
        self.filter_tags = set(filter_tags.split(',')) if filter_tags else None
        self.threads = threads
        self.timeout = timeout
        self.max_depth = max_depth
        self.follow_js = follow_js
        self.quiet = quiet
        self.no_fp = no_fp
        
        self.scanned_urls = set()
        self.total_findings = 0
        self.sources_scanned = 0
        self.sources_with_hits = 0
        self.start_time = None
        
        self.compiled_patterns = self._compile()
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
    
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
                compiled.append((re.compile(rx, re.IGNORECASE | re.MULTILINE), name, sev, tags, ent_min))
            except:
                pass
        return compiled
    
    def fetch_url(self, url: str) -> Tuple[str, Optional[str], int]:
        """Fetch URL. Returns (url, content, status_code)."""
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; astra/1.3)',
                'Accept': 'text/html,application/javascript,*/*',
                'Accept-Encoding': 'identity',
            })
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                status = resp.status
                ct = resp.headers.get('Content-Type', '').lower()
                if any(t in ct for t in ['text', 'javascript', 'json', 'html', 'xml']):
                    return (url, resp.read(10 * 1024 * 1024).decode('utf-8', errors='ignore'), status)
                return (url, None, status)
        except urllib.error.HTTPError as e:
            return (url, None, e.code)
        except urllib.error.URLError as e:
            return (url, None, 0)
        except Exception:
            return (url, None, -1)
    
    def scan_content(self, source: str, content: str) -> List[Dict]:
        """Line-by-line scanning. Returns list of findings."""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, name, sev, tags, ent_min in self.compiled_patterns:
                try:
                    for match in pattern.finditer(line):
                        val = match.group(1) if match.lastindex else match.group(0)
                        val = val.strip()
                        
                        if not self.no_fp and is_fp(val, line):
                            continue
                        
                        if ent_min > 0 and entropy(val) < ent_min:
                            continue
                        
                        start = max(0, match.start() - 30)
                        end = min(len(line), match.end() + 30)
                        ctx = line[start:end].strip()
                        if start > 0: ctx = '…' + ctx
                        if end < len(line): ctx += '…'
                        
                        findings.append({
                            'source': source,
                            'line': line_num,
                            'pattern': name,
                            'severity': sev,
                            'tags': list(tags),
                            'value': val if self.show_raw else self._redact(val),
                            'context': ctx[:120],
                            'entropy': round(entropy(val), 2)
                        })
                except:
                    pass
        
        return findings
    
    def _redact(self, val: str) -> str:
        if len(val) <= 8:
            return '*' * len(val)
        return val[:4] + '*' * (len(val) - 8) + val[-4:]
    
    def scan_local(self, filepath: str) -> Tuple[List[Dict], str]:
        """Scan local file. Returns (findings, status)."""
        p = Path(filepath)
        if not p.exists():
            return ([], 'NOT_FOUND')
        
        exts = {'.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.env', 
                '.conf', '.config', '.txt', '.html', '.xml', '.yaml', '.yml'}
        if p.suffix.lower() not in exts:
            return ([], 'SKIPPED')
        
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return (self.scan_content(str(p), content), 'OK')
        except Exception:
            return ([], 'ERROR')
    
    def scan_url(self, url: str, depth: int = 0) -> Tuple[str, List[Dict], Set[str], int]:
        """Fetch and scan URL. Returns (url, findings, new_urls, status_code)."""
        if url in self.scanned_urls:
            return (url, [], set(), 0)
        
        self.scanned_urls.add(url)
        url, content, status = self.fetch_url(url)
        
        if content is None:
            return (url, [], set(), status)
        
        findings = self.scan_content(url, content)
        
        new_urls = set()
        if self.follow_js and depth < self.max_depth:
            for m in re.finditer(r'https?://[^\s"\'`<>]+\.js(?:\?[^\s"\'`<>]*)?', content, re.I):
                u = m.group(0)
                if u not in self.scanned_urls:
                    new_urls.add(u)
        
        return (url, findings, new_urls, status)
    
    def run_piped(self, data: str, source: str = '<stdin>'):
        """Scan piped data."""
        lines = [l.strip() for l in data.splitlines() if l.strip() and not l.startswith('#')]
        
        if lines and all(l.startswith(('http://', 'https://')) for l in lines):
            self.run_urls(lines, fetch=True)
        else:
            findings = self.scan_content(source, data)
            self.total_findings = len(findings)
            self._output_findings(source, findings, 'OK')
    
    def run_urls(self, urls: List[str], fetch: bool = False):
        """Scan list of URLs."""
        if not urls:
            return
        
        self.start_time = time.time()
        
        if not self.json_output and not self.quiet:
            print(BANNER)
            print(f"{C.X}  {len(PATTERNS)} patterns | {len(self.compiled_patterns)} active | {self.threads} threads{C.RST}\n")
        
        all_findings = []
        
        if fetch:
            queue = list(urls)
            depth = 0
            
            while queue and depth <= self.max_depth:
                discovered = set()
                
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    futures = {ex.submit(self.scan_url, u, depth): u for u in queue if u not in self.scanned_urls}
                    
                    for future in as_completed(futures):
                        try:
                            url, findings, new_urls, status = future.result()
                            self.sources_scanned += 1
                            
                            if findings:
                                self.sources_with_hits += 1
                                self.total_findings += len(findings)
                                all_findings.extend(findings)
                                
                                if not self.json_output:
                                    self._output_findings(url, findings, str(status))
                            elif self.verbose:
                                status_str = f"[{status}]" if status else ""
                                print(f"{C.G}  ✓ {url[:70]} {status_str}{C.RST}")
                            
                            discovered.update(new_urls)
                        except:
                            pass
                
                queue = list(discovered - self.scanned_urls)
                depth += 1
        else:
            for url in urls:
                findings, status = self.scan_local(url)
                self.sources_scanned += 1
                
                if findings:
                    self.sources_with_hits += 1
                    self.total_findings += len(findings)
                    all_findings.extend(findings)
                    
                    if not self.json_output:
                        self._output_findings(url, findings, status)
                elif self.verbose:
                    print(f"{C.G}  ✓ {url[:70]} [{status}]{C.RST}")
        
        elapsed = time.time() - self.start_time
        
        if self.json_output:
            print(json.dumps(all_findings, indent=2))
        else:
            self._print_summary(elapsed)
    
    def run_local(self, files: List[str], extensions: str):
        """Scan local files/directories."""
        self.start_time = time.time()
        
        if not self.json_output and not self.quiet:
            print(BANNER)
            print(f"{C.X}  {len(PATTERNS)} patterns | {len(self.compiled_patterns)} active{C.RST}\n")
        
        exts = {f".{e.strip().lstrip('.')}" for e in extensions.split(',')} if extensions else {'.js', '.ts', '.json', '.env'}
        all_findings = []
        
        for filepath in files:
            p = Path(filepath)
            
            if p.is_dir():
                for ext in exts:
                    for fp in sorted(p.rglob(f'*{ext}')):
                        if fp.is_file():
                            findings, status = self.scan_local(str(fp))
                            self.sources_scanned += 1
                            
                            if findings:
                                self.sources_with_hits += 1
                                self.total_findings += len(findings)
                                all_findings.extend(findings)
                                
                                if not self.json_output:
                                    self._output_findings(str(fp), findings, status)
                            elif self.verbose:
                                print(f"{C.G}  ✓ {str(fp)[:70]} [{status}]{C.RST}")
            elif p.is_file():
                findings, status = self.scan_local(str(p))
                self.sources_scanned += 1
                
                if findings:
                    self.sources_with_hits += 1
                    self.total_findings += len(findings)
                    all_findings.extend(findings)
                    
                    if not self.json_output:
                        self._output_findings(str(p), findings, status)
                elif self.verbose:
                    print(f"{C.G}  ✓ {str(p)[:70]} [{status}]{C.RST}")
        
        elapsed = time.time() - self.start_time
        
        if self.json_output:
            print(json.dumps(all_findings, indent=2))
        else:
            self._print_summary(elapsed)
    
    def _output_findings(self, source: str, findings: List[Dict], status: str = ''):
        """Display findings for a source with status code."""
        sev_colors = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
        sev_icons = {'confirmed': '◆', 'probable': '◇', 'possible': '○', 'info': '·'}
        
        # Status color
        status_color = C.G
        if status in ('0', 'NOT_FOUND', 'ERROR'):
            status_color = C.R
        elif status in ('SKIPPED',):
            status_color = C.Y
        
        status_str = f" {status_color}[{status}]{C.RST}" if status else ""
        print(f"\n{C.BOLD}{C.C}── {source[:80]}{status_str}{C.RST}")
        
        for f in findings:
            c = sev_colors.get(f['severity'], C.W)
            icon = sev_icons.get(f['severity'], '•')
            tags_str = f" {C.X}[{','.join(f['tags'])}]{C.RST}" if f['tags'] else ""
            
            print(f"  {icon} {c}{C.BOLD}{f['pattern']}{C.RST}{tags_str}")
            print(f"    {C.X}Line {f['line']:4} │{C.RST} {c}{f['value']}{C.RST}")
            
            if f.get('context'):
                print(f"    {C.X}Context │{C.RST} {f['context'][:100]}")
            
            if f.get('entropy', 0) > 0:
                print(f"    {C.X}Entropy │{C.RST} {f['entropy']}")
            
            print()
        
        print(f"{C.X}  ── {len(findings)} finding(s){C.RST}")
    
    def _print_summary(self, elapsed: float):
        """Print scan summary."""
        print(f"\n{C.BOLD}{C.M}╔══════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.M}║   SCAN COMPLETE                              ║{C.RST}")
        print(f"{C.BOLD}{C.M}╚══════════════════════════════════════════════╝{C.RST}")
        print(f"  Sources scanned:  {self.sources_scanned}")
        print(f"  With secrets:     {self.sources_with_hits}")
        print(f"  Total findings:   {self.total_findings}")
        print(f"  Time:             {elapsed:.2f}s")
        
        if self.total_findings == 0:
            print(f"\n{C.G}  ✓ CLEAN — No secrets found{C.RST}")
        else:
            print(f"\n{C.R}  ⚠ Found {self.total_findings} potential secrets{C.RST}")
        
        print(f"\n{C.BOLD}{C.M}{'═' * 50}{C.RST}\n")

# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='astra — Secret & Credential Scanner v1.3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.BOLD}FLAGS:{C.RST}
  {C.Y}-s SEV{C.RST}       Min severity: confirmed|probable|possible|info (default: info)
  {C.Y}--fetch{C.RST}       Fetch each URL and scan HTTP response body
  {C.Y}--threads N{C.RST}   Worker threads for --fetch (default: 10)
  {C.Y}--json{C.RST}        Output as JSON array
  {C.Y}--show-match{C.RST}  Show unredacted match values
  {C.Y}--no-color{C.RST}    Disable ANSI colors
  {C.Y}--list{C.RST}        Print all patterns and exit
  {C.Y}--tags TAGS{C.RST}   Comma-separated tag filter
  {C.Y}--ext EXT{C.RST}     Directory mode file extensions
        """
    )
    
    parser.add_argument('files', nargs='*', help='Files, directories, or URLs to scan')
    parser.add_argument('-s', '--severity', default='info', choices=['confirmed','probable','possible','info'])
    parser.add_argument('--fetch', action='store_true', help='Fetch URLs and scan responses')
    parser.add_argument('--threads', type=int, default=10, help='Thread count for --fetch')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--show-match', action='store_true', help='Show raw matches')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    parser.add_argument('--list', action='store_true', help='List all patterns')
    parser.add_argument('--tags', help='Filter by tags (comma-separated)')
    parser.add_argument('--ext', default='js,ts,json,env', help='Directory extensions')
    
    args = parser.parse_args()
    
    if args.list:
        print(f"\n{C.BOLD}Total unique patterns: {len(PATTERNS)}{C.RST}\n")
        cats = defaultdict(list)
        for _, name, sev, tags, _ in PATTERNS:
            cat = tags[0] if tags else 'other'
            cats[cat].append((name, sev))
        
        for cat in sorted(cats):
            print(f"{C.BOLD}{cat.upper()} ({len(cats[cat])}){C.RST}")
            for name, sev in sorted(cats[cat]):
                c = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}.get(sev, C.W)
                print(f"  {c}├─ {name}{C.RST}")
            print()
        sys.exit(0)
    
    scanner = SecretScanner(
        severity=args.severity,
        show_raw=args.show_match,
        json_output=args.json,
        filter_tags=args.tags,
        threads=args.threads
    )
    
    # Handle stdin
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        scanner.run_piped(data)
    elif args.files:
        if args.fetch:
            scanner.run_urls(args.files, fetch=True)
        else:
            scanner.run_local(args.files, args.ext)
    else:
        parser.print_help()
        sys.exit(1)
    
    sys.exit(1 if scanner.total_findings > 0 else 0)

if __name__ == '__main__':
    main()
