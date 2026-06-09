#!/usr/bin/env python3
"""
astra — Live JS Secret Detection Engine v1.2
=============================================
Fetches JS files from URLs, extracts secrets with precision.
Strict false positive filtering. Clean output.
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
from collections import defaultdict, OrderedDict
from typing import List, Dict, Set, Tuple
from urllib.parse import urljoin, urlparse

# ── Colors ───────────────────────────────────────────────────────────────
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; X = '\033[90m'
    BOLD = '\033[1m'; DIM = '\033[2m'; RST = '\033[0m'

# ── Entropy ─────────────────────────────────────────────────────────────
def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    l = len(s)
    return -sum((v/l) * math.log2(v/l) for v in freq.values())

# ── STRICT False Positive Filter ─────────────────────────────────────────
_FP_BLACKLIST = {
    'null','undefined','true','false','none','example','test','sample',
    'dummy','placeholder','your_key','your_token','insert_here','changeme',
    'todo','fixme','password','secret','api_key','apikey','token','redacted',
    'function','object','string','number','boolean','return','export','import',
    'require','module','window','document','console','error','callback',
    'loading','done','errors','retries','version','language','region',
    'libraries','client','channel','options','instance','status','core',
    'default','config','settings','env','environment','development',
    'production','staging','localhost','127.0.0.1','0.0.0.0',
    'xxxxxxxx','xxxxx','yyyyy','zzzzz','abc123','123abc',
}

_FP_PATTERNS = [
    r'^[a-zA-Z]{1,8}$',                    # Short words
    r'^[0-9]{6,}$',                         # Just numbers
    r'^[a-f0-9]{8,64}$',                   # Hex strings (likely hashes)
    r'^[A-Za-z0-9+/=]{44,}$',              # Base64 without context
    r'^\$\{[^}]+\}$',                       # Template literals
    r'^<[^>]+>$',                          # HTML tags
    r'^function\s*\(',                      # Function declarations
    r'^https?://[^\s]+$',                  # Plain URLs (no credentials)
    r'^[a-zA-Z_]+\.[a-zA-Z_]+$',           # Object paths (like window.location)
]

def is_false_positive(val: str) -> bool:
    """Strict false positive check."""
    v = val.strip()
    vl = v.lower()
    
    # Length checks
    if len(v) < 8: return True
    if len(v) > 500: return True
    
    # Blacklist
    if vl in _FP_BLACKLIST: return True
    
    # Character diversity check
    unique_chars = len(set(vl))
    if unique_chars < 6: return True
    
    # Too many repeated characters
    if v.count(v[0]) > len(v) * 0.5: return True
    
    # Looks like a hash (all hex)
    if re.match(r'^[a-f0-9]{32,128}$', vl): return True
    
    # Common FP patterns
    for fp in _FP_PATTERNS:
        if re.match(fp, v): return True
    
    # Looks like minified/obfuscated code
    code_indicators = sum(1 for c in v if c in '.,;:{}[]()=+<>!&|')
    if len(v) > 50 and code_indicators > len(v) * 0.1: return True
    
    # JavaScript identifiers
    if re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', v) and len(v) < 20: return True
    
    return False

# ═══════════════════════════════════════════════════════════════════════════
# PATTERN DATABASE - Organized by Category
# ═══════════════════════════════════════════════════════════════════════════

class PatternDB:
    """Organized pattern database."""
    
    CATEGORIES = OrderedDict([
        ('aws', 'AWS Cloud'),
        ('gcp', 'Google Cloud'),
        ('azure', 'Azure Cloud'),
        ('cloud', 'Other Cloud'),
        ('payment', 'Payment Processors'),
        ('api', 'API Keys'),
        ('auth', 'Authentication'),
        ('database', 'Database DSNs'),
        ('crypto', 'Crypto & Keys'),
        ('token', 'Tokens & JWT'),
        ('email', 'Email Services'),
        ('ci_cd', 'CI/CD'),
        ('social', 'Social Media'),
        ('saas', 'SaaS Platforms'),
        ('web3', 'Web3 & Blockchain'),
        ('monitoring', 'Monitoring'),
        ('security', 'Security Issues'),
        ('recon', 'Reconnaissance'),
    ])
    
    def __init__(self):
        self.patterns = []
        self._build()
        self._deduplicate()
    
    def add(self, rx, name, sev, category, tags, ent=0.0):
        self.patterns.append((rx, name, sev, category, tags, ent))
    
    def _build(self):
        p = self.add
        
        # ── AWS Cloud (8) ────────────────────────────────────────────────
        p(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key ID', 'confirmed', 'aws', ['aws'], 3.0)
        p(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Temporary Key', 'confirmed', 'aws', ['aws'], 3.0)
        p(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', 'aws', ['aws'], 3.0)
        p(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', 'aws', ['aws'], 3.0)
        p(r'(?i)aws_secret_access_key\s*[=:]\s*[\'"]([A-Za-z0-9\/+=]{40})[\'"]', 'AWS Secret Access Key', 'confirmed', 'aws', ['aws'], 4.5)
        p(r'(?i)aws_session_token\s*[=:]\s*[\'"]([A-Za-z0-9\/+=]{100,})[\'"]', 'AWS Session Token', 'confirmed', 'aws', ['aws'], 4.0)
        p(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Auth Token', 'confirmed', 'aws', ['aws'])
        p(r'(FWO[A-Za-z0-9\/+=]{40,})', 'AWS STS FWO Token', 'confirmed', 'aws', ['aws'], 4.0)
        
        # ── Google Cloud (6) ─────────────────────────────────────────────
        p(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', 'gcp', ['google','api'], 3.5)
        p(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth 2.0 Token', 'confirmed', 'gcp', ['google','auth'], 3.5)
        p(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Client Secret', 'confirmed', 'gcp', ['google','auth'])
        p(r'(6L[0-9A-Za-z\-_]{38})', 'Google reCAPTCHA Site Key', 'probable', 'gcp', ['google'])
        p(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'Firebase Cloud Messaging Key', 'confirmed', 'gcp', ['firebase'])
        p(r'[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com', 'Google OAuth Client ID', 'probable', 'gcp', ['google','auth'])
        
        # ── Azure Cloud (5) ──────────────────────────────────────────────
        p(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88})', 'Azure Storage Connection String', 'confirmed', 'azure', ['azure','database'])
        p(r'(Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/[^;"\'\s]*)', 'Azure Service Bus Connection', 'confirmed', 'azure', ['azure'])
        p(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps PAT', 'confirmed', 'azure', ['azure','ci_cd'], 4.0)
        p(r'(?i)azure_client_id\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Application Client ID', 'probable', 'azure', ['azure'])
        p(r'(?i)azure_tenant_id\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Tenant ID', 'probable', 'azure', ['azure'])
        
        # ── Other Cloud (8) ──────────────────────────────────────────────
        p(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean Personal Access Token', 'confirmed', 'cloud', ['digitalocean'], 4.0)
        p(r'DO00[A-Za-z0-9]{32,}', 'DigitalOcean Spaces Access Key', 'confirmed', 'cloud', ['digitalocean'], 3.5)
        p(r'rnd_[A-Za-z0-9]{32}', 'Render API Key', 'confirmed', 'cloud', ['render'], 3.5)
        p(r'SCW[A-Z0-9]{20,}', 'Scaleway API Key', 'confirmed', 'cloud', ['scaleway'], 3.5)
        p(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Cloud AccessKey', 'confirmed', 'cloud', ['alibaba'], 3.0)
        p(r'(?i)heroku_api_key\s*[=:]\s*[\'"]([0-9a-f-]{36})[\'"]', 'Heroku API Key', 'confirmed', 'cloud', ['heroku'])
        p(r'(?i)cloudflare_api_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{37,40})[\'"]', 'Cloudflare API Token', 'confirmed', 'cloud', ['cloudflare'], 3.5)
        p(r'(?i)netlify_access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'Netlify Access Token', 'confirmed', 'cloud', ['netlify'], 3.5)
        
        # ── Payment Processors (10) ──────────────────────────────────────
        p(r'sk_live_[0-9a-zA-Z]{24,99}', 'Stripe Live Secret Key', 'confirmed', 'payment', ['stripe'], 4.0)
        p(r'rk_live_[0-9a-zA-Z]{24,99}', 'Stripe Live Restricted Key', 'confirmed', 'payment', ['stripe'], 4.0)
        p(r'sk_test_[0-9a-zA-Z]{24,99}', 'Stripe Test Secret Key', 'possible', 'payment', ['stripe'])
        p(r'whsec_[0-9a-zA-Z]{32,}', 'Stripe Webhook Signing Secret', 'confirmed', 'payment', ['stripe'], 3.5)
        p(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'PayPal Braintree Production Token', 'confirmed', 'payment', ['paypal'])
        p(r'sq0csp-[A-Za-z0-9_\-]{43}', 'Square OAuth Client Secret', 'confirmed', 'payment', ['square'])
        p(r'rzp_live_[A-Za-z0-9]{14,}', 'Razorpay Live API Key', 'confirmed', 'payment', ['razorpay'], 3.5)
        p(r'sk_live_[A-Za-z0-9]{40}', 'Paystack Live Secret Key', 'confirmed', 'payment', ['paystack'], 4.0)
        p(r'ck_[a-f0-9]{40}', 'WooCommerce Consumer Key', 'confirmed', 'payment', ['woocommerce'], 3.5)
        p(r'cs_[a-f0-9]{40}', 'WooCommerce Consumer Secret', 'confirmed', 'payment', ['woocommerce'], 3.5)
        
        # ── API Keys (8) ─────────────────────────────────────────────────
        p(r'(?i)api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{16,})[\'"]', 'Generic API Key', 'confirmed', 'api', ['api-key'], 3.0)
        p(r'(?i)api_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.~!@#]{12,})[\'"]', 'Generic API Secret', 'probable', 'api', ['secret'], 3.5)
        p(r'(?i)api_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Generic API Token', 'probable', 'api', ['token'], 3.0)
        p(r'(?i)access_key\s*[=:]\s*[\'"]([A-Za-z0-9]{16,})[\'"]', 'Generic Access Key', 'probable', 'api', ['api-key'], 3.0)
        p(r'(?i)app_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{16,})[\'"]', 'Application Key', 'probable', 'api', ['api-key'], 3.0)
        p(r'(?i)admin_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{16,})[\'"]', 'Admin API Key', 'probable', 'api', ['api-key'], 3.0)
        p(r'PMAK-[A-Za-z0-9\-]{40,}', 'Postman API Key', 'confirmed', 'api', ['postman','saas'], 4.0)
        p(r'(?i)algolia_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32})[\'"]', 'Algolia API Key', 'confirmed', 'api', ['algolia','saas'], 3.5)
        
        # ── Authentication (8) ───────────────────────────────────────────
        p(r'(?i)client_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.~]{20,})[\'"]', 'OAuth Client Secret', 'confirmed', 'auth', ['oauth'], 3.0)
        p(r'(?i)auth_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Authentication Token', 'confirmed', 'auth', ['token'], 3.0)
        p(r'(?i)bearer\s+([A-Za-z0-9\-\._~\+\/]{30,}=*)', 'Bearer Authorization Token', 'probable', 'auth', ['token'], 3.5)
        p(r'(?i)Basic\s+([A-Za-z0-9\+\/=]{20,})', 'HTTP Basic Auth Header', 'probable', 'auth', ['auth'], 3.0)
        p(r'(?i)jwt_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'JWT Signing Secret', 'confirmed', 'auth', ['jwt'], 3.5)
        p(r'(?i)session_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Session Secret Key', 'probable', 'auth', ['session'], 3.0)
        p(r'(?i)encryption_key\s*[=:]\s*[\'"]([A-Za-z0-9\+\/=]{32,})[\'"]', 'Encryption Key', 'confirmed', 'auth', ['crypto'], 3.5)
        p(r'(?i)secret_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Generic Secret Key', 'probable', 'auth', ['secret'], 3.5)
        
        # ── Database DSNs (5) ────────────────────────────────────────────
        p(r'mongodb\+srv:\/\/[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'MongoDB Atlas Connection String', 'confirmed', 'database', ['mongodb'], 2.5)
        p(r'postgresql:\/\/[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'PostgreSQL Connection String', 'confirmed', 'database', ['postgresql'], 2.5)
        p(r'mysql:\/\/[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'MySQL Connection String', 'confirmed', 'database', ['mysql'], 2.5)
        p(r'redis:\/\/[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'Redis Connection String', 'confirmed', 'database', ['redis'], 2.5)
        p(r'jdbc:[a-zA-Z]+:\/\/[^\s"\'<>]+', 'JDBC Connection String', 'confirmed', 'database', ['jdbc'], 2.5)
        
        # ── Crypto & Keys (6) ────────────────────────────────────────────
        p(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'confirmed', 'crypto', ['private-key'])
        p(r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 'confirmed', 'crypto', ['private-key'])
        p(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key', 'confirmed', 'crypto', ['ssh'])
        p(r'-----BEGIN PRIVATE KEY-----', 'PKCS#8 Private Key', 'confirmed', 'crypto', ['private-key'])
        p(r'(?i)private_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\+\/=]{40,})[\'"]', 'Private Key Value', 'confirmed', 'crypto', ['private-key'], 4.0)
        p(r'(?i)ssh_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\+\/=]{40,})[\'"]', 'SSH Key Value', 'confirmed', 'crypto', ['ssh'], 4.0)
        
        # ── Tokens & JWT (4) ─────────────────────────────────────────────
        p(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})', 'JSON Web Token (JWT)', 'probable', 'token', ['jwt'], 4.0)
        p(r'(?i)access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Access Token', 'confirmed', 'token', ['token'], 3.0)
        p(r'(?i)refresh_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Refresh Token', 'confirmed', 'token', ['token'], 3.0)
        p(r'(?i)id_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'ID Token', 'probable', 'token', ['token'], 3.0)
        
        # ── Email Services (4) ───────────────────────────────────────────
        p(r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key', 'confirmed', 'email', ['mailgun'])
        p(r'[a-f0-9]{32}-us[0-9]{1,2}', 'Mailchimp API Key', 'confirmed', 'email', ['mailchimp'], 3.5)
        p(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', 'SendGrid API Key', 'confirmed', 'email', ['sendgrid'])
        p(r're_[A-Za-z0-9_]{24,}', 'Resend API Key', 'confirmed', 'email', ['resend'], 4.0)
        
        # ── CI/CD (5) ────────────────────────────────────────────────────
        p(r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token', 'confirmed', 'ci_cd', ['github'], 3.5)
        p(r'ghs_[A-Za-z0-9]{36}', 'GitHub Actions Token', 'confirmed', 'ci_cd', ['github'])
        p(r'github_pat_[A-Za-z0-9_]{82}', 'GitHub Fine-grained PAT', 'confirmed', 'ci_cd', ['github'], 4.0)
        p(r'circleci-[a-f0-9]{40}', 'CircleCI API Token', 'confirmed', 'ci_cd', ['circleci'])
        p(r'glpat-[A-Za-z0-9_\-]{20,}', 'GitLab Personal Access Token', 'confirmed', 'ci_cd', ['gitlab'])
        
        # ── Social Media (4) ─────────────────────────────────────────────
        p(r'AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+\/]{40,}', 'Twitter/X Bearer Token', 'confirmed', 'social', ['twitter'], 4.0)
        p(r'EAACEdEose0cBA[0-9A-Za-z]+', 'Facebook Access Token', 'confirmed', 'social', ['facebook'])
        p(r'oauth:[a-z0-9]{30,}', 'Twitch OAuth Token', 'confirmed', 'social', ['twitch'], 3.5)
        p(r'(?i)linkedin_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{16})[\'"]', 'LinkedIn Client Secret', 'confirmed', 'social', ['linkedin'], 3.0)
        
        # ── SaaS Platforms (8) ───────────────────────────────────────────
        p(r'CFPAT-[A-Za-z0-9_\-]{40,}', 'Contentful Personal Access Token', 'confirmed', 'saas', ['contentful'], 4.0)
        p(r'secret_[A-Za-z0-9]{40,}', 'Notion Integration Token', 'confirmed', 'saas', ['notion'], 3.5)
        p(r'ntn_[A-Za-z0-9]{48,}', 'Notion New API Token', 'confirmed', 'saas', ['notion'], 4.0)
        p(r'figd_[A-Za-z0-9_\-]{40,}', 'Figma Personal Access Token', 'confirmed', 'saas', ['figma'], 4.0)
        p(r'dapi[a-f0-9]{32}', 'Databricks API Token', 'confirmed', 'saas', ['databricks'], 3.5)
        p(r'hvs\.[A-Za-z0-9_\-\+\/=]{50,}', 'HashiCorp Vault Token', 'confirmed', 'saas', ['vault'], 4.0)
        p(r'shpat_[a-fA-F0-9]{32}', 'Shopify Admin API Token', 'confirmed', 'saas', ['shopify'])
        p(r'BBDC-[A-Za-z0-9]{32,}', 'Bitbucket HTTP Access Token', 'confirmed', 'saas', ['bitbucket'], 4.0)
        
        # ── Web3 & Blockchain (4) ────────────────────────────────────────
        p(r'0x[a-fA-F0-9]{40}', 'Ethereum Address', 'info', 'web3', ['ethereum'])
        p(r'alch-[A-Za-z0-9_\-]{32}', 'Alchemy API Key', 'confirmed', 'web3', ['alchemy'], 4.0)
        p(r'(?i)etherscan_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{34})[\'"]', 'Etherscan API Key', 'confirmed', 'web3', ['etherscan'], 3.5)
        p(r'(?i)solana_private_key\s*[=:]\s*[\'"]([1-9A-HJ-NP-Za-km-z]{87,88})[\'"]', 'Solana Private Key', 'confirmed', 'web3', ['solana'], 4.5)
        
        # ── Monitoring (3) ───────────────────────────────────────────────
        p(r'NRAK-[A-Z0-9]{27}', 'New Relic API Key', 'confirmed', 'monitoring', ['newrelic'], 3.5)
        p(r'(?i)datadog_api_key\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Datadog API Key', 'confirmed', 'monitoring', ['datadog'], 3.5)
        p(r'dt0[a-z0-9]{2,5}\.[A-Za-z0-9]{8}\.[A-Za-z0-9]{64}', 'Dynatrace API Token', 'confirmed', 'monitoring', ['dynatrace'], 4.0)
        
        # ── Security Issues (4) ──────────────────────────────────────────
        p(r'eval\s*\([^)]*location\.', 'DOM XSS via eval(location)', 'possible', 'security', ['xss'])
        p(r'\.innerHTML\s*=\s*`[^`]*\$\{', 'DOM XSS via innerHTML', 'possible', 'security', ['xss'])
        p(r'exec\s*\(\s*`[^`]*\$\{[^}]*req\.', 'Command Injection via exec()', 'confirmed', 'security', ['rce'])
        p(r'pickle\.loads\s*\(', 'Insecure Deserialization (pickle)', 'confirmed', 'security', ['rce'])
        
        # ── Reconnaissance (3) ───────────────────────────────────────────
        p(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Private IPv4 Address (Class A)', 'info', 'recon', ['infra'])
        p(r'192\.168\.\d{1,3}\.\d{1,3}', 'Private IPv4 Address (Class C)', 'info', 'recon', ['infra'])
        p(r'[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', 'Email Address', 'info', 'recon', ['pii'])
    
    def _deduplicate(self):
        seen = set()
        unique = []
        for p in self.patterns:
            if p[0] not in seen:
                seen.add(p[0])
                unique.append(p)
        self.patterns = unique
    
    def get_category_stats(self) -> Dict[str, int]:
        stats = defaultdict(int)
        for p in self.patterns:
            stats[p[3]] += 1
        return dict(stats)
    
    def get_severity_stats(self) -> Dict[str, int]:
        stats = defaultdict(int)
        for p in self.patterns:
            stats[p[2]] += 1
        return dict(stats)

# ═══════════════════════════════════════════════════════════════════════════
# JS URL EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════

def extract_js_urls(content: str, base_url: str = None) -> Set[str]:
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js)["\']', content, re.I):
        js_urls.add(m.group(1))
    for m in re.finditer(r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', content, re.I):
        js_urls.add(m.group(0))
    for m in re.finditer(r'["\']([^"\']+(?:chunk|bundle|vendor|app|main|runtime)[^"\']*\.js)["\']', content, re.I):
        js_urls.add(m.group(1))
    
    if base_url:
        resolved = set()
        for url in js_urls:
            if url.startswith('http'): resolved.add(url)
            elif url.startswith('//'): resolved.add('https:' + url)
            elif url.startswith('/'):
                parsed = urlparse(base_url)
                resolved.add(f'{parsed.scheme}://{parsed.netloc}{url}')
            else: resolved.add(urljoin(base_url, url))
        return resolved
    return js_urls

# ═══════════════════════════════════════════════════════════════════════════
# SECRET DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class SecretDetectionEngine:
    """Main detection engine v1.2"""
    
    def __init__(self, severity='possible', show_raw=False, verbose=False,
                 json_output=False, filter_tags=None, threads=20, timeout=30,
                 max_depth=1, follow_js_urls=True, quiet=False, no_fp=False):
        self.severity = severity
        self.show_raw = show_raw
        self.verbose = verbose
        self.json_output = json_output
        self.filter_tags = set(filter_tags.split(',')) if filter_tags else None
        self.threads = threads
        self.timeout = timeout
        self.max_depth = max_depth
        self.follow_js_urls = follow_js_urls
        self.quiet = quiet
        self.no_fp = no_fp
        
        self.db = PatternDB()
        self.scanned_urls = set()
        self.total_findings = 0
        self.urls_scanned = 0
        self.urls_with_secrets = 0
        self.start_time = None
        
        self.compiled = self._compile()
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def _compile(self):
        sev_levels = {'confirmed': 0, 'probable': 1, 'possible': 2, 'info': 3}
        min_level = sev_levels.get(self.severity, 3)
        
        compiled = []
        for rx, name, sev, cat, tags, ent_min in self.db.patterns:
            if sev_levels.get(sev, 3) > min_level: continue
            if self.filter_tags and not self.filter_tags.intersection(tags): continue
            try:
                compiled.append((re.compile(rx, re.IGNORECASE | re.MULTILINE), name, sev, cat, tags, ent_min))
            except: pass
        return compiled
    
    def fetch(self, url: str):
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/javascript,*/*',
                'Accept-Encoding': 'identity',
            })
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                ct = resp.headers.get('Content-Type', '').lower()
                if any(t in ct for t in ['text', 'javascript', 'json', 'html']):
                    content = resp.read(10 * 1024 * 1024).decode('utf-8', errors='ignore')
                    return (url, content)
        except: pass
        return (url, None)
    
    def detect(self, url: str, content: str) -> List[Dict]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, name, sev, cat, tags, ent_min in self.compiled:
                try:
                    for match in pattern.finditer(line):
                        val = match.group(1) if match.lastindex else match.group(0)
                        val = val.strip()
                        
                        if len(val) < 8 or len(val) > 500: continue
                        if not self.no_fp and is_false_positive(val): continue
                        if ent_min > 0 and entropy(val) < ent_min: continue
                        
                        start = max(0, match.start() - 25)
                        end = min(len(line), match.end() + 25)
                        ctx = line[start:end].strip()
                        if start > 0: ctx = '…' + ctx
                        if end < len(line): ctx = ctx + '…'
                        
                        findings.append({
                            'url': url, 'line': line_num, 'pattern': name,
                            'severity': sev, 'category': cat, 'tags': list(tags),
                            'value': val if self.show_raw else self._redact(val),
                            'context': ctx[:100], 'entropy': round(entropy(val), 2)
                        })
                except: pass
        
        return findings
    
    def _redact(self, val):
        if len(val) <= 8: return '*' * len(val)
        return val[:4] + '*' * (len(val) - 8) + val[-4:]
    
    def scan_url(self, url: str, depth: int = 0):
        if url in self.scanned_urls: return (url, [], set())
        self.scanned_urls.add(url)
        
        url, content = self.fetch(url)
        if content is None: return (url, [], set())
        
        findings = self.detect(url, content)
        
        new_js = set()
        if self.follow_js_urls and depth < self.max_depth:
            new_js = {u for u in extract_js_urls(content, url) if u not in self.scanned_urls}
        
        return (url, findings, new_js)
    
    def run(self, urls: List[str]):
        if not urls:
            print(f"{C.R}[✗] No URLs provided{C.RST}", file=sys.stderr)
            return
        
        self.start_time = time.time()
        
        if not self.json_output and not self.quiet:
            self._print_banner()
        
        all_findings = []
        queue = list(urls)
        depth = 0
        
        while queue and depth <= self.max_depth:
            if self.verbose:
                print(f"{C.C}[Depth {depth}] {len(queue)} URLs{C.RST}")
            
            discovered = set()
            
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self.scan_url, u, depth): u for u in queue if u not in self.scanned_urls}
                
                for future in as_completed(futures):
                    try:
                        url, findings, new_js = future.result()
                        self.urls_scanned += 1
                        
                        if findings:
                            self.urls_with_secrets += 1
                            self.total_findings += len(findings)
                            all_findings.extend(findings)
                            if not self.json_output:
                                self._display(url, findings)
                        elif self.verbose:
                            print(f"{C.G}  ✓ {url[:70]}{C.RST}")
                        
                        discovered.update(new_js)
                    except: pass
            
            queue = list(discovered - self.scanned_urls)
            depth += 1
        
        elapsed = time.time() - self.start_time
        
        if self.json_output:
            print(json.dumps({'summary': self._summary(all_findings, elapsed), 'findings': all_findings}, indent=2))
        else:
            self._print_summary(all_findings, elapsed)
    
    def _print_banner(self):
        stats = self.db.get_category_stats()
        sev_stats = self.db.get_severity_stats()
        
        print(f"\n{C.BOLD}{C.C}╔══════════════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.C}║   ASTRA — Secret Detection Engine v1.2               ║{C.RST}")
        print(f"{C.BOLD}{C.C}║   Live JS Secret Hunter                              ║{C.RST}")
        print(f"{C.BOLD}{C.C}╚══════════════════════════════════════════════════════╝{C.RST}")
        print(f"\n{C.BOLD}  Loaded Rules: {len(self.db.patterns)}{C.RST}")
        print()
        
        # Category tree
        cat_names = {
            'aws': 'AWS Cloud', 'gcp': 'Google Cloud', 'azure': 'Azure Cloud',
            'cloud': 'Other Cloud', 'payment': 'Payment Processors',
            'api': 'API Keys', 'auth': 'Authentication', 'database': 'Database DSNs',
            'crypto': 'Crypto & Keys', 'token': 'Tokens & JWT', 'email': 'Email Services',
            'ci_cd': 'CI/CD', 'social': 'Social Media', 'saas': 'SaaS Platforms',
            'web3': 'Web3 & Blockchain', 'monitoring': 'Monitoring',
            'security': 'Security Issues', 'recon': 'Reconnaissance',
        }
        
        for cat_key in self.db.CATEGORIES:
            count = stats.get(cat_key, 0)
            if count > 0:
                name = cat_names.get(cat_key, cat_key)
                print(f"  {C.BOLD}{name} ({count}){C.RST}")
        
        print(f"\n  {C.W}URLs: {C.BOLD}—{C.RST}  {C.W}Threads: {self.threads}{C.RST}  {C.W}Depth: {self.max_depth}{C.RST}  {C.W}Timeout: {self.timeout}s{C.RST}")
        print(f"  {C.W}Severity: {C.BOLD}{self.severity.upper()}{C.RST}  {C.W}FP Filter: {'ON' if not self.no_fp else 'OFF'}{C.RST}")
        print()
    
    def _display(self, url, findings):
        sev_c = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
        sev_i = {'confirmed': '🔴', 'probable': '🟡', 'possible': '🔵', 'info': '⚪'}
        
        print(f"\n{C.BOLD}{C.C}── {url}{C.RST}")
        for f in findings:
            c = sev_c.get(f['severity'], C.W)
            icon = sev_i.get(f['severity'], '•')
            tags = f" {C.X}[{','.join(f['tags'])}]{C.RST}" if f['tags'] else ""
            print(f"  {icon} {c}{C.BOLD}{f['pattern']}{C.RST}{tags}")
            print(f"    {C.X}L{f['line']:4} │{C.RST} {c}{f['value']}{C.RST}")
            if f.get('context'):
                print(f"    {C.X}ctx │{C.RST} {f['context'][:90]}")
            print()
        print(f"{C.X}  ── {len(findings)} finding(s){C.RST}")
    
    def _summary(self, findings, elapsed):
        sev_count = defaultdict(int)
        cat_count = defaultdict(int)
        for f in findings:
            sev_count[f['severity']] += 1
            cat_count[f.get('category', 'unknown')] += 1
        return {
            'urls_scanned': self.urls_scanned,
            'urls_with_secrets': self.urls_with_secrets,
            'total_findings': self.total_findings,
            'time': round(elapsed, 2),
            'by_severity': dict(sev_count),
            'by_category': dict(cat_count)
        }
    
    def _print_summary(self, findings, elapsed):
        s = self._summary(findings, elapsed)
        
        print(f"\n{C.BOLD}{C.M}╔══════════════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.M}║   SCAN COMPLETE                                      ║{C.RST}")
        print(f"{C.BOLD}{C.M}╚══════════════════════════════════════════════════════╝{C.RST}")
        print(f"  URLs scanned:       {s['urls_scanned']}")
        print(f"  With secrets:       {s['urls_with_secrets']}")
        print(f"  Total findings:     {s['total_findings']}")
        print(f"  Time:               {s['time']}s")
        
        if not findings:
            print(f"\n{C.G}  ✓ CLEAN — No secrets detected{C.RST}")
        else:
            print(f"\n  {C.BOLD}By Severity:{C.RST}")
            colors = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
            for sev in ['confirmed', 'probable', 'possible', 'info']:
                if s['by_severity'].get(sev):
                    print(f"  {colors[sev]}{sev.upper():12} {s['by_severity'][sev]}{C.RST}")
        
        print(f"\n{C.BOLD}{C.M}{'═' * 56}{C.RST}\n")

# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=f'{C.BOLD}astra{C.RST} — Live JS Secret Detection Engine v1.2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.BOLD}USAGE EXAMPLES:{C.RST}
  {C.C}astra -u https://example.com/app.js{C.RST}
      Scan a single JS file URL

  {C.C}astra -u https://site1.com/app.js https://site2.com/bundle.js{C.RST}
      Scan multiple URLs

  {C.C}astra -f urls.txt{C.RST}
      Read URLs from file (one per line)

  {C.C}cat urls.txt | astra{C.RST}
      Pipe URLs via stdin

  {C.C}astra -u https://example.com/ -d 2{C.RST}
      Scan page, extract & follow JS URLs (depth 2)

  {C.C}astra -f urls.txt -s confirmed -r{C.RST}
      Only confirmed secrets, show raw values

  {C.C}astra -f urls.txt -t 50 --timeout 60{C.RST}
      50 threads, 60s timeout

  {C.C}astra -f urls.txt --tags aws,stripe{C.RST}
      Filter by tags (only AWS & Stripe)

  {C.C}astra -f urls.txt -j > results.json{C.RST}
      Export results as JSON

  {C.C}astra -l{C.RST}
      List all detection rules

{C.BOLD}FLAGS:{C.RST}
  {C.Y}-u, --urls{C.RST}      URLs to scan (space-separated)
  {C.Y}-f, --file{C.RST}      File containing URLs (one per line)
  {C.Y}-s, --severity{C.RST}  Minimum severity: confirmed|probable|possible|info (default: possible)
  {C.Y}-r, --show-raw{C.RST}  Show raw secret values in output (dangerous!)
  {C.Y}-v, --verbose{C.RST}   Show all URLs being scanned
  {C.Y}-q, --quiet{C.RST}     Minimal output (only findings)
  {C.Y}-j, --json{C.RST}      Output as JSON
  {C.Y}--tags{C.RST}          Filter by comma-separated tags (aws,stripe,github,etc.)
  {C.Y}-t, --threads{C.RST}   Concurrent threads (default: 20)
  {C.Y}--timeout{C.RST}       Request timeout in seconds (default: 30)
  {C.Y}-d, --depth{C.RST}     Max depth for JS URL extraction (default: 1)
  {C.Y}--no-follow{C.RST}     Don't follow extracted JS URLs
  {C.Y}--no-fp{C.RST}         Disable false positive filter
  {C.Y}-l, --list{C.RST}      List all detection rules with categories
  {C.Y}-h, --help{C.RST}      Show this help message

{C.BOLD}SEVERITY LEVELS:{C.RST}
  {C.R}confirmed{C.RST}  — High confidence, known secret format (e.g., AWS keys, Stripe live)
  {C.Y}probable{C.RST}   — Likely secret, common patterns (e.g., JWT, Bearer tokens)
  {C.B}possible{C.RST}   — Potential secret or security issue (e.g., XSS, test keys)
  {C.C}info{C.RST}       — Informational (e.g., IPs, emails, recon data)

{C.BOLD}OUTPUT FORMAT:{C.RST}
  🔴 CONFIRMED — Line number, pattern name, redacted value, context
  🟡 PROBABLE  — Same format, lower confidence
  🔵 POSSIBLE  — Same format, review recommended
  ⚪ INFO      — Recon data, may be useful

{C.BOLD}NOTES:{C.RST}
  • Values are redacted by default for safety. Use {C.Y}-r{C.RST} to see raw values.
  • False positive filter is strict. Use {C.Y}--no-fp{C.RST} to disable.
  • Stdin input auto-detected when piping URLs.
        """
    )
    
    parser.add_argument('-u', '--urls', nargs='*', help=argparse.SUPPRESS)
    parser.add_argument('-f', '--file', help=argparse.SUPPRESS)
    parser.add_argument('-s', '--severity', default='possible', choices=['confirmed','probable','possible','info'], help=argparse.SUPPRESS)
    parser.add_argument('-r', '--show-raw', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-v', '--verbose', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-q', '--quiet', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-j', '--json', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--tags', help=argparse.SUPPRESS)
    parser.add_argument('-t', '--threads', type=int, default=20, help=argparse.SUPPRESS)
    parser.add_argument('--timeout', type=int, default=30, help=argparse.SUPPRESS)
    parser.add_argument('-d', '--depth', type=int, default=1, help=argparse.SUPPRESS)
    parser.add_argument('--no-follow', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--no-fp', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-l', '--list', action='store_true', help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    
    db = PatternDB()
    
    if args.list:
        print(f"\n{C.BOLD}Secret Detection Engine v1.2 — Rule Database{C.RST}")
        print(f"{C.BOLD}Total Rules: {len(db.patterns)}{C.RST}\n")
        
        cat_names = {
            'aws': 'AWS Cloud', 'gcp': 'Google Cloud', 'azure': 'Azure Cloud',
            'cloud': 'Other Cloud', 'payment': 'Payment Processors',
            'api': 'API Keys', 'auth': 'Authentication', 'database': 'Database DSNs',
            'crypto': 'Crypto & Keys', 'token': 'Tokens & JWT', 'email': 'Email Services',
            'ci_cd': 'CI/CD', 'social': 'Social Media', 'saas': 'SaaS Platforms',
            'web3': 'Web3 & Blockchain', 'monitoring': 'Monitoring',
            'security': 'Security Issues', 'recon': 'Reconnaissance',
        }
        
        for cat_key in db.CATEGORIES:
            rules = [p for p in db.patterns if p[3] == cat_key]
            if rules:
                name = cat_names.get(cat_key, cat_key)
                print(f"{C.BOLD}{name} ({len(rules)}){C.RST}")
                for rx, rname, sev, cat, tags, ent in rules:
                    sev_c = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
                    c = sev_c.get(sev, C.W)
                    print(f"  {c}├─ {rname}{C.RST}")
                print()
        sys.exit(0)
    
    urls = []
    if args.urls: urls.extend(args.urls)
    if args.file:
        try:
            with open(args.file) as f:
                urls.extend(l.strip() for l in f if l.strip() and not l.startswith('#'))
        except Exception as e:
            print(f"{C.R}[✗] File error: {e}{C.RST}", file=sys.stderr)
            sys.exit(1)
    if not sys.stdin.isatty() and not urls:
        urls.extend(l.strip() for l in sys.stdin if l.strip() and not l.startswith('#'))
    
    if not urls:
        parser.print_help()
        sys.exit(1)
    
    engine = SecretDetectionEngine(
        severity=args.severity, show_raw=args.show_raw, verbose=args.verbose,
        json_output=args.json, filter_tags=args.tags, threads=args.threads,
        timeout=args.timeout, max_depth=args.depth,
        follow_js_urls=not args.no_follow, quiet=args.quiet, no_fp=args.no_fp
    )
    
    engine.run(urls)
    sys.exit(1 if engine.total_findings > 0 else 0)

if __name__ == '__main__':
    main()
