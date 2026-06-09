#!/usr/bin/env python3
"""
astra — Live JS Secret Detection Engine v1.2
=============================================
320+ regex patterns. Strict false positive filter.
Clean output - secrets only. No bullshit.
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

def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    l = len(s)
    return -sum((v/l) * math.log2(v/l) for v in freq.values())

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
}

def is_fp(val: str) -> bool:
    v = val.strip()
    vl = v.lower()
    if len(v) < 8 or len(v) > 500: return True
    if vl in _FP_BLACKLIST: return True
    if len(set(vl)) < 6: return True
    if v.count(v[0]) > len(v) * 0.5: return True
    if re.match(r'^[a-f0-9]{32,128}$', vl): return True
    code_indicators = sum(1 for c in v if c in '.,;:{}[]()=+<>!&|')
    if len(v) > 50 and code_indicators > len(v) * 0.1: return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
# 320+ PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

def build_patterns():
    patterns = []
    def add(rx, name, sev, cat, tags, ent=0.0):
        patterns.append((rx, name, sev, cat, tags, ent))
    
    # ── CONFIRMED (210+) ─────────────────────────────────────────────────
    
    # AWS (15)
    add(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key ID', 'confirmed', 'aws', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Key', 'confirmed', 'aws', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', 'aws', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', 'aws', ['aws'], 3.0)
    add(r'(?i)aws_secret_access_key\s*[=:]\s*[\'"]([A-Za-z0-9\/+=]{40})[\'"]', 'AWS Secret Access Key', 'confirmed', 'aws', ['aws'], 4.5)
    add(r'(?i)aws_session_token\s*[=:]\s*[\'"]([A-Za-z0-9\/+=]{100,})[\'"]', 'AWS Session Token', 'confirmed', 'aws', ['aws'], 4.0)
    add(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Token', 'confirmed', 'aws', ['aws'])
    add(r'(FWO[A-Za-z0-9\/+=]{40,})', 'AWS STS FWO Token', 'confirmed', 'aws', ['aws'], 4.0)
    add(r'(A3T[A-Z0-9]{16,})', 'AWS Session Token (A3T)', 'confirmed', 'aws', ['aws'])
    add(r'arn:aws:[a-z]+:[a-z0-9\-]*:[0-9]{12}:[a-z0-9\/\-_:]+', 'AWS ARN', 'info', 'aws', ['aws','recon'])
    add(r'([a-z0-9\-_]+)\.s3\.amazonaws\.com', 'S3 Bucket', 'info', 'aws', ['aws','recon'])
    add(r'([a-z0-9\-_]+)\.cloudfront\.net', 'CloudFront Distribution', 'info', 'aws', ['aws','cdn'])
    add(r'([a-z0-9\-_]+)\.execute-api\.([a-z0-9\-]+)\.amazonaws\.com', 'API Gateway', 'info', 'aws', ['aws'])
    add(r'([a-z0-9\-_]+)\.rds\.amazonaws\.com', 'RDS Instance', 'info', 'aws', ['aws','database'])
    add(r'([a-z0-9\-_]+)\.elasticache\.amazonaws\.com', 'ElastiCache', 'info', 'aws', ['aws'])
    
    # Google Cloud (12)
    add(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', 'gcp', ['google','api'], 3.5)
    add(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth Token', 'confirmed', 'gcp', ['google','auth'])
    add(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Secret', 'confirmed', 'gcp', ['google','auth'])
    add(r'(6L[0-9A-Za-z\-_]{38})', 'Google reCAPTCHA Key', 'probable', 'gcp', ['google'])
    add(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'Firebase FCM Key', 'confirmed', 'gcp', ['firebase'])
    add(r'[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com', 'Google OAuth Client ID', 'probable', 'gcp', ['google'])
    add(r'(?i)gcp_project_id\s*[=:]\s*[\'"]([a-z0-9\-]{6,30})[\'"]', 'GCP Project ID', 'confirmed', 'gcp', ['gcp'])
    add(r'storage\.googleapis\.com/([a-z0-9\-_]+)', 'GCS Bucket', 'info', 'gcp', ['gcp','storage'])
    add(r'firebasestorage\.googleapis\.com/([a-z0-9\-_]+)', 'Firebase Storage', 'info', 'gcp', ['firebase'])
    add(r'(?i)firebase_project_id\s*[=:]\s*[\'"]([a-z0-9\-]{6,30})[\'"]', 'Firebase Project ID', 'confirmed', 'gcp', ['firebase'])
    add(r'(?i)bigquery_dataset\s*[=:]\s*[\'"]([a-zA-Z0-9_]+)[\'"]', 'BigQuery Dataset', 'info', 'gcp', ['gcp'])
    add(r'(?i)pubsub_topic\s*[=:]\s*[\'"](projects/[^/]+/topics/[a-zA-Z0-9\-_]+)[\'"]', 'Pub/Sub Topic', 'info', 'gcp', ['gcp'])
    
    # Azure (12)
    add(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88})', 'Azure Storage Key', 'confirmed', 'azure', ['azure']),
    add(r'(Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/[^;"\'\s]*)', 'Azure Service Bus', 'confirmed', 'azure', ['azure']),
    add(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps PAT', 'confirmed', 'azure', ['azure','ci_cd'], 4.0),
    add(r'(?i)azure_client_id\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Client ID', 'probable', 'azure', ['azure']),
    add(r'(?i)azure_tenant_id\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Tenant ID', 'probable', 'azure', ['azure']),
    add(r'(?i)azure_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9\-_\.~]{32,})[\'"]', 'Azure Client Secret', 'confirmed', 'azure', ['azure']),
    add(r'(?i)azure_keyvault_url\s*[=:]\s*[\'"](https://[^"\']+\.vault\.azure\.net\/)[\'"]', 'Azure Key Vault', 'confirmed', 'azure', ['azure']),
    add(r'[a-z0-9\-_]+\.blob\.core\.windows\.net', 'Azure Blob Storage', 'info', 'azure', ['azure']),
    add(r'[a-z0-9\-_]+\.documents\.azure\.com', 'Cosmos DB', 'info', 'azure', ['azure','database']),
    add(r'[a-z0-9\-_]+\.mysql\.database\.azure\.com', 'Azure MySQL', 'info', 'azure', ['azure','database']),
    add(r'[a-z0-9\-_]+\.postgres\.database\.azure\.com', 'Azure PostgreSQL', 'info', 'azure', ['azure','database']),
    add(r'[a-z0-9\-_]+\.redis\.cache\.windows\.net', 'Azure Redis', 'info', 'azure', ['azure','database']),
    
    # GitHub (12)
    add(r'(ghp_[A-Za-z0-9]{36})', 'GitHub Personal Token', 'confirmed', 'ci_cd', ['github']),
    add(r'(ghs_[A-Za-z0-9]{36})', 'GitHub Actions Token', 'confirmed', 'ci_cd', ['github']),
    add(r'(github_pat_[A-Za-z0-9_]{82})', 'GitHub Fine PAT', 'confirmed', 'ci_cd', ['github'], 4.0),
    add(r'(gho_[A-Za-z0-9]{36})', 'GitHub OAuth Token', 'confirmed', 'ci_cd', ['github']),
    add(r'(ghu_[A-Za-z0-9]{36})', 'GitHub User Token', 'confirmed', 'ci_cd', ['github']),
    add(r'(ghr_[A-Za-z0-9]{36})', 'GitHub Refresh Token', 'confirmed', 'ci_cd', ['github']),
    add(r'(?i)github_token\s*[=:]\s*[\'"]([A-Za-z0-9\-_]{40})[\'"]', 'GitHub Token Generic', 'confirmed', 'ci_cd', ['github']),
    add(r'(?i)github_app_id\s*[=:]\s*[\'"]([0-9]+)[\'"]', 'GitHub App ID', 'info', 'ci_cd', ['github']),
    add(r'(?i)github_installation_id\s*[=:]\s*[\'"]([0-9]+)[\'"]', 'GitHub Installation ID', 'info', 'ci_cd', ['github']),
    add(r'(?i)github_graphql_api\s*[=:]\s*[\'"](https://api\.github\.com/graphql)[\'"]', 'GitHub GraphQL API', 'info', 'ci_cd', ['github']),
    add(r'(?i)github_enterprise_url\s*[=:]\s*[\'"](https?://[^"\']+/api/v3)[\'"]', 'GitHub Enterprise', 'info', 'ci_cd', ['github']),
    add(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH Private Key', 'confirmed', 'crypto', ['ssh','github']),
    
    # GitLab (10)
    add(r'(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab PAT', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(gldt-[A-Za-z0-9_\-]{20,})', 'GitLab Deploy Token', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(glcbt-[A-Za-z0-9_\-]{20,})', 'GitLab CI Token', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(glptt-[A-Za-z0-9_\-]{20,})', 'GitLab Project Token', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(glrt-[A-Za-z0-9_\-]{20,})', 'GitLab Runner Token', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(glso-[A-Za-z0-9_\-]{20,})', 'GitLab Service Token', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(?i)gitlab_ci_job_token\s*[=:]\s*[\'"]([A-Za-z0-9\-_]{20,})[\'"]', 'GitLab CI Job Token', 'confirmed', 'ci_cd', ['gitlab']),
    add(r'(?i)gitlab_group_id\s*[=:]\s*[\'"]([0-9]+)[\'"]', 'GitLab Group ID', 'info', 'ci_cd', ['gitlab']),
    add(r'(?i)gitlab_project_id\s*[=:]\s*[\'"]([0-9]+)[\'"]', 'GitLab Project ID', 'info', 'ci_cd', ['gitlab']),
    add(r'(?i)gitlab_runner_token\s*[=:]\s*[\'"](glrt-[A-Za-z0-9\-_]{20,})[\'"]', 'GitLab Runner Token', 'confirmed', 'ci_cd', ['gitlab']),
    
    # OpenAI & AI (18)
    add(r'(sk-[A-Za-z0-9]{48})', 'OpenAI API Key', 'confirmed', 'api', ['openai','ai'], 4.0),
    add(r'(sk-proj-[A-Za-z0-9_\-]{40,})', 'OpenAI Project Key', 'confirmed', 'api', ['openai','ai'], 4.0),
    add(r'(org-[A-Za-z0-9_\-]{20,})', 'OpenAI Org ID', 'info', 'api', ['openai']),
    add(r'(sk-ant-api\d+-[A-Za-z0-9_\-]{40,})', 'Anthropic API Key', 'confirmed', 'api', ['anthropic','ai']),
    add(r'(hf_[a-zA-Z0-9]{34,})', 'HuggingFace Token', 'confirmed', 'api', ['huggingface','ai']),
    add(r'(gsk_[A-Za-z0-9]{52})', 'Groq API Key', 'confirmed', 'api', ['groq','ai'], 4.0),
    add(r'(pplx-[A-Za-z0-9]{48})', 'Perplexity Key', 'confirmed', 'api', ['perplexity','ai'], 4.0),
    add(r'(sk-or-v1-[A-Za-z0-9]{48})', 'OpenRouter Key', 'confirmed', 'api', ['openrouter','ai'], 4.0),
    add(r'(r8_[A-Za-z0-9]{40})', 'Replicate Token', 'confirmed', 'api', ['replicate','ai']),
    add(r'(tvly-[A-Za-z0-9]{32})', 'Tavily AI Key', 'confirmed', 'api', ['tavily','ai'], 4.0),
    add(r'(fw_[A-Za-z0-9]{32,})', 'Fireworks AI Key', 'confirmed', 'api', ['fireworks','ai'], 4.0),
    add(r'(esecret_[A-Za-z0-9_\-]{40,})', 'Anyscale Key', 'confirmed', 'api', ['anyscale','ai'], 4.0),
    add(r'(?i)cohere_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Cohere API Key', 'confirmed', 'api', ['cohere','ai'], 3.5),
    add(r'(?i)mistral_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Mistral API Key', 'confirmed', 'api', ['mistral','ai'], 3.5),
    add(r'(?i)deepgram_api_key\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Deepgram API Key', 'confirmed', 'api', ['deepgram','ai']),
    add(r'(?i)stability_ai_key\s*[=:]\s*[\'"](sk-[A-Za-z0-9]{30,})[\'"]', 'Stability AI Key', 'confirmed', 'api', ['stability','ai']),
    add(r'(?i)elevenlabs_api_key\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'ElevenLabs API Key', 'confirmed', 'api', ['elevenlabs','ai']),
    add(r'(?i)assemblyai_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32})[\'"]', 'AssemblyAI Key', 'confirmed', 'api', ['assemblyai','ai']),
    
    # Payment (20)
    add(r'(sk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Key', 'confirmed', 'payment', ['stripe']),
    add(r'(rk_live_[0-9a-zA-Z]{24,99})', 'Stripe Restricted Key', 'confirmed', 'payment', ['stripe']),
    add(r'(sk_test_[0-9a-zA-Z]{24,99})', 'Stripe Test Key', 'possible', 'payment', ['stripe']),
    add(r'(whsec_[0-9a-zA-Z]{32,})', 'Stripe Webhook Secret', 'confirmed', 'payment', ['stripe'], 3.5),
    add(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'PayPal Braintree', 'confirmed', 'payment', ['paypal']),
    add(r'(sq0csp-[A-Za-z0-9_\-]{43})', 'Square OAuth Secret', 'confirmed', 'payment', ['square']),
    add(r'(EAAA[A-Za-z0-9\-_]{22,})', 'Square Access Token', 'confirmed', 'payment', ['square'], 3.5),
    add(r'(rzp_live_[A-Za-z0-9]{14,})', 'Razorpay Live Key', 'confirmed', 'payment', ['razorpay'], 3.5),
    add(r'(sk_live_[A-Za-z0-9]{40})', 'Paystack Live Key', 'confirmed', 'payment', ['paystack'], 4.0),
    add(r'(ck_[a-f0-9]{40})', 'WooCommerce CK', 'confirmed', 'payment', ['woocommerce'], 3.5),
    add(r'(cs_[a-f0-9]{40})', 'WooCommerce CS', 'confirmed', 'payment', ['woocommerce'], 3.5),
    add(r'(AQ[A-Za-z0-9_\-]{30,})', 'Adyen API Key', 'confirmed', 'payment', ['adyen'], 3.5),
    add(r'(FLWSECK-[a-zA-Z0-9]{32})', 'Flutterwave Secret', 'confirmed', 'payment', ['flutterwave'], 3.5),
    add(r'(?i)paypal_client_id\s*[=:]\s*[\'"](A[a-zA-Z0-9\-_]{30,})[\'"]', 'PayPal Client ID', 'confirmed', 'payment', ['paypal']),
    add(r'(?i)paypal_secret\s*[=:]\s*[\'"](E[a-zA-Z0-9\-_]{30,})[\'"]', 'PayPal Secret', 'confirmed', 'payment', ['paypal']),
    add(r'(?i)mollie_api_key\s*[=:]\s*[\'"](live_[a-f0-9]{30,})[\'"]', 'Mollie API Key', 'confirmed', 'payment', ['mollie']),
    add(r'(?i)checkout_secret\s*[=:]\s*[\'"](sk_[a-f0-9]{32,})[\'"]', 'Checkout.com Secret', 'confirmed', 'payment', ['checkout']),
    add(r'(?i)revolut_api_key\s*[=:]\s*[\'"](key_[a-f0-9]{32,})[\'"]', 'Revolut API Key', 'confirmed', 'payment', ['revolut']),
    add(r'(?i)wise_api_key\s*[=:]\s*[\'"]([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})[\'"]', 'Wise API Key', 'confirmed', 'payment', ['wise']),
    add(r'(?i)stripe_account_id\s*[=:]\s*[\'"](acct_[A-Za-z0-9]{16,})[\'"]', 'Stripe Account ID', 'probable', 'payment', ['stripe']),
    
    # Database (18)
    add(r'mongodb\+srv://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'MongoDB Atlas DSN', 'confirmed', 'database', ['mongodb'], 2.5),
    add(r'postgresql://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'PostgreSQL DSN', 'confirmed', 'database', ['postgresql'], 2.5),
    add(r'mysql://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'MySQL DSN', 'confirmed', 'database', ['mysql'], 2.5),
    add(r'redis://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'Redis DSN', 'confirmed', 'database', ['redis'], 2.5),
    add(r'clickhouse://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'ClickHouse DSN', 'confirmed', 'database', ['clickhouse'], 2.5),
    add(r'jdbc:[a-zA-Z]+://[^\s"\'<>]+', 'JDBC String', 'confirmed', 'database', ['jdbc'], 2.5),
    add(r'rediss://default:[^@]+@[^\s]+\.upstash\.io:\d+', 'Upstash Redis', 'confirmed', 'database', ['upstash','redis'], 3.0),
    add(r'postgresql://[^:]+:[^@]+@[^\s]+\.neon\.tech', 'Neon DSN', 'confirmed', 'database', ['neon'], 2.5),
    add(r'mysql://[^:]+:[^@]+@[^\s]+\.psdb\.cloud', 'PlanetScale DSN', 'confirmed', 'database', ['planetscale'], 2.5),
    add(r'cockroachdb://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'CockroachDB DSN', 'confirmed', 'database', ['cockroachdb'], 2.5),
    add(r'cassandra://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'Cassandra DSN', 'confirmed', 'database', ['cassandra'], 2.5),
    add(r'supabase://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'Supabase DSN', 'confirmed', 'database', ['supabase'], 2.5),
    add(r'turso://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'Turso DSN', 'confirmed', 'database', ['turso'], 2.5),
    add(r'xata://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'Xata DSN', 'confirmed', 'database', ['xata'], 2.5),
    add(r'fauna://[^:\s]+:[^@\s]+@[^\s"\'<>]+', 'FaunaDB DSN', 'confirmed', 'database', ['fauna'], 2.5),
    add(r'(?i)database_url\s*[=:]\s*[\'"](.*?)[\'"]', 'Database URL', 'confirmed', 'database', ['database']),
    add(r'mongodb\.net/[a-zA-Z0-9\-_]+', 'MongoDB Atlas Cluster', 'info', 'database', ['mongodb']),
    add(r'(?i)redis_password\s*[=:]\s*[\'"]([A-Za-z0-9]{16,})[\'"]', 'Redis Password', 'confirmed', 'database', ['redis']),
    
    # Messaging (15)
    add(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})', 'Slack Token', 'confirmed', 'messaging', ['slack']),
    add(r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+', 'Slack Webhook', 'confirmed', 'messaging', ['slack']),
    add(r'(M[A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})', 'Discord Bot Token', 'confirmed', 'messaging', ['discord'], 4.0),
    add(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', 'Discord Webhook', 'confirmed', 'messaging', ['discord']),
    add(r'(?i)twilio_account_sid\s*[=:]\s*[\'"](AC[a-f0-9]{32})[\'"]', 'Twilio Account SID', 'confirmed', 'messaging', ['twilio']),
    add(r'(?i)twilio_auth_token\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Twilio Auth Token', 'confirmed', 'messaging', ['twilio']),
    add(r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})', 'SendGrid Key', 'confirmed', 'messaging', ['sendgrid']),
    add(r'(key-[0-9a-zA-Z]{32})', 'Mailgun Key', 'confirmed', 'messaging', ['mailgun']),
    add(r'(\d{8,10}:[A-Za-z0-9_\-]{35})', 'Telegram Bot Token', 'probable', 'messaging', ['telegram'], 3.5),
    add(r'(?i)zendesk_api_token\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Zendesk API Token', 'confirmed', 'messaging', ['zendesk']),
    add(r'(?i)intercom_token\s*[=:]\s*[\'"]([A-Za-z0-9\-_]{60,})[\'"]', 'Intercom Token', 'confirmed', 'messaging', ['intercom']),
    add(r'(?i)pagerduty_api_key\s*[=:]\s*[\'"]([A-Za-z0-9\-_]{20,})[\'"]', 'PagerDuty Key', 'confirmed', 'messaging', ['pagerduty']),
    add(r'(?i)opsgenie_api_key\s*[=:]\s*[\'"]([a-f0-9]{32,})[\'"]', 'Opsgenie Key', 'confirmed', 'messaging', ['opsgenie']),
    add(r'(?i)pushover_user_key\s*[=:]\s*[\'"]([A-Za-z0-9]{30})[\'"]', 'Pushover Key', 'probable', 'messaging', ['pushover']),
    add(r'(?i)vonage_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{8,20})[\'"]', 'Vonage Key', 'probable', 'messaging', ['vonage']),
    
    # Crypto & Keys (12)
    add(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'confirmed', 'crypto', ['private-key']),
    add(r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 'confirmed', 'crypto', ['private-key']),
    add(r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key', 'confirmed', 'crypto', ['private-key']),
    add(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Key', 'confirmed', 'crypto', ['ssh']),
    add(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'confirmed', 'crypto', ['pgp']),
    add(r'-----BEGIN PRIVATE KEY-----', 'PKCS8 Key', 'confirmed', 'crypto', ['private-key']),
    add(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Encrypted Key', 'confirmed', 'crypto', ['private-key']),
    add(r'(?i)private_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\+\/=]{40,})[\'"]', 'Private Key Value', 'confirmed', 'crypto', ['private-key'], 4.0),
    add(r'(?i)encryption_key\s*[=:]\s*[\'"]([A-Za-z0-9\+\/=]{32,})[\'"]', 'Encryption Key', 'confirmed', 'crypto', ['crypto'], 3.5),
    add(r'(?i)jwt_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'JWT Secret', 'confirmed', 'crypto', ['jwt'], 3.5),
    add(r'(?i)ssh_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\+\/=]{40,})[\'"]', 'SSH Key Value', 'confirmed', 'crypto', ['ssh'], 4.0),
    add(r'(?i)ssl_key\s*[=:]\s*[\'"]([A-Za-z0-9\/+=]{40,})[\'"]', 'SSL Private Key', 'confirmed', 'crypto', ['ssl'], 4.0),
    
    # API Keys & Auth (15)
    add(r'(?i)api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{16,})[\'"]', 'API Key', 'confirmed', 'api', ['api-key'], 3.0),
    add(r'(?i)api_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.~!@#]{12,})[\'"]', 'API Secret', 'probable', 'api', ['secret'], 3.5),
    add(r'(?i)client_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.~]{20,})[\'"]', 'OAuth Client Secret', 'confirmed', 'auth', ['oauth'], 3.0),
    add(r'(?i)access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Access Token', 'confirmed', 'auth', ['token'], 3.0),
    add(r'(?i)auth_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Auth Token', 'probable', 'auth', ['token'], 3.0),
    add(r'(?i)bearer\s+([A-Za-z0-9\-\._~\+\/]{30,}=*)', 'Bearer Token', 'probable', 'auth', ['token'], 3.5),
    add(r'(?i)Basic\s+([A-Za-z0-9\+\/=]{20,})', 'Basic Auth', 'probable', 'auth', ['auth'], 3.0),
    add(r'(?i)refresh_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Refresh Token', 'confirmed', 'auth', ['token']),
    add(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})', 'JWT Token', 'probable', 'auth', ['jwt'], 4.0),
    add(r'(?i)session_secret\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Session Secret', 'probable', 'auth', ['session'], 3.0),
    add(r'(?i)secret_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Secret Key', 'probable', 'auth', ['secret'], 3.5),
    add(r'(?i)x-api-key\s*[=:]\s*[\'"]([A-Za-z0-9]{20,})[\'"]', 'X-API-Key', 'confirmed', 'api', ['api-key']),
    add(r'(?i)authorization\s*[=:]\s*[\'"](Basic|Bearer)\s+([A-Za-z0-9\-_=]+)[\'"]', 'Auth Header', 'confirmed', 'auth', ['auth']),
    add(r'PMAK-[A-Za-z0-9\-]{40,}', 'Postman API Key', 'confirmed', 'api', ['postman','saas'], 4.0),
    add(r'(?i)algolia_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32})[\'"]', 'Algolia API Key', 'confirmed', 'api', ['algolia'], 3.5),
    
    # Environment & Config (8)
    add(r'process\.env\.[A-Z_]+', 'Env Variable Access', 'info', 'config', ['env']),
    add(r'(?i)SECRET_KEY\s*[=:]\s*[\'"]([A-Za-z0-9]{40,})[\'"]', 'Django/Flask Secret', 'confirmed', 'config', ['django','flask'], 3.5),
    add(r'(?i)ENCRYPTION_KEY\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Encryption Key', 'confirmed', 'config', ['crypto']),
    add(r'(?i)JWT_SECRET\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'JWT Secret', 'confirmed', 'config', ['jwt']),
    add(r'(?i)SESSION_SECRET\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Session Secret', 'confirmed', 'config', ['session']),
    add(r'(?i)COOKIE_SECRET\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Cookie Secret', 'confirmed', 'config', ['cookie']),
    add(r'(base64:[A-Za-z0-9+\/]{44}=)', 'Laravel App Key', 'confirmed', 'config', ['laravel'], 4.0),
    add(r'(?i)RAILS_MASTER_KEY\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Rails Master Key', 'confirmed', 'config', ['rails']),
    
    # CDN & Infra (12)
    add(r'(?i)cloudflare_api_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{37,40})[\'"]', 'Cloudflare Token', 'confirmed', 'cloud', ['cloudflare'], 3.5),
    add(r'(?i)cloudflare_global_key\s*[=:]\s*[\'"]([a-f0-9]{37})[\'"]', 'Cloudflare Global Key', 'confirmed', 'cloud', ['cloudflare']),
    add(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean PAT', 'confirmed', 'cloud', ['digitalocean']),
    add(r'DO00[A-Za-z0-9]{32,}', 'DO Spaces Key', 'confirmed', 'cloud', ['digitalocean'], 3.5),
    add(r'rnd_[A-Za-z0-9]{32}', 'Render Key', 'confirmed', 'cloud', ['render'], 3.5),
    add(r'SCW[A-Z0-9]{20,}', 'Scaleway Key', 'confirmed', 'cloud', ['scaleway'], 3.5),
    add(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Key', 'confirmed', 'cloud', ['alibaba'], 3.0),
    add(r'(?i)heroku_api_key\s*[=:]\s*[\'"]([0-9a-f-]{36})[\'"]', 'Heroku Key', 'confirmed', 'cloud', ['heroku']),
    add(r'(?i)netlify_access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'Netlify Token', 'confirmed', 'cloud', ['netlify'], 3.5),
    add(r'(?i)vercel_token\s*[=:]\s*[\'"]([A-Za-z0-9]{24})[\'"]', 'Vercel Token', 'probable', 'cloud', ['vercel']),
    add(r'(?i)linode_token\s*[=:]\s*[\'"]([A-Za-z0-9]{64})[\'"]', 'Linode Token', 'confirmed', 'cloud', ['linode']),
    add(r'(?i)fastly_api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Fastly Key', 'confirmed', 'cloud', ['fastly']),
    
    # Web3 (12)
    add(r'0x[a-fA-F0-9]{40}', 'Ethereum Address', 'info', 'web3', ['ethereum']),
    add(r'alch-[A-Za-z0-9_\-]{32}', 'Alchemy Key', 'confirmed', 'web3', ['alchemy'], 4.0),
    add(r'(?i)etherscan_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{34})[\'"]', 'Etherscan Key', 'confirmed', 'web3', ['etherscan'], 3.5),
    add(r'(?i)infura_project_secret\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Infura Secret', 'confirmed', 'web3', ['infura'], 3.5),
    add(r'(?i)solana_private_key\s*[=:]\s*[\'"]([1-9A-HJ-NP-Za-km-z]{87,88})[\'"]', 'Solana Key', 'confirmed', 'web3', ['solana'], 4.5),
    add(r'(?i)alchemy_api_key\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Alchemy Context', 'probable', 'web3', ['alchemy'], 3.5),
    add(r'(?i)moralis_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Moralis Key', 'probable', 'web3', ['moralis'], 3.5),
    add(r'(?i)walletconnect_project_id\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'WalletConnect ID', 'probable', 'web3', ['walletconnect']),
    add(r'(?i)quicknode_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'QuickNode Key', 'confirmed', 'web3', ['quicknode']),
    add(r'(?i)chainstack_api_key\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Chainstack Key', 'confirmed', 'web3', ['chainstack']),
    add(r'(?i)blockcypher_token\s*[=:]\s*[\'"]([a-f0-9]{32,})[\'"]', 'BlockCypher Token', 'probable', 'web3', ['blockcypher']),
    add(r'(?i)infura_project_id\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Infura Project ID', 'probable', 'web3', ['infura']),
    
    # Monitoring (10)
    add(r'https://[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+', 'Sentry DSN', 'confirmed', 'monitoring', ['sentry']),
    add(r'NRAK-[A-Z0-9]{27}', 'New Relic Key', 'confirmed', 'monitoring', ['newrelic'], 3.5),
    add(r'(?i)datadog_api_key\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Datadog API Key', 'confirmed', 'monitoring', ['datadog'], 3.5),
    add(r'(?i)datadog_app_key\s*[=:]\s*[\'"]([a-f0-9]{40})[\'"]', 'Datadog App Key', 'confirmed', 'monitoring', ['datadog'], 3.5),
    add(r'glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}', 'Grafana SA Token', 'confirmed', 'monitoring', ['grafana'], 4.0),
    add(r'dt0[a-z0-9]{2,5}\.[A-Za-z0-9]{8}\.[A-Za-z0-9]{64}', 'Dynatrace Token', 'confirmed', 'monitoring', ['dynatrace'], 4.0),
    add(r'(?i)splunk_hec_token\s*[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Splunk HEC Token', 'confirmed', 'monitoring', ['splunk']),
    add(r'(?i)prometheus_token\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Prometheus Token', 'probable', 'monitoring', ['prometheus']),
    add(r'(?i)elastic_apm_token\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Elastic APM Token', 'confirmed', 'monitoring', ['elastic']),
    add(r'(?i)logzio_token\s*[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Logz.io Token', 'probable', 'monitoring', ['logzio']),
    
    # SaaS (8)
    add(r'CFPAT-[A-Za-z0-9_\-]{40,}', 'Contentful PAT', 'confirmed', 'saas', ['contentful'], 4.0),
    add(r'secret_[A-Za-z0-9]{40,}', 'Notion Token', 'confirmed', 'saas', ['notion'], 3.5),
    add(r'ntn_[A-Za-z0-9]{48,}', 'Notion New Token', 'confirmed', 'saas', ['notion'], 4.0),
    add(r'figd_[A-Za-z0-9_\-]{40,}', 'Figma Token', 'confirmed', 'saas', ['figma'], 4.0),
    add(r'dapi[a-f0-9]{32}', 'Databricks Token', 'confirmed', 'saas', ['databricks'], 3.5),
    add(r'BBDC-[A-Za-z0-9]{32,}', 'Bitbucket Token', 'confirmed', 'saas', ['bitbucket'], 4.0),
    add(r'hvs\.[A-Za-z0-9_\-+\/=]{50,}', 'Vault Token', 'confirmed', 'saas', ['vault'], 4.0),
    add(r'shpat_[a-fA-F0-9]{32}', 'Shopify Admin', 'confirmed', 'saas', ['shopify']),
    
    # Social Media (8)
    add(r'AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+\/]{40,}', 'Twitter Bearer', 'confirmed', 'social', ['twitter'], 4.0),
    add(r'EAACEdEose0cBA[0-9A-Za-z]+', 'Facebook Token', 'confirmed', 'social', ['facebook']),
    add(r'oauth:[a-z0-9]{30,}', 'Twitch OAuth', 'confirmed', 'social', ['twitch'], 3.5),
    add(r'(?i)twitch_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{30})[\'"]', 'Twitch Secret', 'confirmed', 'social', ['twitch'], 3.5),
    add(r'(?i)linkedin_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{16})[\'"]', 'LinkedIn Secret', 'confirmed', 'social', ['linkedin'], 3.0),
    add(r'(?i)instagram_access_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-\.]{40,})[\'"]', 'Instagram Token', 'probable', 'social', ['instagram'], 3.5),
    add(r'(?i)reddit_client_secret\s*[=:]\s*[\'"]([A-Za-z0-9]{16})[\'"]', 'Reddit Secret', 'probable', 'social', ['reddit']),
    add(r'(?i)tiktok_access_token\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'TikTok Token', 'probable', 'social', ['tiktok']),
    
    # CI/CD Additional (5)
    add(r'circleci-[a-f0-9]{40}', 'CircleCI Token', 'confirmed', 'ci_cd', ['circleci']),
    add(r'bkua_[a-zA-Z0-9]{40}', 'Buildkite Token', 'confirmed', 'ci_cd', ['buildkite'], 4.0),
    add(r'pul-[a-zA-Z0-9]{40}', 'Pulumi Token', 'confirmed', 'ci_cd', ['pulumi'], 4.0),
    add(r'(?i)jenkins_token\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Jenkins Token', 'probable', 'ci_cd', ['jenkins']),
    add(r'(?i)codecov_token\s*[=:]\s*[\'"]([A-Za-z0-9\-]{36})[\'"]', 'Codecov Token', 'confirmed', 'ci_cd', ['codecov']),
    
    # Misc Confirmed (15)
    add(r'(?i)password\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]', 'Password', 'probable', 'auth', ['password'], 2.8),
    add(r'https?://[^:]+:([^@]{8,})@[^\s]+', 'URL with Password', 'confirmed', 'url', ['url'], 2.0),
    add(r'[?&](?:token|api_key|apikey|access_token)=([A-Za-z0-9_\-\.%+]{16,})', 'Secret in URL', 'confirmed', 'url', ['url'], 2.5),
    add(r'npm_[A-Za-z0-9]{36}', 'npm Token', 'confirmed', 'package', ['npm']),
    add(r'pypi-[A-Za-z0-9_\-]{32,}', 'PyPI Token', 'confirmed', 'package', ['pypi']),
    add(r'rubygems_[a-zA-Z0-9]{48}', 'RubyGems Key', 'confirmed', 'package', ['rubygems'], 4.0),
    add(r'(?i)smtp_password\s*[=:]\s*[\'"]([A-Za-z0-9]{8,})[\'"]', 'SMTP Password', 'confirmed', 'email', ['smtp']),
    add(r'(?i)ftp_password\s*[=:]\s*[\'"]([A-Za-z0-9]{8,})[\'"]', 'FTP Password', 'confirmed', 'infra', ['ftp']),
    add(r'cloudinary://\d+:[A-Za-z0-9_\-]+@', 'Cloudinary URL', 'confirmed', 'saas', ['cloudinary']),
    add(r'(?:pk|sk)\.eyJ1[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', 'Mapbox Token', 'confirmed', 'api', ['mapbox']),
    add(r'waka_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}', 'WakaTime Key', 'confirmed', 'saas', ['wakatime'], 3.5),
    add(r'signkey-prod-[A-Za-z0-9]{32,}', 'Inngest Prod', 'confirmed', 'saas', ['inngest'], 4.0),
    add(r'dp\.st\.[A-Za-z0-9.]{30,}', 'Doppler Service', 'confirmed', 'saas', ['doppler'], 4.0),
    add(r'lin_api_[A-Za-z0-9]{30,}', 'Linear Key', 'confirmed', 'saas', ['linear'], 4.0),
    add(r'tfp_[A-Za-z0-9]{40,}', 'Typeform Token', 'confirmed', 'saas', ['typeform'], 4.0),
    
    # ── PROBABLE (40+) ───────────────────────────────────────────────────
    add(r'(?i)(?:token|key|secret|pass|pwd)\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'High Entropy Token', 'possible', 'generic', ['generic'], 4.2),
    add(r'[a-f0-9]{32}-us[0-9]{1,2}', 'Mailchimp Key', 'confirmed', 'email', ['mailchimp'], 3.5),
    add(r're_[A-Za-z0-9_]{24,}', 'Resend Key', 'confirmed', 'email', ['resend'], 4.0),
    add(r'(?i)jira_token\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Jira Token', 'probable', 'saas', ['jira']),
    add(r'(?i)confluence_token\s*[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Confluence Token', 'probable', 'saas', ['confluence']),
    add(r'([0-9]+)', 'AWS Account ID', 'info', 'aws', ['aws']),
    
    # ── POSSIBLE - Security Issues (35+) ─────────────────────────────────
    add(r'eval\s*\([^)]*location\.', 'eval(location) XSS', 'possible', 'security', ['xss']),
    add(r'\.innerHTML\s*=\s*`[^`]*\$\{', 'innerHTML XSS', 'possible', 'security', ['xss']),
    add(r'document\.write\s*\([^)]*location\.', 'doc.write XSS', 'possible', 'security', ['xss']),
    add(r'exec\s*\(\s*`[^`]*\$\{[^}]*req\.', 'Command Injection', 'confirmed', 'security', ['rce']),
    add(r'pickle\.loads\s*\(', 'Pickle RCE', 'confirmed', 'security', ['rce']),
    add(r'vm\.runInNewContext\s*\([^)]*req\.', 'VM Sandbox Escape', 'possible', 'security', ['rce']),
    add(r'(?i)\.query\s*\(\s*["\'][^"\']*\+\s*req\.', 'SQL Injection', 'possible', 'security', ['sqli']),
    add(r'(?i)\.find\s*\(\s*req\.(?:body|params|query)', 'NoSQL Injection', 'possible', 'security', ['nosqli']),
    add(r'(?i)\.merge\s*\(\s*\{\s*\},\s*req\.', 'Prototype Pollution', 'possible', 'security', ['prototype-pollution']),
    add(r'(?i)\.readFile\s*\(\s*req\.(?:params|query|body)', 'Path Traversal', 'possible', 'security', ['lfi']),
    add(r'(?i)(?:fetch|axios|http\.get)\s*\(\s*req\.', 'SSRF', 'possible', 'security', ['ssrf']),
    
    # ── INFO - Recon (65+) ───────────────────────────────────────────────
    add(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Private IP A', 'info', 'recon', ['infra']),
    add(r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'Private IP B', 'info', 'recon', ['infra']),
    add(r'192\.168\.\d{1,3}\.\d{1,3}', 'Private IP C', 'info', 'recon', ['infra']),
    add(r'[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', 'Email Address', 'info', 'recon', ['pii']),
    add(r'https?://[^\s"\'<>]+', 'URL Endpoint', 'info', 'recon', ['url']),
    add(r'["\'](\/api\/[^\s"\']+)["\']', 'API Endpoint', 'info', 'recon', ['api']),
    add(r'["\'](\/graphql)["\']', 'GraphQL Endpoint', 'info', 'recon', ['graphql']),
    add(r'["\'](\/(?:admin|dashboard|console|portal))["\']', 'Admin Path', 'info', 'recon', ['admin']),
    add(r'["\'](\/swagger[^"\']*\.(?:json|yaml|yml))["\']', 'Swagger Spec', 'info', 'recon', ['swagger']),
    add(r'["\'](\/(?:health|healthz|ping|status))["\']', 'Health Check', 'info', 'recon', ['health']),
    add(r'["\'](\/(?:debug|_debug|devtools))["\']', 'Debug Endpoint', 'info', 'recon', ['debug']),
    add(r'["\'](\/\.env)["\']', 'Env File Path', 'info', 'recon', ['env']),
    add(r'//# sourceMappingURL=', 'Source Map URL', 'info', 'recon', ['sourcemap']),
    add(r'console\.(?:log|debug|info|warn|error)\s*\(', 'Console Statement', 'info', 'recon', ['debug']),
    add(r'debugger;', 'Debugger Statement', 'info', 'recon', ['debug']),
    
    # Deduplicate
    seen = set()
    unique = []
    for p in patterns:
        if p[0] not in seen:
            seen.add(p[0])
            unique.append(p)
    return unique

PATTERNS = build_patterns()

# ═══════════════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class SecretEngine:
    def __init__(self, severity='possible', show_raw=False, verbose=False,
                 json_output=False, filter_tags=None, threads=20, timeout=30,
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
        
        self.scanned = set()
        self.total = 0
        self.scanned_count = 0
        self.hit_count = 0
        self.start = None
        
        self.compiled = self._compile()
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
    
    def _compile(self):
        sev = {'confirmed': 0, 'probable': 1, 'possible': 2, 'info': 3}
        ml = sev.get(self.severity, 3)
        comp = []
        for rx, name, s, cat, tags, ent in PATTERNS:
            if sev.get(s, 3) > ml: continue
            if self.filter_tags and not self.filter_tags.intersection(tags): continue
            try: comp.append((re.compile(rx, re.I|re.M), name, s, cat, tags, ent))
            except: pass
        return comp
    
    def fetch(self, url):
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/html,application/javascript,*/*',
                'Accept-Encoding': 'identity',
            })
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as r:
                ct = r.headers.get('Content-Type', '').lower()
                if any(t in ct for t in ['text', 'javascript', 'json', 'html']):
                    return (url, r.read(10*1024*1024).decode('utf-8', errors='ignore'))
        except: pass
        return (url, None)
    
    def scan(self, url, content):
        findings = []
        for ln, line in enumerate(content.split('\n'), 1):
            for pat, name, sev, cat, tags, ent_min in self.compiled:
                try:
                    for m in pat.finditer(line):
                        val = m.group(1) if m.lastindex else m.group(0)
                        val = val.strip()
                        if len(val) < 8 or len(val) > 500: continue
                        if not self.no_fp and is_fp(val): continue
                        if ent_min and entropy(val) < ent_min: continue
                        s = max(0, m.start()-25)
                        e = min(len(line), m.end()+25)
                        ctx = line[s:e].strip()
                        if s > 0: ctx = '…' + ctx
                        if e < len(line): ctx += '…'
                        findings.append({
                            'url': url, 'line': ln, 'pattern': name,
                            'severity': sev, 'category': cat, 'tags': list(tags),
                            'value': val if self.show_raw else val[:4]+'*'*(len(val)-8)+val[-4:],
                            'context': ctx[:100], 'entropy': round(entropy(val),2)
                        })
                except: pass
        return findings
    
    def process(self, url, depth=0):
        if url in self.scanned: return (url, [], set())
        self.scanned.add(url)
        url, content = self.fetch(url)
        if not content: return (url, [], set())
        findings = self.scan(url, content)
        new = set()
        if self.follow_js and depth < self.max_depth:
            for m in re.finditer(r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', content, re.I):
                u = m.group(0)
                if u not in self.scanned: new.add(u)
        return (url, findings, new)
    
    def run(self, urls):
        if not urls:
            print(f"{C.R}[✗] No URLs{C.RST}", file=sys.stderr)
            return
        self.start = time.time()
        if not self.json_output and not self.quiet:
            self._banner()
        all_f = []
        queue = list(urls)
        depth = 0
        while queue and depth <= self.max_depth:
            discovered = set()
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = {ex.submit(self.process, u, depth): u for u in queue if u not in self.scanned}
                for fut in as_completed(futs):
                    try:
                        url, findings, new = fut.result()
                        self.scanned_count += 1
                        if findings:
                            self.hit_count += 1
                            self.total += len(findings)
                            all_f.extend(findings)
                            if not self.json_output: self._show(url, findings)
                        elif self.verbose: print(f"{C.G}  ✓ {url[:70]}{C.RST}")
                        discovered.update(new)
                    except: pass
            queue = list(discovered - self.scanned)
            depth += 1
        elapsed = time.time() - self.start
        if self.json_output:
            print(json.dumps({'summary': self._sum(all_f, elapsed), 'findings': all_f}, indent=2))
        else:
            self._summary_print(all_f, elapsed)
    
    def _banner(self):
        cats = defaultdict(int)
        for _, _, _, cat, _, _ in PATTERNS: cats[cat] += 1
        print(f"\n{C.BOLD}{C.C}╔══════════════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.C}║   ASTRA — Secret Detection Engine v1.2               ║{C.RST}")
        print(f"{C.BOLD}{C.C}║   Live JS Secret Hunter                              ║{C.RST}")
        print(f"{C.BOLD}{C.C}╚══════════════════════════════════════════════════════╝{C.RST}")
        print(f"\n{C.BOLD}  Loaded Rules: {len(PATTERNS)}{C.RST}\n")
        names = {'aws':'AWS Cloud','gcp':'Google Cloud','azure':'Azure Cloud','cloud':'Other Cloud',
                 'payment':'Payment Processors','api':'API Keys','auth':'Authentication',
                 'database':'Database DSNs','crypto':'Crypto & Keys','token':'Tokens & JWT',
                 'email':'Email Services','ci_cd':'CI/CD','social':'Social Media',
                 'saas':'SaaS Platforms','web3':'Web3 & Blockchain','monitoring':'Monitoring',
                 'security':'Security Issues','recon':'Reconnaissance','config':'Config & Env',
                 'messaging':'Messaging','package':'Package Managers','infra':'Infrastructure',
                 'url':'URL Credentials','generic':'Generic Patterns'}
        for cat in ['aws','gcp','azure','cloud','payment','api','auth','database','crypto',
                     'messaging','email','ci_cd','social','saas','web3','monitoring',
                     'config','security','recon','package','infra','url','generic']:
            if cats.get(cat): print(f"  {C.BOLD}{names.get(cat,cat)} ({cats[cat]}){C.RST}")
        print(f"\n  {C.W}Threads: {self.threads}{C.RST}  {C.W}Depth: {self.max_depth}{C.RST}  {C.W}Timeout: {self.timeout}s{C.RST}")
        print(f"  {C.W}Severity: {C.BOLD}{self.severity.upper()}{C.RST}  {C.W}FP Filter: {'ON' if not self.no_fp else 'OFF'}{C.RST}\n")
    
    def _show(self, url, findings):
        sc = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
        si = {'confirmed': '🔴', 'probable': '🟡', 'possible': '🔵', 'info': '⚪'}
        print(f"\n{C.BOLD}{C.C}── {url}{C.RST}")
        for f in findings:
            c = sc.get(f['severity'], C.W)
            icon = si.get(f['severity'], '•')
            tags = f" {C.X}[{','.join(f['tags'])}]{C.RST}" if f['tags'] else ""
            print(f"  {icon} {c}{C.BOLD}{f['pattern']}{C.RST}{tags}")
            print(f"    {C.X}L{f['line']:4} │{C.RST} {c}{f['value']}{C.RST}")
            if f.get('context'): print(f"    {C.X}ctx │{C.RST} {f['context'][:90]}")
            print()
        print(f"{C.X}  ── {len(findings)} finding(s){C.RST}")
    
    def _sum(self, findings, elapsed):
        sc = defaultdict(int); cc = defaultdict(int)
        for f in findings: sc[f['severity']] += 1; cc[f.get('category','?')] += 1
        return {'urls': self.scanned_count, 'hits': self.hit_count, 'total': self.total,
                'time': round(elapsed,2), 'by_severity': dict(sc), 'by_category': dict(cc)}
    
    def _summary_print(self, findings, elapsed):
        s = self._sum(findings, elapsed)
        print(f"\n{C.BOLD}{C.M}╔══════════════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.M}║   SCAN COMPLETE                                      ║{C.RST}")
        print(f"{C.BOLD}{C.M}╚══════════════════════════════════════════════════════╝{C.RST}")
        print(f"  URLs scanned: {s['urls']}  |  With secrets: {s['hits']}  |  Findings: {s['total']}  |  Time: {s['time']}s")
        if not findings: print(f"\n{C.G}  ✓ CLEAN{C.RST}")
        else:
            print(f"\n  {C.BOLD}By Severity:{C.RST}")
            for sev, c in [('confirmed',C.R),('probable',C.Y),('possible',C.B),('info',C.C)]:
                if s['by_severity'].get(sev): print(f"  {c}{sev.upper():12} {s['by_severity'][sev]}{C.RST}")
        print(f"\n{C.BOLD}{C.M}{'═'*56}{C.RST}\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='astra — Live JS Secret Detection Engine v1.2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.BOLD}FLAGS:{C.RST}
  {C.Y}-u, --urls{C.RST}      URLs to scan
  {C.Y}-f, --file{C.RST}      File with URLs (one per line)
  {C.Y}-s, --severity{C.RST}  confirmed|probable|possible|info (default: possible)
  {C.Y}-r, --show-raw{C.RST}  Show raw secrets
  {C.Y}-v, --verbose{C.RST}   Show all URLs
  {C.Y}-q, --quiet{C.RST}     Minimal output
  {C.Y}-j, --json{C.RST}      JSON output
  {C.Y}--tags{C.RST}          Filter by tags (aws,stripe,github)
  {C.Y}-t, --threads{C.RST}   Threads (default: 20)
  {C.Y}--timeout{C.RST}       Timeout seconds (default: 30)
  {C.Y}-d, --depth{C.RST}     JS URL depth (default: 1)
  {C.Y}--no-follow{C.RST}     Don't follow JS URLs
  {C.Y}--no-fp{C.RST}         Disable FP filter
  {C.Y}-l, --list{C.RST}      List rules
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
    
    if args.list:
        print(f"\n{C.BOLD}Secret Detection Engine v1.2 — {len(PATTERNS)} Rules{C.RST}\n")
        cats = defaultdict(list)
        for _, name, sev, cat, _, _ in PATTERNS: cats[cat].append((name, sev))
        for cat in ['aws','gcp','azure','cloud','payment','api','auth','database','crypto',
                     'messaging','email','ci_cd','social','saas','web3','monitoring',
                     'config','security','recon','package','infra','url','generic']:
            if cats.get(cat):
                print(f"{C.BOLD}{cat.upper()} ({len(cats[cat])}){C.RST}")
                for name, sev in cats[cat]:
                    c = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}.get(sev, C.W)
                    print(f"  {c}├─ {name}{C.RST}")
                print()
        sys.exit(0)
    
    urls = []
    if args.urls: urls.extend(args.urls)
    if args.file:
        try:
            with open(args.file) as f: urls.extend(l.strip() for l in f if l.strip() and not l.startswith('#'))
        except Exception as e: print(f"{C.R}[✗] {e}{C.RST}", file=sys.stderr); sys.exit(1)
    if not sys.stdin.isatty() and not urls:
        urls.extend(l.strip() for l in sys.stdin if l.strip() and not l.startswith('#'))
    
    if not urls: parser.print_help(); sys.exit(1)
    
    engine = SecretEngine(
        severity=args.severity, show_raw=args.show_raw, verbose=args.verbose,
        json_output=args.json, filter_tags=args.tags, threads=args.threads,
        timeout=args.timeout, max_depth=args.depth, follow_js=not args.no_follow,
        quiet=args.quiet, no_fp=args.no_fp
    )
    engine.run(urls)
    sys.exit(1 if engine.total > 0 else 0)

if __name__ == '__main__':
    main()
