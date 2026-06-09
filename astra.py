#!/usr/bin/env python3
"""
astra — Live JS Secret Hunter
=================================
Fetches JS files live, scans for secrets, shows ONLY matched patterns.
Clean output - just the secrets, nothing else.
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
from typing import List, Dict, Set, Tuple
from urllib.parse import urljoin, urlparse

# ── Colors ───────────────────────────────────────────────────────────────
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; X = '\033[90m'
    BOLD = '\033[1m'; RST = '\033[0m'

# ── Entropy ─────────────────────────────────────────────────────────────
def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    l = len(s)
    return -sum((v/l) * math.log2(v/l) for v in freq.values())

# ── False Positive Filter ──────────────────────────────────────────────
_FP_SET = {
    'null','undefined','true','false','none','example','test','sample',
    'dummy','placeholder','your_key','your_token','insert_here','changeme',
    'todo','fixme','password','secret','api_key','apikey','token','redacted',
}

def is_fp(val: str) -> bool:
    v = val.strip()
    if len(v) < 6: return True
    if v.lower() in _FP_SET: return True
    if len(set(v.lower())) < 4: return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
# 150+ PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

PATTERNS = []

def P(rx, name, sev, tags, ent=0.0):
    PATTERNS.append((rx, name, sev, tags, ent))

# AWS
P(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key', 'confirmed', ['aws'], 3.0)
P(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Key', 'confirmed', ['aws'], 3.0)
P(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', ['aws'], 3.0)
P(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', ['aws'], 3.0)
P(r'(?i)aws_secret_access_key[=:]\s*[\'"]([A-Za-z0-9/+=]{40})[\'"]', 'AWS Secret Key', 'confirmed', ['aws'], 4.5)
P(r'(?i)aws_session_token[=:]\s*[\'"]([A-Za-z0-9/+=]{100,})[\'"]', 'AWS Session Token', 'confirmed', ['aws'], 4.0)
P(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Token', 'confirmed', ['aws'])
P(r'(FWO[A-Za-z0-9/+=]{40,})', 'AWS STS FWO', 'confirmed', ['aws'], 4.0)

# Google
P(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', ['google'], 3.5)
P(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth Token', 'confirmed', ['google'])
P(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Secret', 'confirmed', ['google'])
P(r'(6L[0-9A-Za-z\-_]{38})', 'Google reCAPTCHA', 'probable', ['google'], 3.5)
P(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'Firebase FCM Key', 'confirmed', ['firebase'])
P(r'"type"\s*:\s*"service_account"', 'GCP Service Account', 'confirmed', ['gcp'])

# GitHub
P(r'(ghp_[A-Za-z0-9]{36})', 'GitHub PAT', 'confirmed', ['github'])
P(r'(ghs_[A-Za-z0-9]{36})', 'GitHub Actions Token', 'confirmed', ['github'])
P(r'(github_pat_[A-Za-z0-9_]{82})', 'GitHub Fine PAT', 'confirmed', ['github'])

# GitLab
P(r'(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab PAT', 'confirmed', ['gitlab'])
P(r'(gldt-[A-Za-z0-9_\-]{20,})', 'GitLab Deploy Token', 'confirmed', ['gitlab'])
P(r'(glcbt-[A-Za-z0-9_\-]{20,})', 'GitLab CI Token', 'confirmed', ['gitlab'])
P(r'(glptt-[A-Za-z0-9_\-]{20,})', 'GitLab Project Token', 'confirmed', ['gitlab'])
P(r'(glrt-[A-Za-z0-9_\-]{20,})', 'GitLab Runner Token', 'confirmed', ['gitlab'])
P(r'(glso-[A-Za-z0-9_\-]{20,})', 'GitLab Service Token', 'confirmed', ['gitlab'])

# Azure
P(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88})', 'Azure Storage Key', 'confirmed', ['azure'])
P(r'(Endpoint=sb://[^;]+\.servicebus\.windows\.net/[^;"\'\s]*)', 'Azure Service Bus', 'confirmed', ['azure'])
P(r'(sig=[A-Za-z0-9%+/]{20,}&se=[0-9T:Z%\-]+&sp=[a-z]+)', 'Azure SAS Token', 'confirmed', ['azure'])
P(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps PAT', 'confirmed', ['azure'], 4.0)
P(r'(?i)azure_client_id[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Client ID', 'probable', ['azure'])
P(r'(?i)azure_tenant_id[=:]\s*[\'"]([a-f0-9-]{36})[\'"]', 'Azure Tenant ID', 'probable', ['azure'])

# Stripe
P(r'(sk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Key', 'confirmed', ['stripe'])
P(r'(rk_live_[0-9a-zA-Z]{24,99})', 'Stripe Restricted Key', 'confirmed', ['stripe'])
P(r'(sk_test_[0-9a-zA-Z]{24,99})', 'Stripe Test Key', 'possible', ['stripe'])
P(r'(whsec_[0-9a-zA-Z]{32,})', 'Stripe Webhook Secret', 'confirmed', ['stripe'], 3.5)

# OpenAI / AI
P(r'(sk-[A-Za-z0-9]{48})', 'OpenAI API Key', 'confirmed', ['openai'], 4.0)
P(r'(sk-proj-[A-Za-z0-9_\-]{40,})', 'OpenAI Project Key', 'confirmed', ['openai'], 4.0)
P(r'(sk-ant-api\d+-[A-Za-z0-9_\-]{40,})', 'Anthropic API Key', 'confirmed', ['anthropic'])
P(r'(hf_[a-zA-Z0-9]{34,})', 'HuggingFace Token', 'confirmed', ['huggingface'])
P(r'(gsk_[A-Za-z0-9]{52})', 'Groq API Key', 'confirmed', ['groq'], 4.0)
P(r'(pplx-[A-Za-z0-9]{48})', 'Perplexity Key', 'confirmed', ['perplexity'], 4.0)
P(r'(sk-or-v1-[A-Za-z0-9]{48})', 'OpenRouter Key', 'confirmed', ['openrouter'], 4.0)
P(r'(r8_[A-Za-z0-9]{40})', 'Replicate Token', 'confirmed', ['replicate'])
P(r'(tvly-[A-Za-z0-9]{32})', 'Tavily AI Key', 'confirmed', ['tavily'], 4.0)
P(r'(fw_[A-Za-z0-9]{32,})', 'Fireworks AI Key', 'confirmed', ['fireworks'], 4.0)
P(r'(esecret_[A-Za-z0-9_\-]{40,})', 'Anyscale Key', 'confirmed', ['anyscale'], 4.0)

# Slack / Discord
P(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})', 'Slack Token', 'confirmed', ['slack'])
P(r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+', 'Slack Webhook', 'confirmed', ['slack'])
P(r'(M[A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})', 'Discord Bot Token', 'confirmed', ['discord'], 4.0)
P(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+', 'Discord Webhook', 'confirmed', ['discord'])

# Private Keys
P(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'confirmed', ['crypto'])
P(r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key', 'confirmed', ['crypto'])
P(r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 'confirmed', ['crypto'])
P(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'confirmed', ['crypto'])
P(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Key', 'confirmed', ['crypto'])
P(r'-----BEGIN PRIVATE KEY-----', 'PKCS8 Key', 'confirmed', ['crypto'])

# Database DSNs
P(r'mongodb\+srv://[^:]+:[^@]+@[^\s"\'<>]+', 'MongoDB Atlas DSN', 'confirmed', ['database'], 2.5)
P(r'postgresql://[^:]+:[^@]+@[^\s"\'<>]+', 'PostgreSQL DSN', 'confirmed', ['database'], 2.5)
P(r'mysql://[^:]+:[^@]+@[^\s"\'<>]+', 'MySQL DSN', 'confirmed', ['database'], 2.5)
P(r'redis://[^:]+:[^@]+@[^\s"\'<>]+', 'Redis DSN', 'confirmed', ['database'], 2.5)
P(r'clickhouse://[^:]+:[^@]+@[^\s"\'<>]+', 'ClickHouse DSN', 'confirmed', ['database'], 2.5)
P(r'jdbc:[a-zA-Z]+://[^\s"\'<>]+', 'JDBC String', 'confirmed', ['database'])
P(r'rediss://default:[^@]+@[^\s]+\.upstash\.io:\d+', 'Upstash Redis', 'confirmed', ['database'], 3.0)
P(r'postgresql://[^:]+:[^@]+@[^\s]+\.neon\.tech', 'Neon DSN', 'confirmed', ['database'], 2.5)
P(r'mysql://[^:]+:[^@]+@[^\s]+\.psdb\.cloud', 'PlanetScale DSN', 'confirmed', ['planetscale'], 2.5)

# Payment
P(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'PayPal Braintree', 'confirmed', ['paypal'])
P(r'EAAA[A-Za-z0-9\-_]{22,}', 'Square Access Token', 'confirmed', ['square'], 3.5)
P(r'sq0atp-[A-Za-z0-9\-_]{22,}', 'Square OAuth Token', 'confirmed', ['square'], 3.5)
P(r'sq0csp-[A-Za-z0-9_\-]{43}', 'Square OAuth Secret', 'confirmed', ['square'])
P(r'AQ[A-Za-z0-9_\-]{30,}', 'Adyen API Key', 'confirmed', ['adyen'], 3.5)
P(r'rzp_live_[A-Za-z0-9]{14,}', 'Razorpay Live', 'confirmed', ['razorpay'], 3.5)
P(r'rzp_test_[A-Za-z0-9]{14,}', 'Razorpay Test', 'possible', ['razorpay'], 3.5)
P(r'FLWSECK-[a-zA-Z0-9]{32}', 'Flutterwave Secret', 'confirmed', ['flutterwave'], 3.5)
P(r'FLWPUBK-[a-zA-Z0-9]{32}', 'Flutterwave Public', 'probable', ['flutterwave'], 3.5)
P(r'sk_live_[A-Za-z0-9]{40}', 'Paystack Live', 'confirmed', ['paystack'], 4.0)
P(r'sk_test_[A-Za-z0-9]{40}', 'Paystack Test', 'possible', ['paystack'], 4.0)
P(r'pk_live_[A-Za-z0-9]{40}', 'Paystack Public', 'probable', ['paystack'], 4.0)
P(r'ck_[a-f0-9]{40}', 'WooCommerce CK', 'confirmed', ['woocommerce'], 3.5)
P(r'cs_[a-f0-9]{40}', 'WooCommerce CS', 'confirmed', ['woocommerce'], 3.5)

# Email
P(r'key-[0-9a-zA-Z]{32}', 'Mailgun Key', 'confirmed', ['mailgun'])
P(r'[a-f0-9]{32}-us[0-9]{1,2}', 'Mailchimp Key', 'confirmed', ['mailchimp'], 3.5)
P(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', 'SendGrid Key', 'confirmed', ['sendgrid'])
P(r're_[A-Za-z0-9_]{24,}', 'Resend Key', 'confirmed', ['resend'], 4.0)

# CI/CD
P(r'circleci-[a-f0-9]{40}', 'CircleCI Token', 'confirmed', ['circleci'])
P(r'bkua_[a-zA-Z0-9]{40}', 'Buildkite Token', 'confirmed', ['buildkite'], 4.0)
P(r'pul-[a-zA-Z0-9]{40}', 'Pulumi Token', 'confirmed', ['pulumi'], 4.0)
P(r'(?i)jenkins_token[=:]\s*[\'"]([A-Za-z0-9_\-]{20,})[\'"]', 'Jenkins Token', 'probable', ['jenkins'], 3.0)
P(r'(?i)travis_token[=:]\s*[\'"]([A-Za-z0-9_\-]{20,})[\'"]', 'Travis Token', 'probable', ['travis'], 3.0)

# Social
P(r'AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+/]{40,}', 'Twitter Bearer', 'confirmed', ['twitter'], 4.0)
P(r'EAACEdEose0cBA[0-9A-Za-z]+', 'Facebook Token', 'confirmed', ['facebook'])
P(r'oauth:[a-z0-9]{30,}', 'Twitch OAuth', 'confirmed', ['twitch'], 3.5)
P(r'(?i)twitch_client_secret[=:]\s*[\'"]([A-Za-z0-9]{30})[\'"]', 'Twitch Secret', 'confirmed', ['twitch'], 3.5)
P(r'(?i)linkedin_client_secret[=:]\s*[\'"]([A-Za-z0-9]{16})[\'"]', 'LinkedIn Secret', 'confirmed', ['linkedin'], 3.0)

# Cloud Services
P(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean PAT', 'confirmed', ['digitalocean'])
P(r'DO00[A-Za-z0-9]{32,}', 'DO Spaces Key', 'confirmed', ['digitalocean'], 3.5)
P(r'rnd_[A-Za-z0-9]{32}', 'Render Key', 'confirmed', ['render'], 3.5)
P(r'SCW[A-Z0-9]{20,}', 'Scaleway Key', 'confirmed', ['scaleway'], 3.5)
P(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Key', 'confirmed', ['alibaba'], 3.0)
P(r'(?i)heroku_api_key[=:]\s*[\'"]([0-9a-f-]{36})[\'"]', 'Heroku Key', 'confirmed', ['heroku'])
P(r'(?i)cloudflare_api_token[=:]\s*[\'"]([A-Za-z0-9_\-]{37,40})[\'"]', 'Cloudflare Token', 'confirmed', ['cloudflare'], 3.5)
P(r'(?i)netlify_access_token[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'Netlify Token', 'confirmed', ['netlify'], 3.5)

# Monitoring
P(r'https://[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+', 'Sentry DSN', 'confirmed', ['sentry'])
P(r'NRAK-[A-Z0-9]{27}', 'New Relic Key', 'confirmed', ['newrelic'], 3.5)
P(r'(?i)datadog_api_key[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Datadog API Key', 'confirmed', ['datadog'], 3.5)
P(r'(?i)datadog_app_key[=:]\s*[\'"]([a-f0-9]{40})[\'"]', 'Datadog App Key', 'confirmed', ['datadog'], 3.5)
P(r'glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}', 'Grafana SA Token', 'confirmed', ['grafana'], 4.0)
P(r'dt0[a-z0-9]{2,5}\.[A-Za-z0-9]{8}\.[A-Za-z0-9]{64}', 'Dynatrace Token', 'confirmed', ['dynatrace'], 4.0)

# Auth / SaaS
P(r'SSWS [A-Za-z0-9_\-]{40,}', 'Okta Token', 'confirmed', ['okta'], 4.0)
P(r'(?i)auth0_client_secret[=:]\s*[\'"]([A-Za-z0-9_\-]{32,})[\'"]', 'Auth0 Secret', 'confirmed', ['auth0'], 3.5)
P(r'sk_[a-z]+_[A-Za-z0-9]{30,}', 'WorkOS Key', 'confirmed', ['workos'], 4.0)
P(r'sk_prod_[A-Za-z0-9]{40,}', 'Liveblocks Prod', 'confirmed', ['liveblocks'], 4.0)
P(r'sk_dev_[A-Za-z0-9]{40,}', 'Liveblocks Dev', 'possible', ['liveblocks'], 4.0)
P(r'secret-live-[A-Za-z0-9\-]{36}', 'Stytch Live', 'confirmed', ['stytch'], 4.0)
P(r'secret_[A-Za-z0-9]{40,}', 'Notion Token', 'confirmed', ['notion'], 3.5)
P(r'ntn_[A-Za-z0-9]{48,}', 'Notion New Token', 'confirmed', ['notion'], 4.0)
P(r'CFPAT-[A-Za-z0-9_\-]{40,}', 'Contentful PAT', 'confirmed', ['contentful'], 4.0)
P(r'PMAK-[A-Za-z0-9\-]{40,}', 'Postman Key', 'confirmed', ['postman'], 4.0)
P(r'figd_[A-Za-z0-9_\-]{40,}', 'Figma Token', 'confirmed', ['figma'], 4.0)
P(r'dapi[a-f0-9]{32}', 'Databricks Token', 'confirmed', ['databricks'], 3.5)
P(r'lin_api_[A-Za-z0-9]{30,}', 'Linear Key', 'confirmed', ['linear'], 4.0)
P(r'tfp_[A-Za-z0-9]{40,}', 'Typeform Token', 'confirmed', ['typeform'], 4.0)
P(r'EZAK[a-zA-Z0-9]{54}', 'EasyPost Key', 'confirmed', ['easypost'], 4.0)
P(r'duffel_live_[A-Za-z0-9_\-]{40}', 'Duffel Live', 'confirmed', ['duffel'], 4.0)
P(r'BBDC-[A-Za-z0-9]{32,}', 'Bitbucket Token', 'confirmed', ['bitbucket'], 4.0)
P(r'hvs\.[A-Za-z0-9_\-+/=]{50,}', 'Vault Token', 'confirmed', ['vault'], 4.0)
P(r'hvb\.[A-Za-z0-9_\-]{40,}', 'Vault Batch', 'confirmed', ['vault'], 4.0)
P(r'pnu_[A-Za-z0-9]{36}', 'Prefect Token', 'confirmed', ['prefect'], 4.0)
P(r'novu_[A-Za-z0-9_\-]{30,}', 'Novu Key', 'confirmed', ['novu'], 4.0)
P(r'xau_[A-Za-z0-9_\-]{40,}', 'Xata Key', 'confirmed', ['xata'], 4.0)
P(r'pscale_oauth_[A-Za-z0-9_]{32,}', 'PlanetScale OAuth', 'confirmed', ['planetscale'], 4.0)

# Crypto / Web3
P(r'0x[a-fA-F0-9]{40}', 'Ethereum Address', 'info', ['ethereum'])
P(r'alch-[A-Za-z0-9_\-]{32}', 'Alchemy Key', 'confirmed', ['alchemy'], 4.0)
P(r'(?i)etherscan_api_key[=:]\s*[\'"]([A-Za-z0-9]{34})[\'"]', 'Etherscan Key', 'confirmed', ['etherscan'], 3.5)
P(r'(?i)infura_project_secret[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Infura Secret', 'confirmed', ['infura'], 3.5)
P(r'(?i)solana_private_key[=:]\s*[\'"]([1-9A-HJ-NP-Za-km-z]{87,88})[\'"]', 'Solana Key', 'confirmed', ['solana'], 4.5)
P(r'(?i)moralis_api_key[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Moralis Key', 'probable', ['moralis'], 3.5)

# Generic Secrets
P(r'(?i)client_secret[=:]\s*[\'"]([A-Za-z0-9_\-\.~]{20,})[\'"]', 'OAuth Client Secret', 'confirmed', ['oauth'], 3.0)
P(r'(?i)api_key[=:]\s*[\'"]([A-Za-z0-9_\-\.]{16,})[\'"]', 'API Key', 'confirmed', ['api-key'], 3.0)
P(r'(?i)access_token[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Access Token', 'confirmed', ['token'], 3.0)
P(r'(?i)private_key[=:]\s*[\'"]([A-Za-z0-9_\-+/=]{40,})[\'"]', 'Private Key', 'confirmed', ['crypto'], 4.0)
P(r'(?i)secret_key[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'Secret Key', 'probable', ['secret'], 3.5)
P(r'(?i)password[=:]\s*[\'"]([^\'"]{8,})[\'"]', 'Password', 'probable', ['password'], 2.8)
P(r'(?i)api_secret[=:]\s*[\'"]([A-Za-z0-9_\-\.~!@#]{8,})[\'"]', 'API Secret', 'probable', ['secret'], 3.5)
P(r'(?i)auth_token[=:]\s*[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', 'Auth Token', 'probable', ['token'], 3.0)
P(r'(?i)encryption_key[=:]\s*[\'"]([A-Za-z0-9+/=]{32,})[\'"]', 'Encryption Key', 'confirmed', ['crypto'], 3.5)

# JWT / Tokens
P(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 'JWT Token', 'probable', ['jwt'], 4.0)
P(r'(?i)bearer\s+([A-Za-z0-9\-\._~+/]{20,}=*)', 'Bearer Token', 'probable', ['token'], 3.5)
P(r'(?i)Basic\s+([A-Za-z0-9+/=]{20,})', 'Basic Auth', 'probable', ['auth'], 3.0)

# URL Credentials
P(r'https?://[^:]+:([^@]{8,})@[^\s]+', 'Basic Auth URL', 'confirmed', ['url'], 2.0)
P(r'[?&](?:token|api_key|apikey|access_token)=([A-Za-z0-9_\-\.%+]{8,})', 'Secret in URL', 'confirmed', ['url'], 2.5)

# Framework
P(r'(?i)django_secret_key[=:]\s*[\'"]([^\'"]{32,})[\'"]', 'Django Key', 'confirmed', ['django'], 3.5)
P(r'base64:[A-Za-z0-9+/]{44}=', 'Laravel Key', 'confirmed', ['laravel'], 4.0)
P(r'(?i)rails_master_key[=:]\s*[\'"]([a-f0-9]{32})[\'"]', 'Rails Key', 'confirmed', ['rails'], 3.5)
P(r'(?i)jwt_secret[=:]\s*[\'"]([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"]', 'JWT Secret', 'confirmed', ['jwt'], 3.5)

# Package Managers
P(r'npm_[A-Za-z0-9]{36}', 'npm Token', 'confirmed', ['npm'])
P(r'pypi-[A-Za-z0-9_\-]{32,}', 'PyPI Token', 'confirmed', ['pypi'])
P(r'rubygems_[a-zA-Z0-9]{48}', 'RubyGems Key', 'confirmed', ['rubygems'], 4.0)

# Security Tools
P(r'sgp_[A-Za-z0-9]{40}', 'Sourcegraph Token', 'confirmed', ['sourcegraph'], 4.0)
P(r'sqa_[A-Za-z0-9]{40}', 'SonarCloud Token', 'confirmed', ['sonarcloud'], 4.0)
P(r'(?i)snyk_api_token[=:]\s*[\'"]([a-f0-9\-]{36})[\'"]', 'Snyk Token', 'confirmed', ['snyk'], 3.5)
P(r'(?i)codecov_token[=:]\s*[\'"]([A-Za-z0-9\-]{36})[\'"]', 'Codecov Token', 'confirmed', ['codecov'], 3.5)

# Mapbox / Shopify / Cloudinary
P(r'(?:pk|sk)\.eyJ1[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', 'Mapbox Token', 'confirmed', ['mapbox'])
P(r'shpat_[a-fA-F0-9]{32}', 'Shopify Admin', 'confirmed', ['shopify'])
P(r'shpca_[a-fA-F0-9]{32}', 'Shopify Custom', 'confirmed', ['shopify'])
P(r'cloudinary://\d+:[A-Za-z0-9_\-]+@', 'Cloudinary URL', 'confirmed', ['cloudinary'])
P(r'(?i)algolia_api_key[=:]\s*[\'"]([A-Za-z0-9]{32})[\'"]', 'Algolia Key', 'confirmed', ['algolia'], 3.5)

# Communication
P(r'\d{8,10}:[A-Za-z0-9_\-]{35}', 'Telegram Bot', 'probable', ['telegram'], 3.5)
P(r'(?i)vonage_api_key[=:]\s*[\'"]([A-Za-z0-9]{8,20})[\'"]', 'Vonage Key', 'probable', ['vonage'], 3.0)

# CMS
P(r'(?i)wordpress_nonce[=:]\s*[\'"]([a-f0-9A-Za-z_]{10,})[\'"]', 'WordPress Nonce', 'probable', ['wordpress'], 3.0)
P(r'(?i)drupal_private_key[=:]\s*[\'"]([A-Za-z0-9_\-]{40,})[\'"]', 'Drupal Key', 'probable', ['drupal'], 3.5)
P(r'(?i)joomla_secret[=:]\s*[\'"]([A-Za-z0-9]{32,})[\'"]', 'Joomla Secret', 'probable', ['joomla'], 3.5)
P(r'(?i)bigcommerce_token[=:]\s*[\'"]([a-f0-9]{32,})[\'"]', 'BigCommerce Token', 'probable', ['bigcommerce'], 3.5)

# Security Issues
P(r'eval\s*\([^)]*location\.', 'eval(location) XSS', 'possible', ['xss'])
P(r'\.innerHTML\s*=\s*`[^`]*\$\{', 'innerHTML XSS', 'possible', ['xss'])
P(r'document\.write\s*\([^)]*location\.', 'doc.write XSS', 'possible', ['xss'])
P(r'exec\s*\(\s*`[^`]*\$\{[^}]*req\.', 'Command Injection', 'confirmed', ['rce'])
P(r'pickle\.loads\s*\(', 'Pickle RCE', 'confirmed', ['rce'])
P(r'vm\.runInNewContext\s*\([^)]*req\.', 'VM Sandbox Escape', 'possible', ['rce'])

# Recon
P(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Private IP A', 'info', ['infra'])
P(r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'Private IP B', 'info', ['infra'])
P(r'192\.168\.\d{1,3}\.\d{1,3}', 'Private IP C', 'info', ['infra'])
P(r'[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', 'Email Address', 'info', ['pii'])

# Misc
P(r'waka_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}', 'WakaTime Key', 'confirmed', ['wakatime'], 3.5)
P(r'signkey-prod-[A-Za-z0-9]{32,}', 'Inngest Prod', 'confirmed', ['inngest'], 4.0)
P(r'signkey-test-[A-Za-z0-9]{32,}', 'Inngest Test', 'possible', ['inngest'], 4.0)
P(r'dp\.st\.[A-Za-z0-9.]{30,}', 'Doppler Service', 'confirmed', ['doppler'], 4.0)
P(r'dp\.ct\.[A-Za-z0-9.]{30,}', 'Doppler Client', 'possible', ['doppler'], 4.0)

# Deduplicate
seen = set()
UNIQUE = []
for p in PATTERNS:
    if p[0] not in seen:
        seen.add(p[0])
        UNIQUE.append(p)
PATTERNS = UNIQUE

# ═══════════════════════════════════════════════════════════════════════════
# JS URL EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════

def extract_js_urls(content: str, base_url: str = None) -> Set[str]:
    """Extract JavaScript URLs from content."""
    js_urls = set()
    
    # <script src="...">
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js)["\']', content, re.I):
        js_urls.add(m.group(1))
    
    # import/require
    for m in re.finditer(r'(?:import|require)\s*\(?["\']([^"\']+\.js)["\']', content):
        js_urls.add(m.group(1))
    
    # Plain .js URLs
    for m in re.finditer(r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', content, re.I):
        js_urls.add(m.group(0))
    
    # webpack chunks
    for m in re.finditer(r'["\']([^"\']+(?:chunk|bundle|vendor|app|main|runtime)[^"\']*\.js)["\']', content, re.I):
        js_urls.add(m.group(1))
    
    if base_url:
        resolved = set()
        for url in js_urls:
            if url.startswith('http'):
                resolved.add(url)
            elif url.startswith('//'):
                resolved.add('https:' + url)
            elif url.startswith('/'):
                parsed = urlparse(base_url)
                resolved.add(f'{parsed.scheme}://{parsed.netloc}{url}')
            else:
                resolved.add(urljoin(base_url, url))
        return resolved
    
    return js_urls

# ═══════════════════════════════════════════════════════════════════════════
# LIVE SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class LiveScanner:
    def __init__(self, severity='possible', show_raw=False, verbose=False,
                 json_output=False, filter_tags=None, threads=20, timeout=30,
                 max_depth=2, follow_js_urls=True, quiet=False):
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
        for rx, name, sev, tags, ent_min in PATTERNS:
            if sev_levels.get(sev, 3) > min_level:
                continue
            if self.filter_tags and not self.filter_tags.intersection(tags):
                continue
            try:
                compiled.append((re.compile(rx, re.IGNORECASE | re.MULTILINE), 
                               name, sev, tags, ent_min))
            except:
                pass
        return compiled
    
    def fetch_url(self, url: str) -> Tuple[str, str]:
        """Fetch URL, return (url, content) or (url, None)."""
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/javascript,*/*',
                'Accept-Encoding': 'identity',
            })
            
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                ct = resp.headers.get('Content-Type', '').lower()
                if 'text' in ct or 'javascript' in ct or 'json' in ct or 'html' in ct:
                    content = resp.read(10 * 1024 * 1024).decode('utf-8', errors='ignore')
                    return (url, content)
                else:
                    return (url, None)
        except:
            return (url, None)
    
    def scan_content(self, url: str, content: str) -> List[Dict]:
        """Scan content, return findings with matched lines ONLY."""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, name, sev, tags, ent_min in self.compiled:
                try:
                    matches = pattern.finditer(line)
                    for match in matches:
                        val = match.group(1) if match.lastindex else match.group(0)
                        val = val.strip()
                        
                        if is_fp(val):
                            continue
                        
                        if ent_min > 0 and entropy(val) < ent_min:
                            continue
                        
                        # Clean the line for display (trim whitespace, truncate if needed)
                        clean_line = line.strip()
                        if len(clean_line) > 120:
                            # Truncate but show the match context
                            match_start = max(0, match.start() - 30)
                            match_end = min(len(clean_line), match.end() + 30)
                            clean_line = '...' + clean_line[match_start:match_end] + '...'
                        
                        findings.append({
                            'url': url,
                            'line': line_num,
                            'pattern': name,
                            'severity': sev,
                            'tags': list(tags),
                            'value': val if self.show_raw else self._redact(val),
                            'matched_line': clean_line,
                            'entropy': round(entropy(val), 2)
                        })
                except:
                    pass
        
        return findings
    
    def _redact(self, val):
        if len(val) <= 6:
            return '*' * len(val)
        return val[:3] + '*' * (len(val) - 6) + val[-3:]
    
    def scan_url(self, url: str, depth: int = 0) -> Tuple[str, List[Dict], Set[str]]:
        """Scan URL, return (url, findings, new_js_urls)."""
        if url in self.scanned_urls:
            return (url, [], set())
        
        self.scanned_urls.add(url)
        
        url, content = self.fetch_url(url)
        
        if content is None:
            return (url, [], set())
        
        findings = self.scan_content(url, content)
        
        new_js_urls = set()
        if self.follow_js_urls and depth < self.max_depth:
            new_js_urls = extract_js_urls(content, url)
            new_js_urls = {u for u in new_js_urls if u not in self.scanned_urls}
        
        return (url, findings, new_js_urls)
    
    def scan_all(self, urls: List[str]):
        """Scan all URLs."""
        if not urls:
            print(f"{C.R}[✗] No URLs{C.RST}", file=sys.stderr)
            return
        
        self.start_time = time.time()
        
        if not self.json_output and not self.quiet:
            print(f"\n{C.BOLD}{C.C}╔══════════════════════════════════════════════╗{C.RST}")
            print(f"{C.BOLD}{C.C}║   ASTRA - Live JS Secret Hunter              ║{C.RST}")
            print(f"{C.BOLD}{C.C}║   {len(PATTERNS)} Patterns - {len(self.compiled)} Active             ║{C.RST}")
            print(f"{C.BOLD}{C.C}╚══════════════════════════════════════════════╝{C.RST}")
            print(f"{C.W}[*] Starting URLs: {len(urls)}{C.RST}")
            print(f"{C.W}[*] Threads: {self.threads} | Timeout: {self.timeout}s | Depth: {self.max_depth}{C.RST}")
            print(f"{C.W}[*] Severity: {self.severity.upper()}{C.RST}")
            print()
        
        all_findings = []
        urls_to_scan = list(urls)
        current_depth = 0
        
        while urls_to_scan and current_depth <= self.max_depth:
            if self.verbose:
                print(f"\n{C.BOLD}{C.C}[Depth {current_depth}] {len(urls_to_scan)} URLs{C.RST}")
            
            new_urls = set()
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_url, url, current_depth): url 
                          for url in urls_to_scan if url not in self.scanned_urls}
                
                for future in as_completed(futures):
                    try:
                        url, findings, extracted_urls = future.result()
                        
                        self.urls_scanned += 1
                        
                        if findings:
                            self.urls_with_secrets += 1
                            self.total_findings += len(findings)
                            all_findings.extend(findings)
                            
                            if not self.json_output:
                                self._show_findings(url, findings)
                        else:
                            if self.verbose and not self.json_output:
                                print(f"{C.G}  ✓ {url[:80]}{C.RST}")
                        
                        new_urls.update(extracted_urls)
                        
                    except Exception as e:
                        if self.verbose:
                            print(f"{C.R}[✗] {e}{C.RST}")
            
            urls_to_scan = list(new_urls - self.scanned_urls)
            current_depth += 1
        
        elapsed = time.time() - self.start_time
        
        if not self.json_output:
            self._print_summary(all_findings, elapsed)
        else:
            print(json.dumps({
                'summary': {
                    'urls_scanned': self.urls_scanned,
                    'urls_with_secrets': self.urls_with_secrets,
                    'total_findings': self.total_findings,
                    'time': round(elapsed, 2)
                },
                'findings': all_findings
            }, indent=2))
    
    def _show_findings(self, url, findings):
        """Show ONLY matched patterns, clean and simple."""
        sev_c = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
        
        # URL header
        print(f"\n{C.BOLD}{C.C}┌── {url}{C.RST}")
        
        for f in findings:
            c = sev_c.get(f['severity'], C.W)
            tags_str = f"{C.X}[{','.join(f['tags'])}]{C.RST}" if f['tags'] else ""
            
            # Format: [SEVERITY] Line XXX | Pattern Name
            print(f"{c}│ [{f['severity'].upper():10}] Line {f['line']:4} │ {f['pattern']}{C.RST} {tags_str}")
            
            # Show the matched line (truncated)
            print(f"{c}│ {'':13} {'':5} │ {C.X}{f['matched_line'][:100]}{C.RST}")
            
            # Show the secret value
            print(f"{c}│ {'':13} {'':5} │ {C.BOLD}Secret: {f['value']}{C.RST}")
            
            if f['entropy'] > 0:
                print(f"{c}│ {'':13} {'':5} │ Entropy: {f['entropy']}{C.RST}")
            
            print(f"{c}│{C.RST}")
        
        print(f"{C.BOLD}{C.C}└── {len(findings)} finding(s){C.RST}")
    
    def _print_summary(self, findings, elapsed):
        print(f"\n{C.BOLD}{C.M}╔══════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.M}║   SCAN COMPLETE                              ║{C.RST}")
        print(f"{C.BOLD}{C.M}╚══════════════════════════════════════════════╝{C.RST}")
        print(f"  URLs scanned:     {self.urls_scanned}")
        print(f"  With secrets:     {self.urls_with_secrets}")
        print(f"  Total findings:   {self.total_findings}")
        print(f"  Time:             {elapsed:.2f}s")
        
        if not findings:
            print(f"\n{C.G}  ✓ CLEAN - No secrets found{C.RST}")
        else:
            print(f"\n{C.R}  ⚠ FOUND {self.total_findings} SECRETS{C.RST}")
            
            sev_count = defaultdict(int)
            tag_count = defaultdict(int)
            for f in findings:
                sev_count[f['severity']] += 1
                for t in f.get('tags', []):
                    tag_count[t] += 1
            
            colors = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
            for s in ['confirmed', 'probable', 'possible', 'info']:
                if sev_count[s]:
                    print(f"  {colors[s]}[{s.upper():10}] {sev_count[s]}{C.RST}")
            
            if tag_count:
                print(f"\n  {C.BOLD}Top Categories:{C.RST}")
                for tag, count in sorted(tag_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  {C.X}[{tag:20}] {count}{C.RST}")
        
        print(f"\n{C.BOLD}{C.M}{'═' * 50}{C.RST}\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='astra - Live JS Secret Hunter - Clean Output',
        epilog="""
EXAMPLES:
  python astra.py -u https://example.com/app.js
  python astra.py -u https://example.com/app.js https://cdn.example.com/bundle.js
  python astra.py -f urls.txt
  cat urls.txt | python astra.py
  python astra.py -u https://example.com/ -d 2 --verbose
  python astra.py -f urls.txt -r --tags aws,stripe
        """
    )
    
    parser.add_argument('-u', '--urls', nargs='*', help='URLs to scan')
    parser.add_argument('-f', '--file', help='File with URLs (one per line)')
    parser.add_argument('-s', '--severity', default='possible',
                       choices=['confirmed','probable','possible','info'])
    parser.add_argument('-r', '--show-raw', action='store_true', help='Show raw secrets')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all URLs being scanned')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only show findings, no header')
    parser.add_argument('-j', '--json', action='store_true', help='JSON output')
    parser.add_argument('--tags', help='Filter by tags (comma-separated)')
    parser.add_argument('-t', '--threads', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('-d', '--depth', type=int, default=1)
    parser.add_argument('--no-follow', action='store_true', help='Don\'t follow JS URLs')
    parser.add_argument('-l', '--list', action='store_true', help='List patterns')
    
    args = parser.parse_args()
    
    if args.list:
        print(f"\n{C.BOLD}Patterns: {len(PATTERNS)}{C.RST}\n")
        for i, (rx, name, sev, tags, ent) in enumerate(sorted(PATTERNS, key=lambda x: (x[2], x[1])), 1):
            print(f'{i:3}. {name:<40} [{sev:<10}] {",".join(tags)}')
        print()
        sys.exit(0)
    
    urls = []
    if args.urls:
        urls.extend(args.urls)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and (line.startswith('http') or line.endswith('.js')):
                        urls.append(line)
        except Exception as e:
            print(f"{C.R}[✗] File error: {e}{C.RST}", file=sys.stderr)
            sys.exit(1)
    if not sys.stdin.isatty() and not urls:
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#') and (line.startswith('http') or line.endswith('.js')):
                urls.append(line)
    
    if not urls:
        print(f"{C.R}[✗] No URLs. Use -u, -f, or stdin{C.RST}", file=sys.stderr)
        sys.exit(1)
    
    scanner = LiveScanner(
        severity=args.severity,
        show_raw=args.show_raw,
        verbose=args.verbose,
        json_output=args.json,
        filter_tags=args.tags,
        threads=args.threads,
        timeout=args.timeout,
        max_depth=args.depth,
        follow_js_urls=not args.no_follow,
        quiet=args.quiet
    )
    
    scanner.scan_all(urls)
    sys.exit(1 if scanner.total_findings > 0 else 0)

if __name__ == '__main__':
    main()
