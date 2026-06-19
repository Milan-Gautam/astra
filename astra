#!/usr/bin/env python3
"""
astra — Live JS Secret Detection Engine v1.5
=============================================
310+ unique patterns · Line‑by‑line scanning
Accurate HTTP status codes · Rate limiting
Smart false‑positive filter (context‑aware)
"""

import sys, re, json, argparse, math, time
import urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Optional
import threading

# ── Colors ───────────────────────────────────────────────────────────────
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; X = '\033[90m'
    BOLD = '\033[1m'; DIM = '\033[2m'; RST = '\033[0m'

BANNER = f"""{C.BOLD}{C.C}
     _    ____ _____ ____      _
    / \\  / ___|_   _|  _ \\    / \\
   / _ \\ \\___ \\ | | | |_) |  / _ \\
  / ___ \\ ___) || | |  _ <  / ___ \\
 /_/   \\_\\____/ |_| |_| \\_\\/_/   \_\\
{C.RST}{C.X}  secret & credential scanner v1.5{C.RST}"""

def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in freq.values())

# ── Context‑aware false‑positive filter ─────────────────────────────────
SECRET_KEYS = {
    'password','passwd','pwd','secret','key','token','auth',
    'api_key','apikey','api_secret','apisecret','access_key','accesskey',
    'access_token','accesstoken','private_key','privatekey',
    'client_secret','clientsecret','secret_key','secretkey',
    'encryption_key','encryptionkey','jwt_secret','jwtsecret',
    'session_secret','sessionsecret','cookie_secret','cookiesecret',
    'refresh_token','refreshtoken','id_token','idtoken',
    'auth_token','authtoken','bearer_token','bearertoken',
    'db_password','dbpassword','smtp_password','ftp_password',
    'admin_password','root_password','master_key','masterkey',
    'app_secret','appsecret','app_key','appkey',
    'webhook_secret','signing_secret','connection_string','dsn','uri',
    'credential','credentials','license_key','subscription_key',
    'authorization','x-api-key',
}

def has_context(line: str) -> bool:
    ll = line.lower()
    return any(k in ll for k in SECRET_KEYS)

def is_false_positive(val: str, line: str, pattern_name: str) -> bool:
    v = val.strip(); vl = v.lower()
    # Always reject known junk
    if vl in {'null','undefined','true','false','none','example','test','sample',
              'dummy','placeholder','your_key','your_token','insert_here','changeme',
              'todo','fixme','redacted','n/a','na','empty','function','object',
              'string','number','boolean','return','export','import','require',
              'module','window','document','console','error','callback','loading',
              'done','errors','retries','version','language','region','libraries',
              'client','channel','options','instance','status','core','default',
              'config','settings','env','environment','development','production',
              'staging','localhost','127.0.0.1','0.0.0.0'}:
        return True
    if len(v) < 4 or len(v) > 500: return True
    if len(set(vl)) < 4: return True
    if v.count(v[0]) > len(v)*0.6: return True
    if re.match(r'^[a-f0-9]{32,128}$', vl): return True  # hash
    # For generic patterns, require a secret keyword in the line
    pn = pattern_name.lower()
    is_generic = any(w in pn for w in ('password','passwd','pwd','secret','token','key'))
    if is_generic and line and not has_context(line):
        return True
    # For all patterns, skip minified junk
    code_chars = sum(1 for c in v if c in '.,;:{}[]()=+<>!&|')
    if len(v) > 50 and code_chars > len(v)*0.15: return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
# 310+ UNIQUE PATTERNS – COMPLETE, NO REDUCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def build_patterns():
    P = []
    def add(rx, name, sev, tags, ent=0.0):
        P.append((rx, name, sev, tags, ent))

    # ── AWS (18) ─────────────────────────────────────────────────────────
    add(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key ID', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Temporary Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', ['aws'], 3.0)
    add(r'(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[=:]\s*[\'"`]([A-Za-z0-9\/+=]{40})[\'"`]', 'AWS Secret Access Key', 'confirmed', ['aws'], 4.5)
    add(r'(?i)(?:aws_session_token|aws_session)\s*[=:]\s*[\'"`]([A-Za-z0-9\/+=]{100,})[\'"`]', 'AWS Session Token', 'confirmed', ['aws'], 4.0)
    add(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Auth Token', 'confirmed', ['aws'])
    add(r'(FWO[A-Za-z0-9\/+=]{40,})', 'AWS STS FWO Token', 'confirmed', ['aws'], 4.0)
    add(r'(A3T[A-Z0-9]{16,})', 'AWS Session Token A3T', 'confirmed', ['aws'])
    add(r'arn:aws:[a-z]+:[a-z0-9\-]*:[0-9]{12}:.+', 'AWS ARN Resource', 'info', ['aws','recon'])
    add(r'([a-z0-9][a-z0-9\-]*\.s3\.amazonaws\.com)', 'AWS S3 Bucket URL', 'info', ['aws','recon'])
    add(r'([a-z0-9][a-z0-9\-]*\.s3-website[\.-][a-z0-9\-]+\.amazonaws\.com)', 'AWS S3 Website URL', 'info', ['aws','recon'])
    add(r'([a-z0-9\-]+\.cloudfront\.net)', 'AWS CloudFront URL', 'info', ['aws','cdn'])
    add(r'([a-z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com)', 'AWS API Gateway URL', 'info', ['aws','api'])
    add(r'([a-z0-9\-]+\.elb\.amazonaws\.com)', 'AWS ELB URL', 'info', ['aws','infra'])
    add(r'([a-z0-9\-]+\.rds\.amazonaws\.com)', 'AWS RDS URL', 'info', ['aws','database'])
    add(r'([a-z0-9\-]+\.elasticache\.amazonaws\.com)', 'AWS ElastiCache URL', 'info', ['aws','database'])
    add(r'([a-z0-9\-]+\.redshift\.amazonaws\.com)', 'AWS Redshift URL', 'info', ['aws','database'])

        # ── Google Cloud (14) ────────────────────────────────────────────────
    add(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', ['google','api'], 3.5)
    add(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth 2.0 Token', 'confirmed', ['google','auth'])
    add(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Client Secret', 'confirmed', ['google','auth'])
    add(r'(6L[0-9A-Za-z\-_]{38})', 'Google reCAPTCHA Site Key', 'probable', ['google'])
    add(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'Firebase Cloud Messaging Key', 'confirmed', ['google','firebase'])
    add(r'[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com', 'Google OAuth 2.0 Client ID', 'probable', ['google','auth'])
    add(r'(?i)gcp[_-]?project[_-]?id\s*[=:]\s*[\'"`]([a-z0-9\-]{6,30})[\'"`]', 'GCP Project ID', 'confirmed', ['google','gcp'])
    add(r'(?i)firebase[_-]?project[_-]?id\s*[=:]\s*[\'"`]([a-z0-9\-]{6,30})[\'"`]', 'Firebase Project ID', 'confirmed', ['google','firebase'])
    add(r'(?i)bigquery[_-]?dataset\s*[=:]\s*[\'"`]([a-zA-Z0-9_]+)[\'"`]', 'BigQuery Dataset ID', 'info', ['google','gcp'])
    add(r'(?i)pubsub[_-]?topic\s*[=:]\s*[\'"`](projects\/[^\/]+\/topics\/[a-zA-Z0-9\-_]+)[\'"`]', 'Pub/Sub Topic Path', 'info', ['google','gcp'])
    add(r'storage\.googleapis\.com\/([a-z0-9\-_]+)', 'GCS Bucket Name', 'info', ['google','gcp','storage'])
    add(r'firebasestorage\.googleapis\.com\/([a-z0-9\-_]+)', 'Firebase Storage Bucket', 'info', ['google','firebase'])
    add(r'(?i)cloud[_-]?run[_-]?service\s*[=:]\s*[\'"`]([a-z0-9\-]+)[\'"`]', 'Cloud Run Service Name', 'info', ['google','gcp'])
    add(r'(?i)spanner[_-]?instance\s*[=:]\s*[\'"`]([a-z0-9\-]+)[\'"`]', 'Spanner Instance ID', 'info', ['google','gcp'])

    # ── Azure (14) ───────────────────────────────────────────────────────
    add(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88})', 'Azure Storage Connection String', 'confirmed', ['azure'])
    add(r'(Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/[^;"\'\s]*)', 'Azure Service Bus Connection', 'confirmed', ['azure'])
    add(r'(sig=[A-Za-z0-9%+\/]{20,}&se=[0-9T:Z%\-]+&sp=[a-z]+)', 'Azure Blob SAS Token', 'confirmed', ['azure'])
    add(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps Personal Access Token', 'confirmed', ['azure','ci_cd'], 4.0)
    add(r'(?i)azure[_-]?client[_-]?id\s*[=:]\s*[\'"`]([a-f0-9\-]{36})[\'"`]', 'Azure Client ID', 'probable', ['azure'])
    add(r'(?i)azure[_-]?tenant[_-]?id\s*[=:]\s*[\'"`]([a-f0-9\-]{36})[\'"`]', 'Azure Tenant ID', 'probable', ['azure'])
    add(r'(?i)azure[_-]?client[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9\-_\.~]{32,})[\'"`]', 'Azure Client Secret', 'confirmed', ['azure'])
    add(r'(?i)azure[_-]?keyvault[_-]?url\s*[=:]\s*[\'"`](https:\/\/[^"\']+\.vault\.azure\.net\/)[\'"`]', 'Azure Key Vault URL', 'confirmed', ['azure'])
    add(r'(?i)cosmos[_-]?db[_-]?endpoint\s*[=:]\s*[\'"`](https:\/\/[^"\']+\.documents\.azure\.com)[\'"`]', 'Cosmos DB Endpoint', 'info', ['azure','database'])
    add(r'(?i)azure[_-]?function[_-]?app\s*[=:]\s*[\'"`]([a-z0-9\-]{3,32})[\'"`]', 'Azure Function App Name', 'info', ['azure'])
    add(r'[a-z0-9\-_]+\.blob\.core\.windows\.net', 'Azure Blob Storage URL', 'info', ['azure','storage'])
    add(r'[a-z0-9\-_]+\.mysql\.database\.azure\.com', 'Azure MySQL Server', 'info', ['azure','database'])
    add(r'[a-z0-9\-_]+\.postgres\.database\.azure\.com', 'Azure PostgreSQL Server', 'info', ['azure','database'])
    add(r'[a-z0-9\-_]+\.redis\.cache\.windows\.net', 'Azure Redis Cache', 'info', ['azure','database'])

    # ── Other Cloud Providers (14) ───────────────────────────────────────
    add(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean Personal Access Token', 'confirmed', ['cloud','digitalocean'], 4.0)
    add(r'DO00[A-Za-z0-9]{32,}', 'DigitalOcean Spaces Access Key', 'confirmed', ['cloud','digitalocean'], 3.5)
    add(r'rnd_[A-Za-z0-9]{32}', 'Render API Key', 'confirmed', ['cloud','render'], 3.5)
    add(r'SCW[A-Z0-9]{20,}', 'Scaleway API Key', 'confirmed', ['cloud','scaleway'], 3.5)
    add(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Cloud AccessKey ID', 'confirmed', ['cloud','alibaba'], 3.0)
    add(r'(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[\'"`]([0-9a-f\-]{36})[\'"`]', 'Heroku API Key', 'confirmed', ['cloud','heroku'])
    add(r'(?i)cloudflare[_-]?api[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{37,40})[\'"`]', 'Cloudflare API Token', 'confirmed', ['cloud','cloudflare'], 3.5)
    add(r'(?i)cloudflare[_-]?global[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{37})[\'"`]', 'Cloudflare Global API Key', 'confirmed', ['cloud','cloudflare'])
    add(r'(?i)netlify[_-]?access[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{40,})[\'"`]', 'Netlify Access Token', 'confirmed', ['cloud','netlify'], 3.5)
    add(r'(?i)vercel[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{24})[\'"`]', 'Vercel Token', 'probable', ['cloud','vercel'])
    add(r'(?i)linode[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{64})[\'"`]', 'Linode API Token', 'confirmed', ['cloud','linode'])
    add(r'(?i)vultr[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{64})[\'"`]', 'Vultr API Key', 'confirmed', ['cloud','vultr'])
    add(r'(?i)fastly[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{32,})[\'"`]', 'Fastly API Key', 'confirmed', ['cloud','fastly'])
    add(r'(?i)ibmcloud[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{44})[\'"`]', 'IBM Cloud API Key', 'confirmed', ['cloud','ibm'], 4.0)

    # ── Payment Processors (22) ──────────────────────────────────────────
    add(r'(sk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Secret Key', 'confirmed', ['payment','stripe'])
    add(r'(rk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Restricted Key', 'confirmed', ['payment','stripe'])
    add(r'(sk_test_[0-9a-zA-Z]{24,99})', 'Stripe Test Secret Key', 'possible', ['payment','stripe'])
    add(r'(whsec_[0-9a-zA-Z]{32,})', 'Stripe Webhook Signing Secret', 'confirmed', ['payment','stripe'], 3.5)
    add(r'(?i)stripe[_-]?account[_-]?id\s*[=:]\s*[\'"`](acct_[A-Za-z0-9]{16,})[\'"`]', 'Stripe Account ID', 'probable', ['payment','stripe'])
    add(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'PayPal Braintree Production Token', 'confirmed', ['payment','paypal'])
    add(r'(?i)paypal[_-]?client[_-]?id\s*[=:]\s*[\'"`](A[A-Za-z0-9\-_]{30,})[\'"`]', 'PayPal Client ID', 'confirmed', ['payment','paypal'])
    add(r'(?i)paypal[_-]?secret\s*[=:]\s*[\'"`](E[A-Za-z0-9\-_]{30,})[\'"`]', 'PayPal Secret Key', 'confirmed', ['payment','paypal'])
    add(r'(?i)paypal[_-]?webhook[_-]?id\s*[=:]\s*[\'"`](WH-[A-Za-z0-9]{32,})[\'"`]', 'PayPal Webhook ID', 'probable', ['payment','paypal'])
    add(r'(sq0csp-[A-Za-z0-9_\-]{43})', 'Square OAuth Client Secret', 'confirmed', ['payment','square'])
    add(r'(EAAA[A-Za-z0-9\-_]{22,})', 'Square Access Token', 'confirmed', ['payment','square'], 3.5)
    add(r'(sq0atp-[A-Za-z0-9\-_]{22,})', 'Square OAuth Access Token', 'confirmed', ['payment','square'], 3.5)
    add(r'(rzp_live_[A-Za-z0-9]{14,})', 'Razorpay Live API Key', 'confirmed', ['payment','razorpay'], 3.5)
    add(r'(rzp_test_[A-Za-z0-9]{14,})', 'Razorpay Test API Key', 'possible', ['payment','razorpay'], 3.5)
    add(r'(sk_live_[A-Za-z0-9]{40})', 'Paystack Live Secret Key', 'confirmed', ['payment','paystack'], 4.0)
    add(r'(ck_[a-f0-9]{40})', 'WooCommerce Consumer Key', 'confirmed', ['payment','woocommerce'], 3.5)
    add(r'(cs_[a-f0-9]{40})', 'WooCommerce Consumer Secret', 'confirmed', ['payment','woocommerce'], 3.5)
    add(r'(AQ[A-Za-z0-9_\-]{30,})', 'Adyen API Key', 'confirmed', ['payment','adyen'], 3.5)
    add(r'(FLWSECK-[a-zA-Z0-9]{32})', 'Flutterwave Secret Key', 'confirmed', ['payment','flutterwave'], 3.5)
    add(r'(?i)mollie[_-]?api[_-]?key\s*[=:]\s*[\'"`](live_[a-f0-9]{30,})[\'"`]', 'Mollie API Key', 'confirmed', ['payment','mollie'])
    add(r'(?i)revolut[_-]?api[_-]?key\s*[=:]\s*[\'"`](key_[a-f0-9]{32,})[\'"`]', 'Revolut API Key', 'confirmed', ['payment','revolut'])
    add(r'(?i)checkout[_-]?secret\s*[=:]\s*[\'"`](sk_[a-f0-9]{32,})[\'"`]', 'Checkout.com Secret Key', 'confirmed', ['payment','checkout'])

    # ── GitHub & GitLab & CI/CD (20) ─────────────────────────────────────
    add(r'(ghp_[A-Za-z0-9]{36})', 'GitHub Personal Access Token', 'confirmed', ['github','ci_cd'])
    add(r'(ghs_[A-Za-z0-9]{36})', 'GitHub Actions Token', 'confirmed', ['github','ci_cd'])
    add(r'(github_pat_[A-Za-z0-9_]{82})', 'GitHub Fine-grained PAT', 'confirmed', ['github','ci_cd'], 4.0)
    add(r'(gho_[A-Za-z0-9]{36})', 'GitHub OAuth Access Token', 'confirmed', ['github'])
    add(r'(ghu_[A-Za-z0-9]{36})', 'GitHub User-to-Server Token', 'confirmed', ['github'])
    add(r'(ghr_[A-Za-z0-9]{36})', 'GitHub Refresh Token', 'confirmed', ['github'])
    add(r'(?i)github[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{40})[\'"`]', 'GitHub Token Generic', 'confirmed', ['github'])
    add(r'(?i)github[_-]?app[_-]?id\s*[=:]\s*[\'"`]([0-9]+)[\'"`]', 'GitHub App ID', 'info', ['github'])
    add(r'(?i)github[_-]?installation[_-]?id\s*[=:]\s*[\'"`]([0-9]+)[\'"`]', 'GitHub Installation ID', 'info', ['github'])
    add(r'(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab Personal Access Token', 'confirmed', ['gitlab','ci_cd'])
    add(r'(gldt-[A-Za-z0-9_\-]{20,})', 'GitLab Deploy Token', 'confirmed', ['gitlab'])
    add(r'(glcbt-[A-Za-z0-9_\-]{20,})', 'GitLab CI/CD Job Token', 'confirmed', ['gitlab'])
    add(r'(glptt-[A-Za-z0-9_\-]{20,})', 'GitLab Project Access Token', 'confirmed', ['gitlab'])
    add(r'(glrt-[A-Za-z0-9_\-]{20,})', 'GitLab Runner Auth Token', 'confirmed', ['gitlab'])
    add(r'(glso-[A-Za-z0-9_\-]{20,})', 'GitLab Service Account Token', 'confirmed', ['gitlab'])
    add(r'(?i)gitlab[_-]?ci[_-]?job[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{20,})[\'"`]', 'GitLab CI Job Token Env', 'confirmed', ['gitlab'])
    add(r'(?i)gitlab[_-]?runner[_-]?token\s*[=:]\s*[\'"`](glrt-[A-Za-z0-9\-_]{20,})[\'"`]', 'GitLab Runner Token Env', 'confirmed', ['gitlab'])
    add(r'circleci-[a-f0-9]{40}', 'CircleCI API Token', 'confirmed', ['ci_cd','circleci'])
    add(r'bkua_[a-zA-Z0-9]{40}', 'Buildkite Agent Token', 'confirmed', ['ci_cd','buildkite'], 4.0)
    add(r'pul-[a-zA-Z0-9]{40}', 'Pulumi Access Token', 'confirmed', ['ci_cd','pulumi'], 4.0)

    # ── OpenAI & AI Services (20) ────────────────────────────────────────
    add(r'(sk-[A-Za-z0-9]{48})', 'OpenAI API Key Classic', 'confirmed', ['ai','openai'], 4.0)
    add(r'(sk-proj-[A-Za-z0-9_\-]{40,})', 'OpenAI Project API Key', 'confirmed', ['ai','openai'], 4.0)
    add(r'(org-[A-Za-z0-9_\-]{20,})', 'OpenAI Organization ID', 'info', ['ai','openai'])
    add(r'(sk-ant-api\d+-[A-Za-z0-9_\-]{40,})', 'Anthropic Claude API Key', 'confirmed', ['ai','anthropic'])
    add(r'(hf_[a-zA-Z0-9]{34,})', 'HuggingFace API Token', 'confirmed', ['ai','huggingface'])
    add(r'(gsk_[A-Za-z0-9]{52})', 'Groq API Key', 'confirmed', ['ai','groq'], 4.0)
    add(r'(pplx-[A-Za-z0-9]{48})', 'Perplexity AI API Key', 'confirmed', ['ai','perplexity'], 4.0)
    add(r'(sk-or-v1-[A-Za-z0-9]{48})', 'OpenRouter API Key', 'confirmed', ['ai','openrouter'], 4.0)
    add(r'(r8_[A-Za-z0-9]{40})', 'Replicate API Token', 'confirmed', ['ai','replicate'])
    add(r'(tvly-[A-Za-z0-9]{32})', 'Tavily AI Search API Key', 'confirmed', ['ai','tavily'], 4.0)
    add(r'(fw_[A-Za-z0-9]{32,})', 'Fireworks AI API Key', 'confirmed', ['ai','fireworks'], 4.0)
    add(r'(esecret_[A-Za-z0-9_\-]{40,})', 'Anyscale API Key', 'confirmed', ['ai','anyscale'], 4.0)
    add(r'(?i)cohere[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Cohere API Key', 'confirmed', ['ai','cohere'], 3.5)
    add(r'(?i)mistral[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Mistral AI API Key', 'confirmed', ['ai','mistral'], 3.5)
    add(r'(?i)deepgram[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Deepgram API Key', 'confirmed', ['ai','deepgram'])
    add(r'(?i)stability[_-]?ai[_-]?key\s*[=:]\s*[\'"`](sk-[A-Za-z0-9]{30,})[\'"`]', 'Stability AI API Key', 'confirmed', ['ai','stability'])
    add(r'(?i)elevenlabs[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'ElevenLabs API Key', 'confirmed', ['ai','elevenlabs'])
    add(r'(?i)assemblyai[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32})[\'"`]', 'AssemblyAI API Key', 'confirmed', ['ai','assemblyai'])
    add(r'(?i)runwayml[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32,})[\'"`]', 'RunwayML API Key', 'confirmed', ['ai','runwayml'])
    add(r'(?i)together[_-]?ai[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{30,})[\'"`]', 'Together AI Key', 'confirmed', ['ai','together'])

    # ── Generic Secrets with KEY=VALUE (14) ──────────────────────────────
    add(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"`]?([^\'"`\s]{4,})[\'"`]?', 'Hardcoded Password', 'confirmed', ['generic','password'], 2.0)
    add(r'(?i)(?:secret|secret_key|secretkey)\s*[=:]\s*[\'"`]?([^\'"`\s]{6,})[\'"`]?', 'Hardcoded Secret', 'confirmed', ['generic','secret'], 2.5)
    add(r'(?i)(?:api_key|apikey)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{12,})[\'"`]?', 'Generic API Key', 'confirmed', ['generic','api-key'], 3.0)
    add(r'(?i)(?:api_secret|apisecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.~!@#]{12,})[\'"`]?', 'Generic API Secret', 'probable', ['generic','secret'], 3.5)
    add(r'(?i)(?:access_token|accesstoken)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{16,})[\'"`]?', 'Access Token', 'confirmed', ['generic','token'], 3.0)
    add(r'(?i)(?:auth_token|authtoken)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{16,})[\'"`]?', 'Authentication Token', 'probable', ['generic','token'], 3.0)
    add(r'(?i)(?:client_secret|clientsecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.~]{20,})[\'"`]?', 'OAuth Client Secret', 'confirmed', ['generic','oauth'], 3.0)
    add(r'(?i)(?:client_id|clientid)\s*[=:]\s*[\'"`]?([A-Za-z0-9]{16,})[\'"`]?', 'OAuth Client ID', 'probable', ['generic','oauth'])
    add(r'(?i)(?:private_key|privatekey)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-+\/=]{40,})[\'"`]?', 'Private Key Value', 'confirmed', ['generic','crypto'], 4.0)
    add(r'(?i)(?:refresh_token|refreshtoken)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{16,})[\'"`]?', 'Refresh Token', 'confirmed', ['generic','token'])
    add(r'(?i)(?:encryption_key|encryptionkey)\s*[=:]\s*[\'"`]?([A-Za-z0-9+\/=]{32,})[\'"`]?', 'Encryption Key', 'confirmed', ['generic','crypto'], 3.5)
    add(r'(?i)(?:session_secret|sessionsecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]?', 'Session Secret', 'probable', ['generic','session'], 3.0)
    add(r'(?i)(?:jwt_secret|jwtsecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]?', 'JWT Signing Secret', 'confirmed', ['generic','jwt'], 3.5)
    add(r'(?i)(?:master_key|masterkey)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]?', 'Master Key', 'confirmed', ['generic','crypto'], 3.5)

    # ── Database DSNs (18) ───────────────────────────────────────────────
    add(r'mongodb\+srv:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MongoDB Atlas Connection String', 'confirmed', ['database','mongodb'], 2.5)
    add(r'mongodb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MongoDB Connection String', 'confirmed', ['database','mongodb'], 2.5)
    add(r'postgresql:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'PostgreSQL Connection String', 'confirmed', ['database','postgresql'], 2.5)
    add(r'postgres:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'PostgreSQL DSN Short', 'confirmed', ['database','postgresql'], 2.5)
    add(r'mysql:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MySQL Connection String', 'confirmed', ['database','mysql'], 2.5)
    add(r'mariadb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MariaDB Connection String', 'confirmed', ['database','mariadb'], 2.5)
    add(r'redis:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Redis Connection String', 'confirmed', ['database','redis'], 2.5)
    add(r'rediss:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Redis TLS Connection String', 'confirmed', ['database','redis'], 2.5)
    add(r'clickhouse:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'ClickHouse Connection String', 'confirmed', ['database','clickhouse'], 2.5)
    add(r'cassandra:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Cassandra Connection String', 'confirmed', ['database','cassandra'], 2.5)
    add(r'cockroachdb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'CockroachDB Connection String', 'confirmed', ['database','cockroachdb'], 2.5)
    add(r'jdbc:[a-zA-Z]+:\/\/[^\s"\'`<>]+', 'JDBC Connection String', 'confirmed', ['database','jdbc'], 2.5)
    add(r'sqlite:\/\/\/[^\s]+', 'SQLite File Path', 'info', ['database','sqlite'])
    add(r'(?i)(?:database_url|db_url|db_uri)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]', 'Database URL Generic', 'confirmed', ['database'])
    add(r'(?i)(?:redis_password|redis_pass)\s*[=:]\s*[\'"`]([A-Za-z0-9]{8,})[\'"`]', 'Redis Password', 'confirmed', ['database','redis'])
    add(r'mongodb\.net\/[a-zA-Z0-9\-_]+', 'MongoDB Atlas Cluster URL', 'info', ['database','mongodb'])
    add(r'rediss:\/\/default:[^@]+@[^\s]+\.upstash\.io:\d+', 'Upstash Redis URL', 'confirmed', ['database','upstash'], 3.0)
    add(r'postgresql:\/\/[^:]+:[^@]+@[^\s]+\.neon\.tech', 'Neon Serverless Postgres DSN', 'confirmed', ['database','neon'], 2.5)

    # ── Messaging & Communication (16) ───────────────────────────────────
    add(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})', 'Slack Bot/User Token', 'confirmed', ['messaging','slack'])
    add(r'https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+', 'Slack Incoming Webhook URL', 'confirmed', ['messaging','slack'])
    add(r'(M[A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})', 'Discord Bot Token', 'confirmed', ['messaging','discord'], 4.0)
    add(r'https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+', 'Discord Webhook URL', 'confirmed', ['messaging','discord'])
    add(r'(?i)twilio[_-]?account[_-]?sid\s*[=:]\s*[\'"`](AC[a-f0-9]{32})[\'"`]', 'Twilio Account SID', 'confirmed', ['messaging','twilio'])
    add(r'(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Twilio Auth Token', 'confirmed', ['messaging','twilio'])
    add(r'(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})', 'SendGrid API Key', 'confirmed', ['messaging','sendgrid'])
    add(r'(key-[0-9a-zA-Z]{32})', 'Mailgun API Key', 'confirmed', ['messaging','mailgun'])
    add(r'(\d{8,10}:[A-Za-z0-9_\-]{35})', 'Telegram Bot Token', 'probable', ['messaging','telegram'], 3.5)
    add(r'(?i)zendesk[_-]?api[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Zendesk API Token', 'confirmed', ['messaging','zendesk'])
    add(r'(?i)intercom[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{60,})[\'"`]', 'Intercom Access Token', 'confirmed', ['messaging','intercom'])
    add(r'(?i)pagerduty[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{20,})[\'"`]', 'PagerDuty API Key', 'confirmed', ['messaging','pagerduty'])
    add(r'(?i)opsgenie[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32,})[\'"`]', 'Opsgenie API Key', 'confirmed', ['messaging','opsgenie'])
    add(r'(?i)pushover[_-]?user[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{30})[\'"`]', 'Pushover User Key', 'probable', ['messaging','pushover'])
    add(r'(?i)vonage[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{8,20})[\'"`]', 'Vonage/Nexmo API Key', 'probable', ['messaging','vonage'])
    add(r'(?i)rocket[_-]?chat[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'RocketChat Token', 'probable', ['messaging','rocketchat'])

    # ── Crypto & Private Keys (16) ───────────────────────────────────────
    add(r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key Header', 'confirmed', ['crypto','private-key'])
    add(r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key Header', 'confirmed', ['crypto','private-key'])
    add(r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key Header', 'confirmed', ['crypto','private-key'])
    add(r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key Header', 'confirmed', ['crypto','ssh'])
    add(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key Block', 'confirmed', ['crypto','pgp'])
    add(r'-----BEGIN PRIVATE KEY-----', 'PKCS8 Private Key Header', 'confirmed', ['crypto','private-key'])
    add(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Encrypted Private Key Header', 'confirmed', ['crypto','private-key'])
    add(r'(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})', 'JSON Web Token (JWT)', 'probable', ['crypto','jwt'], 4.0)
    add(r'(?i)ssh[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\+\/=]{40,})[\'"`]', 'SSH Key Value', 'confirmed', ['crypto','ssh'], 4.0)
    add(r'(?i)ssl[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9\/+=]{40,})[\'"`]', 'SSL/TLS Private Key', 'confirmed', ['crypto','ssl'], 4.0)
    add(r'(?i)ssh-rsa\s+AAAAB3NzaC1yc2[0-9A-Za-z\/+=]+', 'SSH RSA Public Key', 'info', ['crypto','ssh'])
    add(r'-----BEGIN CERTIFICATE-----', 'X.509 Certificate Header', 'info', ['crypto','certificate'])
    add(r'-----BEGIN PUBLIC KEY-----', 'Public Key Header', 'info', ['crypto','public-key'])
    add(r'(?i)(?:bearer|token)\s+([A-Za-z0-9\-\._~\+\/]{30,}=*)', 'Bearer Authorization Token', 'probable', ['crypto','token'], 3.5)
    add(r'(?i)Basic\s+([A-Za-z0-9\+\/=]{20,})', 'HTTP Basic Auth Value', 'probable', ['crypto','auth'], 3.0)
    add(r'(?i)x-api-key\s*[=:]\s*[\'"`]([A-Za-z0-9]{20,})[\'"`]', 'X-API-Key Header Value', 'confirmed', ['crypto','api-key'])

    # ── Social Media (10) ────────────────────────────────────────────────
    add(r'AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+\/]{40,}', 'Twitter/X Bearer Token', 'confirmed', ['social','twitter'], 4.0)
    add(r'EAACEdEose0cBA[0-9A-Za-z]+', 'Facebook Access Token', 'confirmed', ['social','facebook'])
    add(r'oauth:[a-z0-9]{30,}', 'Twitch OAuth Token', 'confirmed', ['social','twitch'], 3.5)
    add(r'(?i)twitch[_-]?client[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9]{30})[\'"`]', 'Twitch Client Secret', 'confirmed', ['social','twitch'], 3.5)
    add(r'(?i)linkedin[_-]?client[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9]{16})[\'"`]', 'LinkedIn Client Secret', 'confirmed', ['social','linkedin'], 3.0)
    add(r'(?i)instagram[_-]?access[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.]{40,})[\'"`]', 'Instagram Access Token', 'probable', ['social','instagram'], 3.5)
    add(r'(?i)reddit[_-]?client[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9]{16})[\'"`]', 'Reddit Client Secret', 'probable', ['social','reddit'])
    add(r'(?i)tiktok[_-]?access[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'TikTok Access Token', 'probable', ['social','tiktok'])
    add(r'(?i)pinterest[_-]?access[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Pinterest Access Token', 'probable', ['social','pinterest'])
    add(r'(?i)snapchat[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Snapchat API Key', 'probable', ['social','snapchat'])

    # ── SaaS Platforms (20) ──────────────────────────────────────────────
    add(r'CFPAT-[A-Za-z0-9_\-]{40,}', 'Contentful Personal Access Token', 'confirmed', ['saas','contentful'], 4.0)
    add(r'secret_[A-Za-z0-9]{40,}', 'Notion Integration Token', 'confirmed', ['saas','notion'], 3.5)
    add(r'ntn_[A-Za-z0-9]{48,}', 'Notion New API Token', 'confirmed', ['saas','notion'], 4.0)
    add(r'figd_[A-Za-z0-9_\-]{40,}', 'Figma Personal Access Token', 'confirmed', ['saas','figma'], 4.0)
    add(r'dapi[a-f0-9]{32}', 'Databricks API Token', 'confirmed', ['saas','databricks'], 3.5)
    add(r'hvs\.[A-Za-z0-9_\-+\/=]{50,}', 'HashiCorp Vault Service Token', 'confirmed', ['saas','vault'], 4.0)
    add(r'hvb\.[A-Za-z0-9_\-]{40,}', 'HashiCorp Vault Batch Token', 'confirmed', ['saas','vault'], 4.0)
    add(r'shpat_[a-fA-F0-9]{32}', 'Shopify Admin API Token', 'confirmed', ['saas','shopify'])
    add(r'shpca_[a-fA-F0-9]{32}', 'Shopify Custom App Token', 'confirmed', ['saas','shopify'])
    add(r'cloudinary:\/\/\d+:[A-Za-z0-9_\-]+@', 'Cloudinary URL with Credentials', 'confirmed', ['saas','cloudinary'])
    add(r'(?:pk|sk)\.eyJ1[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', 'Mapbox Access Token', 'confirmed', ['saas','mapbox'])
    add(r'waka_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}', 'WakaTime API Key', 'confirmed', ['saas','wakatime'], 3.5)
    add(r'signkey-prod-[A-Za-z0-9]{32,}', 'Inngest Production Signing Key', 'confirmed', ['saas','inngest'], 4.0)
    add(r'dp\.st\.[A-Za-z0-9.]{30,}', 'Doppler Service Token', 'confirmed', ['saas','doppler'], 4.0)
    add(r'lin_api_[A-Za-z0-9]{30,}', 'Linear API Key', 'confirmed', ['saas','linear'], 4.0)
    add(r'tfp_[A-Za-z0-9]{40,}', 'Typeform Personal Token', 'confirmed', ['saas','typeform'], 4.0)
    add(r'EZAK[a-zA-Z0-9]{54}', 'EasyPost API Key', 'confirmed', ['saas','easypost'], 4.0)
    add(r'duffel_live_[A-Za-z0-9_\-]{40}', 'Duffel Live API Token', 'confirmed', ['saas','duffel'], 4.0)
    add(r'xau_[A-Za-z0-9_\-]{40,}', 'Xata Database API Key', 'confirmed', ['saas','xata'], 4.0)
    add(r'pscale_oauth_[A-Za-z0-9_]{32,}', 'PlanetScale OAuth Token', 'confirmed', ['saas','planetscale'], 4.0)

    # ── Web3 & Blockchain (14) ───────────────────────────────────────────
    add(r'0x[a-fA-F0-9]{40}', 'Ethereum Wallet Address', 'info', ['web3','ethereum'])
    add(r'alch-[A-Za-z0-9_\-]{32}', 'Alchemy API Key', 'confirmed', ['web3','alchemy'], 4.0)
    add(r'(?i)etherscan[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{34})[\'"`]', 'Etherscan API Key', 'confirmed', ['web3','etherscan'], 3.5)
    add(r'(?i)infura[_-]?project[_-]?secret\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Infura Project Secret', 'confirmed', ['web3','infura'], 3.5)
    add(r'(?i)infura[_-]?project[_-]?id\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Infura Project ID', 'probable', ['web3','infura'])
    add(r'(?i)solana[_-]?private[_-]?key\s*[=:]\s*[\'"`]([1-9A-HJ-NP-Za-km-z]{87,88})[\'"`]', 'Solana Private Key', 'confirmed', ['web3','solana'], 4.5)
    add(r'(?i)alchemy[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{32,})[\'"`]', 'Alchemy API Key (Context)', 'probable', ['web3','alchemy'], 3.5)
    add(r'(?i)moralis[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Moralis Web3 API Key', 'probable', ['web3','moralis'], 3.5)
    add(r'(?i)walletconnect[_-]?project[_-]?id\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'WalletConnect Project ID', 'probable', ['web3','walletconnect'])
    add(r'(?i)quicknode[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'QuickNode API Key', 'confirmed', ['web3','quicknode'])
    add(r'(?i)chainstack[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Chainstack API Key', 'confirmed', ['web3','chainstack'])
    add(r'(?i)blockcypher[_-]?token\s*[=:]\s*[\'"`]([a-f0-9]{32,})[\'"`]', 'BlockCypher API Token', 'probable', ['web3','blockcypher'])
    add(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', 'Bitcoin Wallet Address', 'info', ['web3','bitcoin'])
    add(r'(?i)web3[_-]?provider\s*[=:]\s*[\'"`](https?:\/\/[^"\']+)[\'"`]', 'Web3 Provider URL', 'info', ['web3','rpc'])

    # ── Monitoring & Observability (10) ──────────────────────────────────
    add(r'https:\/\/[0-9a-f]{32}@o\d+\.ingest\.sentry\.io\/\d+', 'Sentry DSN URL', 'confirmed', ['monitoring','sentry'])
    add(r'NRAK-[A-Z0-9]{27}', 'New Relic API Key', 'confirmed', ['monitoring','newrelic'], 3.5)
    add(r'(?i)datadog[_-]?api[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Datadog API Key', 'confirmed', ['monitoring','datadog'], 3.5)
    add(r'(?i)datadog[_-]?app[_-]?key\s*[=:]\s*[\'"`]([a-f0-9]{40})[\'"`]', 'Datadog Application Key', 'confirmed', ['monitoring','datadog'], 3.5)
    add(r'glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}', 'Grafana Service Account Token', 'confirmed', ['monitoring','grafana'], 4.0)
    add(r'glc_eyJ[A-Za-z0-9+\/=]{60,}', 'Grafana Cloud Access Policy', 'confirmed', ['monitoring','grafana'], 4.0)
    add(r'dt0[a-z0-9]{2,5}\.[A-Za-z0-9]{8}\.[A-Za-z0-9]{64}', 'Dynatrace API Token', 'confirmed', ['monitoring','dynatrace'], 4.0)
    add(r'(?i)splunk[_-]?hec[_-]?token\s*[=:]\s*[\'"`]([a-f0-9\-]{36})[\'"`]', 'Splunk HEC Token', 'confirmed', ['monitoring','splunk'])
    add(r'(?i)prometheus[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Prometheus Remote Write Token', 'probable', ['monitoring','prometheus'])
    add(r'(?i)elastic[_-]?apm[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Elastic APM Secret Token', 'confirmed', ['monitoring','elastic'])

    # ── Config & Environment (10) ────────────────────────────────────────
    add(r'process\.env\.[A-Z_]+', 'Node.js Environment Variable', 'info', ['config','env'])
    add(r'(?i)SECRET_KEY\s*[=:]\s*[\'"`]([A-Za-z0-9!@#$%^&*()\-_=+\[\]{}|;:,.<>?\/~`]{32,})[\'"`]', 'Django/Flask SECRET_KEY', 'confirmed', ['config','django','flask'], 3.5)
    add(r'(?i)ENCRYPTION_KEY\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Application Encryption Key', 'confirmed', ['config','crypto'])
    add(r'(?i)JWT_SECRET\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'JWT Secret Key (Env)', 'confirmed', ['config','jwt'])
    add(r'(?i)SESSION_SECRET\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Session Secret (Env)', 'confirmed', ['config','session'])
    add(r'(?i)COOKIE_SECRET\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Cookie Signing Secret', 'confirmed', ['config','cookie'])
    add(r'(base64:[A-Za-z0-9+\/]{44}=)', 'Laravel Application Key', 'confirmed', ['config','laravel'], 4.0)
    add(r'(?i)RAILS_MASTER_KEY\s*[=:]\s*[\'"`]([a-f0-9]{32})[\'"`]', 'Rails Master Key', 'confirmed', ['config','rails'])
    add(r'(?i)APP_KEY\s*[=:]\s*[\'"`](base64:[A-Za-z0-9+\/=]{44})[\'"`]', 'Laravel APP_KEY', 'confirmed', ['config','laravel'])
    add(r'(?i)NODE_ENV\s*[=:]\s*[\'"`]([a-z]+)[\'"`]', 'Node.js Environment', 'info', ['config','node'])

    # ── Package Managers (4) ─────────────────────────────────────────────
    add(r'(npm_[A-Za-z0-9]{36})', 'npm Access Token', 'confirmed', ['package','npm'])
    add(r'(pypi-[A-Za-z0-9_\-]{32,})', 'PyPI Upload Token', 'confirmed', ['package','pypi'])
    add(r'(rubygems_[a-zA-Z0-9]{48})', 'RubyGems API Key', 'confirmed', ['package','rubygems'], 4.0)
    add(r'(?i)npm[_-]?token\s*[=:]\s*[\'"`](npm_[A-Za-z0-9]{36})[\'"`]', 'npm Token (Context)', 'confirmed', ['package','npm'])

    # ── CMS Platforms (8) ────────────────────────────────────────────────
    add(r'(?i)wordpress[_-]?nonce\s*[=:]\s*[\'"`]([a-f0-9A-Za-z_]{10,})[\'"`]', 'WordPress Nonce/API Key', 'probable', ['cms','wordpress'], 3.0)
    add(r'(?i)wp[_-]?json[_-]?nonce\s*[=:]\s*[\'"`]([a-f0-9]{10,})[\'"`]', 'WordPress JSON Nonce', 'probable', ['cms','wordpress'])
    add(r'(?i)drupal[_-]?private[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{40,})[\'"`]', 'Drupal Private Key', 'probable', ['cms','drupal'], 3.5)
    add(r'(?i)joomla[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Joomla Secret Key', 'probable', ['cms','joomla'], 3.5)
    add(r'(?i)magento[_-]?integration[_-]?token\s*[=:]\s*[\'"`]([a-z0-9]{32})[\'"`]', 'Magento Integration Token', 'probable', ['cms','magento'])
    add(r'(?i)prestashop[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'PrestaShop API Key', 'probable', ['cms','prestashop'])
    add(r'(?i)bigcommerce[_-]?access[_-]?token\s*[=:]\s*[\'"`]([a-f0-9]{32,})[\'"`]', 'BigCommerce Access Token', 'probable', ['cms','bigcommerce'], 3.5)
    add(r'(?i)wix[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Wix API Key', 'probable', ['cms','wix'])

    # ── URL Credentials (6) ──────────────────────────────────────────────
    add(r'https?:\/\/[^:]+:([^@]{8,})@[^\s]+', 'URL with Embedded Password', 'confirmed', ['url'], 2.0)
    add(r'[?&](?:token|api_key|apikey|access_token)=([A-Za-z0-9_\-\.%+]{16,})', 'Secret in URL Query Parameter', 'confirmed', ['url'], 2.5)
    add(r'[?&](?:secret|password|passwd)=([A-Za-z0-9_\-\.%+]{8,})', 'Password in URL Query String', 'confirmed', ['url'], 2.5)
    add(r'(?i)secret[_-]?in[_-]?url\s*[=:]\s*[\'"`](https?:\/\/[^"\']+)[\'"`]', 'Secret URL Reference', 'probable', ['url'])
    add(r'curl\s+-[uU]\s+[^:]+:[^@\s]+', 'cURL Command with Credentials', 'probable', ['url','infra'])
    add(r'(?i)\.env\s*[=:]\s*[\'"`]([^\'"]+)[\'"`]', 'Environment File Reference', 'info', ['config','env'])

    # ── Security Issues (14) ─────────────────────────────────────────────
    add(r'eval\s*\([^)]*location\.', 'DOM XSS via eval(location)', 'possible', ['security','xss'])
    add(r'eval\s*\([^)]*req\.(?:body|params|query)', 'Code Injection via eval', 'possible', ['security','rce'])
    add(r'\.innerHTML\s*=\s*`[^`]*\$\{', 'DOM XSS via innerHTML Template', 'possible', ['security','xss'])
    add(r'\.innerHTML\s*=\s*["\'][^"\']*\+[^+]+', 'DOM XSS via innerHTML Concat', 'possible', ['security','xss'])
    add(r'document\.write\s*\([^)]*location\.', 'DOM XSS via document.write', 'possible', ['security','xss'])
    add(r'exec\s*\(\s*`[^`]*\$\{[^}]*req\.', 'Command Injection via exec()', 'confirmed', ['security','rce'])
    add(r'execSync\s*\(\s*\+', 'Command Injection via execSync', 'confirmed', ['security','rce'])
    add(r'pickle\.loads\s*\(', 'Insecure Deserialization (Python pickle)', 'confirmed', ['security','rce'])
    add(r'vm\.runInNewContext\s*\([^)]*req\.', 'VM Sandbox Escape via User Input', 'possible', ['security','rce'])
    add(r'(?i)\.query\s*\(\s*["\'][^"\']*\+\s*req\.', 'SQL Injection via String Concat', 'possible', ['security','sqli'])
    add(r'(?i)\.find\s*\(\s*req\.(?:body|params|query)', 'NoSQL Injection via User Input', 'possible', ['security','nosqli'])
    add(r'(?i)\.merge\s*\(\s*\{\s*\},\s*req\.', 'Prototype Pollution via merge()', 'possible', ['security','prototype-pollution'])
    add(r'(?i)\.readFile\s*\(\s*req\.(?:params|query|body)', 'Path Traversal via readFile', 'possible', ['security','lfi'])
    add(r'(?i)(?:fetch|axios|http\.get)\s*\(\s*req\.', 'SSRF via HTTP Request from Input', 'possible', ['security','ssrf'])

    # ── Reconnaissance (16) ──────────────────────────────────────────────
    add(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Private IPv4 (Class A: 10.x)', 'info', ['recon','infra'])
    add(r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'Private IPv4 (Class B: 172.16-31.x)', 'info', ['recon','infra'])
    add(r'192\.168\.\d{1,3}\.\d{1,3}', 'Private IPv4 (Class C: 192.168.x)', 'info', ['recon','infra'])
    add(r'[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', 'Email Address (Potential PII)', 'info', ['recon','pii'])
    add(r'https?:\/\/[^\s"\'<>]+', 'URL Endpoint Discovery', 'info', ['recon','url'])
    add(r'["\'](\/api\/[^\s"\']+)["\']', 'API Endpoint Path', 'info', ['recon','api'])
    add(r'["\'](\/graphql)["\']', 'GraphQL Endpoint', 'info', ['recon','graphql'])
    add(r'["\'](\/(?:admin|administrator|dashboard|console|portal|manage))["\']', 'Admin Panel Path', 'info', ['recon','admin'])
    add(r'["\'](\/swagger[^"\']*\.(?:json|yaml|yml))["\']', 'Swagger/OpenAPI Specification', 'info', ['recon','swagger'])
    add(r'["\'](\/api-docs[^"\']*)["\']', 'API Documentation Path', 'info', ['recon','api'])
    add(r'["\'](\/(?:health|healthz|ping|status|ready|alive))["\']', 'Health Check Endpoint', 'info', ['recon','health'])
    add(r'["\'](\/(?:debug|_debug|devtools|profiler|trace|pprof))["\']', 'Debug/Profiler Endpoint', 'info', ['recon','debug'])
    add(r'["\'](\/\.env)["\']', 'Environment File Path', 'info', ['recon','env'])
    add(r'\/\/#\s*sourceMappingURL=', 'Source Map Reference', 'info', ['recon','sourcemap'])
    add(r'console\.(?:log|debug|info|warn|error)\s*\(', 'Console Log Statement', 'info', ['recon','debug'])
    add(r'debugger;', 'JavaScript Debugger Statement', 'info', ['recon','debug'])
    
    # ── Additional patterns to reach 310+ ────────────────────────────────
    add(r'(?i)firebase[_-]?api[_-]?key\s*[=:]\s*[\'"`](AIza[0-9A-Za-z\-_]{35})[\'"`]', 'Firebase API Key (context)', 'confirmed', ['google','firebase'], 3.5)
    add(r'(?i)google[_-]?cloud[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{30,})[\'"`]', 'Google Cloud Key (generic)', 'probable', ['google','gcp'], 3.5)
    add(r'(?i)heroku[_-]?oauth[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{30,})[\'"`]', 'Heroku OAuth Token', 'confirmed', ['cloud','heroku'])
    add(r'(?i)netlify[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{40,})[\'"`]', 'Netlify API Key (alt)', 'confirmed', ['cloud','netlify'], 3.5)
    add(r'(?i)vercel[_-]?access[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{24,})[\'"`]', 'Vercel Access Token', 'probable', ['cloud','vercel'])
    add(r'(?i)upstash[_-]?redis[_-]?url\s*[=:]\s*[\'"`](rediss:\/\/[^\s"\']+)[\'"`]', 'Upstash Redis URL (context)', 'confirmed', ['database','upstash'], 3.0)
    add(r'(?i)planetscale[_-]?dsn\s*[=:]\s*[\'"`](mysql:\/\/[^\s"\']+)[\'"`]', 'PlanetScale DSN (context)', 'confirmed', ['database','planetscale'], 2.5)
    add(r'(?i)supabase[_-]?url\s*[=:]\s*[\'"`](https:\/\/[a-z0-9]+\.supabase\.co)[\'"`]', 'Supabase URL', 'info', ['database','supabase'])
    add(r'(?i)supabase[_-]?anon[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-\.]+)[\'"`]', 'Supabase Anon Key', 'probable', ['database','supabase'])
    add(r'(?i)nhost[_-]?admin[_-]?secret\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{32,})[\'"`]', 'Nhost Admin Secret', 'confirmed', ['database','nhost'], 3.5)
    add(r'(?i)appwrite[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Appwrite API Key', 'confirmed', ['saas','appwrite'], 3.5)
    add(r'(?i)contentful[_-]?delivery[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{40,})[\'"`]', 'Contentful Delivery Token', 'probable', ['saas','contentful'])
    add(r'(?i)sanity[_-]?token\s*[=:]\s*[\'"`](sk[A-Za-z0-9\-_]{40,})[\'"`]', 'Sanity.io Token', 'confirmed', ['saas','sanity'], 4.0)
    add(r'(?i)hygraph[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Hygraph Token', 'probable', ['saas','hygraph'])
    add(r'(?i)strapi[_-]?token\s*[=:]\s*[\'"`]([A-Za-z0-9\-_]{32,})[\'"`]', 'Strapi Token', 'probable', ['cms','strapi'])
    add(r'(?i)ghost[_-]?admin[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Ghost Admin API Key', 'confirmed', ['cms','ghost'], 3.5)
    add(r'(?i)paypal[_-]?access[_-]?token\s*[=:]\s*[\'"`](A21[A-Za-z0-9\-_]{80,})[\'"`]', 'PayPal Access Token', 'confirmed', ['payment','paypal'])
    add(r'(?i)adyen[_-]?api[_-]?key\s*[=:]\s*[\'"`](AQ[A-Za-z0-9_\-]{30,})[\'"`]', 'Adyen API Key (context)', 'confirmed', ['payment','adyen'], 3.5)
    add(r'(?i)klarna[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{20,})[\'"`]', 'Klarna API Key', 'probable', ['payment','klarna'])
    add(r'(?i)affirm[_-]?api[_-]?key\s*[=:]\s*[\'"`]([A-Za-z0-9]{32,})[\'"`]', 'Affirm API Key', 'probable', ['payment','affirm'])

    # Deduplicate
    seen = set()
    unique = []
    for p in P:
        if p[0] not in seen:
            seen.add(p[0])
            unique.append(p)
    return unique

PATTERNS = build_patterns()

# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, requests_per_second: float = 10.0):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.max_tokens = requests_per_second
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()
    
    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens < 1:
                time.sleep((1 - self.tokens) / self.rate)
                self.tokens = 0
            else:
                self.tokens -= 1

# ═══════════════════════════════════════════════════════════════════════════
# SECRET SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class SecretScanner:
    def __init__(self, severity='possible', show_raw=False, verbose=False,
                 json_output=False, filter_tags=None, threads=20, timeout=30,
                 max_depth=1, follow_js=True, quiet=False, no_fp=False,
                 rate_limit: float = 0):
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
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
        self.scanned = set()
        self.total = 0
        self.scanned_count = 0
        self.hit_count = 0
        self.status_counts = defaultdict(int)
        self.start = None
        self.compiled = self._compile()
        # SSL context that accepts any certificate (for CDNs etc.)
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
    
    def _compile(self):
        sev = {'confirmed': 0, 'probable': 1, 'possible': 2, 'info': 3}
        ml = sev.get(self.severity, 3)
        comp = []
        for rx, name, s, tags, ent in PATTERNS:
            if sev.get(s, 3) > ml: continue
            if self.filter_tags and not self.filter_tags.intersection(tags): continue
            try: comp.append((re.compile(rx, re.I|re.M), name, s, tags, ent))
            except: pass
        return comp
    
    def fetch(self, url: str) -> Tuple[str, Optional[str], int]:
        if self.rate_limiter: self.rate_limiter.acquire()
        # Try with custom headers to avoid 403/406
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'identity',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as r:
                status = r.getcode()
                # Follow redirects manually? urlopen follows by default, but we record the final status
                ct = r.headers.get('Content-Type', '').lower()
                if any(t in ct for t in ['text', 'javascript', 'json', 'html', 'xml', 'plain']):
                    content = r.read(10*1024*1024).decode('utf-8', errors='ignore')
                    return (url, content, status)
                return (url, None, status)
        except urllib.error.HTTPError as e:
            return (url, None, e.code)
        except urllib.error.URLError as e:
            return (url, None, -1)
        except Exception:
            return (url, None, -2)
    
    def scan(self, url: str, content: str) -> List[Dict]:
        findings = []
        for ln, line in enumerate(content.split('\n'), 1):
            for pat, name, sev, tags, ent_min in self.compiled:
                try:
                    for m in pat.finditer(line):
                        val = m.group(1) if m.lastindex else m.group(0)
                        val = val.strip()
                        if not self.no_fp and is_false_positive(val, line, name):
                            continue
                        if ent_min and entropy(val) < ent_min:
                            continue
                        s, e = max(0, m.start()-25), min(len(line), m.end()+25)
                        ctx = line[s:e].strip()
                        if s > 0: ctx = '…' + ctx
                        if e < len(line): ctx += '…'
                        findings.append({
                            'url': url, 'line': ln, 'pattern': name,
                            'severity': sev, 'tags': list(tags),
                            'value': val if self.show_raw else val[:4]+'*'*(max(0,len(val)-8))+val[-4:],
                            'context': ctx[:100], 'entropy': round(entropy(val),2)
                        })
                except: pass
        return findings
    
    def process_url(self, url: str, depth: int = 0):
        if url in self.scanned: return (url, [], set(), -3)
        self.scanned.add(url)
        url, content, status = self.fetch(url)
        self.status_counts[status] += 1
        if content is None: return (url, [], set(), status)
        findings = self.scan(url, content)
        new = set()
        if self.follow_js and depth < self.max_depth:
            for m in re.finditer(r'https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?', content, re.I):
                u = m.group(0)
                if u not in self.scanned: new.add(u)
        return (url, findings, new, status)
    
    def run(self, urls: List[str]):
        if not urls:
            print(f"{C.R}[✗] No URLs{C.RST}", file=sys.stderr)
            return
        self.start = time.time()
        if not self.json_output and not self.quiet:
            print(BANNER)
            rl = f" | Rate: {self.rate_limiter.rate}/s" if self.rate_limiter else ""
            print(f"{C.X}  {len(PATTERNS)} patterns | {len(self.compiled)} active | {self.threads} threads{rl}{C.RST}\n")
        all_f = []
        queue = list(urls)
        depth = 0
        while queue and depth <= self.max_depth:
            discovered = set()
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = {ex.submit(self.process_url, u, depth): u for u in queue if u not in self.scanned}
                for fut in as_completed(futs):
                    try:
                        url, findings, new, status = fut.result()
                        self.scanned_count += 1
                        if findings:
                            self.hit_count += 1
                            self.total += len(findings)
                            all_f.extend(findings)
                            if not self.json_output: self._show(url, findings, status)
                        elif self.verbose: self._show_status(url, status)
                        discovered.update(new)
                    except: pass
            queue = list(discovered - self.scanned)
            depth += 1
        elapsed = time.time() - self.start
        if self.json_output:
            print(json.dumps({'summary': self._sum(all_f, elapsed), 'findings': all_f}, indent=2))
        else:
            self._summary_print(all_f, elapsed)
    
    def _status_color(self, status: int) -> str:
        if 200 <= status < 300: return C.G
        if 300 <= status < 400: return C.Y
        if 400 <= status < 500: return C.Y
        if status < 0: return C.R
        return C.R
    
    def _status_label(self, status: int) -> str:
        if status == -1: return "CONN_ERR"
        if status == -2: return "ERROR"
        if status == -3: return "DUP"
        return str(status)
    
    def _show_status(self, url: str, status: int):
        sc = self._status_color(status)
        sl = self._status_label(status)
        print(f"{sc}  [{sl:>8}] {url[:70]}{C.RST}")
    
    def _show(self, url: str, findings: List[Dict], status: int):
        sc = {'confirmed': C.R, 'probable': C.Y, 'possible': C.B, 'info': C.C}
        si = {'confirmed': '◆', 'probable': '◇', 'possible': '○', 'info': '·'}
        stc = self._status_color(status)
        stl = self._status_label(status)
        print(f"\n{C.BOLD}{C.C}── {url} {stc}[{stl}]{C.RST}")
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
        sc = defaultdict(int)
        for f in findings: sc[f['severity']] += 1
        return {'urls': self.scanned_count, 'hits': self.hit_count, 'total': self.total,
                'time': round(elapsed,2), 'by_severity': dict(sc), 'status_codes': dict(self.status_counts)}
    
    def _summary_print(self, findings, elapsed):
        s = self._sum(findings, elapsed)
        print(f"\n{C.BOLD}{C.M}╔══════════════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.M}║   SCAN COMPLETE                                      ║{C.RST}")
        print(f"{C.BOLD}{C.M}╚══════════════════════════════════════════════════════╝{C.RST}")
        print(f"  URLs: {s['urls']} | Hits: {s['hits']} | Findings: {s['total']} | Time: {s['time']}s")
        if s.get('status_codes'):
            print(f"  Status: ", end="")
            for code in sorted(s['status_codes']):
                count = s['status_codes'][code]
                label = self._status_label(code)
                c = self._status_color(code)
                print(f"{c}{label}={count}{C.RST} ", end="")
            print()
        if not findings: print(f"\n{C.G}  ✓ CLEAN{C.RST}")
        else:
            for sev, c in [('confirmed',C.R),('probable',C.Y),('possible',C.B),('info',C.C)]:
                if s['by_severity'].get(sev): print(f"  {c}{sev.upper():12} {s['by_severity'][sev]}{C.RST}")
        print(f"\n{C.BOLD}{C.M}{'═'*56}{C.RST}\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='astra v1.5', add_help=False)
    parser.add_argument('-u', '--urls', nargs='*')
    parser.add_argument('-f', '--file')
    parser.add_argument('-s', '--severity', default='possible', choices=['confirmed','probable','possible','info'])
    parser.add_argument('-r', '--show-raw', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument('-j', '--json', action='store_true')
    parser.add_argument('--tags')
    parser.add_argument('-t', '--threads', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('-d', '--depth', type=int, default=1)
    parser.add_argument('--no-follow', action='store_true')
    parser.add_argument('--no-fp', action='store_true')
    parser.add_argument('--rate', type=float, default=0, help='Rate limit (req/sec, 0=unlimited)')
    parser.add_argument('-l', '--list', action='store_true')
    parser.add_argument('-h', '--help', action='store_true')
    
    args = parser.parse_args()
    
    if args.help:
        print(f"""
{C.BOLD}astra v1.5 — Live JS Secret Detection Engine{C.RST}

{C.BOLD}USAGE:{C.RST}
  astra -u https://example.com/app.js     Scan a single URL
  astra -f urls.txt                       Scan URLs from file
  cat urls.txt | astra                    Pipe URLs via stdin
  astra -f urls.txt -s confirmed -r       Confirmed only, show raw
  astra -f urls.txt -t 50 --rate 10       50 threads, 10 req/s rate limit
  astra -f urls.txt --tags aws,stripe     Filter by tags
  astra -l                                List all patterns

{C.BOLD}FLAGS:{C.RST}
  -u, --urls      URLs to scan
  -f, --file      File with URLs
  -s, --severity  confirmed|probable|possible|info (default: possible)
  -r, --show-raw  Show raw secret values
  -v, --verbose   Show all URLs
  -q, --quiet     Minimal output
  -j, --json      JSON output
  --tags          Filter by tags (aws,stripe,ai,github)
  -t, --threads   Threads (default: 20)
  --timeout       Timeout seconds (default: 30)
  -d, --depth     JS URL depth (default: 1)
  --no-follow     Don't follow JS URLs
  --no-fp         Disable FP filter
  --rate          Rate limit (req/sec, 0=unlimited)
  -l, --list      List patterns
  -h, --help      Show help
""")
        sys.exit(0)
    
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
    
    urls = []
    if args.urls: urls.extend(args.urls)
    if args.file:
        try:
            with open(args.file) as f: urls.extend(l.strip() for l in f if l.strip() and not l.startswith('#'))
        except Exception as e: print(f"{C.R}[✗] {e}{C.RST}", file=sys.stderr); sys.exit(1)
    if not sys.stdin.isatty() and not urls:
        urls.extend(l.strip() for l in sys.stdin if l.strip() and not l.startswith('#'))
    if not urls: print(f"{C.R}[✗] No URLs. Use -u, -f, or stdin{C.RST}", file=sys.stderr); sys.exit(1)
    
    scanner = SecretScanner(
        severity=args.severity, show_raw=args.show_raw, verbose=args.verbose,
        json_output=args.json, filter_tags=args.tags, threads=args.threads,
        timeout=args.timeout, max_depth=args.depth, follow_js=not args.no_follow,
        quiet=args.quiet, no_fp=args.no_fp, rate_limit=args.rate
    )
    scanner.run(urls)
    sys.exit(1 if scanner.total > 0 else 0)

if __name__ == '__main__':
    main()
