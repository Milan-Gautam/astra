#!/usr/bin/env python3
"""
astra — Live JS Secret Detection Engine v1.3
=============================================
Fixed status codes, rate limiting, context-aware detection.
Strict false positive filter. Clean output.
"""

import sys, re, json, argparse, math, time
import urllib.request, urllib.error, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, OrderedDict
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse
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
 /_/   \\_\\____/ |_| |_| \\_\\/_/   \\_\\
{C.RST}{C.X}  secret & credential scanner v1.3{C.RST}"""

def entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in freq.values())

# ── Context-aware false positive filter ──────────────────────────────────
SECRET_KEYWORDS = {
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
}

FP_BLACKLIST = {
    'null','undefined','true','false','none','example','test','sample',
    'dummy','placeholder','your_key','your_token','insert_here','changeme',
    'todo','fixme','redacted','n/a','na','empty','function','object',
    'string','number','boolean','return','export','import','require',
    'module','window','document','console','error','callback','loading',
    'done','errors','retries','version','language','region','libraries',
    'client','channel','options','instance','status','core','default',
    'config','settings','env','environment','development','production',
    'staging','localhost','127.0.0.1','0.0.0.0',
}

def has_secret_keyword(line: str) -> bool:
    """Check if line contains a secret-related keyword."""
    ll = line.lower()
    return any(kw in ll for kw in SECRET_KEYWORDS)

def is_false_positive(val: str, line: str = "") -> bool:
    """Context-aware false positive check."""
    v = val.strip(); vl = v.lower()
    
    if len(v) < 4 or len(v) > 500: return True
    if vl in FP_BLACKLIST: return True
    if len(set(vl)) < 4: return True
    if v.count(v[0]) > len(v) * 0.6: return True
    if re.match(r'^[a-f0-9]{32,128}$', vl): return True
    
    # If line has NO secret keyword, be VERY strict
    if line and not has_secret_keyword(line):
        if len(v) < 16: return True
        if len(set(vl)) < 8: return True
    
    ci = sum(1 for c in v if c in '.,;:{}[]()=+<>!&|')
    if len(v) > 50 and ci > len(v) * 0.15: return True
    return False

# ═══════════════════════════════════════════════════════════════════════════
# PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

def build_patterns():
    P = []
    def add(rx, name, sev, tags, ent=0.0):
        P.append((rx, name, sev, tags, ent))
    
    # AWS (18)
    add(r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Access Key ID', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ASIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS STS Temp Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ABIA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Billing Key', 'confirmed', ['aws'], 3.0)
    add(r'(?<![A-Z0-9])(ACCA[A-Z0-9]{16})(?![A-Z0-9])', 'AWS Context Key', 'confirmed', ['aws'], 3.0)
    add(r'(?i)(?:aws_secret_access_key|aws_secret)\s*[=:]\s*[\'"`]?([A-Za-z0-9\/+=]{40})[\'"`]?', 'AWS Secret Key', 'confirmed', ['aws'], 4.5)
    add(r'(?i)(?:aws_session_token)\s*[=:]\s*[\'"`]?([A-Za-z0-9\/+=]{100,})[\'"`]?', 'AWS Session Token', 'confirmed', ['aws'], 4.0)
    add(r'(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 'Amazon MWS Token', 'confirmed', ['aws'])
    add(r'(FWO[A-Za-z0-9\/+=]{40,})', 'AWS STS FWO', 'confirmed', ['aws'], 4.0)
    add(r'(A3T[A-Z0-9]{16,})', 'AWS Session A3T', 'confirmed', ['aws'])
    add(r'arn:aws:[a-z]+:[a-z0-9\-]*:[0-9]{12}:.+', 'AWS ARN', 'info', ['aws','recon'])
    add(r'([a-z0-9][a-z0-9\-]*\.s3\.amazonaws\.com)', 'S3 Bucket', 'info', ['aws','recon'])
    add(r'([a-z0-9\-]+\.cloudfront\.net)', 'CloudFront', 'info', ['aws','cdn'])
    add(r'([a-z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com)', 'API Gateway', 'info', ['aws','api'])
    add(r'([a-z0-9\-]+\.elb\.amazonaws\.com)', 'ELB', 'info', ['aws','infra'])
    add(r'([a-z0-9\-]+\.rds\.amazonaws\.com)', 'RDS', 'info', ['aws','database'])
    add(r'([a-z0-9\-]+\.elasticache\.amazonaws\.com)', 'ElastiCache', 'info', ['aws','database'])
    add(r'([a-z0-9\-]+\.redshift\.amazonaws\.com)', 'Redshift', 'info', ['aws','database'])
    add(r'([a-z0-9][a-z0-9\-]*\.s3-website[\.-][a-z0-9\-]+\.amazonaws\.com)', 'S3 Website', 'info', ['aws','recon'])

    # Google Cloud (14)
    add(r'(AIza[0-9A-Za-z\-_]{35})', 'Google API Key', 'confirmed', ['google','api'], 3.5)
    add(r'(ya29\.[0-9A-Za-z\-_]{100,})', 'Google OAuth Token', 'confirmed', ['google','auth'])
    add(r'(GOCSPX-[A-Za-z0-9_\-]{28})', 'Google OAuth Secret', 'confirmed', ['google','auth'])
    add(r'(6L[0-9A-Za-z\-_]{38})', 'reCAPTCHA Key', 'probable', ['google'])
    add(r'(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 'FCM Key', 'confirmed', ['google','firebase'])
    add(r'[0-9]+-[0-9A-Za-z_]+\.apps\.googleusercontent\.com', 'Google OAuth Client ID', 'probable', ['google','auth'])
    add(r'(?i)gcp[_-]?project[_-]?id\s*[=:]\s*[\'"`]?([a-z0-9\-]{6,30})[\'"`]?', 'GCP Project ID', 'confirmed', ['google','gcp'])
    add(r'(?i)firebase[_-]?project[_-]?id\s*[=:]\s*[\'"`]?([a-z0-9\-]{6,30})[\'"`]?', 'Firebase Project ID', 'confirmed', ['google','firebase'])
    add(r'(?i)bigquery[_-]?dataset\s*[=:]\s*[\'"`]?([a-zA-Z0-9_]+)[\'"`]?', 'BigQuery Dataset', 'info', ['google','gcp'])
    add(r'(?i)pubsub[_-]?topic\s*[=:]\s*[\'"`]?(projects\/[^\/]+\/topics\/[a-zA-Z0-9\-_]+)[\'"`]?', 'Pub/Sub Topic', 'info', ['google','gcp'])
    add(r'storage\.googleapis\.com\/([a-z0-9\-_]+)', 'GCS Bucket', 'info', ['google','gcp','storage'])
    add(r'firebasestorage\.googleapis\.com\/([a-z0-9\-_]+)', 'Firebase Storage', 'info', ['google','firebase'])
    add(r'(?i)cloud[_-]?run[_-]?service\s*[=:]\s*[\'"`]?([a-z0-9\-]+)[\'"`]?', 'Cloud Run Service', 'info', ['google','gcp'])
    add(r'(?i)spanner[_-]?instance\s*[=:]\s*[\'"`]?([a-z0-9\-]+)[\'"`]?', 'Spanner Instance', 'info', ['google','gcp'])

    # Azure (14)
    add(r'(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88})', 'Azure Storage Connection', 'confirmed', ['azure'])
    add(r'(Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/[^;"\'\s]*)', 'Azure Service Bus', 'confirmed', ['azure'])
    add(r'(sig=[A-Za-z0-9%+\/]{20,}&se=[0-9T:Z%\-]+&sp=[a-z]+)', 'Azure SAS Token', 'confirmed', ['azure'])
    add(r'(azp_[A-Za-z0-9]{52})', 'Azure DevOps PAT', 'confirmed', ['azure','ci_cd'], 4.0)
    add(r'(?i)azure[_-]?client[_-]?id\s*[=:]\s*[\'"`]?([a-f0-9\-]{36})[\'"`]?', 'Azure Client ID', 'probable', ['azure'])
    add(r'(?i)azure[_-]?tenant[_-]?id\s*[=:]\s*[\'"`]?([a-f0-9\-]{36})[\'"`]?', 'Azure Tenant ID', 'probable', ['azure'])
    add(r'(?i)azure[_-]?client[_-]?secret\s*[=:]\s*[\'"`]?([A-Za-z0-9\-_\.~]{32,})[\'"`]?', 'Azure Client Secret', 'confirmed', ['azure'])
    add(r'(?i)azure[_-]?keyvault[_-]?url\s*[=:]\s*[\'"`]?(https:\/\/[^"\']+\.vault\.azure\.net\/)[\'"`]?', 'Azure Key Vault', 'confirmed', ['azure'])
    add(r'(?i)cosmos[_-]?db[_-]?endpoint\s*[=:]\s*[\'"`]?(https:\/\/[^"\']+\.documents\.azure\.com)[\'"`]?', 'Cosmos DB', 'info', ['azure','database'])
    add(r'[a-z0-9\-_]+\.blob\.core\.windows\.net', 'Azure Blob URL', 'info', ['azure','storage'])
    add(r'[a-z0-9\-_]+\.mysql\.database\.azure\.com', 'Azure MySQL', 'info', ['azure','database'])
    add(r'[a-z0-9\-_]+\.postgres\.database\.azure\.com', 'Azure PostgreSQL', 'info', ['azure','database'])
    add(r'[a-z0-9\-_]+\.redis\.cache\.windows\.net', 'Azure Redis', 'info', ['azure','database'])
    add(r'(?i)azure[_-]?function[_-]?app\s*[=:]\s*[\'"`]?([a-z0-9\-]{3,32})[\'"`]?', 'Azure Function', 'info', ['azure'])

    # Other Cloud (14)
    add(r'dop_v1_[a-f0-9]{64}', 'DigitalOcean PAT', 'confirmed', ['cloud','digitalocean'], 4.0)
    add(r'DO00[A-Za-z0-9]{32,}', 'DO Spaces Key', 'confirmed', ['cloud','digitalocean'], 3.5)
    add(r'rnd_[A-Za-z0-9]{32}', 'Render API Key', 'confirmed', ['cloud','render'], 3.5)
    add(r'SCW[A-Z0-9]{20,}', 'Scaleway Key', 'confirmed', ['cloud','scaleway'], 3.5)
    add(r'LTAI[A-Za-z0-9]{16,20}', 'Alibaba Key', 'confirmed', ['cloud','alibaba'], 3.0)
    add(r'(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([0-9a-f\-]{36})[\'"`]?', 'Heroku Key', 'confirmed', ['cloud','heroku'])
    add(r'(?i)cloudflare[_-]?api[_-]?token\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-]{37,40})[\'"`]?', 'Cloudflare Token', 'confirmed', ['cloud','cloudflare'], 3.5)
    add(r'(?i)cloudflare[_-]?global[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([a-f0-9]{37})[\'"`]?', 'Cloudflare Global Key', 'confirmed', ['cloud','cloudflare'])
    add(r'(?i)netlify[_-]?access[_-]?token\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-]{40,})[\'"`]?', 'Netlify Token', 'confirmed', ['cloud','netlify'], 3.5)
    add(r'(?i)vercel[_-]?token\s*[=:]\s*[\'"`]?([A-Za-z0-9]{24})[\'"`]?', 'Vercel Token', 'probable', ['cloud','vercel'])
    add(r'(?i)linode[_-]?token\s*[=:]\s*[\'"`]?([A-Za-z0-9]{64})[\'"`]?', 'Linode Token', 'confirmed', ['cloud','linode'])
    add(r'(?i)vultr[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9]{64})[\'"`]?', 'Vultr Key', 'confirmed', ['cloud','vultr'])
    add(r'(?i)fastly[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-]{32,})[\'"`]?', 'Fastly Key', 'confirmed', ['cloud','fastly'])
    add(r'(?i)ibmcloud[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-]{44})[\'"`]?', 'IBM Cloud Key', 'confirmed', ['cloud','ibm'], 4.0)

    # Payment (22)
    add(r'(sk_live_[0-9a-zA-Z]{24,99})', 'Stripe Live Key', 'confirmed', ['payment','stripe'])
    add(r'(rk_live_[0-9a-zA-Z]{24,99})', 'Stripe Restricted Key', 'confirmed', ['payment','stripe'])
    add(r'(sk_test_[0-9a-zA-Z]{24,99})', 'Stripe Test Key', 'possible', ['payment','stripe'])
    add(r'(whsec_[0-9a-zA-Z]{32,})', 'Stripe Webhook Secret', 'confirmed', ['payment','stripe'], 3.5)
    add(r'access_token\$production\$[A-Za-z0-9]{16}\$[A-Za-z0-9]{32}', 'Braintree Token', 'confirmed', ['payment','paypal'])
    add(r'(?i)paypal[_-]?client[_-]?id\s*[=:]\s*[\'"`]?(A[A-Za-z0-9\-_]{30,})[\'"`]?', 'PayPal Client ID', 'confirmed', ['payment','paypal'])
    add(r'(?i)paypal[_-]?secret\s*[=:]\s*[\'"`]?(E[A-Za-z0-9\-_]{30,})[\'"`]?', 'PayPal Secret', 'confirmed', ['payment','paypal'])
    add(r'(sq0csp-[A-Za-z0-9_\-]{43})', 'Square OAuth Secret', 'confirmed', ['payment','square'])
    add(r'(EAAA[A-Za-z0-9\-_]{22,})', 'Square Token', 'confirmed', ['payment','square'], 3.5)
    add(r'(sq0atp-[A-Za-z0-9\-_]{22,})', 'Square OAuth Token', 'confirmed', ['payment','square'], 3.5)
    add(r'(rzp_live_[A-Za-z0-9]{14,})', 'Razorpay Live', 'confirmed', ['payment','razorpay'], 3.5)
    add(r'(rzp_test_[A-Za-z0-9]{14,})', 'Razorpay Test', 'possible', ['payment','razorpay'], 3.5)
    add(r'(sk_live_[A-Za-z0-9]{40})', 'Paystack Live', 'confirmed', ['payment','paystack'], 4.0)
    add(r'(ck_[a-f0-9]{40})', 'WooCommerce CK', 'confirmed', ['payment','woocommerce'], 3.5)
    add(r'(cs_[a-f0-9]{40})', 'WooCommerce CS', 'confirmed', ['payment','woocommerce'], 3.5)
    add(r'(AQ[A-Za-z0-9_\-]{30,})', 'Adyen Key', 'confirmed', ['payment','adyen'], 3.5)
    add(r'(FLWSECK-[a-zA-Z0-9]{32})', 'Flutterwave Secret', 'confirmed', ['payment','flutterwave'], 3.5)
    add(r'(?i)mollie[_-]?api[_-]?key\s*[=:]\s*[\'"`]?(live_[a-f0-9]{30,})[\'"`]?', 'Mollie Key', 'confirmed', ['payment','mollie'])
    add(r'(?i)revolut[_-]?api[_-]?key\s*[=:]\s*[\'"`]?(key_[a-f0-9]{32,})[\'"`]?', 'Revolut Key', 'confirmed', ['payment','revolut'])
    add(r'(?i)checkout[_-]?secret\s*[=:]\s*[\'"`]?(sk_[a-f0-9]{32,})[\'"`]?', 'Checkout.com Key', 'confirmed', ['payment','checkout'])
    add(r'(?i)stripe[_-]?account[_-]?id\s*[=:]\s*[\'"`]?(acct_[A-Za-z0-9]{16,})[\'"`]?', 'Stripe Account ID', 'probable', ['payment','stripe'])
    add(r'(?i)paypal[_-]?webhook[_-]?id\s*[=:]\s*[\'"`]?(WH-[A-Za-z0-9]{32,})[\'"`]?', 'PayPal Webhook ID', 'probable', ['payment','paypal'])

    # GitHub & GitLab & CI/CD (20)
    add(r'(ghp_[A-Za-z0-9]{36})', 'GitHub PAT', 'confirmed', ['github','ci_cd'])
    add(r'(ghs_[A-Za-z0-9]{36})', 'GitHub Actions', 'confirmed', ['github','ci_cd'])
    add(r'(github_pat_[A-Za-z0-9_]{82})', 'GitHub Fine PAT', 'confirmed', ['github','ci_cd'], 4.0)
    add(r'(gho_[A-Za-z0-9]{36})', 'GitHub OAuth', 'confirmed', ['github'])
    add(r'(ghu_[A-Za-z0-9]{36})', 'GitHub User Token', 'confirmed', ['github'])
    add(r'(ghr_[A-Za-z0-9]{36})', 'GitHub Refresh', 'confirmed', ['github'])
    add(r'(?i)github[_-]?token\s*[=:]\s*[\'"`]?([A-Za-z0-9\-_]{40})[\'"`]?', 'GitHub Token Generic', 'confirmed', ['github'])
    add(r'(?i)github[_-]?app[_-]?id\s*[=:]\s*[\'"`]?([0-9]+)[\'"`]?', 'GitHub App ID', 'info', ['github'])
    add(r'(?i)github[_-]?installation[_-]?id\s*[=:]\s*[\'"`]?([0-9]+)[\'"`]?', 'GitHub Install ID', 'info', ['github'])
    add(r'(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab PAT', 'confirmed', ['gitlab','ci_cd'])
    add(r'(gldt-[A-Za-z0-9_\-]{20,})', 'GitLab Deploy', 'confirmed', ['gitlab'])
    add(r'(glcbt-[A-Za-z0-9_\-]{20,})', 'GitLab CI Job', 'confirmed', ['gitlab'])
    add(r'(glptt-[A-Za-z0-9_\-]{20,})', 'GitLab Project', 'confirmed', ['gitlab'])
    add(r'(glrt-[A-Za-z0-9_\-]{20,})', 'GitLab Runner', 'confirmed', ['gitlab'])
    add(r'(glso-[A-Za-z0-9_\-]{20,})', 'GitLab Service', 'confirmed', ['gitlab'])
    add(r'circleci-[a-f0-9]{40}', 'CircleCI Token', 'confirmed', ['ci_cd','circleci'])
    add(r'bkua_[a-zA-Z0-9]{40}', 'Buildkite Token', 'confirmed', ['ci_cd','buildkite'], 4.0)
    add(r'pul-[a-zA-Z0-9]{40}', 'Pulumi Token', 'confirmed', ['ci_cd','pulumi'], 4.0)
    add(r'BBDC-[A-Za-z0-9]{32,}', 'Bitbucket Token', 'confirmed', ['ci_cd','bitbucket'], 4.0)
    add(r'(?i)codecov[_-]?token\s*[=:]\s*[\'"`]?([A-Za-z0-9\-]{36})[\'"`]?', 'Codecov Token', 'confirmed', ['ci_cd','codecov'])

    # OpenAI & AI (20)
    add(r'(sk-[A-Za-z0-9]{48})', 'OpenAI API Key', 'confirmed', ['ai','openai'], 4.0)
    add(r'(sk-proj-[A-Za-z0-9_\-]{40,})', 'OpenAI Project Key', 'confirmed', ['ai','openai'], 4.0)
    add(r'(org-[A-Za-z0-9_\-]{20,})', 'OpenAI Org ID', 'info', ['ai','openai'])
    add(r'(sk-ant-api\d+-[A-Za-z0-9_\-]{40,})', 'Anthropic Key', 'confirmed', ['ai','anthropic'])
    add(r'(hf_[a-zA-Z0-9]{34,})', 'HuggingFace Token', 'confirmed', ['ai','huggingface'])
    add(r'(gsk_[A-Za-z0-9]{52})', 'Groq Key', 'confirmed', ['ai','groq'], 4.0)
    add(r'(pplx-[A-Za-z0-9]{48})', 'Perplexity Key', 'confirmed', ['ai','perplexity'], 4.0)
    add(r'(sk-or-v1-[A-Za-z0-9]{48})', 'OpenRouter Key', 'confirmed', ['ai','openrouter'], 4.0)
    add(r'(r8_[A-Za-z0-9]{40})', 'Replicate Token', 'confirmed', ['ai','replicate'])
    add(r'(tvly-[A-Za-z0-9]{32})', 'Tavily Key', 'confirmed', ['ai','tavily'], 4.0)
    add(r'(fw_[A-Za-z0-9]{32,})', 'Fireworks Key', 'confirmed', ['ai','fireworks'], 4.0)
    add(r'(esecret_[A-Za-z0-9_\-]{40,})', 'Anyscale Key', 'confirmed', ['ai','anyscale'], 4.0)
    add(r'(?i)cohere[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9]{32,})[\'"`]?', 'Cohere Key', 'confirmed', ['ai','cohere'], 3.5)
    add(r'(?i)mistral[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9]{32,})[\'"`]?', 'Mistral Key', 'confirmed', ['ai','mistral'], 3.5)
    add(r'(?i)deepgram[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([a-f0-9]{32})[\'"`]?', 'Deepgram Key', 'confirmed', ['ai','deepgram'])
    add(r'(?i)stability[_-]?ai[_-]?key\s*[=:]\s*[\'"`]?(sk-[A-Za-z0-9]{30,})[\'"`]?', 'Stability AI Key', 'confirmed', ['ai','stability'])
    add(r'(?i)elevenlabs[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([a-f0-9]{32})[\'"`]?', 'ElevenLabs Key', 'confirmed', ['ai','elevenlabs'])
    add(r'(?i)assemblyai[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9]{32})[\'"`]?', 'AssemblyAI Key', 'confirmed', ['ai','assemblyai'])
    add(r'(?i)runwayml[_-]?api[_-]?key\s*[=:]\s*[\'"`]?([a-f0-9]{32,})[\'"`]?', 'RunwayML Key', 'confirmed', ['ai','runwayml'])
    add(r'(?i)together[_-]?ai[_-]?key\s*[=:]\s*[\'"`]?([A-Za-z0-9]{30,})[\'"`]?', 'Together AI Key', 'confirmed', ['ai','together'])

    # Generic Secrets with KEY=VALUE - Catches password=12345, pwd=12345, etc.
    add(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"`]?([^\'"`\s]{3,})[\'"`]?', 'Hardcoded Password', 'confirmed', ['generic','password'], 2.0)
    add(r'(?i)(?:secret|secret_key|secretkey)\s*[=:]\s*[\'"`]?([^\'"`\s]{6,})[\'"`]?', 'Hardcoded Secret', 'confirmed', ['generic','secret'], 2.5)
    add(r'(?i)(?:api_key|apikey)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{12,})[\'"`]?', 'Generic API Key', 'confirmed', ['generic','api-key'], 3.0)
    add(r'(?i)(?:api_secret|apisecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.~!@#]{12,})[\'"`]?', 'Generic API Secret', 'probable', ['generic','secret'], 3.5)
    add(r'(?i)(?:access_token|accesstoken)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{16,})[\'"`]?', 'Access Token', 'confirmed', ['generic','token'], 3.0)
    add(r'(?i)(?:auth_token|authtoken)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{16,})[\'"`]?', 'Auth Token', 'probable', ['generic','token'], 3.0)
    add(r'(?i)(?:client_secret|clientsecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.~]{20,})[\'"`]?', 'OAuth Client Secret', 'confirmed', ['generic','oauth'], 3.0)
    add(r'(?i)(?:private_key|privatekey)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-+\/=]{40,})[\'"`]?', 'Private Key Value', 'confirmed', ['generic','crypto'], 4.0)
    add(r'(?i)(?:encryption_key|encryptionkey)\s*[=:]\s*[\'"`]?([A-Za-z0-9+\/=]{32,})[\'"`]?', 'Encryption Key', 'confirmed', ['generic','crypto'], 3.5)
    add(r'(?i)(?:jwt_secret|jwtsecret)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]?', 'JWT Secret', 'confirmed', ['generic','jwt'], 3.5)
    add(r'(?i)(?:master_key|masterkey)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-!@#$%^&*]{32,})[\'"`]?', 'Master Key', 'confirmed', ['generic','crypto'], 3.5)
    add(r'(?i)(?:token|key)\s*[=:]\s*[\'"`]?([A-Za-z0-9_\-\.]{16,})[\'"`]?', 'Generic Token/Key', 'possible', ['generic'], 3.5)
    add(r'(?i)(?:db_password|dbpassword|database_password)\s*[=:]\s*[\'"`]?([^\'"`\s]{4,})[\'"`]?', 'DB Password', 'confirmed', ['generic','database'], 2.0)
    add(r'(?i)(?:admin_password|root_password)\s*[=:]\s*[\'"`]?([^\'"`\s]{4,})[\'"`]?', 'Admin Password', 'confirmed', ['generic','password'], 2.0)

    # Database DSNs (18)
    add(r'mongodb\+srv:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MongoDB Atlas DSN', 'confirmed', ['database','mongodb'], 2.5)
    add(r'mongodb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MongoDB DSN', 'confirmed', ['database','mongodb'], 2.5)
    add(r'postgresql:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'PostgreSQL DSN', 'confirmed', ['database','postgresql'], 2.5)
    add(r'postgres:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Postgres DSN', 'confirmed', ['database','postgresql'], 2.5)
    add(r'mysql:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MySQL DSN', 'confirmed', ['database','mysql'], 2.5)
    add(r'mariadb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'MariaDB DSN', 'confirmed', ['database','mariadb'], 2.5)
    add(r'redis:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Redis DSN', 'confirmed', ['database','redis'], 2.5)
    add(r'rediss:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Redis TLS DSN', 'confirmed', ['database','redis'], 2.5)
    add(r'clickhouse:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'ClickHouse DSN', 'confirmed', ['database','clickhouse'], 2.5)
    add(r'cassandra:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'Cassandra DSN', 'confirmed', ['database','cassandra'], 2.5)
    add(r'cockroachdb:\/\/[^:\s]+:[^@\s]+@[^\s"\'`<>]+', 'CockroachDB DSN', 'confirmed', ['database','cockroachdb'], 2.5)
    add(r'jdbc:[a-zA-Z]+:\/\/[^\s"\'`<>]+', 'JDBC String', 'confirmed', ['database','jdbc'], 2.5)
    add(r'sqlite:\/\/\/[^\s]+', 'SQLite Path', 'info', ['database','sqlite'])
    add(r'(?i)(?:database_url|db_url|db_uri)\s*[=:]\s*[\'"`]?([^\'"`]+)[\'"`]?', 'DB URL Generic', 'confirmed', ['database'])
    add(r'(?i)(?:redis_password|redis_pass)\s*[=:]\s*[\'"`]?([A-Za-z0-9]{8,})[\'"`]?', 'Redis Password', 'confirmed', ['database','redis'])
    add(r'mongodb\.net\/[a-zA-Z0-9\-_]+', 'MongoDB Atlas Cluster', 'info', ['database','mongodb'])
    add(r'rediss:\/\/default:[^@]+@[^\s]+\.upstash\.io:\d+', 'Upstash Redis', 'confirmed', ['database','upstash'], 3.0)
    add(r'postgresql:\/\/[^:]+:[^@]+@[^\s]+\.neon\.tech', 'Neon DSN', 'confirmed', ['database','neon'], 2.5)

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
    """Token bucket rate limiter for HTTP requests."""
    def __init__(self, requests_per_second: float = 10.0):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.max_tokens = requests_per_second
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()
    
    def acquire(self):
        """Wait until a token is available."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
            self.last_refill = now
            
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(sleep_time)
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
        """Fetch URL with proper status code handling."""
        if self.rate_limiter:
            self.rate_limiter.acquire()
        
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; astra/1.3)',
                'Accept': 'text/html,application/javascript,*/*',
                'Accept-Encoding': 'identity',
            })
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as r:
                # SUCCESS - status is the actual HTTP status code
                status = r.getcode()
                ct = r.headers.get('Content-Type', '').lower()
                if any(t in ct for t in ['text', 'javascript', 'json', 'html', 'xml']):
                    return (url, r.read(10*1024*1024).decode('utf-8', errors='ignore'), status)
                return (url, None, status)
        except urllib.error.HTTPError as e:
            # HTTP error - e.code is the actual status (404, 403, 500, etc.)
            return (url, None, e.code)
        except urllib.error.URLError as e:
            # Connection error - host unreachable, DNS failure, etc.
            return (url, None, -1)
        except Exception:
            return (url, None, -2)
    
    def scan(self, url: str, content: str) -> List[Dict]:
        """LINE-BY-LINE scanning with context-aware detection."""
        findings = []
        for ln, line in enumerate(content.split('\n'), 1):
            for pat, name, sev, tags, ent_min in self.compiled:
                try:
                    for m in pat.finditer(line):
                        val = m.group(1) if m.lastindex else m.group(0)
                        val = val.strip()
                        if not self.no_fp and is_false_positive(val, line):
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
    
    def process_url(self, url: str, depth: int = 0) -> Tuple[str, List[Dict], Set[str], int]:
        """Process a single URL."""
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
                            if not self.json_output:
                                self._show(url, findings, status)
                        elif self.verbose:
                            self._show_status(url, status)
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
        if status >= 200 and status < 300: return C.G
        if status >= 300 and status < 400: return C.Y
        if status >= 400 and status < 500: return C.Y
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
        # Status code summary
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
    parser = argparse.ArgumentParser(description='astra — Live JS Secret Detection Engine v1.3', add_help=False)
    parser.add_argument('-u', '--urls', nargs='*', help='URLs to scan')
    parser.add_argument('-f', '--file', help='File with URLs')
    parser.add_argument('-s', '--severity', default='possible', choices=['confirmed','probable','possible','info'])
    parser.add_argument('-r', '--show-raw', action='store_true', help='Show raw secrets')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all URLs')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    parser.add_argument('-j', '--json', action='store_true', help='JSON output')
    parser.add_argument('--tags', help='Filter by tags (aws,stripe,github)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout (default: 30s)')
    parser.add_argument('-d', '--depth', type=int, default=1, help='JS URL depth (default: 1)')
    parser.add_argument('--no-follow', action='store_true', help="Don't follow JS URLs")
    parser.add_argument('--no-fp', action='store_true', help='Disable FP filter')
    parser.add_argument('--rate', type=float, default=0, help='Rate limit (requests/sec, 0=unlimited)')
    parser.add_argument('-l', '--list', action='store_true', help='List patterns')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    
    args = parser.parse_args()
    
    if args.help:
        print(f"""
{C.BOLD}astra v1.3 — Live JS Secret Detection Engine{C.RST}

{C.BOLD}USAGE:{C.RST}
  {C.C}astra -u https://example.com/app.js{C.RST}     Scan a single URL
  {C.C}astra -f urls.txt{C.RST}                       Scan URLs from file
  {C.C}cat urls.txt | astra{C.RST}                    Pipe URLs via stdin
  {C.C}astra -f urls.txt -s confirmed -r{C.RST}       Confirmed only, show raw
  {C.C}astra -f urls.txt -t 50 -d 2 --rate 10{C.RST}  50 threads, depth 2, 10 req/s
  {C.C}astra -f urls.txt --tags aws,stripe{C.RST}     Filter by tags
  {C.C}astra -l{C.RST}                                 List all patterns

{C.BOLD}FLAGS:{C.RST}
  -u, --urls      URLs to scan (space-separated)
  -f, --file      File with URLs (one per line)
  -s, --severity  Minimum severity: confirmed|probable|possible|info
  -r, --show-raw  Show raw secret values
  -v, --verbose   Show all URLs being scanned
  -q, --quiet     Minimal output (only findings)
  -j, --json      JSON output format
  --tags          Filter by tags (comma-separated: aws,stripe,ai,github)
  -t, --threads   Concurrent threads (default: 20)
  --timeout       Request timeout in seconds (default: 30)
  -d, --depth     Max depth for JS URL extraction (default: 1)
  --no-follow     Don't follow extracted JS URLs
  --no-fp         Disable false positive filter
  --rate          Rate limit in requests/second (0=unlimited)
  -l, --list      List all detection patterns
  -h, --help      Show this help message
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
