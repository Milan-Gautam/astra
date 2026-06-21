# Astra

```
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
  secret & credential scanner
```

318 patterns · zero dependencies · Python 3.10+

---

## Install

```bash
curl -O https://raw.githubusercontent.com/Milan-Gautam/astra/main/astra.py
chmod +x astra.py
```

No pip. No Go. No Docker.

---

## Usage

```bash
FLAGS:
  -u, --urls      URLs to scan
  -f, --file      File with URLs (one per line)
  -s, --severity  confirmed|probable|possible|info (default: possible)
  -r, --show-raw  Show raw secrets
  -v, --verbose   Show all URLs
  -q, --quiet     Minimal output
  -j, --json      JSON output
  --tags          Filter by tags (aws,stripe,github)
  -t, --threads   Threads (default: 20)
  --timeout       Timeout seconds (default: 30)
  --retries       Extra fetch attempts on transient failure (default: 2)
  -d, --depth     JS URL depth (default: 1)
  --no-follow     Don't follow JS URLs
  --no-fp         Disable FP filter
  -l, --list      List rules
```

---

## Severity

| Label | Meaning |
|---|---|
| `◆ confirmed` | Unambiguous format — extremely rare false positives |
| `◇ probable` | Strong match — worth a quick manual check |
| `○ possible` | Lower confidence — verify manually |
| `· info` | Recon data (IPs, emails, endpoints) |

---

## Comparison with other tools

| Feature | **Astra** | **Gitleaks** | **TruffleHog** | **SecretFinder** |
|---|:---:|:---:|:---:|:---:|
| **Pattern count** | 318 regex patterns | ~150 built-in + custom TOML rules | Similar curated set + verification | Smaller, JS-focused regex set |
| **Live secret verification** | ❌ No — format match only | ❌ No | ✅ Yes — actively validates AWS/GitHub/Stripe and other supported credentials against their APIs | ❌ No |
| **Entropy analysis** | ✅ Yes, per-pattern thresholds | ✅ Yes | ✅ Yes | Limited |
| **Git history scanning** | ❌ No — scans live URLs only | ✅ Yes — core use case | ✅ Yes — full git history, including deleted commits | ❌ No |
| **Maturity / false-positive tuning** | New, hand-tuned, still settling | Years of community-hardened tuning | Years of community-hardened tuning + active maintenance | Mature, JS-focused |
| **JS-specific recon** (endpoints, admin paths, source maps, internal IPs) | ✅ Yes | ❌ No | ❌ No | ✅ Yes |

**Where astra doesn't try to compete:** it has no verification step, so every finding is "this is shaped like a secret," not "this credential is currently live." For that, pair astra's output with TruffleHog. Astra also doesn't touch git history at all — it only fetches what's live over HTTP right now.

**Where astra is built differently:** it's purpose-built for scanning live JS/TS bundles over the wire — fetching URLs, following discovered `.js` references, and reporting accurate per-URL HTTP status alongside findings — rather than scanning a local git checkout.

---

## What it finds

Real counts from the current pattern set (`astra -l` to see the full breakdown):

**Payment** (26) — Stripe live/test/restricted keys + webhook secret, PayPal + Braintree, Square, Razorpay, Paystack, WooCommerce, Adyen, Flutterwave, Mollie, Revolut, Checkout.com, Klarna, Affirm

**SaaS platforms** (24) — Notion, Figma, Databricks, HashiCorp Vault, Shopify, Cloudinary, Mapbox, WakaTime, Inngest, Doppler, Linear, Typeform, EasyPost, Duffel, Xata, PlanetScale, Contentful, Sanity, Hygraph, Strapi, Ghost, Appwrite

**Database** (23) — MySQL, PostgreSQL, MongoDB (incl. Atlas), Redis, MariaDB, ClickHouse, CockroachDB, Cassandra, JDBC, SQLite, Supabase, Neon, Upstash

**AI / LLM** (20) — OpenAI (`sk-` classic + `sk-proj-`), Anthropic, HuggingFace, Groq, Perplexity, OpenRouter, Replicate, Together AI, Mistral, ElevenLabs, Deepgram, AssemblyAI, Stability AI, Cohere, Fireworks AI, Anyscale, Tavily

**AWS** (18) — Access Key ID, STS/billing/context keys, secret access key, session tokens, MWS auth token, plus recon patterns for S3/CloudFront/RDS/ELB/etc. URLs

**Cloud hosting** (17) — DigitalOcean, Render, Scaleway, Alibaba Cloud, Heroku, Cloudflare, Netlify, Vercel, Linode, Vultr, Fastly, IBM Cloud

**Google Cloud** (16) — API keys, OAuth tokens/client secrets, reCAPTCHA, Firebase Cloud Messaging, GCP/Firebase project IDs, BigQuery, Pub/Sub, Cloud Run, Spanner

**Messaging** (16) — Slack token + webhook, Discord bot token + webhook, Telegram bot token, Twilio, SendGrid, Mailgun, Zendesk, Intercom, PagerDuty, Opsgenie, Pushover, Vonage, RocketChat

**Crypto / private keys** (16) — RSA, DSA, EC, OpenSSH, PGP, PKCS8 (plain + encrypted) private key headers, JWTs, SSH/SSL key values, Basic Auth, X-API-Key headers

**Recon** (16) — private IPv4, email addresses, URL endpoint discovery, GraphQL endpoints, admin panels, Swagger/OpenAPI specs, health/debug endpoints, source map references

**Azure** (14) — Storage connection strings, Service Bus, Blob SAS tokens, DevOps PAT, Client ID/Secret/Tenant ID, Key Vault, Cosmos DB, Blob/MySQL/PostgreSQL/Redis hostnames

**Generic credentials** (14) — `password=`, `secret=`, `api_key=`, `client_secret=`, `private_key=`, `refresh_token=`, encryption/session/JWT/master keys — all require a matching contextual keyword in the line to reduce noise

**Web3** (14) — Ethereum/Bitcoin addresses, Alchemy, Etherscan, Infura, Solana private keys, Moralis, WalletConnect, QuickNode, Chainstack, BlockCypher

**Security issues** (14) — DOM XSS via `eval(location)`/`innerHTML` templates/`document.write`, command injection (`exec`, `execSync`), `pickle.loads`, VM sandbox escape, SQLi/NoSQLi via concatenation, prototype pollution, path traversal, SSRF

**Source control / CI** — GitHub PAT (classic + fine-grained) + Actions/OAuth/refresh tokens, GitLab PAT + deploy/runner/CI-job tokens, CircleCI, Buildkite, Pulumi

**Config / environment** (11) — Django/Flask `SECRET_KEY`, Laravel `APP_KEY`, Rails master key, JWT/session/cookie secrets, `process.env.*` references

**Social media** — Twitter/X bearer token, Facebook access token, Twitch OAuth + client secret, LinkedIn, Instagram, Reddit, TikTok, Pinterest, Snapchat

**URL-embedded credentials** — Basic Auth in URLs, secrets in query parameters, cURL commands with inline credentials

**CMS** — WordPress nonces, Drupal, Joomla, Magento, PrestaShop, BigCommerce, Wix

> Not yet covered, despite earlier drafts of this README claiming otherwise: Bitbucket, Codecov, Terraform Cloud, Wise, WorkOS, Stytch, Liveblocks, and `postMessage`-based XSS. If you use these, a pattern-file PR is genuinely the fastest way to get them added — see Contributing.

---

## Design philosophy

astra takes a **precision-first, JS-aware approach** rather than maximizing pattern count alone. Key design decisions:

- **Line-by-line scanning with chunking** — extremely long minified lines are split into overlapping windows so multi-megabyte bundles get fully scanned, not just the first portion before a slow pattern stalls
- **Context-aware false positive filter** — generic catch-all patterns (tagged `generic`) require a matching secret-keyword nearby in the line; pattern-specific, strict-format matches (AWS `AKIA...`, GitHub `ghp_...`, Stripe `sk_live_...`, etc.) do **not** need extra context, since the format itself is the confirmation
- **Per-pattern entropy thresholds** — filters out low-randomness strings (repeated characters, sequential patterns) that match a format but clearly aren't a real secret; the tradeoff is that an intentionally low-entropy test/demo key can occasionally be filtered along with the noise
- **HEAD+GET status verification with retries** — HEAD is used as a best-effort optimization only; GET is always the authoritative source for the reported status code, and `--retries` (default 2) absorbs transient timeouts/connection errors before a URL is reported dead
- **Threaded URL fetching** with discovered-`.js`-URL following, up to `--depth` levels
- **4-tier severity classification** (confirmed → probable → possible → info) to help prioritize triage
- **Tag-based filtering** (`--tags aws,stripe`) to scope a run to specific categories

**What astra does not do:** validate that a found credential is actually live (no API calls back to AWS/Stripe/etc. to confirm), and it doesn't touch git history — only what's reachable over HTTP right now. astra is meant to complement tools like TruffleHog and Gitleaks for JS/TS-heavy codebases and live web targets, not replace them.

---

## 🥟 Buy Me a Momo

Love **astra**? Treat me to some momos → [Click here to donate](https://buymemomo.com/milang)

## Contributing

I'd be particularly interested in **new pattern files**. If there's something you regularly grep for in your own work, PRs adding pattern files to the `examples/` directory are very welcome — especially for the services listed as "not yet covered" above.

Bug fixes are, as always, appreciated.
