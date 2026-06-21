# Astra

```
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
  secret & credential scanner
```

300+ patterns · zero dependencies · Python 3.10+

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
| `· info` | Recon data (IPs, emails) |

---

## Comparison with other tools

| Feature | **Astra** | **Gitleaks** | **TruffleHog** | **SecretFinder** |
|---|:---:|:---:|:---:|:---:|
| **Pattern set** | 318 regex patterns | ~150 + custom TOML rules | Curated patterns + verification | Smaller JS-focused set |
| **Live secret verification** | ❌ | ❌ | ✅ | ❌ |
| **Entropy analysis** | ✅ (per-pattern thresholds) | ✅ | ✅ | Limited |
| **Git history scanning** | ❌ | ✅ | ✅ | ❌ |
| **Scans deleted commits** | ❌ | ✅ | ✅ | ❌ |
| **Live URL / JS scanning** | ✅ | ❌ | ❌ | ✅ |
| **Status-code aware fetching** | ✅ | ❌ | ❌ | ❌ |
| **JS bundle focused** | ✅ | ❌ | ❌ | ✅ |
| **JS recon findings** (endpoints, admin paths, source maps, internal IPs) | ✅ | ❌ | ❌ | ✅ |
| **Primary target** | Live web assets | Git repositories | Git repositories | JavaScript files |
| **Credential validation** | Pattern matching only | Pattern matching only | Real API verification | Pattern matching only |
| **Rule maturity** | New, hand-tuned | Community-hardened | Community-hardened + actively maintained | Mature, JS-focused |
| **False-positive tuning** | Early-stage | Mature | Mature | Mature |
| **Best use case** | Pentest recon + JS secret hunting | Repository auditing | Verified secret detection | Client-side JS analysis |

---

## What it finds

**Cloud** — AWS key ID + secret, GCP service account, Azure Storage DSN, DigitalOcean PAT, Cloudflare, Heroku, Netlify, Vercel, Linode, Scaleway, Alibaba Cloud

**AI / LLM** — OpenAI (`sk-` classic + `sk-proj-`), Anthropic, Google Gemini, HuggingFace, Groq (`gsk_`), Perplexity (`pplx-`), OpenRouter (`sk-or-v1-`), Replicate, Together AI, Mistral, ElevenLabs, Deepgram, AssemblyAI, Stability AI, Cohere, Fireworks AI, Anyscale, Tavily

**Source control / CI** — GitHub PAT + Actions token, GitLab PAT + deploy token, CircleCI, Travis CI, Jenkins, Buildkite, Pulumi, Bitbucket, Codecov, Terraform Cloud

**Comms** — Slack token + webhook, Discord bot token + webhook, Telegram bot token, Twilio, SendGrid, Mailgun, Zendesk, Intercom, PagerDuty

**Payment** — Stripe live/restricted/test keys + webhook secret, PayPal Braintree, Square, Razorpay, Paystack, WooCommerce, Adyen, Flutterwave, Mollie, Revolut, Wise, Checkout.com

**Email** — Mailchimp, SendGrid, Mailgun, Resend

**Auth / sessions** — JWT, OAuth2 `client_secret`, `api_key=`, `access_token=`, `password=` (quoted values only), Basic Auth in URLs, secrets in query params, Okta, Auth0, WorkOS, Stytch, Liveblocks

**Crypto** — RSA / DSA / EC / PGP / OpenSSH / PKCS8 private key headers

**Database** — MySQL, PostgreSQL, MongoDB, Redis, MSSQL, MariaDB, ClickHouse, CockroachDB, Cassandra DSNs with credentials, Supabase, PlanetScale, Neon, Upstash, Turso, Xata

**DOM XSS** — `eval(location.*)`, `innerHTML` from template literal, `document.write+location`, `postMessage+eval`

**RCE / Injection** — `child_process.exec`, `pickle.loads`, `vm.runInNewContext`, SQLi via concatenation, NoSQL injection, prototype pollution, path traversal, SSRF

**Recon** — private IPv4, email addresses, API endpoints, GraphQL endpoints, admin panels, Swagger/OpenAPI specs, source maps, debug endpoints

---

## Design philosophy

astra takes a **precision-first, JS-aware approach** rather than maximizing pattern count. Key design decisions:

- **Line-by-line scanning** with context extraction ensures every match includes surrounding code for verification
- **Strict false positive filter** eliminates common JavaScript identifiers, minified code chunks, and hex strings
- **Quoted-value enforcement** avoids flagging common variable assignments like `var x = req.token`
- **Per-pattern entropy thresholds** allow fine-tuned noise reduction
- **Threaded URL fetching** enables scanning live web applications at scale
- **4-tier severity classification** (confirmed → probable → possible → info) helps prioritize findings
- **Tag-based filtering** allows targeting specific categories (aws, stripe, ai, etc.)

astra complements general-purpose tools like trufflehog and gitleaks — it's a specialized instrument for JavaScript/TypeScript-heavy codebases and modern web stacks where precision matters.

---

## 🥟 Buy Me a Momo

Love **astra**? Treat me to some momos → [Click here to donate](https://buymemomo.com/milang)

## Contributing

I'd be particularly interested in **new pattern files**. If there's something you regularly grep for in your own work, PRs adding pattern files to the `examples/` directory are very welcome.

Bug fixes are, as always, appreciated.
