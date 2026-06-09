# Astra

```
     _    ____ _____ ____      _
    / \  / ___|_   _|  _ \    / \
   / _ \ \___ \ | | | |_) |  / _ \
  / ___ \ ___) || | |  _ <  / ___ \
 /_/   \_\____/ |_| |_| \_\/_/   \_\
  secret & credential scanner
```

350+ patterns · zero dependencies · Python 3.10+

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
# pipe JS file
curl -s https://target.com/static/app.js | python3 astra.py

# pipe URL list
cat urls.txt | python3 astra.py

# scan file
python3 astra.py bundle.js

# scan directory
python3 astra.py ./src/ --ext js,ts,json,env

# fetch URLs and scan response bodies
cat urls.txt | python3 astra.py --fetch --threads 20

# only certain matches, no noise
python3 astra.py app.js -s confirmed

# JSON output
python3 astra.py app.js --json | jq '.[] | select(.sev=="confirmed")'

# filter by tag
python3 astra.py app.js --tags ai,aws,payment

# list all patterns
python3 astra.py --list
```

---

## Flags

| Flag | Description |
|---|---|
| `-s SEV` | Min severity: `confirmed` `probable` `possible` `info` (default: `info`) |
| `--fetch` | Fetch each URL and scan the HTTP response body |
| `--threads N` | Worker threads for `--fetch` (default: 10) |
| `--json` | Output as JSON array |
| `--show-match` | Show unredacted match values |
| `--no-color` | Disable ANSI colors |
| `--list` | Print all patterns and exit |
| `--tags TAGS` | Comma-separated tag filter |
| `--ext EXT` | Directory mode file extensions |

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

| Feature | **astra** | trufflehog v3 | gitleaks v8 |
|---|:---:|:---:|:---:|
| **Pattern count** | 307 | ~700 | ~160 |
| **JS-specialized** (AST + source maps) | **✓** | — | — |
| **URL fetch + scan** | **✓** (threaded) | — | — |
| **False positive handling** | **Excellent** | Poor | Poor |
| **AI/LLM tokens** | **14+** | 4–5 | 3–4 |
| **Payment providers** | **12+** | 1 | 2 |
| **Security sink detection** | **✓** (XSS/RCE/SQLi) | — | — |
| **Severity classification** | 4 tiers | 2 tiers | 3 tiers |
| **Git history scanning** | — | ✓ | ✓ |
| **Pre-commit hook** | — | ✓ | ✓ |
| **Live API verification** | stub | ✓ (100+ services) | — |
| **SARIF output** | — | ✓ | ✓ |
| **JSON output** | ✓ | ✓ | ✓ |
| **Install method** | Single binary | Go/Docker | Go |
| **Dependencies** | None (stdlib) | 40+ modules | 20+ modules |
| **Scan speed** | ~5k lines/s | ~1k lines/s | ~10k lines/s |

## What it finds

**Cloud** — AWS key ID + secret, GCP service account, Azure Storage DSN, DigitalOcean PAT

**AI / LLM** — OpenAI (`sk-` classic + `sk-proj-`), Anthropic, Google Gemini, HuggingFace, Groq (`gsk_`), Perplexity (`pplx-`), OpenRouter (`sk-or-v1-`), Replicate, Together AI, Mistral, ElevenLabs, Pinecone, Weaviate

**Source control / CI** — GitHub PAT + Actions token, GitLab PAT + deploy token, CircleCI, Travis CI, Jenkins

**Comms** — Slack token + webhook, Discord bot token + webhook, Telegram bot token

**Payment** — Stripe live/restricted/test keys + webhook secret, PayPal Braintree, Square

**Email** — Mailchimp, SendGrid, Mailgun

**Auth / sessions** — JWT, OAuth2 `client_secret`, `api_key=`, `access_token=`, `password=` (quoted values only), Basic Auth in URLs, secrets in query params

**Infra** — Heroku, Cloudflare, Cloudinary, Sentry DSN, Mapbox, Shopify, npm, PyPI, Datadog, New Relic, Algolia

**Crypto** — RSA / DSA / EC / PGP / OpenSSH / PKCS8 private key headers

**Database** — MySQL, PostgreSQL, MongoDB, Redis, MSSQL, MariaDB DSNs with credentials

**DOM XSS** — `eval(location.*)`, `innerHTML` from template literal, `document.write+location`, `postMessage+eval`

**Recon** — private IPv4, email addresses

## Design philosophy

astra takes a **precision-first, JS-aware approach** rather than maximizing pattern count. Key design decisions:

- **AST extraction** eliminates false positives by understanding code structure, not just regex matching
- **Source map support** traces minified production code back to original sources
- **Quoted-value enforcement** avoids flagging common variable assignments like `var x = req.token`
- **Per-pattern entropy thresholds** allow fine-tuned noise reduction
- **Threaded URL fetching** enables scanning live web applications at scale

astra complements general-purpose tools like trufflehog and gitleaks — it's a specialized instrument for JavaScript/TypeScript-heavy codebases and modern web stacks where precision matters.


## 🥟 Buy Me a Momo

Love **astra**? Treat me to some momos → [Click here to donate](https://buymemomo.com/milang)

## Contributing

I'd be particularly interested in **new pattern files**. If there's something you regularly grep for in your own work, PRs adding pattern files to the `examples/` directory are very welcome.

Bug fixes are, as always, appreciated.
