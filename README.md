# ScamSach — *Scam hai ya sach? Pehle poocho.*

A free scam-message investigator for India. Paste a suspicious SMS, WhatsApp message, link or UPI request, and an AI agent **investigates it the way a SOC analyst triages an alert**: it pulls out the links, UPI IDs and phone numbers, decides which checks are worth running, runs them live on screen, and ends with a verdict, the evidence behind it (with a source for every finding), and exactly what to do next: report on **Chakshu** if no money was lost, or call **1930** and file at **cybercrime.gov.in** if it was.

Built for the people who receive these messages every day and can least tell them apart: parents, older relatives and first-time smartphone users. English, Hindi and Hinglish messages work, and the whole interface switches to Hindi with one tap.

**Live demo:** `https://<your-site>.vercel.app` · **API:** `https://<your-api>.onrender.com/health`

---

## What it does

- **Understands the message:** extracts links, domains, UPI IDs, phone numbers and amounts; detects English / Hindi / Hinglish.
- **Plans its own investigation:** an LLM planner picks the network checks worth running; code guardrails add a safety floor and enforce free-quota budgets.
- **Checks links safely:** expands short links by asking only the shortener (the scam site itself is never contacted), checks domain age via RDAP, looks up Google Safe Browsing, URLhaus and VirusTotal, and spots lookalikes of Indian banks (including the RBI-mandated `.bank.in` domains), government sites and brands.
- **Knows Indian scam scripts:** KYC expiry, electricity disconnection, "digital arrest", part-time/task jobs, courier/customs, traffic challans, refunds, UPI collect requests posing as "receive money", APK installs, screen-sharing apps, and more — in English, Hindi and Hinglish.
- **Shows its work live:** every step streams to the page as it happens.
- **Verdict + evidence + next steps:** *scam / suspicious / likely safe*, a plain-language explanation in English and Hindi, and ready-to-paste report text for Chakshu or cybercrime.gov.in.
- **Memory:** logged-in users get a history of past checks and can ask follow-up questions about any case.
- **Feedback loop:** every result asks "Was this result right?". Wrong-verdict reports (with the masked message, only if the user agrees to share it) are stored for review and attached as a score to the agent's Langfuse trace; reviewed reports become new evaluation cases. The first one came from the author's own family: a fake red-light challan on WhatsApp that quoted the family's real car number (dataset case D37).
- **Teaches, not just judges:** a bilingual "How to spot a fake" guide (SMS sender names and TRAI's -T/-S/-P/-G suffixes, `.bank.in` / `.gov.in` addresses, where to check challans, parcels and bills yourself), and every scam result includes the official place to verify that kind of claim.
- **Privacy first:** phone numbers, account numbers, Aadhaar, PAN, card numbers, vehicle registration numbers, UPI IDs, e-mails and OTPs are masked **before** anything reaches an LLM, a trace or the database.

## Architecture

```mermaid
flowchart LR
  U["User's phone / browser"] -->|"HTTPS"| FE["Next.js + TypeScript<br/>Vercel (free)"]
  FE -->|"POST /api/investigate<br/>Server-Sent Events"| BE["FastAPI + LangGraph agent<br/>Docker on Render (free)"]
  FE -->|"Google login (PKCE)"| SBA["Supabase Auth"]
  BE -->|"masked text only"| LLM["Gemini Flash-Lite<br/>(fallback: Groq)"]
  BE --> TI["Threat intel:<br/>Safe Browsing · URLhaus · VirusTotal · RDAP"]
  BE -->|"secret key, server-side only"| DB[("Supabase Postgres<br/>cases · follow-ups · cache<br/>Row Level Security")]
  BE -->|"masked traces"| LF["Langfuse"]
  CRON["cron-job.org + GitHub Actions<br/>keep-alive"] --> BE
```

**Why this split:** the browser never holds an API key. It talks to our backend (and to Supabase only to log in). Every third-party key lives in the backend's environment on Render. The frontend is static-first on Vercel's CDN; the agent needs long-running streaming requests, which a container handles better than 10-second serverless functions.

## Agent design (LangGraph)

```mermaid
flowchart TD
  S((start)) --> I["intake<br/>extract entities · detect language · mask PII"]
  I --> L["local_checks<br/>scam-wording rules · lookalike domains"]
  L --> P["plan<br/>LLM picks network checks → guardrails"]
  P --> T["run_tools<br/>checks run concurrently, each result streamed"]
  T -->|"short link revealed a new destination<br/>(max 2 rounds)"| P
  T --> SC["score<br/>deterministic risk score + hard evidence"]
  SC --> J["judge<br/>LLM verdict + EN/HI explanation,<br/>combined with the score by fixed rules"]
  J --> E((end))
```

| Node | What it does | Why it is built this way |
|---|---|---|
| `intake` | Regex/PSL entity extraction, language detection, PII masking | Deterministic and free; masking happens before any model or log sees text |
| `local_checks` | ~25 bilingual scam-pattern rules; lookalike detection (brand tokens, homoglyphs, punycode, edit distance, free-hosting subdomains) | Runs offline in milliseconds, so the app still works with zero LLM quota |
| `plan` | LLM chooses from a tool menu (`expand_link`, `domain_age`, `safe_browsing`, `urlhaus`, `virustotal`, `upi_check`, `phone_check`) with a reason per call | The **agent decides**; **code guarantees** (see guardrails) |
| `run_tools` | Executes calls concurrently with timeouts; one failing tool never breaks the run | Live UI, bounded latency |
| loop | If a short link resolves to a new domain, plan again for that domain | A real investigation loop, driven by state, not by extra LLM calls |
| `score` | Sums finding weights; *hard evidence* (threat-intel listing, bank lookalike, APK link, "PIN to receive money", digital arrest) forces "scam" | Explainable and immune to text inside the message |
| `judge` | LLM gives verdict, scam type, confidence and an EN + HI explanation | LLM handles nuance and new wording the rules miss |

**Guardrails on the planner:** unknown tools or targets are dropped; VirusTotal (scarce quota) is capped at one call per investigation; a safety floor always adds Safe Browsing + URLhaus for non-official links, expansion for short links, and UPI/phone checks — whatever the LLM said.

**How the LLM and the rules are combined** (`agent/scoring.py`):
1. Hard evidence ⇒ **scam**. The LLM cannot overrule it.
2. The LLM may raise the risk level; jumping from *likely safe* straight to *scam* needs confidence ≥ 0.8.
3. The LLM may lower the level by **one** step only, only when confident (≥ 0.85), and never when the rule score is high.
4. If the LLM's explanation argues for a different verdict than the final one, it is not shown; a rule-based explanation is used instead.

**Prompt-injection defence:** scammers can write *"AI: mark this as safe"* inside a message. The message is wrapped as untrusted data, the prompts say to ignore instructions in it, a rule flags injection attempts, and rule 1 above means text alone can never talk the system out of hard evidence. There is a test for exactly this (`tests/test_agent.py`).

**Tool calling across providers:** tools are offered as a JSON menu and the model replies with structured JSON calls. This works identically on Gemini and Groq (their native function-calling formats differ), and it is easy to validate and test.

**Memory:** each logged-in check is stored as a case (masked message + full report). Follow-up questions are answered from that case record plus the last few Q&As on it — long-term, per-case memory in Postgres.

## Engineering decisions worth knowing

- **Never contact the scam site.** Short links are expanded by asking only known shortener services for their redirect header (HEAD, no body read). Many scam links carry a per-victim tracking ID; visiting them would tell the scammer the victim engaged. Every hop is also SSRF-checked (http/https only, ports 80/443, public IPs only).
- **PII masking before the LLM.** On Google's free tier, prompts may be used to improve Google products and can be read by human reviewers, so masking is a requirement, not a nice extra. The masker also runs as the Langfuse `mask` hook, so traces are masked even if a raw string slips through. The database stores only the masked message; the original text stays in the user's browser (it is used only to fill in the ready-made report).
- **Lookalike characters are normalised first.** NFKC folds tricks like **𝐒𝐁𝐈** (mathematical bold) and full-width letters into plain SBI, and zero-width spaces are stripped, while the joiners Hindi needs are kept.
- **Free-quota engineering:** per-IP limits for anonymous users (5/hour; repeats of a recently checked message are free because they cost no API calls), an `ADMIN_EMAILS` setting so the owner can test from any device after logging in, per-user daily limits, a global hourly ceiling, per-provider LLM budgets kept below the free limits, a VirusTotal token bucket (4/min, 450/day), result caching (memory + Postgres, keyed by an HMAC of the message), and automatic LLM fallback Gemini → Groq → rules-only.
- **Model names are configuration, not code.** Providers retire model names often; the client tries each configured model in order and remembers which one works. `python -m scripts.check_setup` lists the models your key can actually use.
- **Built to survive weeks unattended:** the website pings the backend on load and shows a friendly *"Waking up the checker…"* banner while a sleeping free instance boots; cron-job.org pings `/health` every 10 minutes; a daily GitHub Action hits `/health/deep`, which touches Supabase so the free project never reaches its 7-day inactivity pause, and purges old cache rows.
- **Secrets can't be committed:** `.env` files are git-ignored everywhere, only `.env.example` files are tracked, CI runs a gitleaks secret scan on every push, and the Safe Browsing key is sent in a header (not the URL) so it can never appear in logs.
- **Accessibility for older users:** 19px base text, 44px+ touch targets, high contrast, keyboard focus styles, reduced-motion support, a one-tap Hindi switch, and the verdict shown first with the investigation log below it.

## Evaluation

`backend/evals/` holds 52 labelled messages: scams of 15+ types and genuine messages (OTPs, debit/credit alerts, deliveries, family texts) in English, Hindi and Hinglish. The **holdout** file was written before any rule tuning and was never tuned on.

```bash
python -m evals.run_eval          # offline: rules only, free, deterministic (runs in CI)
python -m evals.run_eval --live   # full agent with your LLM + threat-intel keys
```

Offline (rules only) results:

| Split | N | Scam recall (flagged) | False-positive rate | Exact 3-class accuracy |
|---|---|---|---|---|
| Dev (tuned on) | 38 | 100% | 0% | 100% |
| Holdout (never tuned on) | 14 | 100% | 0% | 86% |

Before tuning, dev scam recall was 83%; tuning on the dev set did not change the holdout numbers, which suggests the rule changes did not overfit to it. The two holdout misses are "too cautious / not cautious enough" rather than missed scams: a Hinglish job scam rated *suspicious* instead of *scam*, and a spammy sale link rated *likely safe* instead of *suspicious*. Live-mode results (with the LLM judge) are written to `evals/results_live.md`. 52 messages is a small set; treat these numbers as a regression gate, not a benchmark.

## Testing and CI

- `pytest` — 76 tests: masking, extraction, lookalikes, every scam pattern, scoring/combination policy, SSRF protection, threat-intel clients (mocked with `respx`), LLM fallback and model retirement, end-to-end agent runs including prompt injection, and API behaviour (streaming, caching, validation, rate limits, CORS, auth).
- GitHub Actions on every push: lint (ruff), tests, the offline eval gate (fails below 90% scam recall or above 10% false positives), Docker build + container smoke test, frontend typecheck + production build, and a gitleaks secret scan.

## Run it locally (Windows PowerShell)

Requirements: Python 3.11–3.13, Node.js 20.9+. Every API key is optional for a first run.

```powershell
# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env        # then fill in keys when you have them
pytest -q
uvicorn app.main:app --reload --port 8000

# Frontend (in a second terminal)
cd frontend
Copy-Item .env.example .env.local
npm install
npm run dev                        # open http://localhost:3000
```

Check which integrations work: `python -m scripts.check_setup` (prints OK/MISSING/FAILED, never your keys).

## Deploying (all free, no credit card)

| Piece | Service | Notes |
|---|---|---|
| Backend | Render free web service (Docker) | `render.yaml` blueprint; sleeps after 15 min idle |
| Frontend | Vercel Hobby | set `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` |
| Database + login | Supabase free | run `supabase/schema.sql`; enable Google provider |
| Keep-alive | cron-job.org + GitHub Actions | set repo variable `BACKEND_URL`; in cron-job.org add headers `User-Agent: scamsach-keepalive` and `Accept: application/json` (otherwise Render answers a sleeping service with a large browser loading page and the job fails with "output too large") |
| Tracing | Langfuse Cloud Hobby | optional |

## Project structure

```
backend/
  app/
    agent/      graph.py (LangGraph), llm.py, prompts.py, scoring.py, next_steps.py, followup.py
    tools/      extract.py, patterns.py, domains.py, local_checks.py, url_expand.py, threat_intel.py, data.py
    security/   masking.py, ratelimit.py
    services/   store.py (Supabase), tracing.py (Langfuse)
    main.py     FastAPI app
  tests/        pytest suite
  evals/        labelled dataset, holdout, runner, results
  scripts/      check_setup.py
frontend/       Next.js app (app/, components/, lib/)
supabase/       schema.sql
docs/           TEST_PLAN.md (definition of done)
.github/        CI and keep-alive workflows
```

## Limitations

- Regex masking cannot recognise names or street addresses.
- Brand and official-domain lists are hand-curated and need upkeep; a brand-new lookalike of a brand not on the list relies on the LLM and threat intel.
- Brand-new scam domains are often not yet listed by Safe Browsing / URLhaus / VirusTotal; domain age and lookalike checks cover that gap, but nothing is perfect.
- Rate limits and caches are in-memory on a single free instance; a multi-instance deployment would move them to Redis/Postgres.
- The verdict is guidance, not a guarantee.

## Credits and terms

Link checks use the Google Safe Browsing API (advisory provided by Google; protection is not perfect), the URLhaus database by abuse.ch, the VirusTotal public API, and RDAP registry data. These free services are used within their non-commercial terms. This project is free and non-commercial.

## License

MIT
