# SentinelRAG

SentinelRAG is a small, local-first cybersecurity runbook assistant built as a portfolio project. It retrieves relevant passages from a fixed set of fictional incident-response documents, can return grounded answers in offline mode, and optionally calls an OpenAI-compatible LLM API to produce a structured response.

It also demonstrates basic application controls: static API-key authentication, simple in-memory rate limiting, heuristic prompt-injection blocking, a retrieval-score refusal rule, and SQLite audit logging. **This is an educational prototype, not production-grade security software.**

## Features

- TF-IDF retrieval over eight local Markdown runbooks.
- `POST /ask` endpoint with citations and retrieval scores.
- `mode: "offline"` for local retrieval without an LLM API call.
- `mode: "llm"` for a configured OpenAI-compatible chat-completions provider.
- Refusal when no passage matches or the top retrieval score is below the configured threshold.
- Heuristic detection of several common prompt-injection phrases before retrieval/LLM calls.
- Static `X-API-Key` protection and an in-memory sliding-window request limit.
- SQLite audit events and a command-line audit viewer.
- Pytest unit and API tests, using a fake LLM in tests so tests do not consume API credits.

## Architecture

```text
Client
  |
  | POST /ask + X-API-Key
  v
FastAPI request validation
  |
  v
API-key check -> rate limit -> injection heuristic
  |                                   |
  |                                   +--> block (403) + audit log
  v
TF-IDF retrieval over local runbooks
  |
  +--> weak/no match -> refusal + audit log
  |
  v
Offline evidence response OR OpenAI-compatible LLM call
  |
  v
Citations + retrieval scores + SQLite audit log
```

## Requirements

- Python 3.11 or 3.12 recommended
- VS Code (or another Python editor)
- An LLM API key only if you want to use `mode: "llm"`; offline mode needs no LLM account or API credits.

## Setup on Windows PowerShell

Run these commands from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Open `.env` and replace `SENTINELRAG_API_KEY` with a long random local secret. Do not commit `.env`. For LLM mode, set `LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL` for your provider. The adapter expects an OpenAI-compatible `POST {LLM_BASE_URL}/chat/completions` endpoint. Provider-specific differences may require adjustments to `app/llm_client.py`.

After creating or editing `.env`, stop and restart Uvicorn. The application reads the fixed project-root path `C:\Users\ammun\Downloads\sentinelrag\sentinelrag\.env` when its settings are created; an already running worker keeps its existing settings. A usable `SENTINELRAG_API_KEY` set in the process environment takes precedence, while empty or example placeholder process values fall back to a usable value in `.env`.

To make the API key available to demo commands in your current PowerShell window, set it to the same value as `.env`:

```powershell
$env:SENTINELRAG_API_KEY = "replace-with-the-same-local-key-from-your-env-file"
```

Start the API:

```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API documentation or check `http://127.0.0.1:8000/health`.

LLM mode uses the OpenAI-compatible Chat Completions format: `POST {LLM_BASE_URL}/chat/completions` with Bearer authentication and a `choices[0].message.content` response. Configure `LLM_BASE_URL`, `LLM_MODEL`, and `LLM_API_KEY` only if your provider documents that format. A provider with a different protocol needs a dedicated adapter in `app/llm_client.py`; no live provider was configured or called during this project verification.

## Example requests

### Offline mode

```powershell
$body = @{ question = "What should I do about a suspicious email attachment?"; mode = "offline" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/ask" -Headers @{ "X-API-Key" = $env:SENTINELRAG_API_KEY } -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 8
```

### LLM mode

```powershell
$body = @{ question = "What should I do about a suspicious email attachment?"; mode = "llm" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/ask" -Headers @{ "X-API-Key" = $env:SENTINELRAG_API_KEY } -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 8
```

### Response structure

Successful offline responses contain source-backed evidence. Refusals have `refusal: true`, no citations, and do not call an LLM. A recognised injection attempt returns HTTP `403` before retrieval or LLM use.

```json
{
  "answer": "Retrieved evidence (offline mode): ...",
  "citations": [{"document": "phishing_triage.md", "section": "Evidence to preserve", "chunk_id": 2}],
  "retrieval": [{"chunk_id": 2, "score": 0.175}],
  "refusal": false,
  "flagged": false,
  "request_id": 1
}
```

### Check the audit trail

```powershell
python -m app.view_logs --limit 20
python -m app.view_logs --flagged-only
```

Or run the bundled demo after the API starts:

```powershell
.\demo\run_demo.ps1
```

If your PowerShell execution policy blocks unsigned local scripts, use this process-only alternative (it does not change your system policy):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\demo\run_demo.ps1
```

The demo uses only offline mode and fictional data. It shows a healthy API, an evidence-backed answer, an evidence refusal, a blocked injection attempt, recorded audit events, and the automated test suite. It does not make a live LLM request.

## Run tests

```powershell
python -m pytest -v
```

Tests do not call a live LLM provider. The LLM endpoint is replaced with a deterministic fake in the API tests.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `SENTINELRAG_API_KEY` | Required static API key for `/ask` | unset (endpoint returns 503) |
| `SENTINELRAG_MIN_SIMILARITY` | Minimum TF-IDF cosine score before answer generation | `0.10` |
| `SENTINELRAG_RATE_LIMIT` | Requests per key in one window | `10` |
| `SENTINELRAG_RATE_WINDOW_SECONDS` | Sliding-window duration | `60` |
| `SENTINELRAG_MAX_QUESTION_CHARS` | Additional application limit | `2000` |
| `SENTINELRAG_DB_PATH` | SQLite audit database path | `data/sentinelrag.db` |
| `SENTINELRAG_DATA_DIR` | Runbook directory | `data` |
| `LLM_API_KEY` | Provider secret for LLM mode | unset |
| `LLM_BASE_URL` | OpenAI-compatible API base URL | `https://api.openai.com/v1` |
| `LLM_MODEL` | Provider model identifier | unset |
| `LLM_TIMEOUT_SECONDS` | Upstream request timeout | `30` |

The score threshold is a heuristic, not a confidence guarantee. Calibration uncovered that a CVE query could not match when titles and headings were only metadata, so those labels are now included in the search index. After that change, representative questions for all eight runbooks scored from `0.175` to `0.440`, while unrelated parking and recipe queries returned no result. The default `0.10` leaves room for concise in-scope wording while rejecting weak lexical matches. Recalibrate it whenever the runbooks change, using both in-scope and out-of-scope queries.

## Security design and limitations

- API keys are compared with `secrets.compare_digest`; empty or example placeholder values fail closed. Raw keys are never written to the database. A short SHA-256 fingerprint is used for rate-limit grouping and audit correlation.
- Known prompt-injection phrases are checked before retrieval and before any LLM call. Pattern matching can miss obfuscated or novel attacks and can produce false positives; it is not a complete prompt-injection defense.
- The system prompt marks retrieved content as untrusted, but prompt wording alone does not guarantee safe LLM behaviour.
- TF-IDF uses lexical overlap and may miss semantically similar questions that use different vocabulary. A score above the threshold does not prove the resulting answer is correct.
- The audit database records bounded, whitespace-normalized question and answer previews plus an explicit decision. It redacts common email addresses, phone numbers, named secrets, and OpenAI-style keys, but redaction is best-effort. Do not submit confidential or personal information to this local prototype. Production logging needs stronger data-minimisation, retention, access-control, and monitoring policies.
- If persistent audit logging is unavailable, `/ask` returns a safe `503` response rather than presenting the request as successfully audited. Existing local databases are migrated by adding the `decision` field without deleting prior events.
- The rate limiter is in memory and resets on restart; it does not coordinate across multiple server workers.
- The static API key is for a local demo, not a replacement for a production identity/access-management system.
- Use only fictional or authorised defensive runbook content. Follow your organisation's incident-response procedures and obtain approval before taking actions on real systems.

## Project scope / future work

Explicitly out of scope for this first version: vector databases, embeddings, Docker, CI/CD, cloud deployment, frontend UI, multi-turn memory, Redis, OAuth/JWT, and production-grade security controls.

## Resume bullets

Use only the bullets that correspond to features you have personally verified:

- Built SentinelRAG, a Python/FastAPI runbook Q&A API using TF-IDF retrieval, source citations, and a score-based refusal rule.
- Implemented heuristic prompt-injection blocking, API-key authentication, in-memory rate limiting, and SQLite audit logging.
- Added automated tests for retrieval, refusal behaviour, access control, rate limiting, and suspicious input handling.

Do not call the prototype production-ready and report the actual output of your test suite, not an assumed pass count.
