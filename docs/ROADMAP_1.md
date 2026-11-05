# SentinelQA — Development Roadmap & Acceptance Criteria

Each phase ends with something you can **run and see**. A phase is done only when every acceptance criterion has been checked on your own machine.

| # | Phase | You will be able to… |
|---|---|---|
| 1 | Requirements & architecture | Read and explain the design (this folder) |
| 2 | Database & backend structure | Start Postgres + API in Docker, log in, see OpenAPI docs at `/docs` |
| 3 | Website scanning engine | Crawl Juice Shop, see pages, broken links, response times in the API |
| 4 | Playwright + Pytest engine | Run login/registration/form/session tests against Juice Shop, see screenshots of failures |
| 5 | Security scanning | Run ZAP + passive checks, see findings with evidence and status |
| 6 | Frontend dashboard | Use every page in the browser; charts show real stored data |
| 7 | AI analysis (optional) | Get labelled AI summaries/draft tests when an API key is set; feature hides cleanly without one |
| 8 | Reporting | Download PDF/HTML/JSON reports for a real scan |
| 9 | Hardening & tests | Platform test suite passes; threat model written |
| 10 | Docker, CI/CD, docs | One-command startup; green GitHub Actions badge; polished README |

---

## Acceptance criteria

### Phase 2 — Backend foundation
- [ ] `docker compose up` starts `db` and `api`; `GET /api/health` returns `{"status":"ok"}` with DB connectivity checked.
- [ ] Alembic migration creates every table in `ARCHITECTURE.md §6`.
- [ ] An admin is created by a CLI command (no default password in code).
- [ ] Login sets an `HttpOnly`, `SameSite=Strict` cookie; wrong password returns 401 with a generic message.
- [ ] 6th failed login within the window returns 429.
- [ ] A state-changing request without the CSRF header returns 403.
- [ ] A `viewer` calling an admin endpoint gets 403; the attempt is in `audit_logs`.
- [ ] Registering target `http://169.254.169.254/` or any host not in the allowlist is rejected (tested).

### Phase 3 — Scanner (Module A)
- [ ] A crawl of Juice Shop stays on the target origin (verified by a test with an external link).
- [ ] Max pages / depth / duration limits are enforced and reported.
- [ ] Every link has a result (`ok`, `broken`, `redirect_issue`, `out_of_scope`, `timeout`) and redirect chain.
- [ ] Pages store status, response time, title, meta tags, and accessibility issues (missing labels, missing `alt`, missing `lang`).
- [ ] Unit tests use a local test HTTP server, not the internet.

### Phase 4 — QA automation (Module B)
- [ ] Suites cover login, registration, forms, invalid/empty input, boundary values, navigation, search, session persistence, logout, responsive viewports.
- [ ] The worker launches Pytest without a shell, with a timeout, and stores results parsed from JUnit XML.
- [ ] A deliberately failing test produces a stored screenshot and diagnostics (URL, console errors, failed requests).
- [ ] A crash of the test process marks the scan `failed` with a reason — never `passed`.

### Phase 5 — Security (Module C)
- [ ] ZAP runs in its own container with an API key; the platform refuses active scans on non-lab targets (tested).
- [ ] Passive checks: security headers, cookie flags, HTTPS/HSTS, server/version disclosure, directory listing, verbose errors.
- [ ] Every ZAP alert becomes `suspected` unless a deterministic re-check confirms it; evidence is stored.
- [ ] Each finding has severity, confidence, CWE/OWASP mapping, reproduction steps, remediation and verification guidance.
- [ ] Juice Shop produces known findings (e.g. missing headers, an XSS indicator) — documented with real output.

### Phase 6 — Dashboard
- [ ] Pages: Overview, Scans, Test execution, Vulnerabilities, History, Reports, Configuration, User settings.
- [ ] Charts: risk distribution, pass rate, severity — computed from the API, empty-state when no data.
- [ ] Search and filtering on findings and scans; progress bar on running scans.
- [ ] Every button calls a real endpoint; loading and error states visible.
- [ ] Responsive at 375px, 768px, 1440px (checked by Playwright e2e tests).

### Phase 7 — AI (optional)
- [ ] Without `LLM_API_KEY`, AI buttons are hidden and the endpoints return 503 "not configured".
- [ ] AI output is stored in `ai_insights` and shown with an "AI-generated — not verified" label.
- [ ] Prompts only include stored evidence; AI cannot change findings or test outcomes (tested).
- [ ] The API key never appears in frontend bundles (CI grep check).

### Phase 8 — Reports
- [ ] PDF, HTML and JSON contain: target & config, date, test counts, pass/fail, findings by severity, evidence, reproduction steps, recommendations, summary.
- [ ] Confirmed / suspected / informational are separate sections.
- [ ] JSON validates against a published schema; downloads require authorization.

### Phase 9 — Hardening & platform tests
- [ ] Unit, integration, API, browser, security and error-handling tests exist and pass.
- [ ] Security tests cover SSRF bypass attempts (decimal IPs, DNS to private IP, redirects to metadata), CSRF, RBAC, rate limiting, path traversal on downloads.
- [ ] `docs/THREAT_MODEL.md` (STRIDE) and `SECURITY.md` written.
- [ ] `bandit`, `pip-audit`, `npm audit`, `ruff`, `mypy` clean or each exception documented.

### Phase 10 — Delivery
- [ ] `docker compose up` brings up the full stack from a clean clone using only `.env`.
- [ ] GitHub Actions runs lint, types, tests (with Juice Shop as a service) and uploads reports.
- [ ] README: overview, screenshots, architecture diagram, quick start, demo walkthrough, troubleshooting, ethics/authorization notice.
- [ ] Sample reports in `samples/reports/` generated from a real Juice Shop scan.
- [ ] No secrets in git history (`gitleaks` check in CI).
