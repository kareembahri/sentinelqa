# Development Guide

How to run, test and troubleshoot SentinelQA on your computer.
All commands are run in **PowerShell** from the project folder:

```powershell
cd $HOME\Projects\sentinelqa
```

## First-time setup

1. Create your local secrets file:
   ```powershell
   Copy-Item .env.example .env
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
   Open `.env` in VS Code (`code .env`). Paste the first value after `POSTGRES_PASSWORD=` and the second after `SECRET_KEY=`. Save.
2. Build the API image (large download the first time):
   ```powershell
   docker compose build
   ```
3. Start the database and create the first migration:
   ```powershell
   docker compose up -d db
   docker compose run --rm api alembic revision --autogenerate -m "initial schema"
   ```
   A new file appears in `backend/alembic/versions/`. Commit it: it is the official definition of the database schema.
4. Start everything:
   ```powershell
   docker compose up -d
   ```
5. Create your admin account (you choose the password; there is no default):
   ```powershell
   docker compose run --rm api python -m app.cli create-admin --email you@gmail.com
   ```
   Use a real email domain. Special-use domains such as `.local` or `.test` are rejected by the email validator.

## Trying the API in the browser (http://localhost:8000/docs)

Every POST, PATCH and DELETE needs a CSRF token:
1. Open **GET /api/auth/csrf** → *Try it out* → *Execute*. Copy the `csrf_token` value.
2. Open **POST /api/auth/login** → *Try it out*. Paste the token into the **X-CSRF-Token** field, enter your email and password, *Execute*. The browser now holds your session cookie.
3. **GET /api/auth/me** shows who you are. Paste the same token into X-CSRF-Token for every other POST/PATCH/DELETE.
4. Create a target with **POST /api/targets**: `{"name": "Juice Shop", "base_url": "http://juice-shop:3000", "is_lab": true}`.

The token stays valid until you log out. After logging out, get a new one from step 1.

## Running a website scan (Phase 3)

The API only queues a scan; the **worker** container runs it in the background.

1. In /docs, **POST /api/scans** (with X-CSRF-Token), body: `{"target_id": "<id of your Juice Shop target>"}`.
   The response is `202 Accepted` with `"status": "queued"`. Copy the scan `id`.
2. **GET /api/scans/{scan_id}**: repeat until `status` is `completed`. `progress_pct` and `summary` update as it runs.
3. Results:
   - **GET /api/scans/{scan_id}/pages**: every page with status, response time, title, metadata and accessibility issues.
   - **GET /api/scans/{scan_id}/links?result=broken**: broken links. Other filters: `redirect_issue`, `out_of_scope`, `timeout`, `ok`.
4. Optional limits in the body, for example `{"target_id": "...", "options": {"max_pages": 20, "max_depth": 2}}`.
5. **POST /api/scans/{scan_id}/cancel** stops a scan; pages found so far are kept.

Watch the worker: `docker compose logs -f worker`.

**What the crawler can and cannot see.** It reads the HTML the server sends. Juice Shop is a single-page app: most of its screens are drawn by JavaScript in the browser, so the crawler sees the start page, its scripts and styles, and paths found in robots.txt (such as `/ftp`). Phase 4 adds a real browser (Playwright) for the JavaScript-rendered screens.

## Everyday commands

| Task | Command |
|---|---|
| Start everything | `docker compose up -d` |
| Status of containers | `docker compose ps` |
| API logs (Ctrl + C to stop watching) | `docker compose logs -f api` |
| Worker logs (scans) | `docker compose logs -f worker` |
| Restart after editing code | `docker compose restart api worker` |
| Run the platform's tests | `docker compose run --rm api pytest` |
| Run one test file | `docker compose run --rm api pytest tests/api/test_health.py -v` |
| Stop everything (keeps data) | `docker compose down` |
| Stop and **delete** the database | `docker compose down -v` |
| Rebuild after changing requirements | `docker compose build api` |
| Open a database shell | `docker compose exec db psql -U sentinelqa -d sentinelqa` |
| Create another admin | `docker compose run --rm api python -m app.cli create-admin --email x@gmail.com` |

Open in your browser:
- API documentation: http://localhost:8000/docs
- Health check: http://localhost:8000/api/health
- OWASP Juice Shop (lab target): http://localhost:3000

## Database changes (Alembic)

When a model in `backend/app/models.py` changes:
```powershell
docker compose run --rm api alembic revision --autogenerate -m "describe the change"
# read the generated file in backend/alembic/versions/ before applying it
docker compose run --rm api alembic upgrade head
```
Always read generated migrations. Autogenerate can miss renames (it sees a drop plus an add).

## Lockfile

`requirements.txt` pins the packages we use directly. To record the exact version of *every* installed package:
```powershell
docker compose run --rm api pip freeze | Out-File -Encoding utf8 backend/requirements.lock
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `required variable SECRET_KEY is missing a value` | `.env` is missing or not filled in. Repeat first-time setup step 1. The file must be named exactly `.env` in the project folder (not `.env.txt`). |
| `SECRET_KEY must be at least 32 characters` | Paste a generated value, not a short word. |
| `error during connect` / `cannot find the file specified` | Docker Desktop is not running. Open it and wait for **Engine running**. |
| `port is already allocated` for 8000 | Another program uses port 8000. Stop it, or change the left number in `docker-compose.yml` (for example `127.0.0.1:8001:8000`) and use that port in the browser. |
| `/api/health` returns `"database": "unavailable"` | Check `docker compose ps` (db should be `healthy`) and `docker compose logs db`. If you changed `POSTGRES_PASSWORD` after the first start, the old password is still stored: run `docker compose down -v` (deletes DB data) and start again. |
| `password authentication failed` | Same as above: the database volume was created with a different password. |
| `Permission denied` writing to `alembic/versions` | Run the command as root once: `docker compose run --rm --user root api alembic revision --autogenerate -m "initial schema"`. |
| `Target database is not up to date` | Apply migrations: `docker compose run --rm api alembic upgrade head`. |
| `403 CSRF token missing or invalid` | Get a token from GET /api/auth/csrf and send it in the X-CSRF-Token header. In /docs, paste it into the X-CSRF-Token field. |
| `401 Invalid email or password` although the password is right | After 5 wrong attempts the account is locked for 15 minutes. Wait, or have another admin unlock it with PATCH /api/users/{id} `{"unlock": true}`. |
| `429 Too many requests` | More than 5 login attempts in a minute from your computer. Wait 60 seconds. |
| `Target host could not be resolved` for juice-shop | The juice-shop container is not running: `docker compose up -d juice-shop`. |
| `value is not a valid email address` in create-admin | Use a normal email domain (for example gmail.com), not `.local` or `.test`. |
| Scan stays `queued` forever | The worker is not running. `docker compose ps` should list `worker` as running; check `docker compose logs worker`. |
| Scan `failed`: "Target failed the authorization check" | The target's host is no longer in ALLOWED_TARGET_HOSTS, or it now resolves to a blocked address. Check `.env` and `docker compose ps juice-shop`. |
| `409 You already have 3 scans queued or running` | Wait for one to finish, or cancel one with POST /api/scans/{id}/cancel. |
| Scan `failed`: "The worker stopped unexpectedly" | The worker was restarted mid-scan. Start the scan again. |
| `FAILED to resolve 'db'` | The command was run outside Compose. Use `docker compose run --rm api ...` so the container joins the project network. |
