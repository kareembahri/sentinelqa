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
4. Start the API:
   ```powershell
   docker compose up -d api
   ```

## Everyday commands

| Task | Command |
|---|---|
| Start everything | `docker compose up -d` |
| Status of containers | `docker compose ps` |
| API logs (Ctrl + C to stop watching) | `docker compose logs -f api` |
| Restart the API after editing code | `docker compose restart api` |
| Run the platform's tests | `docker compose run --rm api pytest` |
| Run one test file | `docker compose run --rm api pytest tests/api/test_health.py -v` |
| Stop everything (keeps data) | `docker compose down` |
| Stop and **delete** the database | `docker compose down -v` |
| Rebuild after changing requirements | `docker compose build api` |
| Open a database shell | `docker compose exec db psql -U sentinelqa -d sentinelqa` |

Open in your browser:
- API documentation: http://localhost:8000/docs
- Health check: http://localhost:8000/api/health

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
| `FAILED to resolve 'db'` | The command was run outside Compose. Use `docker compose run --rm api ...` so the container joins the project network. |
