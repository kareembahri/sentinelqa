# SentinelQA

**Intelligent web application security & quality assurance platform.**
Python · FastAPI · PostgreSQL · Playwright · Pytest · OWASP ZAP · React · Docker

> 🚧 **Work in progress.** Built phase by phase; see the [roadmap](docs/ROADMAP.md).
> Current status: **Phase 3: website scanner**.

SentinelQA runs automated functional tests and security checks against web applications you are **authorized** to test, and produces evidence-backed reports. Security findings are classified as *confirmed*, *suspected* or *informational*. Scanner alerts are never reported as confirmed vulnerabilities without verification.

## Quick start

Requirements: Docker Desktop, Git.

```bash
git clone https://github.com/kareembahri/sentinelqa.git
cd sentinelqa
cp .env.example .env        # then fill in POSTGRES_PASSWORD and SECRET_KEY
docker compose up -d --build
```

Open http://localhost:8000/docs.

Full instructions and troubleshooting: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md): system design, data flow, database schema, security design
- [Roadmap & acceptance criteria](docs/ROADMAP.md)
- [Development guide](docs/DEVELOPMENT.md)

## Responsible use

SentinelQA refuses to scan hosts that are not on a server-side allowlist, and active security tests are limited to local lab targets such as OWASP Juice Shop. Only test systems you own or have written permission to test.

## License

MIT (license file added in Phase 10).
