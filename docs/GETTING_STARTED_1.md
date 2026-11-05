# Getting Started — Making SentinelQA Yours

This guide answers three questions: **where is the project, how do you get it, and how do you open it.**

## Where it lives

SentinelQA is not hosted anywhere yet. It will live in three places, all owned by you:

| Place | What it is | Address |
|---|---|---|
| Your computer | The real working copy of the code | e.g. `C:\Users\<you>\Projects\sentinelqa` or `~/Projects/sentinelqa` |
| Your GitHub account | The public portfolio copy recruiters see | `https://github.com/<your-username>/sentinelqa` |
| Your browser (while running) | The dashboard website | `http://localhost:5173` (from Phase 6); API docs at `http://localhost:8000/docs` (from Phase 2) |

"localhost" means *your own computer*. Nobody else can open it, which is exactly what we want for a tool that runs security scans.

---

## Step 1 — Install the tools (one time)

1. **Git** — https://git-scm.com/downloads
   Check: `git --version`
2. **Docker Desktop** — https://www.docker.com/products/docker-desktop/
   On Windows, accept the WSL 2 option during install, then restart.
   Check: `docker --version` and `docker compose version`
3. **Python 3.12** — https://www.python.org/downloads/ (tick "Add Python to PATH" on Windows)
   Check: `python --version`
4. **Node.js 20 LTS or newer** — https://nodejs.org/ (needed from Phase 6)
   Check: `node --version`
5. **VS Code** (recommended editor) — https://code.visualstudio.com/
6. **A GitHub account** — https://github.com/signup

## Step 2 — Create your project folder

```bash
mkdir -p ~/Projects
cd ~/Projects
```
(Windows PowerShell: `mkdir $HOME\Projects; cd $HOME\Projects`)

Download the files I send you in this chat and place them so the structure is:

```
Projects/
└── sentinelqa/
    └── docs/
        ├── ARCHITECTURE.md
        ├── ROADMAP.md
        └── GETTING_STARTED.md
```

## Step 3 — Turn it into a git repository

```bash
cd ~/Projects/sentinelqa
git init
git branch -M main
git config user.name "Your Name"
git config user.email "your-email@example.com"
git add .
git commit -m "Phase 1: architecture and roadmap"
```

## Step 4 — Create the GitHub repository and push

1. Go to https://github.com/new
2. Repository name: `sentinelqa`. Description: *Web application security & QA testing platform (Python, Playwright, OWASP ZAP, FastAPI, React)*.
3. Choose **Public** (for your portfolio). Do **not** tick "Add README" — we create our own.
4. Click **Create repository**, then run the commands GitHub shows under *"push an existing repository"*:

```bash
git remote add origin https://github.com/<your-username>/sentinelqa.git
git push -u origin main
```

When asked to log in, use your browser sign-in or a Personal Access Token (GitHub no longer accepts your account password on the command line).

Your project is now at `https://github.com/<your-username>/sentinelqa`. That link goes on your CV.

## Step 5 — After every phase

```bash
git add .
git commit -m "Phase N: <what was built>"
git push
```

Small, meaningful commits show recruiters how you work.

## Step 6 — Opening the website (from Phase 2 onward)

```bash
cd ~/Projects/sentinelqa
docker compose up --build
```

Then open in your browser:
- `http://localhost:8000/docs` — backend API (Phase 2+)
- `http://localhost:5173` — SentinelQA dashboard (Phase 6+)
- `http://localhost:3000` — OWASP Juice Shop, the practice target (Phase 3+)

Stop everything with `Ctrl + C`, then `docker compose down`.

## Should I put it on the public internet?

Not the scanning engine. SentinelQA runs active security attacks, so a public instance would be a risk for you and could be misused. The professional approach for a portfolio is:

- Code public on GitHub.
- Screenshots, a short demo video/GIF, and sample reports in the README.
- Recruiters who want to try it run `docker compose up` locally.

Later, if you want a live demo link, we can deploy a **read-only demo mode** (no scanning, pre-recorded real results clearly labelled as such).
