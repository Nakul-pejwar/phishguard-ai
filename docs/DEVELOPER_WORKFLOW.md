# PhishGuard AI - Developer & Deployment Workflow

This guide establishes the strict development, git branching, review, and VPS deployment protocol for PhishGuard AI.

---

## 1. Core Rule: Developer Machine & GitHub Only

```
Developer Laptop ──push/PR──▶ GitHub (main) ──pull──▶ VPS ──deploy──▶ Containers
```

- **Only the developer's laptop and GitHub change code.**
- **The VPS only pulls releases and runs containers.**
- **Nobody edits or patches code directly on the production VPS.**

---

## 2. One-Time Developer Setup (Local Machine)

Configure your local git client to ensure clean rebases and prune stale branches:

```bash
git clone https://github.com/Nakul-pejwar/phishguard-ai.git
cd phishguard-ai

# Git safety configs
git config pull.rebase true
git config rerere.enabled true
git config fetch.prune true
```

> [!IMPORTANT]
> Local secrets belong in `.env` (which is git-ignored). **Never commit credentials or server-specific values.**

---

## 3. Daily Developer Workflow (Every Change)

1. **Sync with Main:**
   ```bash
   git switch main
   git pull --rebase
   ```
2. **Create Feature Branch:**
   ```bash
   git switch -c feat/<short-descriptive-name>
   ```
   *Never commit directly to `main`.*
3. **Commit in Small, Atomic Increments:**
   Make small, clean commits daily with descriptive conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`).
4. **Run CI Quality Checks Locally:**
   ```bash
   # Linter
   ruff check .

   # Test suite & coverage
   cd phishing_backend
   pytest --cov=scanner --cov=accounts
   cd ..
   ```
5. **Rebase on Latest Main Before Pushing:**
   ```bash
   git fetch origin main
   git rebase origin/main
   ```
   *If conflicts occur, resolve them, run `git add <file>`, and execute `git rebase --continue`.*
6. **Push Branch & Open Pull Request:**
   ```bash
   git push -u origin feat/<short-descriptive-name>
   ```
7. **Merge via Squash Merge:**
   Merge only after all automated CI tests pass green. Delete the feature branch after merging.

---

## 4. Conflict Prevention Rules

| Area | Rule |
| :--- | :--- |
| **Hot Files** | Avoid simultaneous uncoordinated edits to `Dockerfile`, `docker-compose.yml`, `requirements.txt`, and `deploy/*`. |
| **Dependencies** | Whenever `requirements.txt` changes, state it in the PR description so the VPS rebuilds images. |
| **ML Models** | Models in `phishing_backend/scanner/ml/*.joblib` must be pickled with the pinned scikit-learn version (`1.9.1`). |
| **No Artifact Commits** | Never commit build/test artifacts (`.coverage`, `dist/`, `.env`, `htmlcov/`). These are enforced via `.gitignore`. |
| **Main Branch Protection** | Never `git push --force` to `main`. |

---

## 5. Server: Safe Deployment & Release (`safe_sync.sh`)

On the production VPS:

```bash
cd /srv/projects/phishguard-ai/phishguard-ai   # or your VPS project directory

# 1. Safely pull release (stops if tree is dirty or has conflicts)
./scripts/safe_sync.sh

# 2. Build and restart containers
docker compose build && docker compose up -d

# 3. Apply any database migrations
docker compose exec -T web python manage.py migrate --noinput

# 4. Verify API health
curl -s http://127.0.0.1:8093/api/health/
```

---

## 6. Troubleshooting on VPS

- **If the working tree is dirty:**
  ```bash
  git status
  git stash      # safely park unexpected local changes
  ./scripts/safe_sync.sh
  ```
- **If a release needs to be rolled back:**
  ```bash
  git reset --hard <LAST_GOOD_COMMIT_SHA>
  docker compose up -d --build
  ```
