# PhishGuard AI Workspace Rules

Project: PhishGuard AI. Chrome MV3 extension + Django 5/DRF backend + sklearn model.
Stack target: Python 3.11, Django 5, DRF, PostgreSQL, Redis, Celery, Docker, Razorpay.

## Rules:
- Never hardcode secrets. Use env vars (python-dotenv / django-environ). Provide .env.example.
- Every new feature needs unit tests (pytest + pytest-django). Do not mark done with failing tests.
- Never store full URLs containing query tokens/PII in logs or DB; store domain + hashed full URL.
- Keep extension permissions minimal. Justify any new permission in the PR notes.
- Small commits per task, conventional commit messages.
- Before big changes, produce an Implementation Plan and wait for approval.
- Do not change the ML model's public predict interface without updating tests.
