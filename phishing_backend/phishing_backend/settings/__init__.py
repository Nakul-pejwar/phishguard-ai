import os

env = os.getenv("DJANGO_ENV", "dev").lower()

if env == "prod" or env == "production":
    from .prod import *  # noqa: F403, F401
else:
    from .dev import *  # noqa: F403, F401
