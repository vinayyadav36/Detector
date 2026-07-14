import os

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
csrf = CSRFProtect()

# Limiter storage: use memory:// for local dev (not production-grade).
# For production, set REDIS_URL env var (e.g. redis://host:6379/0).
# Memory storage does not persist across restarts and is not shared across workers.
storage_uri = os.getenv("REDIS_URL", "memory://")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=storage_uri,
)
