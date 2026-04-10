import os
from pathlib import Path
from typing import Optional

DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def get_backend_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def get_project_root() -> Path:
    return get_backend_dir().parent


def get_default_geolite2_db_path() -> Path:
    return get_project_root() / "data" / "GeoLite2-City.mmdb"


def get_allowed_origins() -> list[str]:
    raw_origins = os.getenv("ALLOWED_ORIGINS", "")
    origins = [
        origin.rstrip("/")
        for origin in (value.strip() for value in raw_origins.split(","))
        if origin and origin != "*"
    ]
    return origins or list(DEFAULT_ALLOWED_ORIGINS)


def load_env_file(env_path: Optional[Path] = None, override: bool = False) -> None:
    env_path = env_path or get_backend_dir() / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)
