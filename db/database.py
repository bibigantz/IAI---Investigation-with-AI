import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "iai.db")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db():
    from . import models  # noqa: F401 -- register model classes on Base before create_all
    models.Base.metadata.create_all(bind=engine)
    _seed_defaults()


def _seed_defaults():
    """First-run seed: a default admin account (must-change-password flagged)
    and a default local-Ollama LLM provider config, so the app is usable
    immediately in a fully offline environment with no manual setup step."""
    import time as _time
    from datetime import datetime, timezone
    from werkzeug.security import generate_password_hash
    from . import models

    with get_session() as session:
        if session.query(models.User).count() == 0:
            session.add(models.User(
                username="admin",
                password_hash=generate_password_hash("changeme"),
                role="admin",
                created_at=datetime.now(timezone.utc).isoformat(),
                must_change_password=True,
            ))
        if session.get(models.LlmProviderConfig, 1) is None:
            session.add(models.LlmProviderConfig(id=1))


@contextmanager
def get_session():
    """Yield a SQLAlchemy session, committing on success and rolling back on
    error -- every route handler that touches the DB should go through this
    rather than holding a session open across a request."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
