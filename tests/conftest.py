import tempfile

import pytest

from app import create_app, init_db
from app.config import Config
from app.extensions import db
from app.models import Repository, User

_KEYS = tempfile.mkdtemp(prefix="florepo-keys-")


@pytest.fixture()
def app(tmp_path):
    class TestConfig(Config):
        TESTING = True
        DATA_DIR = str(tmp_path)
        STORAGE_PATH = str(tmp_path / "storage")
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        SECRET_KEY = "test"
        ADMIN_PASSWORD = "admin-pass"
        WTF_CSRF_ENABLED = False
        OSV_ENABLED = False
        BASE_URL = "http://localhost"
        KEYS_PATH = _KEYS  # shared: key generation (RSA 4096 + GPG) is slow

    app = create_app(TestConfig)
    init_db(app)
    with app.app_context():
        for name, fmt, public in [("py", "pypi", False), ("js", "npm", False), ("img", "docker", False)]:
            db.session.add(Repository(name=name, format=fmt, kind="hosted", public=public, allow_redeploy=True))
        reader = User(username="alice", role="reader")
        reader.set_password("alice-pass")
        db.session.add(reader)
        db.session.commit()
    yield app
