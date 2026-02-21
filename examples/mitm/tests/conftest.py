import sqlite3
import tempfile
from pathlib import Path

import pytest

from config import DATA_DIR

_CERTS_DB = DATA_DIR / "certs.db"


@pytest.fixture
def proxy():
    return {"host": "localhost", "port": 9090}


@pytest.fixture
def ca_cert():
    db = sqlite3.connect(str(_CERTS_DB))
    row = db.execute("SELECT cert_pem FROM root_cert WHERE id = 1").fetchone()
    db.close()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(bytes(row[0]))
        tmp_path = Path(f.name)
    yield tmp_path
    tmp_path.unlink(missing_ok=True)
