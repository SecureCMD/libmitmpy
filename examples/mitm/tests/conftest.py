import sqlite3
import tempfile
from pathlib import Path

import pytest

# examples/mitm/tests/ -> examples/mitm/ -> examples/ -> encriptón/
_CERTS_DB = Path(__file__).resolve().parents[3] / "certs/certs.db"


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
