from pathlib import Path

import pytest


@pytest.fixture
def proxy():
    return {"host": "localhost", "port": 9090}


@pytest.fixture
def ca_cert():
    # examples/mitm/tests/ -> examples/mitm/ -> examples/ -> encriptón/
    return Path(__file__).resolve().parents[3] / "src/certs/encripton.pem"
