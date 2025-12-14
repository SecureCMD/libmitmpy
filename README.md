1. Create venv and use it

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install deps

```bash
python -m pip install --upgrade pip setuptools wheel
pip install -e .
```

3. Run some examples

```bash
python examples/mitm/main.py
```

```bash
python examples/mitm/tests/https.py
```