1. Create venv and use it

python3 -m venv .venv
source .venv/bin/activate

2. Install deps

pip install -r requirements.txt

3. Generate root cert and install in OS CA

python generate_root_cert.py
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain encripton.pem

4.