from pathlib import Path

import requests

my_path = Path(__file__).resolve()

resp = requests.get(
    "https://www.google.com/",
    proxies=dict(
        http="socks5h://localhost:9090",
        https="socks5h://localhost:9090",
    ),
    headers={"Accept-Encoding": "identity"},
    verify=my_path.parents[3] / "src/certs/encripton.pem",
    # verify="/Users/alexandernst/.mitmproxy/mitmproxy-ca.pem"
)

print(resp.text)
