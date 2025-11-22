import requests

resp = requests.get(
    "https://www.google.com/",
    proxies=dict(
        http="socks5h://localhost:9090",
        https="socks5h://localhost:9090",
    ),
    headers={"Accept-Encoding": "identity"},
    verify="../certs/encripton.pem",
    # verify="/Users/alexandernst/.mitmproxy/mitmproxy-ca.pem"
)

print(resp.text)
