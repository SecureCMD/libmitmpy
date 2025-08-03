import requests

resp = requests.get(
    "http://geoapi.es",
    proxies=dict(
        http="socks5h://localhost:9090",
        https="socks5h://localhost:9090",
    ),
    headers={'Accept-Encoding': 'identity'}
)

print(resp.text)
