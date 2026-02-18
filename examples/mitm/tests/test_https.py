import requests


def test_https_through_proxy(proxy, ca_cert):
    resp = requests.get(
        "https://www.google.com/",
        proxies=dict(
            http=f"socks5h://{proxy['host']}:{proxy['port']}",
            https=f"socks5h://{proxy['host']}:{proxy['port']}",
        ),
        headers={"Accept-Encoding": "identity"},
        verify=ca_cert,
    )
    assert resp.status_code == 200
