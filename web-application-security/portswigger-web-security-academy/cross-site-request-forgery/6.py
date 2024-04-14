# usage:
# python3 6.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net
# --w wiener
# --p peter

import http.client
import re
from argparse import ArgumentParser

import requests

http.client.HTTPConnection.debuglevel = 1


class Solution:
    def __init__(self, url: str, who: str, password: str) -> None:
        self.url = url.rstrip("/")
        self.who = who
        self.password = password
        self.s = None

    def login(self, username: str, password: str) -> requests.Response:
        self.s = requests.Session()
        login_url = f"{self.url}/login"
        r = self.s.get(login_url)
        r = self.s.post(
            login_url,
            data={
                "csrf": self.s.cookies["csrf"],
                "username": username,
                "password": password,
            },
        )

        return r

    def solve(self) -> None:
        self.login(self.who, self.password)
        print(f"CSRF cookie: {self.s.cookies['csrf']}")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--w", "--who", dest="who")
    parser.add_argument("--p", "--password", dest="password")
    args = parser.parse_args()
    s = Solution(args.url, args.who, args.password)
    s.solve()


if __name__ == "__main__":
    main()
