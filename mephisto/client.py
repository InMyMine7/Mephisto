"""HTTP client handed to every exploit module.

A module receives one :class:`Exploit` instance and is expected to use only the
public surface below, so the transport details can change without touching the
individual exploits:

``url`` / ``session`` / ``headers`` / ``proxy`` / ``CONFIG``
    Request context.
``log_message``
    Colour-aware logging.
``check_file`` / ``payload_path`` / ``result_path``
    Payload and result file helpers.
``simulate_browser_navigation``
    Warms the session with two benign requests.
``random_email`` / ``random_filename`` / ``random_password`` / ``random_username`` / ``random_cookie``
    Identity and naming helpers.
"""

from __future__ import annotations

import os
import random
import string
import time
from collections import OrderedDict

import requests
import urllib3

from . import config as config_module
from . import ui

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9,fr;q=0.8",
    "en-GB,en;q=0.9,de;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en;q=0.8",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.yahoo.com/",
    "https://www.facebook.com/",
    "https://x.com/",
    "https://www.linkedin.com/",
]

PLATFORMS = {
    "Windows": '"Windows"',
    "Mac OS X": '"macOS"',
    "Linux": '"Linux"',
    "Android": '"Android"',
    "iPhone": '"iOS"',
}

RESULT_KINDS = {
    "shell": "SHELLS_FILE",
    "password": "PASSWORDS_FILE",
    "admin": "ADMINS_FILE",
    "register": "REGISTER_FILE",
}


class Exploit:
    def __init__(self, url, config=None):
        self.url = self.normalize_url(url)
        self.session = requests.Session()
        self.headers = self.get_headers()
        self.proxies = list(config.get("PROXIES", [])) if config else []
        self.proxy = random.choice(self.proxies) if self.proxies else None
        self.CONFIG = config if config is not None else config_module.load()

    def log_message(self, message, success=False, error=False):
        if not ui.is_verbose():
            return
        if success:
            mark, colour = "+", ui.ACCENT
        elif error:
            mark, colour = "!", ui.DANGER
        else:
            mark, colour = ui.GLYPH.bullet, ui.FAINT
        text = ui.paint(str(message), ui.MUTED if success else ui.FAINT)
        print(f"       {ui.paint(mark, colour)} {text}")

    def payload_path(self, filename):
        return os.path.join(self.CONFIG["FILES_DIR"], filename)

    def result_path(self, filename):
        return os.path.join(self.CONFIG["RESULT_DIR"], filename)

    def record(self, kind, value):
        """Append one finding to a result file.

        ``kind`` is one of ``RESULT_KINDS``; the file itself comes from
        ``config.json`` so the output format lives in one place.
        """
        try:
            filename = self.CONFIG[RESULT_KINDS[kind]]
        except KeyError:
            raise ValueError(f"unknown result kind {kind!r}") from None
        os.makedirs(self.CONFIG["RESULT_DIR"], exist_ok=True)
        line = str(value).strip("\n")
        with open(self.result_path(filename), "a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")

    def check_file(self, filename):
        file_path = self.payload_path(filename)
        if not os.path.exists(file_path):
            self.log_message(f"File {filename} not found", error=True)
            return False
        return True

    def simulate_browser_navigation(self):
        try:
            self.session.get(self.url, headers=self.headers, proxies=self.proxy, verify=False, timeout=self.CONFIG["TIMEOUT"])
            time.sleep(random.uniform(0.3, 1.5))
            self.session.get(f"{self.url}wp-login.php", headers=self.headers, proxies=self.proxy, verify=False, timeout=self.CONFIG["TIMEOUT"])
        except requests.RequestException:
            pass

    def random_cookie(self, length=16):
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def random_email(self):
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        domain = random.choice(["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"])
        return f"{name}@{domain}"

    def random_filename(self, ext="php", length=8):
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{name}.{ext}"

    def random_password(self, prefix="mine", length=8):
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return prefix + suffix

    def random_username(self):
        return f"nx_{random.randint(1000, 9999)}_{''.join(random.choices(string.ascii_lowercase, k=6))}"

    def obfuscate_shell(self, data):
        """Return the shell payload as upload-ready bytes.

        Loaderlayer exploits hand the raw payload to the target unless a module
        needs a transformed copy; keeping this a normalisation point preserves
        the call sites that rely on it.
        """
        if isinstance(data, bytes):
            return data
        return data.encode("latin1", errors="ignore")

    def get_headers(self):
        time.sleep(random.uniform(0.5, 2.0))
        user_agent = random.choice(USER_AGENTS)
        is_chrome = "Chrome" in user_agent or "Chromium" in user_agent or "Edg" in user_agent
        is_firefox = "Firefox" in user_agent
        is_safari = "Safari" in user_agent and not is_chrome
        is_mobile = "Mobile" in user_agent or "Android" in user_agent or "iPhone" in user_agent
        platform = next((p for k, p in PLATFORMS.items() if k in user_agent), '"Unknown"')
        headers = {
            "Connection": random.choice(["keep-alive", "close"]),
            "Cache-Control": random.choice(["no-cache", "max-age=0", "no-store"]),
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": user_agent,
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "application/json, text/plain, */*",
                "*/*",
            ]),
            "Accept-Encoding": random.choice(["gzip, deflate, br", "gzip, deflate", "br"]),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": f"session={self.random_cookie()}; lang={random.choice(['en', 'id', 'fr', 'es'])}; cf_clearance={self.random_cookie(32)}",
            "Sec-GPC": "1" if random.random() > 0.5 else None,
        }
        if random.random() > 0.1:
            headers["Referer"] = random.choice(REFERERS)
        if random.random() > 0.2:
            headers["DNT"] = str(random.randint(0, 1))
        if random.random() > 0.4:
            headers["Pragma"] = "no-cache"
        if is_chrome:
            headers.update({
                "Sec-Ch-Ua": '"Chromium";v="129", "Not=A?Brand";v="8", "Google Chrome";v="129"' if "Chrome" in user_agent else '"Microsoft Edge";v="129", "Chromium";v="129", "Not=A?Brand";v="8"',
                "Sec-Ch-Ua-Mobile": "?1" if is_mobile else "?0",
                "Sec-Ch-Ua-Platform": platform,
                "Sec-Ch-Ua-Full-Version-List": '"Chromium";v="129.0.6668.71", "Not=A?Brand";v="8.0.0.0", "Google Chrome";v="129.0.6668.71"' if "Chrome" in user_agent else '"Microsoft Edge";v="129.0.2792.79", "Chromium";v="129.0.6668.71", "Not=A?Brand";v="8.0.0.0"',
                "Sec-Fetch-Dest": random.choice(["document", "iframe", "script", "image"]),
                "Sec-Fetch-Mode": random.choice(["navigate", "no-cors", "cors"]),
                "Sec-Fetch-Site": random.choice(["none", "same-origin", "same-site", "cross-site"]),
                "Sec-Fetch-User": "?1" if random.random() > 0.3 else None,
                "Priority": random.choice(["u=0, i", "u=1", "u=2"]) if random.random() > 0.5 else None,
            })
        elif is_firefox:
            headers.update({
                "TE": "trailers",
                "Sec-Fetch-Dest": random.choice(["document", "script"]),
                "Sec-Fetch-Mode": random.choice(["navigate", "cors"]),
                "Sec-Fetch-Site": random.choice(["none", "same-origin"]),
            })
        elif is_safari:
            headers.update({
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Priority": "u=0, i" if random.random() > 0.5 else None,
            })
        headers = {k: v for k, v in headers.items() if v is not None}
        return OrderedDict(random.sample(list(headers.items()), len(headers)))

    def normalize_url(self, url):
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/") + "/"
