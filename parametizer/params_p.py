# === params_p.py actualizado con deduplicación inteligente y consistente ===

import requests
import sys
from urllib.parse import urlparse, parse_qs
import urllib3
import random

from .progress import fmt_line

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

user_agents = [
    "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
]


def get_headers():
    return {"User-Agent": random.choice(user_agents)}

def normalize_url(url):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    keys = sorted(parse_qs(parsed.query).keys())
    if keys:
        return f"{base}?{'&'.join(keys)}"
    return base

def parametizer_params(urls, output_file=None):
    results = []
    seen = set()

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.scheme.startswith("http"):
                continue
            
            if '=' not in parsed.query:
                continue

            params = parse_qs(parsed.query)
            unique_signature = parsed.path + "?" + "&".join(sorted(params.keys()))
            if unique_signature not in seen:
                seen.add(unique_signature)
                results.append(url)

        except Exception as e:
            sys.stdout.write(f"[!] Error processing {url}: {e}\n")
            sys.stdout.flush()

    sys.stdout.write(
        fmt_line("1;36", "[+] Total unique param URLs:", str(len(results))) + "\n"
    )
    sys.stdout.flush()

    if output_file:
        with open(output_file, "a") as f:
            for line in results:
                f.write(line + "\n")

    return results
