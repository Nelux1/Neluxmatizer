"""
throttle.py — per-request delay + jitter + auto-throttle based on rate-limit detection.

Usage in any scanner test_* function:
    from scanners.throttle import request_throttle
    ...
    def test_url(url, payload):
        request_throttle(urlparse(url).netloc)
        ...
"""
from __future__ import annotations

import os
import time
import random


def request_throttle(domain: str = "") -> None:
    """
    Insert a rate-control sleep before firing an HTTP request.

    Reads from environment variables (set once by neluxmatizer.py at startup):
      NELUXMATIZER_REQUEST_DELAY  — base delay in seconds (float, default 0.0)
      NELUXMATIZER_JITTER         — "1" to randomise delay in [0, base] (default off)

    Also reads the auto-throttle extra delay from BanDetector when the target
    has been returning consecutive 429 Rate-Limited responses, so the tool
    automatically backs off without the user having to restart.
    """
    base = float(os.environ.get("NELUXMATIZER_REQUEST_DELAY", "0"))
    jitter = os.environ.get("NELUXMATIZER_JITTER", "0") == "1"

    # Auto-throttle: extra delay injected by BanDetector on repeated 429s
    extra = 0.0
    if domain:
        try:
            from scanners.ban_detector import get_ban_detector
            extra = get_ban_detector().get_extra_delay(domain)
        except Exception:
            try:
                from ban_detector import get_ban_detector
                extra = get_ban_detector().get_extra_delay(domain)
            except Exception:
                pass

    total = base + extra
    if total <= 0:
        return

    if jitter:
        # Randomise in [0, total] so requests don't arrive in a perfectly regular pattern
        total = random.uniform(0, total)

    if total > 0:
        time.sleep(total)
