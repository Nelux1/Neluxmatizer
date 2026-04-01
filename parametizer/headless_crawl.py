#!/usr/bin/env python3
"""
Headless Chromium crawl (Playwright) para descubrir URLs tras render JS.

Comportamiento tipo Katana (acotado): BFS por mismo sitio — parte de la semilla, sigue enlaces
hasta max_depth y como mucho max_pages navegaciones. Las miles de URLs del parametizer suelen
venir de Wayback/fuentes estáticas; esto complementa con lo que el DOM vivo expone al navegar.
"""

from __future__ import annotations

import site
import sys
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse


def _prefer_bundled_playwright() -> Optional[str]:
    """
    Debian/Kali ship python3-playwright without an embedded Node driver and delegate
    to /usr/share/nodejs/playwright — a mismatched node build causes
    KeyError: 'deviceDescriptors' at LocalUtils init. Pip wheels include
    playwright/driver/package/cli.js; prepend that site-packages so import wins.
    """
    roots: List[Path] = []
    try:
        u = site.getusersitepackages()
        if u:
            roots.append(Path(u))
    except Exception:
        pass
    try:
        for p in site.getsitepackages():
            roots.append(Path(p))
    except Exception:
        pass
    seen: set[str] = set()
    for root in roots:
        try:
            key = str(root.resolve())
        except Exception:
            key = str(root)
        if key in seen:
            continue
        seen.add(key)
        cli = root / "playwright" / "driver" / "package" / "cli.js"
        if cli.is_file():
            pkg_root = str(root)
            if pkg_root in sys.path:
                sys.path.remove(pkg_root)
            sys.path.insert(0, pkg_root)
            return pkg_root
    return None


def _restore_sys_path(inserted: Optional[str]) -> None:
    if not inserted:
        return
    try:
        sys.path.remove(inserted)
    except ValueError:
        pass


def _canonical_netloc(netloc: str) -> str:
    """blog.example.com y www.blog.example.com se consideran el mismo host para el crawl."""
    n = (netloc or "").lower()
    if n.startswith("www."):
        n = n[4:]
    return n


def _same_site_or_child(seed_netloc: str, url_netloc: str) -> bool:
    if not url_netloc:
        return False
    s = _canonical_netloc(seed_netloc)
    u = _canonical_netloc(url_netloc)
    if u == s:
        return True
    return u.endswith("." + s)


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0] if url else url


def _ensure_http_scheme(url: str) -> str:
    """Si el usuario no puso http/https, anteponer https:// (igual que parametizer)."""
    u = (url or "").strip()
    if not u:
        return u
    p = urlparse(u)
    if not p.scheme:
        return "https://" + u
    return u


def _extract_same_site_links(
    page: Any,
    base_for_relative: str,
    seed_netloc: str,
) -> List[str]:
    """Extrae hrefs del DOM ya cargado (dedupe solo dentro de esta página)."""
    out: List[str] = []
    local: Set[str] = set()

    def consider(raw: Optional[str]) -> None:
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#")):
            return
        abs_u = _strip_fragment(urljoin(base_for_relative, raw))
        pu = urlparse(abs_u)
        if pu.scheme not in ("http", "https"):
            return
        if not _same_site_or_child(seed_netloc, (pu.netloc or "").lower()):
            return
        if abs_u not in local:
            local.add(abs_u)
            out.append(abs_u)

    for sel in ("a[href]", 'link[href][rel="alternate"]', "area[href]"):
        try:
            for loc in page.locator(sel).all():
                try:
                    consider(loc.get_attribute("href"))
                except Exception:
                    continue
        except Exception:
            continue
    try:
        for loc in page.locator("form[action]").all():
            try:
                consider(loc.get_attribute("action") or base_for_relative)
            except Exception:
                continue
    except Exception:
        pass
    return out


def headless_collect_urls(
    seed_url: str,
    headers: Optional[Dict[str, str]] = None,
    cookies_dict: Optional[Dict[str, str]] = None,
    max_urls: int = 800,
    goto_timeout_ms: int = 45000,
    max_depth: int = 3,
    max_pages: int = 100,
) -> Tuple[List[str], Optional[str]]:
    """
    Headless Chromium: crawl BFS por mismo host (estilo Katana acotado).

    - max_depth: saltos desde la semilla (0 = solo la primera página).
    - max_pages: tope de navegaciones GET (evita escaneos eternos en blogs enormes).

    Returns:
        (list_of_urls, None) on success (list may be empty),
        ([], error_message) on failure (import, browser, navigation, etc.).
    """
    inserted_path = _prefer_bundled_playwright()
    try:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return [], (
                "paquete 'playwright' no instalado — ejecutá: pip install playwright && playwright install chromium"
            )

        seed_url = _ensure_http_scheme(seed_url)

        headers = dict(headers) if headers else {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

        parsed = urlparse(seed_url)
        if not parsed.scheme.startswith("http"):
            return [], "URL inválida (se espera http/https)"

        seed_netloc = (parsed.netloc or "").lower()
        if not seed_netloc:
            return [], "URL sin host"

        seed_norm = _strip_fragment(seed_url)
        collected: List[str] = []
        all_seen: Set[str] = set()
        visited: Set[str] = set()
        queued: Set[str] = set()

        def remember(url: str) -> None:
            u = _strip_fragment(url)
            if u not in all_seen and len(collected) < max_urls:
                all_seen.add(u)
                collected.append(_strip_fragment(url))

        queue: deque[Tuple[str, int]] = deque()
        queue.append((seed_norm, 0))
        queued.add(seed_norm)

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-software-rasterizer",
                    ],
                )
                try:
                    context = browser.new_context(
                        ignore_https_errors=True,
                        extra_http_headers=headers,
                    )

                    if cookies_dict:
                        cookie_specs = []
                        for name, value in cookies_dict.items():
                            cookie_specs.append(
                                {
                                    "name": name.strip(),
                                    "value": value.strip(),
                                    "domain": seed_netloc,
                                    "path": "/",
                                }
                            )
                        if cookie_specs:
                            try:
                                context.add_cookies(cookie_specs)
                            except Exception as ce:
                                sys.stderr.write(f"[headless] cookie warning: {ce}\n")

                    page = context.new_page()
                    pages_done = 0

                    while queue and pages_done < max_pages and len(collected) < max_urls:
                        current, depth = queue.popleft()
                        cur = _strip_fragment(current)
                        queued.discard(cur)
                        if cur in visited:
                            continue
                        try:
                            page.goto(
                                current,
                                wait_until="domcontentloaded",
                                timeout=goto_timeout_ms,
                            )
                        except Exception:
                            visited.add(cur)
                            continue
                        visited.add(cur)
                        pages_done += 1
                        remember(current)

                        try:
                            page.wait_for_load_state("networkidle", timeout=12000)
                        except Exception:
                            pass
                        try:
                            page.wait_for_timeout(1200)
                        except Exception:
                            pass

                        for link in _extract_same_site_links(page, current, seed_netloc):
                            if len(collected) >= max_urls:
                                break
                            lf = _strip_fragment(link)
                            if lf not in all_seen:
                                all_seen.add(lf)
                                collected.append(lf)
                            if depth >= max_depth:
                                continue
                            if lf in visited or lf in queued:
                                continue
                            queued.add(lf)
                            queue.append((link, depth + 1))

                finally:
                    try:
                        browser.close()
                    except Exception:
                        pass

        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            if isinstance(e, KeyError) and e.args and e.args[0] == "deviceDescriptors":
                err += (
                    " — cliente Python y driver Node de Playwright no coinciden. "
                    "Probá: pip install -U playwright && python -m playwright install chromium "
                    "(o quitá el paquete del sistema: apt remove python3-playwright)"
                )
            return [], err

        if len(collected) > max_urls:
            collected = collected[:max_urls]

        # DEBUG: descomentar y añadir `from .progress import fmt_line` arriba para ver el conteo
        # sys.stdout.write(
        #     fmt_line("1;36", "[headless-debug] URLs del crawl headless:", str(len(collected))) + "\n"
        # )
        # sys.stdout.flush()

        return collected, None
    finally:
        _restore_sys_path(inserted_path)


def run_headless_phase(
    seed_url: str,
    custom_headers: Optional[Dict[str, str]],
    auth_manager: Any,
) -> Tuple[List[str], Optional[str]]:
    """
    Build headers/cookies from AuthManager (same as rest of Neluxmatizer) and run headless crawl.
    """
    headers: Dict[str, str] = {}
    if custom_headers:
        headers.update(custom_headers)
    cookies_dict: Optional[Dict[str, str]] = None

    if auth_manager is not None and getattr(auth_manager, "is_authenticated", lambda: False)():
        try:
            h = auth_manager.get_session_headers(custom_headers)
            if h:
                headers.update(h)
        except Exception:
            pass
        try:
            cd = auth_manager.get_cookies_dict()
            if cd:
                cookies_dict = cd
        except Exception:
            pass

    return headless_collect_urls(seed_url, headers=headers or None, cookies_dict=cookies_dict)
