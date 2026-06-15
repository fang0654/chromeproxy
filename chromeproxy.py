"""
chromeproxy — an HTTP proxy that routes requests through a headless Chrome
browser via Playwright. The target sees a real Chrome TLS / HTTP fingerprint
and any JS challenges run in a real browser.

Usage:
    pip install -e .
    playwright install chromium
    chromeproxy --listen 127.0.0.1:8080 --mode raw

Then point your client (Burp, curl, etc.) at http://127.0.0.1:8080. On first
run mitmproxy writes a CA cert to ~/.mitmproxy/; trust mitmproxy-ca-cert.pem
so HTTPS interception works.

Per-request override: send `X-CP-Mode: rendered` or `X-CP-Mode: raw`.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import signal
from typing import Optional

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from playwright.async_api import (
    Browser,
    BrowserContext,
    Playwright,
    TimeoutError as PWTimeout,
    async_playwright,
)

log = logging.getLogger("chromeproxy")

# RFC 7230 §6.1 hop-by-hop headers — never forwarded.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}

MODE_HEADER = "x-cp-mode"

# Runs inside the page. fetch() goes through Chrome's network stack, so the
# target sees a real Chrome TLS/HTTP fingerprint. Body is passed as base64 to
# avoid encoding issues; response body comes back the same way.
FETCH_JS = """
async (args) => {
    const body = args.body
        ? Uint8Array.from(atob(args.body), c => c.charCodeAt(0))
        : undefined;
    const init = {
        method: args.method,
        headers: args.headers,
        redirect: 'manual',
        credentials: 'include',
    };
    if (body && args.method !== 'GET' && args.method !== 'HEAD') {
        init.body = body;
    }
    const r = await fetch(args.url, init);
    const buf = await r.arrayBuffer();
    const view = new Uint8Array(buf);
    let bin = '';
    const chunk = 0x8000;
    for (let i = 0; i < view.length; i += chunk) {
        bin += String.fromCharCode.apply(null, view.subarray(i, i + chunk));
    }
    const hdrs = [];
    r.headers.forEach((v, k) => hdrs.push([k, v]));
    return { status: r.status, headers: hdrs, body_b64: btoa(bin) };
}
"""


def strip_request_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP or kl in ("host", "content-length"):
            continue
        out[k] = v
    return out


class BrowserBridge:
    def __init__(self, mode: str, concurrency: int, headless: bool) -> None:
        self.default_mode = mode
        self.headless = headless
        self.sem = asyncio.Semaphore(concurrency)
        self._pw: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._ctx: Optional[BrowserContext] = None

    async def start(self) -> None:
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(
            headless=self.headless,
            args=[
                # Lets in-page fetch() read responses from any origin.
                "--disable-web-security",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        self._ctx = await self._browser.new_context(ignore_https_errors=True)
        log.info("chromium ready (headless=%s)", self.headless)

    async def stop(self) -> None:
        for closer in (self._ctx, self._browser):
            if closer is not None:
                try:
                    await closer.close()
                except Exception:
                    pass
        if self._pw is not None:
            await self._pw.stop()

    async def dispatch(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        mode: str,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        assert self._ctx is not None
        async with self.sem:
            page = await self._ctx.new_page()
            try:
                if mode == "rendered" and method.upper() == "GET":
                    return await self._dispatch_rendered(page, url)
                return await self._dispatch_raw(page, method, url, headers, body)
            finally:
                await page.close()

    async def _dispatch_raw(
        self, page, method: str, url: str,
        headers: dict[str, str], body: bytes,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        await page.goto("about:blank")
        result = await page.evaluate(
            FETCH_JS,
            {
                "method": method,
                "url": url,
                "headers": strip_request_headers(headers),
                "body": base64.b64encode(body or b"").decode(),
            },
        )
        return (
            int(result["status"]),
            [(k, v) for k, v in result["headers"]],
            base64.b64decode(result["body_b64"]),
        )

    async def _dispatch_rendered(
        self, page, url: str,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        status = 200
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            if resp is not None:
                status = resp.status
        except PWTimeout:
            log.warning("networkidle timeout for %s; returning current DOM", url)
        html = await page.content()
        return status, [("content-type", "text/html; charset=utf-8")], html.encode("utf-8")


class ChromeProxyAddon:
    def __init__(self, bridge: BrowserBridge) -> None:
        self.bridge = bridge

    async def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request

        mode = req.headers.pop(MODE_HEADER, self.bridge.default_mode).lower()
        if mode not in ("raw", "rendered"):
            mode = self.bridge.default_mode

        url = req.pretty_url
        headers = {k: v for k, v in req.headers.items()}
        body = req.raw_content or b""

        try:
            status, resp_headers, resp_body = await self.bridge.dispatch(
                req.method, url, headers, body, mode,
            )
        except Exception as e:
            log.exception("dispatch failed: %s %s", req.method, url)
            flow.response = http.Response.make(
                502,
                f"chromeproxy: {e}".encode(),
                {"content-type": "text/plain"},
            )
            return

        clean: list[tuple[bytes, bytes]] = []
        for k, v in resp_headers:
            kl = k.lower()
            if kl in HOP_BY_HOP or kl == "content-length":
                continue
            clean.append((k.encode("latin-1"), v.encode("latin-1")))

        flow.response = http.Response.make(status, resp_body, clean)


async def amain(host: str, port: int, mode: str, concurrency: int, headless: bool) -> None:
    bridge = BrowserBridge(mode=mode, concurrency=concurrency, headless=headless)
    await bridge.start()

    opts = Options(listen_host=host, listen_port=port)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(ChromeProxyAddon(bridge))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, master.shutdown)

    log.info("listening on %s:%d (mode=%s, concurrency=%d)", host, port, mode, concurrency)
    try:
        await master.run()
    finally:
        await bridge.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--listen", default="127.0.0.1:8080",
                    help="host:port to listen on (default 127.0.0.1:8080)")
    ap.add_argument("--mode", choices=["raw", "rendered"], default="raw",
                    help="default response mode (per-request override via X-CP-Mode header)")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="max concurrent in-flight requests (default 4)")
    ap.add_argument("--no-headless", action="store_true",
                    help="run Chrome with a visible window (useful for debugging)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    host, port_str = args.listen.rsplit(":", 1)
    asyncio.run(amain(host, int(port_str), args.mode, args.concurrency, not args.no_headless))


if __name__ == "__main__":
    main()
