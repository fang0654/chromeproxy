# chromeproxy

HTTP/S proxy that tunnels requests through a real headless Chromium (via Playwright) so the target sees a genuine Chrome TLS / HTTP fingerprint and any JS challenges execute in a real browser. Intended as an upstream for tools like Burp or curl.

## Architecture

Single module: `chromeproxy.py`. Two cooperating pieces:

- **`ChromeProxyAddon`** — a mitmproxy addon. mitmproxy terminates the client's TLS, hands each request to the addon's `request()` hook, and the addon writes back a synthetic `flow.response` instead of letting mitmproxy forward upstream itself.
- **`BrowserBridge`** — owns the Playwright `Playwright` / `Browser` / `BrowserContext` lifecycle and a semaphore that bounds in-flight requests. For each request it opens a fresh page, dispatches in one of two modes, then closes the page.

Two modes:

- **`raw`** (default) — `page.goto("about:blank")` then `page.evaluate(FETCH_JS, …)`. The in-page `fetch()` goes through Chrome's network stack, so the *target* sees Chrome's fingerprint. Request and response bodies are passed as base64 to dodge encoding issues. Used for arbitrary methods/bodies.
- **`rendered`** — `page.goto(url, wait_until="networkidle")` then return `page.content()`. Only meaningful for GET; gives back the post-JS DOM as `text/html`. Falls back to current DOM if `networkidle` times out (30s).

Per-request override via `X-CP-Mode: raw|rendered` header (stripped before forwarding). CLI `--mode` sets the default.

## Things to know when editing

- **Header hygiene matters.** `HOP_BY_HOP` plus `host` and `content-length` are stripped from outbound headers (`strip_request_headers`); `HOP_BY_HOP` and `content-length` are stripped from the response before it goes back to the client. Adding new header handling means thinking about both directions.
- **`--disable-web-security`** is intentional — it lets the in-page `fetch()` read cross-origin response bodies. Don't remove it without replacing the cross-origin read path.
- **`ignore_https_errors=True`** on the browser context is intentional — mitmproxy is sitting between the page and the real upstream, and the page sees mitmproxy's cert, not the upstream's. The actual upstream cert is validated by Chrome inside the `fetch()` call against mitmproxy's CA (which is itself the trust anchor for the *client*, not the upstream). If you care about upstream cert validation, that's a separate change.
- **Concurrency** is bounded by `asyncio.Semaphore(concurrency)` around `dispatch`. One page per in-flight request; pages are not pooled.
- **Redirects** are `redirect: 'manual'` in raw mode — the proxy returns the 3xx to the client and lets the client decide. Don't switch this to `'follow'` without thinking through how Burp/etc. will see the chain.
- **`rendered` mode is GET-only** by design — the code silently falls through to `raw` for other methods. Worth preserving that fallback.

## Run / dev

```
pip install -e .
playwright install chromium
chromeproxy --listen 127.0.0.1:8080 --mode raw
```

First run, mitmproxy writes a CA to `~/.mitmproxy/`. The client (Burp, browser, curl `--cacert`) must trust `mitmproxy-ca-cert.pem` for HTTPS interception to work — this is a client-side step, not something the proxy can fix.

Flags: `--listen host:port`, `--mode {raw,rendered}`, `--concurrency N`, `--no-headless` (visible Chrome window, useful for debugging challenges), `-v` (DEBUG logging).
