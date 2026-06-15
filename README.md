# chromeproxy

An HTTP/S proxy that tunnels every request through a real headless Chromium (via Playwright). The target server sees a genuine Chrome TLS / HTTP fingerprint, and any JavaScript challenges run in a real browser.

Useful as an upstream for tools like Burp Suite or curl when the target blocks non-browser clients.

## Install

Requires Python 3.11+.

```sh
pip install -e .
playwright install chromium
```

## Usage

```sh
chromeproxy --listen 127.0.0.1:8080 --mode raw
```

Point your client (Burp, curl, browser, etc.) at `http://127.0.0.1:8080`.

On first run, mitmproxy writes a CA certificate to `~/.mitmproxy/`. For HTTPS interception to work, your client must trust `mitmproxy-ca-cert.pem`:

- **curl** — `curl --proxy http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com`
- **Burp** — import the cert into Burp's CA trust, or simply set Burp's upstream proxy to chromeproxy and let Burp handle its own client trust.
- **Browser** — import `mitmproxy-ca-cert.pem` into the OS / browser trust store.

### Modes

- **`raw`** (default) — the request is replayed inside the browser via `fetch()`. Works for any method and body. The target sees a real Chrome network stack.
- **`rendered`** — the browser navigates to the URL with `page.goto(...)`, waits for `networkidle`, and returns the post-JavaScript DOM as `text/html`. GET-only; other methods fall back to `raw`.

Override the mode on a per-request basis with the `X-CP-Mode` header:

```sh
curl --proxy http://127.0.0.1:8080 -H 'X-CP-Mode: rendered' https://example.com
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--listen HOST:PORT` | `127.0.0.1:8080` | Address to bind. |
| `--mode {raw,rendered}` | `raw` | Default response mode. |
| `--concurrency N` | `4` | Max concurrent in-flight requests. |
| `--no-headless` | off | Run Chrome with a visible window (debugging). |
| `-v`, `--verbose` | off | Enable DEBUG logging. |

## How it works

`chromeproxy` is a [mitmproxy](https://mitmproxy.org/) addon. mitmproxy terminates the client's TLS, hands each request to the addon, and the addon dispatches it through a Playwright-controlled Chromium instance instead of forwarding directly. The browser's response is then written back as the proxy response.

Because the actual HTTP request to the target is made by Chromium, the target sees Chrome's real TLS fingerprint, HTTP/2 frame ordering, and header order — making this useful against fingerprint-based bot detection.

## License

No license specified — treat as all rights reserved unless you add one.
