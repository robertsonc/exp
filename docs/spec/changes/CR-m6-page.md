# CR-m6-page: decisions of the speedtest page (M6 step s2, WP-10)

Binding on later steps. Additive; no shared/ change.

1. **Pure-JS crypto.** `crypto.subtle` does not exist on plain HTTP, so the page implements SHA-256/HMAC itself (tested against
   `exp_common.speedtest.view_proof` through the live server). The sentinel session id of CR-m6-speedtest-server item 1 is used.
2. **Fonts** are served as `/st/assets/{archivo,inter,jetbrains-mono}.woff2` from `static/assets/` (the only place the box serves
   fonts from; `font-src 'self'`), not inlined and not in a `static/fonts/` folder.
3. **vendor.lock**: `packaging/vendor.py` accepts only wheel|binary items, so the committed (non-fetched) library and fonts are
   recorded under a new top-level `committed_sources` key (ignored by the packager, checked by `test_page_build.py`).
   `build.py --out DIR` also copies `assets/` so DIR is the whole static tree for the packaging hook.
4. **Streams**: `min(limits.streams_max, 5)`: Chromium allows six HTTP/1.1 connections per host and one is reserved for loaded pings.
5. **Internet leg**: the library runs with `logAimApiUrl: null`; the colo comes from the `/cdn-cgi/trace` body; a slot is acquired
   first; `queued` waits up to 45 s (then leg status `queued`), `paused`/`unavailable` do not wait; unreachable Cloudflare is
   `unavailable`. Plan sizes are trimmed so down <= 55 % and up <= 40 % of `bytes_internet`.
6. **Correct-the-zone** has no API route; it is sent through the comment route as `[where I was] <text>` ahead of the problem report
   (<= 500 chars total, last write wins, 3 replacements). Zone choices are not offered because the public config lists no zones.
7. **Waterfall** is coarse (on-network vs beyond) until the session view's evidence state leaves `pending`, then it adds the box's
   gateway/edge/edge+1 segments; always labelled an estimate.
8. **Test hygiene**: Chromium inherits the sandbox's `HTTPS_PROXY` and would send `speed.cloudflare.com` to the real internet even
   with `--no-proxy-server`; the page tests strip proxy variables and assert the fake served the internet leg.

## Validator fix: SVG namespace URL removed from the page

The page no longer contains any foreign absolute URL (previously `http://www.w3.org/2000/svg`, then a split-literal form). `svgEl` takes the namespace from the page's own inline `<svg>` (`document.querySelector('svg').namespaceURI`). The build test now allows exactly one literal host, `speed.cloudflare.com`, and asserts `w3.org` and `github.com` are absent. The vendored library's `https://${...}` template literals (rpki/msm hosts) are runtime values, covered by the browser test's request-host allowlist.
