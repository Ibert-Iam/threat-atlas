# AtlasSOC web page (ibert.se/AtlasSOC)

Static files only. Build the WebAssembly module with `scripts/build-web.sh`, then upload `web/AtlasSOC/` as is
(`index.html`, `atlassoc.js`, `atlassoc.css`, `atlassoc.wasm`, `atlassoc-preview.jpg`, `icon.svg`, `sitemap.xml`).
No keys, tokens or tracking are involved; the browser connects to GreyNoise only after the visitor presses Start.

## Search engines
- `index.html` carries the title, description, canonical URL (`https://ibert.se/AtlasSOC/`), Open Graph / Twitter
  tags and JSON-LD (`WebApplication`). The text under the start panel is plain HTML, so crawlers can read it
  without running WebAssembly.
- `robots.txt` only counts at the site root. Merge `web/site-root/robots.txt` into `https://ibert.se/robots.txt`
  (keep the rules already there, and make sure nothing there says `Disallow: /AtlasSOC`).
- The server must not send `X-Robots-Tag: noindex` for `/AtlasSOC/`.
- Optional: add `https://ibert.se/AtlasSOC/sitemap.xml` in Google Search Console and request indexing.

## Headers (`.htaccess` on the host, not in this repository)
Keep `Content-Security-Policy` with `frame-ancestors 'none'` and the other security headers. The page needs
`img-src 'self'` (preview image and icon) and nothing else new. Serve `atlassoc.wasm` as `application/wasm`.

## Screen size and pixel density
The core draws a 900-pixel-high frame whose width (1440 to 2160) follows the screen's shape (`web_layout`).
The page scales it into a canvas sized in device pixels (`devicePixelRatio`), and re-fits on resize, rotation,
zoom and moving to another display. Portrait phones get the 16:10 frame letterboxed and a hint to rotate.
