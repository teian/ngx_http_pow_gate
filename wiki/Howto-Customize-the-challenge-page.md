# How to customize the challenge page

Goal: your own branding on the "Just a moment…" page. The look is entirely
yours; the module needs four element ids and one script tag.

## 1. Start from a minimal page

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Checking your browser…</title>
</head>
<body>
  <main role="status" aria-live="polite">
    <h1>Just a moment…</h1>

    <progress id="pow-progress" max="100" value="0"></progress>
    <p><span id="pow-status">Preparing…</span> — <span id="pow-percent">0</span>%</p>

    <p id="pow-error" style="display:none">
      Verification failed. <a href="" onclick="location.reload();return false;">Try again</a>.
    </p>

    <noscript>JavaScript is required to complete this check.</noscript>
  </main>

  <script src="{{endpoint}}solver.js"
          data-difficulty="{{difficulty}}"
          data-endpoint="{{endpoint}}"
          defer></script>
</body>
</html>
```

Leave `{{endpoint}}` and `{{difficulty}}` literally in the file; the module
fills them in. For a polished base, copy the shipped
[assets/challenge.html](https://github.com/teian/ngx_http_pow_gate/blob/main/assets/challenge.html) instead — it has the
light/dark theme, 26 languages and the clock warning.

| Element id | The solver… |
| --- | --- |
| `pow-status` | writes the status text |
| `pow-progress` | sets `.value` on a `<progress>`, otherwise `style.width` |
| `pow-percent` | writes the integer percent |
| `pow-error` | shows it on failure |
| `pow-clock` (optional) | shows the wrong-device-clock warning |

## 2. Install it

```nginx
http {
    pow_gate_page /etc/pow/challenge.html;
}
```

```bash
sudo nginx -t && sudo nginx -s reload
```

The file is read **once at config load**. Every edit needs a reload. An
unreadable file makes `nginx -t` fail rather than silently falling back.

`pow_gate_page` inherits, so a `location` can carry different branding.

## 3. Mind these

- **Keep it self-contained.** Inline the CSS and images. Anything the page loads
  from a gated path is challenged too — or exclude those paths with
  `pow_gate off;`.
- **Keep a `</body>`.** The gate inserts the kept form submission just before it.
- **Content-Security-Policy:** allow `worker-src 'self'`, or solving drops to a
  single core.
- **The solver itself is not replaceable.** It is the client half of the
  protocol and always comes from the module.
- **The bar slows towards the end** by design: it shows the probability that the
  search has finished, not a fixed amount of work.

## The no-JavaScript page

Clients routed to `challenge:nojs` get a separate page, replaceable with
`pow_gate_nojs_page <file>;`. It must send the client to `{{pass_url}}` after
`{{delay}}` seconds, by meta-refresh or a link. Start from
[assets/challenge-nojs.html](https://github.com/teian/ngx_http_pow_gate/blob/main/assets/challenge-nojs.html).

## Try it locally

[The local sandbox](Howto-Try-it-in-the-local-sandbox) serves a page through
`pow_gate_page`, so you can iterate without a server.

Reference: [challenge-page.md](https://github.com/teian/ngx_http_pow_gate/blob/main/docs/challenge-page.md).
