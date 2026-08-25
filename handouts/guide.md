# Student Guide — Heap Pwn Tutorial

This guide gives you the **concepts, the bug, and the strategy** for each
challenge. It does NOT spell out the exploit commands — that is what the
`skeleton.py` files are for. Read the guide, then implement each stage
where the `TODO` blocks are.

The handout is self-contained — unzip it, enter the `challenges/` dir, and run a
skeleton. The binaries and pinned libcs are already included, so there is
nothing to fetch or build:

```bash
unzip handout.zip
cd handouts/challenges
python3 c1_double_free/skeleton.py          # run your exploit
python3 c1_double_free/skeleton.py --demo   # live pwndbg in a tmux split
```

Run c1–c4 skeletons from the `challenges/` dir (their binaries use a relative
loader path that resolves there). The `baby_talk/` skeleton sets its own
working dir, so it runs from anywhere.

The binary for C1–C3 is `./heapnote` (glibc 2.27 — the Ubuntu 18.04 **GA**
build `2.27-3ubuntu1`, which has **no tcache key**; don't use a later 2.27
patch level or the double-free aborts). C4 uses `./heapnote_235` (glibc
`2.35-0ubuntu3.14`). Watch the heap change under pwndbg as you go:

```bash
gdb ./heapnote
(pwndbg) break del
(pwndbg) run
```

Or use the skeleton's `--demo` mode (inside tmux) for a paced walkthrough.

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
Indices and sizes are parsed as **decimal**. `add()` mallocs TWO chunks per
note: the `note_t` struct (0x10 → 0x20 chunk) AND the data buffer.

---

## How to leak libc (the mechanic you reuse in C2/C3/C4)

tcache only serves chunk sizes 0x20–0x410. A request **>= 0x418** makes a
0x420 chunk that tcache will NOT hold → on free it lands in the **unsorted
bin** (keep a small guard chunk after it so it doesn't merge into top).

A freed unsorted-bin chunk's `fd` points at the bin head, whose "chunk"
address is `main_arena + 96` on 2.27 x86-64, and `main_arena` sits right
after `__malloc_hook` (`main_arena = __malloc_hook + 0x10`). UAF-read that
fd with `show()` and solve:

```
libc_base = leak - (__malloc_hook + 0x10) - 96
```

Read every offset from the shipped libc at runtime (so it's robust across
2.27-3ubuntu1.x sub-versions). From `libc_base` you get `system`,
`__free_hook`, and the `"/bin/sh"` string.

> **2.34+ note (C4):** `__malloc_hook` becomes a compat NO-OP, NOT
> `main_arena-0x10`, so the formula above breaks. Use the fixed offset of
> the unsorted-bin head from `libc_base` directly (leak once, read the real
> base from `/proc/<pid>/maps`, take the difference).

---

## C1 — double-free → GOT overwrite → win()

**No leak needed** (binary is `-no-PIE`, so `free@GOT` and `&win` are fixed).

**Key insight — pick data size 0x28 (→ 0x30 chunk), NOT 0x18:**
`add()` mallocs the `note_t` struct (0x20 chunk) *and* the data buffer. If
data were 0x18 → 0x20, struct and data would share the same 0x20 tcache
bin, and the struct malloc would eat your poisoned chunk before the data
malloc sees it. 0x28 → 0x30 keeps the data bin (0x30) separate from the
struct bin (0x20).

**Strategy** (you write the calls in `c1_double_free/skeleton.py`):
1. Allocate one chunk A in the 0x30 bin.
2. Double-free A → tcache list becomes a self-loop `A→A`, counts=2.
   (Allowed on 2.27: no tcache key, no double-free check.)
3. **3-malloc rule**: malloc #1 returns A — write `free@GOT` into A's `fd`;
   malloc #2 returns A again (drains the self-loop), head now `= free@GOT`;
   malloc #3 returns `free@GOT` — write `&win` there.
4. Trigger: free any still-live note whose data pointer is still valid
   (del never NULLs it) → hijacked `free@GOT` → `win()` → shell.
   Don't allocate a fresh note to trigger — the 0x30 bin is left poisoned
   after the 3-malloc chain, so a new malloc would hand back a bogus
   address and crash.

**pwndbg checkpoints**: `tcache` after step 2 (0x30 bin, self-loop,
counts=2); `tcache` after step 3 (`A → free@GOT`); `got` after step 3
(`free → win`).

---

## C2 — unsorted bin leak → `__free_hook` → system

**Strategy** (in `c2_unsorted_leak/skeleton.py`):
1. Leak `libc_base` via the unsorted bin (mechanic above).
2. Reuse C1's double-free 3-malloc, but point `fd` at `__free_hook` instead
   of `free@GOT`. A 0x68 request → 0x70 chunk is a comfortable size.
3. Pop `__free_hook` and write `system` there. (When you pop
   `__free_hook`, the bin is left empty because the hook was 0, so the
   next malloc comes fresh from top — no poisoned-bin crash.)
4. Allocate a chunk whose data is `"/bin/sh\x00"` and free it →
   `__free_hook(ptr)` → `system("/bin/sh")`.

`__libc_free` calls `hook(ptr, caller)` (two args); `system` reads only
`rdi`, so the extra arg is harmless.

**pwndbg checkpoints**: `bins` after the unsorted free (0x420 chunk);
`tcache` after the double-free (0x70 self-loop, counts=2);
`p &__free_hook` after the write (value == system).

---

## C3 — UAF-Edit poisoning → `__free_hook` (one_gadget alt)

Same shell as C2, but the poison uses a **single** UAF-Edit — no
double-free, so it generalizes to glibc 2.29+ (where the tcache key
detects double-frees).

**Strategy** (in `c3_uaf_poison/skeleton.py`):
1. Leak `libc_base` exactly as in C2.
2. Free **two distinct** chunks into the same tcache bin (counts=2, but
   NO self-loop and NO double-free signature). The HEAD's dangling data
   overlaps the freed chunk's `fd` — use `edit()` on the head note to
   overwrite that `fd` with `__free_hook`.
3. malloc #1 returns the head chunk; malloc #2 returns `__free_hook` —
   write `system`.
4. Free a `"/bin/sh"` chunk → shell.

> **The count rule**: `tcache_get` needs `counts > 0`. To pop
> victim-then-target you need `counts >= 2` — hence freeing **two**
> distinct chunks (never the same one twice).

### one_gadget alternative (`--one-gadget`)

```bash
one_gadget glibc-2.27/libc-2.27.so
```

A one_gadget replaces `system`+"/bin/sh" with a single gadget that calls
`execve("/bin/sh", …)` — BUT it only fires if the stack satisfies the
gadget's constraint (e.g. `[rsp+0x40] == NULL`). The constraint depends on
the **call site**: the same gadget may fire from `free()`'s hook call site
but NOT from `malloc()`'s, because the stack frames differ. On the pinned
2.27 build, `0x4f322` fires via `__free_hook` + `free()`; via
`__malloc_hook` + `malloc()` it fails (execve fails → `_exit(127)` → the
process dies, looks like a hang). So: target `__free_hook`, trigger by
freeing a live note. `system`+"/bin/sh" remains the reliable default; run
`python3 c3_uaf_poison/exp.py --one-gadget` for the verified gadget path.

---

## C4 (stretch) — safe-linking bypass on glibc 2.35

Target: `./heapnote_235` (glibc 2.35). Same `heapnote.c` source as C1–C3,
but linked/patched against the pinned 2.35 libc. The prebuilt binary is
included in the handout; you don't build it.

### The new defense (2.32+)

tcache `fd` is obfuscated: `stored_fd = (&fd >> 12) XOR next`. To poison
`fd` → target `T`, write `(&fd >> 12) XOR T` — you need `&fd >> 12` (a
heap-page leak).

### The heap-page leak

If a chunk is the **only** entry in its bin, its real `next` is NULL, so
`stored_fd = &fd >> 12 XOR 0 = &fd >> 12`. A UAF-read of that stored fd
leaks exactly the heap page (the `>>12` key). `PROTECT_PTR` only uses
`&fd >> 12` — the page — and all your small chunks share a page, so the
leaked `heap_page` is the value to XOR with any target:

```
forged = heap_page ^ target     # = PROTECT_PTR(&fd, target)
```

### Finisher: GOT overwrite → shell

Hooks are gone on 2.35, so the C2/C3 one-shot finisher doesn't exist — BUT
`heapnote_235` is still `-no-PIE` + partial RELRO (writable GOT), so reuse
C1's GOT-overwrite finisher on top of the safe-linking bypass: forge `fd`
→ a GOT slot, pop it, write `&win`; the next `menu()` call through that
slot → `win()` → shell.

> **Which GOT slot?** glibc 2.34+ `tcache_get()` writes `e->key = 0` at
> `returned_ptr + 8`, so it also zeroes the GOT slot **after** the one you
> overwrite. Pick a slot whose `+8` neighbour is NOT used in the menu path.
> `free@GOT`'s `+8` is `puts@GOT` (menu calls `puts` → crash before you
> trigger); `puts@GOT`'s `+8` is `write@GOT` (only `show()` uses it).
> `win()` must still reach a working `system@GOT` — leave that untouched.

**Strategy** (in `c4_safe_linking/skeleton.py`):
1. libc leak via the unsorted bin (use the unsorted-head offset, NOT
   `__malloc_hook`).
2. heap-page leak via a singly-freed tcache chunk (stored fd = `&fd>>12`).
3. Forge `fd = PROTECT_PTR(&fd, <chosen GOT slot>)` → pop the slot → write
   `&win` → next menu loop auto-triggers → shell. Mind the `+8` zeroing.

### Honest scope

This is a shell because `heapnote` hands us a **writable GOT**. A real 2.35
target (full RELRO, no `win()`) needs the structural finishers — FSOP /
**House of Apple** (fake an `_IO_FILE` + a vtable in the validated range),
`exit_funcs` / TLS `dtor_list` (gated by `PTR_MANGLE` → also leak the
pointer guard), `__printf_function_table` (House of Husk). That's theory in
`SLIDES.md` (the C4 / safe-linking slides).

---

## baby_talk (capstone, DiceCTF 2024) — strtok overlap → `__free_hook`

Target: `baby_talk/binary` (glibc 2.27, Full RELRO, PIE). Self-contained
dir with its own libc + ld.

**The three commands**:
- `str(size, data)` : `read(0, ptr, size)` — **NO null terminator** appended.
- `tok(idx, delim)` : `strtok(ptr, delim)` — scans to `\0` with **no length bound**.
- `del(idx)` : `free(ptr)` and **NULLs** the pointer (no UAF / no double-free).

**The bug**: `str` writes `size` bytes with no trailing `\0`. `tok`/`strtok`
then scans forward until it hits a `\0`, ignoring the chunk boundary → it
walks into the NEXT chunk's header. When `strtok` finds the delimiter it
writes a `\0` over it — if that byte is the low byte of the next chunk's
size field, the size changes (e.g. `0x101 → 0x100`) and `PREV_INUSE` is
cleared, enabling a **backward consolidation** that produces an **overlap**
with a live tcache chunk.

**Strategy** (in `baby_talk/skeleton.py`):
1. **Leak heap + libc**: malloc never zeroes reused memory, so a freed
   tcache chunk's slot keeps a **residual fd**. There's no `show`/UAF-read
   command — use `tok` (strtok) to read those residual bytes back out.
   Prime one size class, free into it, re-alloc, then `tok` with a
   delimiter that stops right where the residual fd sits.
2. **Build the overlap**: sculpt a fake prev chunk, then use `tok`'s null
   write to clear `PREV_INUSE` on a neighbour → free it → backward
   consolidation → one chunk now spans a live tcache entry.
3. **Poison + trigger**: through the overlap, forge a fake tcache chunk
   whose `fd` points at `__free_hook`. Allocate to pop `__free_hook`, write
   `system`. Allocate a `"/bin/sh"` chunk and free it → `system("/bin/sh")`.

Full RELRO means no writable GOT — that's why this challenge must finish
via `__free_hook` (not the C1/C4 GOT path).

---

## After the course

- Redo C1–C3 against a glibc 2.31 build, then 2.35, adapting each step.
- Work through [pwn.college Dynamic Allocator Misuse](https://pwn.college/program-security/dynamic-allocator-misuse).
- Study [how2heap](https://github.com/shellphish/how2heap) PoCs.
- Try the agentic loop — SLIDES.md Part III sketches the loop (Claude
  Code + a decompiler MCP + pwndbg output fed back as context) and
  suggests starting by using it as a tutor (explain your exploit, suggest
  next steps) before an autonomous solver.