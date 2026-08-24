# Heap Pwn CTF Training Tutorial (~3h05, beginner)

A self-contained, live-demoable heap-pwn course for CTF beginners. One
shared buggy binary, four escalating challenges, runnable `exp.py` for
each, a reproducible **local** environment (no Docker), and a 30-minute
segment on **agentic pwn**.

## Quick start

```bash
cd challenges
make setup        # one-time: fetch .debs -> glibc-2.27/ glibc-2.35/ sysroot-2.27/
make all          # -> heapnote (glibc 2.27) + heapnote_235 (glibc 2.35)
python3 c1_double_free/exp.py   # expect a shell, then: cat flag.txt
```

`make setup` downloads signed `libc6` / `libc6-dev` `.deb` packages straight
from the Ubuntu archive (via `curl` + `dpkg -x`, no third-party repo) and
assembles the pinned runtimes plus a linkable 2.27 sysroot. The shipped libcs
are stripped (no `libc6-dbg` fetched) — pwndbg resolves `heap` / `tcache` /
`bins` via its built-in heuristics, which is enough for the live demos. See
`SLIDES.md` (the "Pwn Environment Setup" section) for the full toolchain + the
libc-version rationale, and `challenges/setup.sh` for exactly what gets
fetched.

## The four challenges

| # | Topic | Leak | Target | libc | Win |
|---|-------|------|--------|------|-----|
| C1 | tcache double-free → poisoning → GOT overwrite | no | `free@GOT`→`&win` | 2.27 | shell |
| C2 | unsorted bin libc leak → `__free_hook` → `system` | yes | `__free_hook` | 2.27 | shell |
| C3 | UAF-Edit poisoning → `__free_hook` (+ one_gadget alt) | yes | `__free_hook` | 2.27 | shell |
| C4 | safe-linking (PROTECT_PTR) bypass | yes | `puts@GOT` → `&win` (GOT overwrite) | 2.35 | shell |

All four exploit the **same** `heapnote` binary. The single bug is that
`del()` never sets `notes[i] = NULL`, which yields both **double-free** and
**use-after-free**.

## Repository layout

```
heap-pwn-tutorial/
├── challenges/
│   ├── heapnote.c                    the ONE shared source
│   ├── Makefile                      build against pinned libcs (2.27 sysroot + 2.35)
│   ├── setup.sh                       one-time: fetch pinned .debs, build runtimes + sysroot
│   ├── flag.txt                       demo flag (cat it from the popped shell)
│   ├── glibc-2.27/ glibc-2.35/        pinned loaders/libcs (fetched by setup.sh)
│   ├── sysroot-2.27/                 linkable 2.27 crt + libc.so + headers (built by setup.sh)
│   ├── c1_double_free/exp.py
│   ├── c2_unsorted_leak/exp.py
│   ├── c3_uaf_poison/exp.py
│   ├── c4_safe_linking/exp.py
│   └── baby_talk/                     real CTF capstone (DiceCTF 2024): binary + libc + solve.py
├── SLIDES.md         the full deck (plain Markdown, `---` page dividers)
└── handouts/student_guide.md         step-by-step solves
```

## Agenda (~3h05)

| Time | Segment | Slides |
|---|---|---|
| 0:00–0:45 | Concepts: heap layout, chunks, bins, tcache | `01`,`02` |
| 0:45–1:30 | Environment setup (pwntools, pwndbg, patchelf, pinned libcs) | `03` |
| 1:30–2:00 | C1 + C2 | `04`,`05` |
| 2:00–2:30 | C3 + C4 | `06`,`07` |
| 2:30–3:00 | Real CTF: `baby_talk` (10 min self-read + 20 min walkthrough/PoC) | `08` |
| 3:00–3:05 | Agentic pwn heap (5 min intro) | `09` |

## Teaching references

- Beginner backbone: [pwn.college — Dynamic Allocator Misuse](https://pwn.college/program-security/dynamic-allocator-misuse)
  (UAF, tcache metadata, safe-linking, overlapping allocations).
- "What's next": [pwn.college — Dynamic Allocator Exploitation](https://pwn.college/software-exploitation/dynamic-allocator-exploitation)
  (glibc 2.35, consolidation, advanced heap exploits).
- [how2heap](https://github.com/shellphish/how2heap) — canonical exploit PoCs.

## Instructor notes (read before demo)

- **Pre-flight every exp.py** on your host; see the "Pwn Environment Setup"
  section in `SLIDES.md`.
- The pinned 2.27 is `2.27-3ubuntu1` (the Ubuntu 18.04 **GA** build) on
  purpose — later 2.27 patch levels backported the tcache double-free key,
  which would abort C1's self-loop. If you re-pin a different 2.27 build,
  C1/C3 may need adjustments (and re-run `one_gadget` for C3's alt path).
- `setup.sh` fetches **no** `libc6-dbg` — the shipped libcs are stripped and
  pwndbg resolves `heap` / `tcache` / `bins` via its built-in heuristics
  (auto-fallback when no debug symbols are present). Just break after the
  first `malloc` (so the heap is initialized) and run `heap` / `tcache`.
  Fallback if the heuristic ever fails on some libc: `main_arena =
  &__malloc_hook + 0x10` (2.27; `__malloc_hook` is an exported dynsym). Want
  source-level libc debugging? Install `libc6-dbg` yourself and
  `set debug-file-directory` — optional, not needed for this course.
- All `exp.py` read libc offsets at runtime
  (`ELF('./glibc-2.27/libc-2.27.so')`), so they tolerate minor sub-version
  drift; C4's unsorted-head offset (`0x21ace0`) is hardcoded for
  `2.35-0ubuntu3.14` — recompute it (leak once, compare to `/proc/<pid>/maps`)
  if you pin a different 2.35.
- C4 pops a shell by reusing C1's GOT-overwrite finisher on top of the
  safe-linking bypass (heapnote_235 is -no-pie / partial-RELRO). This works
  because the binary hands us a writable GOT; a real 2.35 target (full RELRO,
  no win()) needs FSOP / House of Apple / exit_funcs — set that expectation.
- ASLR: C1 needs none (no-PIE); C2/C3 leak libc so ASLR is fine. To show
  the leak math is stable you may first run with
  `setarch $(uname -m) -R ./heapnote`.

## Prerequisites for students

- Comfortable reading C and using a Linux shell.
- Has seen a stack buffer overflow / ret2libc before (not strictly required).
- Bring a Linux laptop with `gcc`, `patchelf`, `gdb`, and `pip`/`gem` (the
  `make setup` flow fetches the rest), or use the pwn.college dojo.

## The slide deck

The whole 3h deck lives in one file: `SLIDES.md` — plain Markdown with
`---` dividers between pages (no frontmatter, no build step). Read it
directly, or paste it into any Markdown-aware presenter.

- **Notion presenter:** the deck has been copied to the
  `Pwn - Heap` Notion page — open it there and use Notion's presenter mode.
- **Local preview:** any Markdown viewer works; the `---` lines render as
  horizontal rules separating pages. To get a PDF, open `SLIDES.md` in
  your editor/preview and print to PDF, or import it into Notion.

