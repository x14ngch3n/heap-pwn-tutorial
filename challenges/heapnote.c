/*
 * heapnote.c — a single shared "heap note" binary for the heap-pwn tutorial.
 *
 * Built once, exploited by 4 challenges at escalating difficulty:
 *   C1: tcache double-free -> poisoning -> GOT overwrite -> win()
 *   C2: unsorted bin libc leak -> __free_hook -> system
 *   C3: UAF-Edit -> tcache poisoning -> __free_hook (+ one_gadget alt)
 *   C4: 2.35 safe-linking (PROTECT_PTR) bypass
 *
 * THE BUG (shared by every challenge): del() frees the note and its data
 * but never sets notes[i] = NULL. This single mistake gives us BOTH:
 *   - double-free  (del the same index twice)
 *   - use-after-free (edit/show a deleted index)
 *
 * Build (glibc 2.27 / Ubuntu 18.04):
 *   gcc heapnote.c -o heapnote -no-pie -z lazy -g
 *
 * Flags chosen for teaching:
 *   -no-pie   -> GOT, BSS, and win() addresses are fixed (great for C1)
 *   -z lazy   -> partial RELRO, GOT is writable
 *   -g        -> source-level view in pwndbg
 *
 * No seccomp, no canary bypass needed (we hijack pointers, not return addr).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 16

/* A note is a heap struct holding a size and a pointer to a data buffer.
 * Both the struct and the data buffer are separate malloc'd chunks, which
 * gives us lots of chunks to play with on the heap. */
typedef struct {
    size_t size;
    char  *data;
} note_t;

note_t *notes[MAX_NOTES];   /* BSS array of note pointers */

/* C1 win target. With -no-pie its address is fixed, so the student can
 * overwrite a GOT entry with &win without needing any libc leak. */
void win(void) {
    system("/bin/sh");
}

/* Read UP TO n bytes in a single read() call (does not loop-fill). This is
 * used for the DATA payloads in add()/edit(): a short send is fine, which
 * keeps the student's exp.py readable (e.g. sending 4 bytes of "AAAA" for
 * a 0x18 note). The UAF-write in edit() still gets to overwrite the fd
 * because the freed chunk's data area starts at offset 0. */
static size_t readn(int fd, char *buf, size_t n) {
    ssize_t r = read(fd, buf, n);
    return r > 0 ? (size_t)r : 0;
}

/* Read a single newline-terminated line into buf (up to cap-1 bytes),
 * dropping the newline. Returns the parsed integer. This is what the
 * MENU CHOICE / idx / size fields use: a fill-to-N read would block
 * forever on a short sendline, so we parse line-by-line instead. */
/* Set when a menu/idx/size read hits EOF with no data, so the menu loop can
 * exit cleanly instead of spinning forever on strtol("") == 0 -> default. */
static int g_eof;

static int read_line_int(int cap_note) {
    (void)cap_note;
    char buf[16] = {0};
    size_t off = 0;
    while (off < sizeof(buf) - 1) {
        ssize_t r = read(0, buf + off, 1);
        if (r <= 0) { if (off == 0) g_eof = 1; break; }
        if (buf[off] == '\n') { buf[off] = '\0'; break; }
        off++;
    }
    return (int)strtol(buf, NULL, 10);
}

static int read_idx(void) {
    return read_line_int(0);
}

static int read_size(void) {
    return read_line_int(0);
}

void add(int i, size_t sz) {
    if (i < 0 || i >= MAX_NOTES || notes[i] || sz == 0 || sz > 0x500) {
        printf("invalid\n");
        return;
    }
    notes[i] = malloc(sizeof(note_t));
    notes[i]->size = sz;
    notes[i]->data = malloc(sz);
    printf("data: ");
    readn(0, notes[i]->data, sz);
}

/* BUG: we never do  notes[i] = NULL  after freeing. The dangling pointer
 * stays in notes[], so the caller can del() again (double-free) or
 * edit()/show() again (use-after-free).
 *
 * Note we only free the DATA buffer, not the note struct. This is
 * deliberate for the tutorial: keeping notes[i]->size and notes[i]->data
 * intact after free means a subsequent show(i) UAF-read still has a valid
 * size to print, which is exactly how the C2/C3 unsorted-bin leak works. */
void del(int i) {
    if (i < 0 || i >= MAX_NOTES || !notes[i]) {
        printf("invalid\n");
        return;
    }
    free(notes[i]->data);   /* only the data buffer */
    /* BUG: missing  notes[i] = NULL;  */
}

/* edit writes n bytes into notes[i]->data. n is NOT bounded by
 * notes[i]->size, which makes a UAF-write of an exact 8-byte fd trivial
 * (and keeps the exploits readable). It does not allocate. */
void edit(int i, size_t n) {
    if (i < 0 || i >= MAX_NOTES || !notes[i] || n == 0 || n > 0x500) {
        printf("invalid\n");
        return;
    }
    printf("data: ");
    readn(0, notes[i]->data, n);
}

/* show prints size then the data buffer. A UAF-show on a freed unsorted-bin
 * chunk leaks the fd pointer (= main_arena+96 on 2.27). */
void show(int i) {
    if (i < 0 || i >= MAX_NOTES || !notes[i]) {
        printf("invalid\n");
        return;
    }
    printf("size=%zu data=", notes[i]->size);
    /* notes[i] may be freed; for the UAF-read we print whatever the
     * (possibly freed) data buffer currently holds. */
    write(1, notes[i]->data, notes[i]->size);
    puts("");
}

static void menu(void) {
    puts("=== heapnote ===");
    puts("1) add    2) delete   3) edit   4) show   5) exit");
    printf("> ");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    while (1) {
        menu();
        int c = read_idx();
        if (g_eof) return 0;
        switch (c) {
        case 1: {
            printf("idx: "); int i = read_idx();
            printf("size: "); int sz = read_size();
            add(i, (size_t)sz);
            break;
        }
        case 2: {
            printf("idx: "); int i = read_idx();
            del(i);
            break;
        }
        case 3: {
            printf("idx: "); int i = read_idx();
            printf("len: "); int n = read_size();
            edit(i, (size_t)n);
            break;
        }
        case 4: {
            printf("idx: "); int i = read_idx();
            show(i);
            break;
        }
        case 5:
            return 0;
        default:
            break;
        }
    }
}
