// Variant B1 (fileless-plain control). Read payload -> memfd_create -> execveat.
// No carrier, no decode: read ~= exec size. See docs/dynamic-detection.md.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "/usr/local/bin/payload";

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open payload"); return 1; }
    off_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    unsigned char *buf = malloc(sz);
    if (read(fd, buf, sz) != sz) { perror("read"); return 1; }
    close(fd);

    int mfd = memfd_create("x", MFD_CLOEXEC);
    if (mfd < 0) { perror("memfd_create"); return 3; }
    write(mfd, buf, sz);

    char *av[] = {"x", NULL}, *ev[] = {NULL};
    syscall(SYS_execveat, mfd, "", av, ev, AT_EMPTY_PATH);
    perror("execveat");
    return 4;
}
