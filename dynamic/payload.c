// Benign freestanding x86-64 payload (no libc). Drops /tmp/stego_marker.
// Identical bytes across all variants. See docs/dynamic-detection.md.
#define SYS_openat 257
#define SYS_write   1
#define SYS_close   3
#define SYS_exit    60
#define AT_FDCWD   -100
#define O_WRONLY    1
#define O_CREAT     0100

static long sys4(long n, long a, long b, long c, long d) {
    long ret;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return ret;
}

void _start(void) {
    const char path[] = "/tmp/stego_marker";
    const char msg[]  = "[*] payload executed (fileless)\n";
    long fd = sys4(SYS_openat, AT_FDCWD, (long)path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) sys4(SYS_close, fd, 0, 0, 0);
    sys4(SYS_write, 1, (long)msg, sizeof(msg) - 1, 0);
    sys4(SYS_exit, 0, 0, 0, 0);
}
