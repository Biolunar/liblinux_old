#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL6_RET(mmap, void*, addr, size_t, len, unsigned long, prot, unsigned long, flags, linux_fd_t, fd, linux_off_t, off, void*)
