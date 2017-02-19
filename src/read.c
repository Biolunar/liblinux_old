#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL3_RET(read, linux_fd_t, fd, void*, buf, size_t, count, size_t)
