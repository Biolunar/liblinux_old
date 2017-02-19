#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL3_RET(write, linux_fd_t, fd, void const*, buf, size_t, count, size_t)
