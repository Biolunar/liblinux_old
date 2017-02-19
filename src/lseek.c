#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL3_RET(lseek, linux_fd_t, fd, linux_off_t, offset, unsigned int, whence, linux_off_t)
