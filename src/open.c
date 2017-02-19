#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL3_RET(open, char const*, filename, int, flags, linux_umode_t, mode, linux_fd_t)
