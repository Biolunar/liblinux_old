#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL3_RET(poll, struct linux_pollfd_t*, ufds, unsigned int, nfds, int, timeout, unsigned int)
