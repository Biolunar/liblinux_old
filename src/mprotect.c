#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL3_NORET(mprotect, void*, start, size_t, len, unsigned long, prot)
