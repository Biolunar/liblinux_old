#include <liblinux/linux.h>

LINUX_DEFINE_SYSCALL2_NORET(munmap, void*, addr, size_t, len)
