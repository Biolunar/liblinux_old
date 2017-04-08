#ifndef HEADER_LIBLINUX_LINUX_H_INCLUDED
#define HEADER_LIBLINUX_LINUX_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <linux_syscall/syscall.h>

typedef unsigned int linux_fd_t;
typedef unsigned short linux_umode_t;

struct linux_stat_t
{
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned long st_nlink;

	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int __pad0;
	unsigned long st_rdev;
	long st_size;
	long st_blksize;
	long st_blocks; // Number 512-byte blocks allocated.

	unsigned long st_atime;
	unsigned long st_atime_nsec;
	unsigned long st_mtime;
	unsigned long st_mtime_nsec;
	unsigned long st_ctime;
	unsigned long st_ctime_nsec;
	long __unused[3];
};

struct linux_pollfd_t
{
	int fd;
	short events;
	short revents;
};
typedef long linux_off_t;

#define linux_O_ACCMODE      00000003
#define linux_O_RDONLY       00000000
#define linux_O_WRONLY       00000001
#define linux_O_RDWR         00000002
#define linux_O_CREAT        00000100 // not fcntl
#define linux_O_EXCL         00000200 // not fcntl
#define linux_O_NOCTTY       00000400 // not fcntl
#define linux_O_TRUNC        00001000 // not fcntl
#define linux_O_APPEND       00002000
#define linux_O_NONBLOCK     00004000
#define linux_O_DSYNC        00010000 // used to be O_SYNC, see below
#define linux_FASYNC         00020000 // fcntl, for BSD compatibility
#define linux_O_DIRECT       00040000 // direct disk access hint
#define linux_O_LARGEFILE    00100000
#define linux_O_DIRECTORY    00200000 // must be a directory
#define linux_O_NOFOLLOW     00400000 // don't follow links
#define linux_O_NOATIME      01000000
#define linux_O_CLOEXEC      02000000 // set close_on_exec

#define linux__O_SYNC        04000000
#define linux_O_SYNC         (linux__O_SYNC | linux_O_DSYNC)

#define linux_O_PATH         010000000

#define linux__O_TMPFILE     020000000

// a horrid kludge trying to make sure that this will fail on old kernels
#define linux_O_TMPFILE      (linux__O_TMPFILE | linux_O_DIRECTORY)
#define linux_O_TMPFILE_MASK (linux__O_TMPFILE | linux_O_DIRECTORY | linux_O_CREAT)      

#define linux_O_NDELAY       linux_O_NONBLOCK

#define linux_S_IFMT   00170000
#define linux_S_IFSOCK  0140000
#define linux_S_IFLNK   0120000
#define linux_S_IFREG   0100000
#define linux_S_IFBLK   0060000
#define linux_S_IFDIR   0040000
#define linux_S_IFCHR   0020000
#define linux_S_IFIFO   0010000
#define linux_S_ISUID   0004000
#define linux_S_ISGID   0002000
#define linux_S_ISVTX   0001000

#define linux_S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define linux_S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define linux_S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define linux_S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define linux_S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define linux_S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define linux_S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define linux_S_IRWXU 00700
#define linux_S_IRUSR 00400
#define linux_S_IWUSR 00200
#define linux_S_IXUSR 00100

#define linux_S_IRWXG 00070
#define linux_S_IRGRP 00040
#define linux_S_IWGRP 00020
#define linux_S_IXGRP 00010

#define linux_S_IRWXO 00007
#define linux_S_IROTH 00004
#define linux_S_IWOTH 00002
#define linux_S_IXOTH 00001

#define linux_stdin 0u
#define linux_stdout 1u
#define linux_stderr 2u

// All arguments have the same size as in the kernel sources.
static inline LINUX_DEFINE_SYSCALL3_RET(read, linux_fd_t, fd, char*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(write, linux_fd_t, fd, char const*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(open, char const*, filename, int, flags, linux_umode_t, mode, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(close, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL2_NORET(stat, char const*, filename, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(fstat, linux_fd_t, fd, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(lstat, char const*, filename, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL3_RET(poll, struct linux_pollfd_t*, ufds, unsigned int, nfds, int, timeout, unsigned int)
static inline LINUX_DEFINE_SYSCALL3_RET(lseek, linux_fd_t, fd, linux_off_t, offset, unsigned int, whence, linux_off_t)
static inline LINUX_DEFINE_SYSCALL6_RET(mmap, void*, addr, size_t, len, unsigned long, prot, unsigned long, flags, linux_fd_t, fd, linux_off_t, off, void*)
static inline LINUX_DEFINE_SYSCALL3_NORET(mprotect, void*, start, size_t, len, unsigned long, prot)
static inline LINUX_DEFINE_SYSCALL2_NORET(munmap, void*, addr, size_t, len)
static inline LINUX_DEFINE_SYSCALL1_RET(brk, void*, brk, void*)

#endif // HEADER_LIBLINUX_LINUX_H_INCLUDED
