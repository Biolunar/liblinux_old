#ifndef HEADER_LIBLINUX_LINUX_H_INCLUDED
#define HEADER_LIBLINUX_LINUX_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

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

enum
{
	linux_stdin = 0u,
	linux_stdout = 1u,
	linux_stderr = 2u,
};

enum
{
	linux_O_ACCMODE      = 00000003,
	linux_O_RDONLY       = 00000000,
	linux_O_WRONLY       = 00000001,
	linux_O_RDWR         = 00000002,
	linux_O_CREAT        = 00000100, // not fcntl
	linux_O_EXCL         = 00000200, // not fcntl
	linux_O_NOCTTY       = 00000400, // not fcntl
	linux_O_TRUNC        = 00001000, // not fcntl
	linux_O_APPEND       = 00002000,
	linux_O_NONBLOCK     = 00004000,
	linux_O_DSYNC        = 00010000, // used to be O_SYNC, see below
	linux_FASYNC         = 00020000, // fcntl, for BSD compatibility
	linux_O_DIRECT       = 00040000, // direct disk access hint
	linux_O_LARGEFILE    = 00100000,
	linux_O_DIRECTORY    = 00200000, // must be a directory
	linux_O_NOFOLLOW     = 00400000, // don't follow links
	linux_O_NOATIME      = 01000000,
	linux_O_CLOEXEC      = 02000000, // set close_on_exec

	linux__O_SYNC        = 04000000,
	linux_O_SYNC         = (linux__O_SYNC | linux_O_DSYNC),

	linux_O_PATH         = 010000000,

	linux__O_TMPFILE     = 020000000,

	// a horrid kludge trying to make sure that this will fail on old kernels
	linux_O_TMPFILE      = (linux__O_TMPFILE | linux_O_DIRECTORY),
	linux_O_TMPFILE_MASK = (linux__O_TMPFILE | linux_O_DIRECTORY | linux_O_CREAT),

	linux_O_NDELAY       = linux_O_NONBLOCK,
};

enum
{
	linux_S_IFMT   = 00170000,
	linux_S_IFSOCK = 0140000,
	linux_S_IFLNK  = 0120000,
	linux_S_IFREG  = 0100000,
	linux_S_IFBLK  = 0060000,
	linux_S_IFDIR  = 0040000,
	linux_S_IFCHR  = 0020000,
	linux_S_IFIFO  = 0010000,
	linux_S_ISUID  = 0004000,
	linux_S_ISGID  = 0002000,
	linux_S_ISVTX  = 0001000,

	linux_S_IRWXU  = 00700,
	linux_S_IRUSR  = 00400,
	linux_S_IWUSR  = 00200,
	linux_S_IXUSR  = 00100,

	linux_S_IRWXG  = 00070,
	linux_S_IRGRP  = 00040,
	linux_S_IWGRP  = 00020,
	linux_S_IXGRP  = 00010,

	linux_S_IRWXO  = 00007,
	linux_S_IROTH  = 00004,
	linux_S_IWOTH  = 00002,
	linux_S_IXOTH  = 00001,
};

static inline bool linux_S_ISLNK(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFLNK; }
static inline bool linux_S_ISREG(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFREG; }
static inline bool linux_S_ISDIR(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFDIR; }
static inline bool linux_S_ISCHR(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFCHR; }
static inline bool linux_S_ISBLK(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFBLK; }
static inline bool linux_S_ISFIFO(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFIFO; }
static inline bool linux_S_ISSOCK(linux_umode_t const m) { return (m & linux_S_IFMT) == linux_S_IFSOCK; }

enum
{
	// These are specified by iBCS2
	linux_POLLIN     = 0x0001,
	linux_POLLPRI    = 0x0002,
	linux_POLLOUT    = 0x0004,
	linux_POLLERR    = 0x0008,
	linux_POLLHUP    = 0x0010,
	linux_POLLNVAL   = 0x0020,

	// The rest seem to be more-or-less nonstandard. Check them!
	linux_POLLRDNORM = 0x0040,
	linux_POLLRDBAND = 0x0080,
	linux_POLLWRNORM = 0x0100,
	linux_POLLWRBAND = 0x0200,
	linux_POLLMSG    = 0x0400,
	linux_POLLREMOVE = 0x1000,
	linux_POLLRDHUP  = 0x2000,

	linux_POLLFREE   = 0x4000, // currently only for epoll

	linux_POLL_BUSY_LOOP = 0x8000,
};

enum
{
	linux_SEEK_SET  = 0, // seek relative to beginning of file
	linux_SEEK_CUR  = 1, // seek relative to current file position
	linux_SEEK_END  = 2, // seek relative to end of file
	linux_SEEK_DATA = 3, // seek to the next data
	linux_SEEK_HOLE = 4, // seek to the next hole
	linux_SEEK_MAX  = linux_SEEK_HOLE,
};

enum
{
	linux_PROT_READ      = 0x1,        // page can be read
	linux_PROT_WRITE     = 0x2,        // page can be written
	linux_PROT_EXEC      = 0x4,        // page can be executed
	linux_PROT_SEM       = 0x8,        // page may be used for atomic ops
	linux_PROT_NONE      = 0x0,        // page can not be accessed
	linux_PROT_GROWSDOWN = 0x01000000, // mprotect flag: extend change to start of growsdown vma
	linux_PROT_GROWSUP   = 0x02000000, // mprotect flag: extend change to end of growsup vma
};

enum
{
	linux_MAP_SHARED        = 0x01,      // Share changes
	linux_MAP_PRIVATE       = 0x02,      // Changes are private
	linux_MAP_TYPE          = 0x0f,      // Mask for type of mapping
	linux_MAP_FIXED         = 0x10,      // Interpret addr exactly
	linux_MAP_ANONYMOUS     = 0x20,      // don't use a file
	linux_MAP_UNINITIALIZED = 0x4000000, // For anonymous mmap, memory could be uninitialized

	linux_MAP_FILE          = 0,         // compatibility flag

	linux_MAP_HUGE_SHIFT    = 26,
	linux_MAP_HUGE_MASK     = 0x3f,

	linux_MAP_GROWSDOWN     = 0x0100,    // stack-like segment
	linux_MAP_DENYWRITE     = 0x0800,    // ETXTBSY
	linux_MAP_EXECUTABLE    = 0x1000,    // mark it as an executable
	linux_MAP_LOCKED        = 0x2000,    // pages are locked
	linux_MAP_NORESERVE     = 0x4000,    // don't check for reservations
	linux_MAP_POPULATE      = 0x8000,    // populate (prefault) pagetables
	linux_MAP_NONBLOCK      = 0x10000,   // do not block on IO
	linux_MAP_STACK         = 0x20000,   // give out an address that is best suited for process/thread stacks
	linux_MAP_HUGETLB       = 0x40000,   // create a huge page mapping

	linux_MAP_32BIT         = 0x40,      // only give out 32bit addresses

	linux_MAP_HUGE_2MB      = (21 << linux_MAP_HUGE_SHIFT),
	linux_MAP_HUGE_1GB      = (30 << linux_MAP_HUGE_SHIFT),
};

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
