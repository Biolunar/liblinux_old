#ifndef HEADER_LIBLINUX_LINUX_H_INCLUDED
#define HEADER_LIBLINUX_LINUX_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include <linux_syscall/syscall.h>

typedef unsigned int linux_fd_t;
typedef unsigned short linux_umode_t;
typedef long linux_off_t;
typedef int linux_kernel_pid_t;
typedef unsigned int linux_kernel_uid32_t;
typedef int linux_kernel_timer_t;
typedef long linux_kernel_clock_t;
typedef long long linux_loff_t;
typedef long linux_kernel_time_t;
typedef long linux_kernel_suseconds_t;

struct linux_stat_t
{
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned long st_nlink;

	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int _pad0;
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
	long _unused[3];
};

struct linux_pollfd_t
{
	int fd;
	short events;
	short revents;
};

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

	//linux__O_SYNC        = 04000000,
	//linux_O_SYNC         = (linux__O_SYNC | linux_O_DSYNC),
	linux_O_SYNC         = 04010000,

	linux_O_PATH         = 010000000,

	//linux__O_TMPFILE     = 020000000,

	// a horrid kludge trying to make sure that this will fail on old kernels
	//linux_O_TMPFILE      = (linux__O_TMPFILE | linux_O_DIRECTORY),
	//linux_O_TMPFILE_MASK = (linux__O_TMPFILE | linux_O_DIRECTORY | linux_O_CREAT),
	linux_O_TMPFILE      = 020200000,
	linux_O_TMPFILE_MASK = (linux_O_TMPFILE | linux_O_CREAT),

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

enum
{
	linux_SIGHUP    =  1,
	linux_SIGINT    =  2,
	linux_SIGQUIT   =  3,
	linux_SIGILL    =  4,
	linux_SIGTRAP   =  5,
	linux_SIGABRT   =  6,
	linux_SIGIOT    =  6,
	linux_SIGBUS    =  7,
	linux_SIGFPE    =  8,
	linux_SIGKILL   =  9,
	linux_SIGUSR1   = 10,
	linux_SIGSEGV   = 11,
	linux_SIGUSR2   = 12,
	linux_SIGPIPE   = 13,
	linux_SIGALRM   = 14,
	linux_SIGTERM   = 15,
	linux_SIGSTKFLT = 16,
	linux_SIGCHLD   = 17,
	linux_SIGCONT   = 18,
	linux_SIGSTOP   = 19,
	linux_SIGTSTP   = 20,
	linux_SIGTTIN   = 21,
	linux_SIGTTOU   = 22,
	linux_SIGURG    = 23,
	linux_SIGXCPU   = 24,
	linux_SIGXFSZ   = 25,
	linux_SIGVTALRM = 26,
	linux_SIGPROF   = 27,
	linux_SIGWINCH  = 28,
	linux_SIGIO     = 29,
	linux_SIGPOLL   = linux_SIGIO,
	//linux_SIGLOST   = 29,
	linux_SIGPWR    = 30,
	linux_SIGSYS    = 31,
	linux_SIGUNUSED = 31,

	linux_SIGRTMIN  = 32,
	linux_SIGRTMAX  = 64,
};

union linux_sigval_t
{
	int sival_int;
	void* sival_ptr;
};

struct linux_siginfo_t
{
	int si_signo;
	int si_errno;
	int si_code;

	char _pad[4];
	union
	{
		int _pad[(128 - 4 * sizeof(int)) / sizeof(int)];

		// kill()
		struct
		{
			linux_kernel_pid_t si_pid; // sender's pid
			linux_kernel_uid32_t si_uid; // sender's uid
		} kill;

		// POSIX.1b timers
		struct
		{
			linux_kernel_timer_t si_timerid; // timer id
			int si_overrun; // overrun count
			union linux_sigval_t si_value; // same as below
			int _sys_private; // not to be passed to user
			char _pad[4];
		} timer;

		// POSIX.1b signals
		struct
		{
			linux_kernel_pid_t si_pid; // sender's pid
			linux_kernel_uid32_t si_uid; // sender's uid
			union linux_sigval_t si_value;
		} rt;

		// SIGCHLD
		struct
		{
			linux_kernel_pid_t si_pid; // which child
			linux_kernel_uid32_t si_uid; // sender's uid
			int si_status; // exit code
			char _pad[4];
			linux_kernel_clock_t si_utime;
			linux_kernel_clock_t si_stime;
		} sigchld;

		// SIGILL, SIGFPE, SIGSEGV, SIGBUS
		struct
		{
			void* si_addr; // faulting insn/memory ref.
			short si_addr_lsb; // LSB of the reported address
			char _pad[6];
			union
			{
				// used when si_code=SEGV_BNDERR
				struct
				{
					void* si_lower;
					void* si_upper;
				} addr_bnd;
				// used when si_code=SEGV_PKUERR
				uint32_t si_pkey;
			};
		} sigfault;

		// SIGPOLL
		struct
		{
			long si_band; // POLL_IN, POLL_OUT, POLL_MSG
			int si_fd;
			char _pad[4];
		} sigpoll;

		// SIGSYS
		struct
		{
			void* si_call_addr; // calling user insn
			int si_syscall; // triggering system call number
			unsigned int si_arch; // AUDIT_ARCH_* of syscall
		} sigsys;
	} sifields;
};

typedef unsigned long linux_sigset_t;

struct linux_stack_t
{
	void* ss_sp;
	int ss_flags;
	size_t ss_size;
};

struct linux_sigcontext
{
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t rdx;
	uint64_t rax;
	uint64_t rcx;
	uint64_t rsp;
	uint64_t rip;
	uint64_t eflags; // RFLAGS
	uint16_t cs;

	/*
	 * Prior to 2.5.64 ("[PATCH] x86-64 updates for 2.5.64-bk3"),
	 * Linux saved and restored fs and gs in these slots.  This
	 * was counterproductive, as fsbase and gsbase were never
	 * saved, so arch_prctl was presumably unreliable.
	 *
	 * These slots should never be reused without extreme caution:
	 *
	 *  - Some DOSEMU versions stash fs and gs in these slots manually,
	 *    thus overwriting anything the kernel expects to be preserved
	 *    in these slots.
	 *
	 *  - If these slots are ever needed for any other purpose,
	 *    there is some risk that very old 64-bit binaries could get
	 *    confused.  I doubt that many such binaries still work,
	 *    though, since the same patch in 2.5.64 also removed the
	 *    64-bit set_thread_area syscall, so it appears that there
	 *    is no TLS API beyond modify_ldt that works in both pre-
	 *    and post-2.5.64 kernels.
	 *
	 * If the kernel ever adds explicit fs, gs, fsbase, and gsbase
	 * save/restore, it will most likely need to be opt-in and use
	 * different context slots.
	 */
	uint16_t gs;
	uint16_t fs;
	union
	{
		uint16_t ss;    // If UC_SIGCONTEXT_SS
		uint16_t _pad0; // Alias name for old (!UC_SIGCONTEXT_SS) user-space
	};
	uint64_t err;
	uint64_t trapno;
	uint64_t oldmask;
	uint64_t cr2;
	struct _fpstate* fpstate; // Zero when no FPU context
	uint64_t reserved1[8];
};

struct linux_ucontext
{
	unsigned long uc_flags;
	struct linux_ucontext* uc_link;
	struct linux_stack_t uc_stack;
	struct linux_sigcontext uc_mcontext;
	linux_sigset_t uc_sigmask; // mask last for extensibility
};

typedef void (*linux_sighandler_t)(int signum);
typedef void (*linux_sigactionhandler_t)(int signum, struct linux_siginfo_t* info, void* context);
typedef void (*linux_sigrestore_t)(void);

struct linux_sigaction
{
	linux_sighandler_t sa_handler;
	unsigned long sa_flags;
	linux_sigrestore_t sa_restorer;
	linux_sigset_t sa_mask; // mask last for extensibility
};

#define linux_SIG_DFL (linux_sighandler_t)0
#define linux_SIG_IGN (linux_sighandler_t)1
#define linux_SIG_ERR (linux_sighandler_t)-1

enum
{
	linux_SA_NOCLDSTOP = 0x00000001u,
	linux_SA_NOCLDWAIT = 0x00000002u,
	linux_SA_SIGINFO   = 0x00000004u,
	linux_SA_ONSTACK   = 0x08000000u,
	linux_SA_RESTART   = 0x10000000u,
	linux_SA_NODEFER   = 0x40000000u,
	//linux_SA_RESETHAND = 0x80000000u, // TODO: ISO C restricts enumerator values to range of 'int'.

	linux_SA_NOMASK    = linux_SA_NODEFER,
	//linux_SA_ONESHOT   = linux_SA_RESETHAND, // TODO: ISO C restricts enumerator values to range of 'int'.

	linux_SA_RESTORER  = 0x04000000,
};
// TODO: Those are workarounds for the maximum size of an enum.
#define linux_SA_RESETHAND   0x80000000u
#define linux_SA_ONESHOT     linux_SA_RESETHAND

enum
{
	linux_SIG_BLOCK   = 0,
	linux_SIG_UNBLOCK = 1,
	linux_SIG_SETMASK = 2,
};

static inline void linux_sigemptyset(linux_sigset_t* const set)
{
	*set = 0ul;
}

static inline void linux_sigfillset(linux_sigset_t* const set)
{
	*set = -1ul;
}

static inline enum linux_error_t linux_sigaddset(linux_sigset_t* const set, int const signum)
{
	if (signum == 0 || signum > 64)
		return linux_EINVAL;
	*set |= 1ul << (signum - 1);
	return linux_error_none;
}

static inline enum linux_error_t linux_sigdelset(linux_sigset_t* const set, int const signum)
{
	if (signum == 0 || signum > 64)
		return linux_EINVAL;
	*set &= ~(1ul << (signum - 1));
	return linux_error_none;
}

static inline enum linux_error_t linux_sigismember(linux_sigset_t const* const set, int const signum, bool* const ret)
{
	if (signum == 0 || signum > 64)
		return linux_EINVAL;
	*ret = *set & (1ul << (signum - 1));
	return linux_error_none;
}

struct linux_iovec
{
	void* iov_base; // BSD uses caddr_t (1003.1g requires void *)
	size_t iov_len; // Must be size_t (1003.1g)
};

enum // TODO: Kernel sources do not explicitly define these constants. They correspond to S_IXOTH, S_IWOTH and S_IROTH.
{
	linux_F_OK = 0,
	linux_X_OK = 1,
	linux_W_OK = 2,
	linux_R_OK = 4,
};

struct linux_timeval_t
{
	linux_kernel_time_t      tv_sec;  // seconds
	linux_kernel_suseconds_t tv_usec; // microseconds
};

struct linux_fd_set_t
{
	unsigned long _fds_bits[1024 / (CHAR_BIT * sizeof(long))];
};

static inline void linux_FD_ZERO(struct linux_fd_set_t* set)
{
	// Don't use memset here because that needs a libc.
	unsigned long* p = set->_fds_bits;
	for(size_t i = sizeof(struct linux_fd_set_t) / sizeof(long); i; --i)
		*p++ = 0;
}

static inline void linux_FD_SET(int fd, struct linux_fd_set_t* set)
{
	set->_fds_bits[(unsigned)fd / (CHAR_BIT * sizeof(long))] |= (1ul << ((unsigned)fd % (CHAR_BIT * sizeof(long))));
}

static inline void linux_FD_CLR(int fd, struct linux_fd_set_t* set)
{
	set->_fds_bits[(unsigned)fd / (CHAR_BIT * sizeof(long))] &= ~(1ul << ((unsigned)fd % (CHAR_BIT * sizeof(long))));
}

static inline bool linux_FD_ISSET(int fd, struct linux_fd_set_t* set)
{
	return set->_fds_bits[(unsigned)fd / (CHAR_BIT * sizeof(long))] & (1ul << ((unsigned)fd % (CHAR_BIT * sizeof(long))));
}

enum
{
	linux_MREMAP_MAYMOVE = 1,
	linux_MREMAP_FIXED   = 2,
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
static inline LINUX_DEFINE_SYSCALL4_NORET(rt_sigaction, int, signum, struct linux_sigaction const*, act, struct linux_sigaction*, oact, size_t, sigsetsize)
static inline LINUX_DEFINE_SYSCALL4_NORET(rt_sigprocmask, int, how, linux_sigset_t*, set, linux_sigset_t*, oset, size_t, sigsetsize)
//rt_sigreturn
static inline LINUX_DEFINE_SYSCALL3_RET(ioctl, unsigned int, fd, unsigned int, cmd, uintptr_t, arg, unsigned int)
static inline LINUX_DEFINE_SYSCALL4_RET(pread64, unsigned int, fd, char*, buf, size_t, count, linux_loff_t, pos, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(pwrite64, unsigned int, fd, char const*, buf, size_t, count, linux_loff_t, pos, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(readv, unsigned int, fd, struct linux_iovec const*, vec, unsigned long, vlen, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(writev, unsigned int, fd, struct linux_iovec const*, vec, unsigned long, vlen, size_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(access, char const*, filename, int, mode)
static inline LINUX_DEFINE_SYSCALL1_NORET(pipe, int*, fildes)
static inline LINUX_DEFINE_SYSCALL5_RET(select, int, n, struct linux_fd_set_t*, inp, struct linux_fd_set_t*, outp, struct linux_fd_set_t*, exp, struct linux_timeval_t*, tvp, unsigned int)
static inline LINUX_DEFINE_SYSCALL0_NORET(sched_yield)
static inline LINUX_DEFINE_SYSCALL5_RET(mremap, void*, addr, size_t, old_len, size_t, new_len, unsigned long, flags, void*, new_addr, void*)

#endif // HEADER_LIBLINUX_LINUX_H_INCLUDED
