/*
 * Copyright 2017 Mahdi Khanalizadeh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HEADER_LIBLINUX_LINUX_H_INCLUDED
#define HEADER_LIBLINUX_LINUX_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include <linux_syscall/syscall.h>

/* C types
 *
 * _Bool, char, signed char, unsigned char
 * signed short, unsigned short
 * signed int, unsigned int
 * signed long, unsigned long
 * signed long long, unsigned long long
 * float, double, long double
 * size_t, ptrdiff_t, max_align_t, wchar_t
 * intX_t, uintX_t
 * int_fastX_t, uint_fastX_t
 * int_leastX_t, uint_leastX_t
 * intmax_t, uintmax_t
 * intptr_t, uintptr_t
 */

// Some syscalls do not modify a parameter but are passed as non-const
// pointers in the kernel sources. Define this macro so that our syscalls also
// expect non-const pointers. Do not define this macro if you wish to have const
// correctness.
#ifdef LINUX_NO_SAFE_CONST
#define LINUX_SAFE_CONST
#else
#define LINUX_SAFE_CONST const
#endif // LINUX_NO_SAFE_CONST

//------------------------------------------------------------------------------
// Custom types

typedef unsigned int linux_fd_t;

// Custom types
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Kernel types

typedef unsigned short linux_kernel_mode_t;
typedef unsigned short linux_umode_t;
typedef long long linux_kernel_long_t;
typedef unsigned long long linux_kernel_ulong_t;
typedef linux_kernel_long_t linux_kernel_off_t;
typedef linux_kernel_off_t linux_off_t;
typedef int linux_kernel_pid_t;
typedef linux_kernel_pid_t linux_pid_t;
typedef unsigned int linux_kernel_uid32_t;
typedef unsigned int linux_kernel_gid32_t;
typedef linux_kernel_uid32_t linux_arch_si_uid_t;
typedef int linux_kernel_timer_t;
typedef linux_kernel_long_t linux_kernel_clock_t;
typedef linux_kernel_clock_t linux_arch_si_clock_t;
typedef long linux_arch_si_band_t;
typedef unsigned long linux_sigset_t;
typedef linux_kernel_ulong_t linux_kernel_size_t;
typedef long long linux_kernel_loff_t;
typedef linux_kernel_loff_t linux_loff_t;
typedef linux_kernel_long_t linux_kernel_time_t;
typedef linux_kernel_long_t linux_kernel_suseconds_t;
typedef int linux_kernel_key_t;
typedef linux_kernel_key_t linux_key_t;
struct linux_stat_t
{
	linux_kernel_ulong_t st_dev;
	linux_kernel_ulong_t st_ino;
	linux_kernel_ulong_t st_nlink;

	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int _pad0;
	linux_kernel_ulong_t st_rdev;
	linux_kernel_long_t st_size;
	linux_kernel_long_t st_blksize;
	linux_kernel_long_t st_blocks; // Number 512-byte blocks allocated.

	linux_kernel_ulong_t st_atime;
	linux_kernel_ulong_t st_atime_nsec;
	linux_kernel_ulong_t st_mtime;
	linux_kernel_ulong_t st_mtime_nsec;
	linux_kernel_ulong_t st_ctime;
	linux_kernel_ulong_t st_ctime_nsec;
	linux_kernel_long_t _unused[3];
};
struct linux_pollfd_t
{
	int fd; // TODO: int is used as a file descriptor.
	short events;
	short revents;
};
typedef void linux_signalfn_t(int sig);
typedef linux_signalfn_t* linux_sighandler_t;
typedef void linux_restorefn_t(void);
typedef linux_restorefn_t* linux_sigrestore_t;
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
			linux_arch_si_uid_t si_uid; // sender's uid
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
			linux_arch_si_uid_t si_uid; // sender's uid
			union linux_sigval_t si_value;
		} rt;

		// SIGCHLD
		struct
		{
			linux_kernel_pid_t si_pid; // which child
			linux_arch_si_uid_t si_uid; // sender's uid
			int si_status; // exit code
			char _pad[4];
			linux_arch_si_clock_t si_utime;
			linux_arch_si_clock_t si_stime;
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
			linux_arch_si_band_t si_band; // POLL_IN, POLL_OUT, POLL_MSG
			int si_fd; // TODO: int is used as a file descriptor.
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
typedef struct
{
	void* ss_sp;
	int ss_flags;
	size_t ss_size;
} linux_stack_t;
struct linux_fpx_sw_bytes_t
{
	// If set to FP_XSTATE_MAGIC1 then this is an xstate context.
	// 0 if a legacy frame.
	uint32_t magic1;

	// Total size of the fpstate area:
	//
	//  - if magic1 == 0 then it's sizeof(struct _fpstate)
	//  - if magic1 == FP_XSTATE_MAGIC1 then it's sizeof(struct _xstate)
	//    plus extensions (if any)
	uint32_t extended_size;

	// Feature bit mask (including FP/SSE/extended state) that is present
	// in the memory layout:
	uint64_t xfeatures;

	// Actual XSAVE state size, based on the xfeatures saved in the layout.
	// 'extended_size' is greater than 'xstate_size':
	uint32_t xstate_size;

	// For future use:
	uint32_t _padding[7];
};
struct linux_fpstate_t
{
	uint16_t cwd;
	uint16_t swd;
	// Note this is not the same as the 32-bit/x87/FSAVE twd:
	uint16_t twd;
	uint16_t fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcsr_mask;
	uint32_t st_space[32];  //  8x  FP registers, 16 bytes each
	uint32_t xmm_space[64];	// 16x XMM registers, 16 bytes each
	uint32_t reserved2[12];
	union
	{
		uint32_t eserved3[12];
		struct linux_fpx_sw_bytes_t sw_reserved; // Potential extended state is encoded here
	};
};
struct linux_sigcontext_t
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
	struct linux_fpstate_t* fpstate; // Zero when no FPU context
	uint64_t _reserved1[8];
};
struct linux_ucontext_t
{
	unsigned long uc_flags;
	struct linux_ucontext_t* uc_link;
	linux_stack_t uc_stack;
	struct linux_sigcontext_t uc_mcontext;
	linux_sigset_t uc_sigmask; // mask last for extensibility
};
typedef void linux_infofn_t(int sig, struct linux_siginfo_t* info, struct linux_ucontext_t* context);
typedef linux_infofn_t* linux_siginfo_t;
struct linux_sigaction_t
{
	linux_sighandler_t sa_handler;
	unsigned long sa_flags;
	linux_sigrestore_t sa_restorer;
	linux_sigset_t sa_mask; // mask last for extensibility
};
struct linux_iovec_t
{
	void* iov_base; // BSD uses caddr_t (1003.1g requires void *)
	linux_kernel_size_t iov_len; // Must be size_t (1003.1g)
};
typedef struct
{
	unsigned long _fds_bits[1024 / (CHAR_BIT * sizeof(long))];
} linux_kernel_fd_set_t;
typedef linux_kernel_fd_set_t linux_fd_set_t;
struct linux_timeval_t
{
	linux_kernel_time_t      tv_sec;  // seconds
	linux_kernel_suseconds_t tv_usec; // microseconds
};
struct linux_ipc64_perm
{
	linux_kernel_key_t key;
	linux_kernel_uid32_t uid;
	linux_kernel_gid32_t gid;
	linux_kernel_uid32_t cuid;
	linux_kernel_gid32_t cgid;
	linux_kernel_mode_t mode;
	// pad if mode_t is u16:
	unsigned char _pad1[4 - sizeof(linux_kernel_mode_t)];
	unsigned short seq;
	unsigned char _pad2[6];
	linux_kernel_ulong_t _unused1;
	linux_kernel_ulong_t _unused2;
};
struct linux_shmid64_ds
{
	struct linux_ipc64_perm shm_perm; // operation perms
	size_t shm_segsz; // size of segment (bytes)
	linux_kernel_time_t shm_atime; // last attach time
	linux_kernel_time_t shm_dtime; // last detach time
	linux_kernel_time_t shm_ctime; // last change time
	linux_kernel_pid_t shm_cpid; //  of creator
	linux_kernel_pid_t shm_lpid; //  of last operator
	linux_kernel_ulong_t shm_nattch; // no. of current attaches
	linux_kernel_ulong_t _unused4;
	linux_kernel_ulong_t _unused5;
};
struct linux_shminfo64
{
	linux_kernel_ulong_t shmmax;
	linux_kernel_ulong_t shmmin;
	linux_kernel_ulong_t shmmni;
	linux_kernel_ulong_t shmseg;
	linux_kernel_ulong_t shmall;
	linux_kernel_ulong_t _unused1;
	linux_kernel_ulong_t _unused2;
	linux_kernel_ulong_t _unused3;
	linux_kernel_ulong_t _unused4;
};
struct linux_shm_info
{
	int used_ids;
	unsigned char _pad[4];
	linux_kernel_ulong_t shm_tot; // total allocated shm
	linux_kernel_ulong_t shm_rss; // total resident shm
	linux_kernel_ulong_t shm_swp; // total swapped shm
	linux_kernel_ulong_t swap_attempts;
	linux_kernel_ulong_t swap_successes;
};
struct linux_timespec_t
{
	linux_kernel_time_t tv_sec;
	long tv_nsec;
};
struct linux_itimerval_t
{
	struct linux_timeval_t it_interval; // timer interval
	struct linux_timeval_t it_value; // current value
};

// Kernel types
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Constants

enum
{
	linux_stdin  = 0u,
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

	linux_O_SYNC         = 04010000,

	linux_O_PATH         = 010000000,

	linux_O_TMPFILE      = 020200000, // a horrid kludge trying to make sure that this will fail on old kernels
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

enum
{
	// These are specified by iBCS2
	linux_POLLIN         = 0x0001,
	linux_POLLPRI        = 0x0002,
	linux_POLLOUT        = 0x0004,
	linux_POLLERR        = 0x0008,
	linux_POLLHUP        = 0x0010,
	linux_POLLNVAL       = 0x0020,

	// The rest seem to be more-or-less nonstandard. Check them!
	linux_POLLRDNORM     = 0x0040,
	linux_POLLRDBAND     = 0x0080,
	linux_POLLWRNORM     = 0x0100,
	linux_POLLWRBAND     = 0x0200,
	linux_POLLMSG        = 0x0400,
	linux_POLLREMOVE     = 0x1000,
	linux_POLLRDHUP      = 0x2000,

	linux_POLLFREE       = 0x4000, // currently only for epoll

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

#define linux_SIG_DFL ((linux_sighandler_t)0)
#define linux_SIG_IGN ((linux_sighandler_t)1)
#define linux_SIG_ERR ((linux_sighandler_t)-1)

_Static_assert((unsigned)INT_MIN == 0x80000000u, "Needs a two's complement platform.");
enum
{
	linux_SA_NOCLDSTOP = 0x00000001u,
	linux_SA_NOCLDWAIT = 0x00000002u,
	linux_SA_SIGINFO   = 0x00000004u,
	linux_SA_ONSTACK   = 0x08000000u,
	linux_SA_RESTART   = 0x10000000u,
	linux_SA_NODEFER   = 0x40000000u,
	linux_SA_RESETHAND = INT_MIN, // Workaround for the value 0x80000000u as a signed int.

	linux_SA_NOMASK    = linux_SA_NODEFER,
	linux_SA_ONESHOT   = linux_SA_RESETHAND,

	linux_SA_RESTORER  = 0x04000000,
};

enum
{
	linux_SIG_BLOCK   = 0,
	linux_SIG_UNBLOCK = 1,
	linux_SIG_SETMASK = 2,
};

enum
{
	linux_FP_XSTATE_MAGIC1      = 0x46505853u,
	linux_FP_XSTATE_MAGIC2      = 0x46505845u,
};
#define linux_FP_XSTATE_MAGIC2_SIZE   (sizeof linux_FP_XSTATE_MAGIC2)

enum // Kernel sources do not explicitly define these constants. They correspond to S_IXOTH, S_IWOTH and S_IROTH.
{
	linux_F_OK = 0,
	linux_X_OK = 1,
	linux_W_OK = 2,
	linux_R_OK = 4,
};

enum
{
	linux_MREMAP_MAYMOVE = 1,
	linux_MREMAP_FIXED   = 2,
};

enum
{
	linux_MS_ASYNC      = 1, // sync memory asynchronously
	linux_MS_INVALIDATE = 2, // invalidate the caches
	linux_MS_SYNC       = 4, // synchronous memory sync
};

enum
{
	linux_MADV_NORMAL       =   0, // no further special treatment
	linux_MADV_RANDOM       =   1, // expect random page references
	linux_MADV_SEQUENTIAL   =   2, // expect sequential page references
	linux_MADV_WILLNEED     =   3, // will need these pages
	linux_MADV_DONTNEED     =   4, // don't need these pages
	linux_MADV_FREE         =   8, // free pages only if memory pressure
	linux_MADV_REMOVE       =   9, // remove these pages & resources
	linux_MADV_DONTFORK     =  10, // don't inherit across fork
	linux_MADV_DOFORK       =  11, // do inherit across fork
	linux_MADV_HWPOISON     = 100, // poison a page for testing
	linux_MADV_SOFT_OFFLINE = 101, // soft offline page for testing
	linux_MADV_MERGEABLE    =  12, // KSM may merge identical pages
	linux_MADV_UNMERGEABLE  =  13, // KSM may not merge identical pages
	linux_MADV_HUGEPAGE     =  14, // Worth backing with hugepages
	linux_MADV_NOHUGEPAGE   =  15, // Not worth backing with hugepages
	linux_MADV_DONTDUMP     =  16, // Explicity exclude from the core dump, overrides the coredump filter bits
	linux_MADV_DODUMP       =  17, // Clear the MADV_DONTDUMP flag
};

enum
{
	linux_IPC_PRIVATE = 0,
};

enum
{
	// resource get request flags
	linux_IPC_CREAT  = 00001000, // create if key is nonexistent
	linux_IPC_EXCL   = 00002000, // fail if key exists
	linux_IPC_NOWAIT = 00004000, // return error on wait

	// Control commands used with semctl, msgctl and shmctl
	// see also specific commands in sem.h, msg.h and shm.h
	linux_IPC_RMID   = 0, // remove resource
	linux_IPC_SET    = 1, // set ipc_perm options
	linux_IPC_STAT   = 2, // get ipc_perm options
	linux_IPC_INFO   = 3, // see ipcs
};

enum
{
	linux_SHMMIN = 1, // min shared seg size (bytes)
	linux_SHMMNI = 4096, // max num of segs system wide
#define linux_SHMMAX   (ULONG_MAX - (1ul << 24)) // max shared seg size (bytes)
#define linux_SHMALL   (ULONG_MAX - (1ul << 24)) // max shm system wide (pages)
	linux_SHMSEG = linux_SHMMNI, // max shared segs per process
};

enum
{
	// permission flag for shmget
	linux_SHM_R      = 0400, // or S_IRUGO from <linux/stat.h>
	linux_SHM_W      = 0200, // or S_IWUGO from <linux/stat.h>

	// mode for attach
	linux_SHM_RDONLY = 010000, // read-only access
	linux_SHM_RND    = 020000, // round attach address to SHMLBA boundary
	linux_SHM_REMAP  = 040000, // take-over region on attach
	linux_SHM_EXEC   = 0100000, // execution access

	// super user shmctl commands
	linux_SHM_LOCK   = 11,
	linux_SHM_UNLOCK = 12,

	// ipcs ctl commands
	linux_SHM_STAT   = 13,
	linux_SHM_INFO   = 14,

	// shm_mode upper byte flags
	linux_SHM_DEST      = 01000, // egment will be destroyed on last detach
	linux_SHM_LOCKED    = 02000, // segment will not be swapped
	linux_SHM_HUGETLB   = 04000, // segment will use huge TLB pages
	linux_SHM_NORESERVE = 010000, // don't check for reservations

	// Bits [26:31] are reserved

	// When SHM_HUGETLB is set bits [26:31] encode the log2 of the huge page size.
	// This gives us 6 bits, which is enough until someone invents 128 bit address
	// spaces.
	//
	// Assume these are all power of twos.
	// When 0 use the default page size.
#define linux_SHM_HUGE_SHIFT  26
	linux_SHM_HUGE_2MB  = (21 << linux_SHM_HUGE_SHIFT),
	linux_SHM_HUGE_1GB  = (30 << linux_SHM_HUGE_SHIFT),
};

enum
{
	linux_PAGE_SIZE = 4096,
	linux_SHMLBA = linux_PAGE_SIZE,
};

enum
{
	linux_ITIMER_REAL    = 0,
	linux_ITIMER_VIRTUAL = 1,
	linux_ITIMER_PROF    = 2,
};

// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Helper functions

static inline bool linux_S_ISLNK(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFLNK;
}

static inline bool linux_S_ISREG(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFREG;
}

static inline bool linux_S_ISDIR(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFDIR;
}

static inline bool linux_S_ISCHR(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFCHR;
}

static inline bool linux_S_ISBLK(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFBLK;
}

static inline bool linux_S_ISFIFO(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFIFO;
}

static inline bool linux_S_ISSOCK(linux_umode_t const m)
{
	return (m & linux_S_IFMT) == linux_S_IFSOCK;
}

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

static inline void linux_FD_ZERO(linux_fd_set_t* const set)
{
	// Don't use memset here because that needs a libc.
	unsigned long* p = set->_fds_bits;
	for(size_t i = sizeof(linux_fd_set_t) / sizeof(long); i; --i)
		*p++ = 0;
}

static inline void linux_FD_SET(int const fd, linux_fd_set_t* const set)
{
	set->_fds_bits[(unsigned)fd / (CHAR_BIT * sizeof(long))] |= (1ul << ((unsigned)fd % (CHAR_BIT * sizeof(long))));
}

static inline void linux_FD_CLR(int const fd, linux_fd_set_t* const set)
{
	set->_fds_bits[(unsigned)fd / (CHAR_BIT * sizeof(long))] &= ~(1ul << ((unsigned)fd % (CHAR_BIT * sizeof(long))));
}

static inline bool linux_FD_ISSET(int const fd, linux_fd_set_t* const set)
{
	return set->_fds_bits[(unsigned)fd / (CHAR_BIT * sizeof(long))] & (1ul << ((unsigned)fd % (CHAR_BIT * sizeof(long))));
}

// Helper functions
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Syscalls

static inline LINUX_DEFINE_SYSCALL3_RET(read, linux_fd_t, fd, void*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(write, linux_fd_t, fd, void const*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(open, char const*, filename, int, flags, linux_umode_t, mode, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(close, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL2_NORET(stat, char const*, filename, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(fstat, linux_fd_t, fd, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(lstat, char const*, filename, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL3_RET(poll, struct linux_pollfd_t*, ufds, unsigned int, nfds, int, timeout, unsigned int)
static inline LINUX_DEFINE_SYSCALL3_RET(lseek, linux_fd_t, fd, linux_off_t, offset, unsigned int, whence, linux_off_t)
static inline LINUX_DEFINE_SYSCALL6_RET(mmap, void const*, addr, size_t, len, unsigned long, prot, unsigned long, flags, linux_fd_t, fd, linux_off_t, off, void*)
static inline LINUX_DEFINE_SYSCALL3_NORET(mprotect, void const*, start, size_t, len, unsigned long, prot)
static inline LINUX_DEFINE_SYSCALL2_NORET(munmap, void const*, addr, size_t, len)
static inline LINUX_DEFINE_SYSCALL1_RET(brk, void const*, brk, void*)
static inline LINUX_DEFINE_SYSCALL4_NORET(rt_sigaction, int, sig, struct linux_sigaction_t const*, act, struct linux_sigaction_t*, oact, size_t, sigsetsize)
static inline LINUX_DEFINE_SYSCALL4_NORET(rt_sigprocmask, int, how, linux_sigset_t LINUX_SAFE_CONST*, set, linux_sigset_t*, oset, size_t, sigsetsize)
//rt_sigreturn
static inline LINUX_DEFINE_SYSCALL3_RET(ioctl, linux_fd_t, fd, unsigned int, cmd, uintptr_t, arg, unsigned int)
static inline LINUX_DEFINE_SYSCALL4_RET(pread64, linux_fd_t, fd, void*, buf, size_t, count, linux_loff_t, pos, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(pwrite64, linux_fd_t, fd, void const*, buf, size_t, count, linux_loff_t, pos, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(readv, linux_fd_t, fd, struct linux_iovec_t const*, vec, unsigned long, vlen, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(writev, linux_fd_t, fd, struct linux_iovec_t const*, vec, unsigned long, vlen, size_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(access, char const*, filename, int, mode)
static inline LINUX_DEFINE_SYSCALL1_NORET(pipe, linux_fd_t*, fildes)
static inline LINUX_DEFINE_SYSCALL5_RET(select, int, n, linux_fd_set_t*, inp, linux_fd_set_t*, outp, linux_fd_set_t*, exp, struct linux_timeval_t*, tvp, unsigned int)
static inline LINUX_DEFINE_SYSCALL0_NORET(sched_yield)
static inline LINUX_DEFINE_SYSCALL5_RET(mremap, void const*, addr, size_t, old_len, size_t, new_len, unsigned long, flags, void const*, new_addr, void*)
static inline LINUX_DEFINE_SYSCALL3_NORET(msync, void const*, start, size_t, len, int, flags)
static inline LINUX_DEFINE_SYSCALL3_NORET(mincore, void const*, start, size_t, len, unsigned char*, vec)
static inline LINUX_DEFINE_SYSCALL3_NORET(madvise, void const*, start, size_t, len, int, behavior)
static inline LINUX_DEFINE_SYSCALL3_RET(shmget, linux_key_t, key, size_t, size, int, flag, int)
static inline LINUX_DEFINE_SYSCALL3_RET(shmat, int, shmid, void LINUX_SAFE_CONST*, shmaddr, int, shmflg, void*)
static inline LINUX_DEFINE_SYSCALL3_RET(shmctl, int, shmid, int, cmd, struct linux_shmid64_ds*, buf, int)
static inline LINUX_DEFINE_SYSCALL1_RET(dup, linux_fd_t, fildes, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_RET(dup2, linux_fd_t, oldfd, linux_fd_t, newfd, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL0_NORET(pause)
static inline LINUX_DEFINE_SYSCALL2_NORET(nanosleep, struct linux_timespec_t LINUX_SAFE_CONST*, rqtp, struct linux_timespec_t*, rmtp)
static inline LINUX_DEFINE_SYSCALL2_NORET(getitimer, int, which, struct linux_itimerval_t*, value)
static inline LINUX_DEFINE_SYSCALL1_RET(alarm, unsigned int, seconds, unsigned int)
static inline LINUX_DEFINE_SYSCALL3_NORET(setitimer, int, which, struct linux_itimerval_t  LINUX_SAFE_CONST*, value, struct linux_itimerval_t*, ovalue)
static inline LINUX_DEFINE_SYSCALL0_RET(getpid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL4_RET(sendfile, linux_fd_t, out_fd, linux_fd_t, in_fd, linux_loff_t, offset, size_t, count, size_t)
// Insert more syscalls here first.
static inline LINUX_DEFINE_SYSCALL2_NORET(kill, linux_pid_t, pid, int, sig)
// Insert more syscalls here first.
static inline LINUX_DEFINE_SYSCALL1_NORET(shmdt, void LINUX_SAFE_CONST*, shmaddr)

// Syscalls
//------------------------------------------------------------------------------

#endif // HEADER_LIBLINUX_LINUX_H_INCLUDED
