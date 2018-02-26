/*
 * Copyright 2018 Mahdi Khanalizadeh
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
#include <stdalign.h>
#include <limits.h>

#include <liblinux/syscall.h>

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
typedef int linux_shmid_t;
typedef int linux_semid_t;
typedef int linux_msgid_t;

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
typedef linux_kernel_clock_t linux_clock_t;
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
typedef unsigned short linux_kernel_sa_family_t;
typedef linux_kernel_sa_family_t linux_sa_family_t;
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
typedef struct linux_sigaltstack_t
{
	void* ss_sp;
	int ss_flags;
	char _pad[4];
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
typedef unsigned char linux_cc_t;
typedef unsigned int linux_speed_t;
typedef unsigned int linux_tcflag_t;
struct linux_termios2_t
{
	linux_tcflag_t c_iflag; // input mode flags
	linux_tcflag_t c_oflag; // output mode flags
	linux_tcflag_t c_cflag; // control mode flags
	linux_tcflag_t c_lflag; // local mode flags
	linux_cc_t c_line; // line discipline
	linux_cc_t c_cc[19]; // control characters
	linux_speed_t c_ispeed; // input speed
	linux_speed_t c_ospeed; // output speed
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
struct linux_timezone_t
{
	int tz_minuteswest; // minutes west of Greenwich
	int tz_dsttime; // type of dst correction
};
struct linux_ipc64_perm_t
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
struct linux_shmid64_ds_t
{
	struct linux_ipc64_perm_t shm_perm; // operation perms
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
struct linux_shminfo64_t
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
struct linux_shm_info_t
{
	int used_ids;
	unsigned char _pad[4];
	linux_kernel_ulong_t shm_tot; // total allocated shm
	linux_kernel_ulong_t shm_rss; // total resident shm
	linux_kernel_ulong_t shm_swp; // total swapped shm
	linux_kernel_ulong_t swap_attempts;
	linux_kernel_ulong_t swap_successes;
};
struct linux_semid64_ds_t
{
	struct linux_ipc64_perm_t sem_perm; // permissions
	linux_kernel_time_t sem_otime; // last semop time
	linux_kernel_ulong_t _pad1;
	linux_kernel_time_t sem_ctime; // last change time
	linux_kernel_ulong_t _pad2;
	linux_kernel_ulong_t sem_nsems; // no. of semaphores in array
	linux_kernel_ulong_t _pad3;
	linux_kernel_ulong_t _pad4;
};
struct linux_sembuf_t
{
	unsigned short sem_num; // semaphore index in array
	short sem_op; // semaphore operation
	short sem_flg; // operation flags
};
struct linux_seminfo_t
{
	int semmap;
	int semmni;
	int semmns;
	int semmnu;
	int semmsl;
	int semopm;
	int semume;
	int semusz;
	int semvmx;
	int semaem;
};
union linux_semun_t
{
	int val; // value for SETVAL
	struct linux_semid64_ds_t* buf; // buffer for IPC_STAT & IPC_SET
	unsigned short* array; // array for GETALL & SETALL
	struct linux_seminfo_t* info; // buffer for IPC_INFO
	void* _pad;
};
_Static_assert(sizeof(union linux_semun_t) == sizeof(unsigned long), "union linux_semun_t and unsigned long must have the same size. This is a bug in a liblinux header.");
struct linux_msqid64_ds_t
{
	struct linux_ipc64_perm_t msg_perm;
	linux_kernel_time_t msg_stime; // last msgsnd time
	linux_kernel_time_t msg_rtime; // last msgrcv time
	linux_kernel_time_t msg_ctime; // last change time
	linux_kernel_ulong_t msg_cbytes; // current number of bytes on queue
	linux_kernel_ulong_t msg_qnum; // number of messages in queue
	linux_kernel_ulong_t msg_qbytes; // max number of bytes on queue
	linux_kernel_pid_t msg_lspid; // pid of last msgsnd
	linux_kernel_pid_t msg_lrpid; // last receive pid
	linux_kernel_ulong_t _unused1;
	linux_kernel_ulong_t _unused2;
};
struct linux_msgbuf_t
{
	linux_kernel_long_t mtype; // type of message
	char mtext[]; // message text
};
struct linux_msginfo_t
{
	int msgpool;
	int msgmap; 
	int msgmax; 
	int msgmnb; 
	int msgmni; 
	int msgssz; 
	int msgtql; 
	unsigned short msgseg; 
	char _pad[2];
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
struct linux_rusage_t
{
	struct linux_timeval_t ru_utime; // user time used
	struct linux_timeval_t ru_stime; // system time used
	linux_kernel_long_t ru_maxrss; // maximum resident set size
	linux_kernel_long_t ru_ixrss; // integral shared memory size
	linux_kernel_long_t ru_idrss; // integral unshared data size
	linux_kernel_long_t ru_isrss; // integral unshared stack size
	linux_kernel_long_t ru_minflt; // page reclaims
	linux_kernel_long_t ru_majflt; // page faults
	linux_kernel_long_t ru_nswap; // swaps
	linux_kernel_long_t ru_inblock; // block input operations
	linux_kernel_long_t ru_oublock; // block output operations
	linux_kernel_long_t ru_msgsnd; // messages sent
	linux_kernel_long_t ru_msgrcv; // messages received
	linux_kernel_long_t ru_nsignals; // signals received
	linux_kernel_long_t ru_nvcsw; // voluntary context switches
	linux_kernel_long_t ru_nivcsw; // involuntary context switches
};
struct linux_sockaddr_t
{
	linux_sa_family_t sa_family; // address family, AF_xxx
	char sa_data[14]; // 14 bytes of protocol address
};
struct linux_sockaddr_storage_t
{
	alignas(struct linux_sockaddr_t*) linux_kernel_sa_family_t ss_family; // address family
	// Following field(s) are implementation specific
	char _data[128 - sizeof(linux_kernel_sa_family_t)];
		// space to achieve desired size,
		// 128 minus size of ss_family
};
_Static_assert(alignof(struct linux_sockaddr_storage_t) == alignof(struct linux_sockaddr_t*), "Structure alignment missmatch. This is a bug in a liblinux header.");
struct linux_in_addr_t
{
	uint32_t s_addr;
};
_Static_assert(sizeof(struct linux_in_addr_t) >= 4, "IPv4 address struct size is not large enough. This is a bug in a liblinux header.");
struct linux_sockaddr_in_t
{
	linux_kernel_sa_family_t sin_family; // Address family
	uint16_t sin_port; // Port number
	struct linux_in_addr_t sin_addr; // Internet address

	// Pad to size of `struct linux_sockaddr_t'.
	unsigned char _pad[sizeof(struct linux_sockaddr_t) - sizeof(linux_kernel_sa_family_t) - sizeof(uint16_t) - sizeof(struct linux_in_addr_t)];
};
_Static_assert(sizeof(struct linux_sockaddr_t) == sizeof(struct linux_sockaddr_in_t), "Struct size missmatch. This is a bug in a liblinux header.");
struct linux_in6_addr_t
{
	union
	{
		uint8_t s6_addr[16];
		uint16_t s6_addr16[8];
		uint32_t s6_addr32[4];
	};
};
_Static_assert(sizeof(struct linux_in6_addr_t) >= 16, "IPv6 address struct size is not large enough. This is a bug in a liblinux header.");
struct linux_sockaddr_in6_t
{
	unsigned short sin6_family; // AF_INET6
	uint16_t sin6_port; // Transport layer port #
	uint32_t sin6_flowinfo; // IPv6 flow information
	struct linux_in6_addr_t sin6_addr; // IPv6 address
	uint32_t sin6_scope_id; // scope id (new in RFC2553)
};
struct linux_user_msghdr_t
{
	void* msg_name; // ptr to socket address structure
	int msg_namelen; // size of socket address structure
	char _pad0[4];
	struct linux_iovec_t* msg_iov; // scatter/gather array
	linux_kernel_size_t msg_iovlen; // # elements in msg_iov
	void* msg_control; // ancillary data
	linux_kernel_size_t msg_controllen; // ancillary data buffer length
	unsigned int msg_flags; // flags on received message
	char _pad1[4];
};
enum
{
	linux_UNIX_PATH_MAX = 108,
};
struct linux_sockaddr_un_t
{
	linux_kernel_sa_family_t sun_family; // AF_UNIX
	char sun_path[linux_UNIX_PATH_MAX]; // pathname
};
enum
{
	linux_NEW_UTS_LEN = 64,
};
struct linux_new_utsname_t
{
	char sysname[linux_NEW_UTS_LEN + 1];
	char nodename[linux_NEW_UTS_LEN + 1];
	char release[linux_NEW_UTS_LEN + 1];
	char version[linux_NEW_UTS_LEN + 1];
	char machine[linux_NEW_UTS_LEN + 1];
	char domainname[linux_NEW_UTS_LEN + 1];
};
struct linux_f_owner_ex_t
{
	int type;
	linux_kernel_pid_t pid;
};
struct linux_flock_t
{
	short l_type;
	short l_whence;
	linux_kernel_off_t l_start;
	linux_kernel_off_t l_len;
	linux_kernel_pid_t l_pid;
};
struct linux_dirent_t
{
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[6]; // TODO: Hack to supress struct padding warning. Use flexible array member when ready.
};
typedef linux_kernel_uid32_t linux_uid_t;
typedef linux_kernel_gid32_t linux_gid_t;
struct linux_rlimit_t
{
	linux_kernel_ulong_t rlim_cur;
	linux_kernel_ulong_t rlim_max;
};
struct linux_sysinfo_t
{
	linux_kernel_long_t uptime; // Seconds since boot
	linux_kernel_ulong_t loads[3]; // 1, 5, and 15 minute load averages
	linux_kernel_ulong_t totalram; // Total usable main memory size
	linux_kernel_ulong_t freeram; // Available memory size
	linux_kernel_ulong_t sharedram; // Amount of shared memory
	linux_kernel_ulong_t bufferram; // Memory used by buffers
	linux_kernel_ulong_t totalswap; // Total swap space size
	linux_kernel_ulong_t freeswap; // swap space still available
	uint16_t procs; // Number of current processes
	char _pad1[6]; // Explicit padding for m68k
	linux_kernel_ulong_t totalhigh;	// Total high memory size
	linux_kernel_ulong_t freehigh;	// Available high memory size
	uint32_t mem_unit; // Memory unit size in bytes
	char _pad2[4];
};
struct linux_tms_t
{
	linux_kernel_clock_t tms_utime;
	linux_kernel_clock_t tms_stime;
	linux_kernel_clock_t tms_cutime;
	linux_kernel_clock_t tms_cstime;
};
struct linux_ptrace_peeksiginfo_args_t
{
	uint64_t off; // from which siginfo to start
	uint32_t flags;
	int32_t nr; // how may siginfos to take
};
struct linux_user_i387_struct_t
{
	unsigned short cwd;
	unsigned short swd;
	unsigned short twd; // Note this is not the same as the 32bit/x87/FSAVE twd
	unsigned short fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcsr_mask;
	uint32_t st_space[32]; // 8*16 bytes for each FP-reg = 128 bytes
	uint32_t xmm_space[64]; // 16*16 bytes for each XMM-reg = 256 bytes
	uint32_t padding[24];
};
struct linux_user_regs_struct_t
{
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
};
struct linux_user_t
{
	// We start with the registers, to mimic the way that "memory" is returned from the ptrace(3,...) function.
	struct linux_user_regs_struct_t regs; // Where the registers are actually stored
	// ptrace does not yet supply these.  Someday....
	int u_fpvalid; // True if math co-processor being used.
	// for this mess. Not yet used.
	int pad0;
	struct linux_user_i387_struct_t i387; // Math Co-processor registers.
	// The rest of this junk is to help gdb figure out what goes where
	unsigned long int u_tsize; // Text segment size (pages).
	unsigned long int u_dsize; // Data segment size (pages).
	unsigned long int u_ssize; // Stack segment size (pages).
	unsigned long start_code; // Starting virtual address of text.
	unsigned long start_stack; // Starting virtual address of stack area.
	                           // This is actually the bottom of the stack,
	                           // the top of the stack is always found in the
	                           // esp register.
	long int signal; // Signal that caused the core dump.
	int reserved; // No longer used
	int pad1;
	unsigned long u_ar0; // Used by gdb to help find the values for
	// the registers.
	struct user_i387_struct* u_fpstate; // Math Co-processor pointer.
	unsigned long magic; // To uniquely identify a core file
	char u_comm[32]; // User command that was responsible
	unsigned long u_debugreg[8];
	unsigned long error_code; // CPU error code or 0
	unsigned long fault_address; // CR3 or 0
};
typedef struct linux_user_cap_header_struct_t
{
	uint32_t version;
	linux_pid_t pid;
} *linux_cap_user_header_t;
typedef struct linux_user_cap_data_struct_t
{
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
} *linux_cap_user_data_t;
struct linux_utimbuf_t
{
	linux_kernel_time_t actime;
	linux_kernel_time_t modtime;
};
typedef uint32_t linux_kernel_dev_t;
typedef linux_kernel_dev_t linux_dev_t;
typedef int linux_kernel_daddr_t;
typedef linux_kernel_ulong_t linux_kernel_ino_t;
struct linux_ustat_t
{
	linux_kernel_daddr_t f_tfree;
	char _pad1[4];
	linux_kernel_ino_t f_tinode;
	char f_fname[6];
	char f_fpack[6];
	char _pad2[4];
};
typedef struct
{
	int val[2];
} linux_kernel_fsid_t;
typedef linux_kernel_long_t linux_statfs_word;
struct linux_statfs_t
{
	linux_statfs_word f_type;
	linux_statfs_word f_bsize;
	linux_statfs_word f_blocks;
	linux_statfs_word f_bfree;
	linux_statfs_word f_bavail;
	linux_statfs_word f_files;
	linux_statfs_word f_ffree;
	linux_kernel_fsid_t f_fsid;
	linux_statfs_word f_namelen;
	linux_statfs_word f_frsize;
	linux_statfs_word f_flags;
	linux_statfs_word f_spare[4];
};

// Kernel types
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Constants

_Static_assert((unsigned)INT_MIN == 0x80000000u, "Needs a two's complement platform.");

enum
{
	linux_stdin  = 0u,
	linux_stdout = 1u,
	linux_stderr = 2u,
};

enum // Limits
{
	linux_NR_OPEN        =   1024,

	linux_NGROUPS_MAX    =  65536, // supplemental group IDs are available
	linux_ARG_MAX        = 131072, // # bytes of args + environ for exec()
	linux_LINK_MAX       =    127, // # links a file may have
	linux_MAX_CANON      =    255, // size of the canonical input queue
	linux_MAX_INPUT      =    255, // size of the type-ahead buffer
	linux_NAME_MAX       =    255, // # chars in a file name
	linux_PATH_MAX       =   4096, // # chars in a path name including nul
	linux_PIPE_BUF       =   4096, // # bytes in atomic write to a pipe
	linux_XATTR_NAME_MAX =    255, // # chars in an extended attribute name
	linux_XATTR_SIZE_MAX =  65536, // size of an extended attribute value (64k)
	linux_XATTR_LIST_MAX =  65536, // size of extended attribute namelist (64k)

	linux_RTSIG_MAX      =     32,
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
	linux_F_DUPFD               =    0, // dup
	linux_F_GETFD               =    1, // get close_on_exec
	linux_F_SETFD               =    2, // set/clear close_on_exec
	linux_F_GETFL               =    3, // get file->f_flags
	linux_F_SETFL               =    4, // set file->f_flags
	linux_F_GETLK               =    5,
	linux_F_SETLK               =    6,
	linux_F_SETLKW              =    7,
	linux_F_SETOWN              =    8, // for sockets.
	linux_F_GETOWN              =    9, // for sockets.
	linux_F_SETSIG              =   10, // for sockets.
	linux_F_GETSIG              =   11, // for sockets.

	linux_F_SETOWN_EX           =   15,
	linux_F_GETOWN_EX           =   16,

	linux_F_GETOWNER_UIDS       =   17,

	linux_F_OFD_GETLK           =   36,
	linux_F_OFD_SETLK           =   37,
	linux_F_OFD_SETLKW          =   38,

	linux_F_LINUX_SPECIFIC_BASE = 1024,

	linux_F_SETLEASE            = linux_F_LINUX_SPECIFIC_BASE + 0,
	linux_F_GETLEASE            = linux_F_LINUX_SPECIFIC_BASE + 1,

	linux_F_DUPFD_CLOEXEC       = linux_F_LINUX_SPECIFIC_BASE + 6, // Create a file descriptor with FD_CLOEXEC set.

	// Request nofications on a directory.
	// See below for events that may be notified.
	linux_F_NOTIFY              = linux_F_LINUX_SPECIFIC_BASE + 2,

	// Set and get of pipe page size array
	linux_F_SETPIPE_SZ          = linux_F_LINUX_SPECIFIC_BASE + 7,
	linux_F_GETPIPE_SZ          = linux_F_LINUX_SPECIFIC_BASE + 8,

	// Set/Get seals
	linux_F_ADD_SEALS           = linux_F_LINUX_SPECIFIC_BASE + 9,
	linux_F_GET_SEALS           = linux_F_LINUX_SPECIFIC_BASE + 10,

	// Set/Get write life time hints. {GET,SET}_RW_HINT operate on the
	// underlying inode, while {GET,SET}_FILE_RW_HINT operate only on
	// the specific file.
	linux_F_GET_RW_HINT         = linux_F_LINUX_SPECIFIC_BASE + 11,
	linux_F_SET_RW_HINT         = linux_F_LINUX_SPECIFIC_BASE + 12,
	linux_F_GET_FILE_RW_HINT    = linux_F_LINUX_SPECIFIC_BASE + 13,
	linux_F_SET_FILE_RW_HINT    = linux_F_LINUX_SPECIFIC_BASE + 14,
};

enum
{
	linux_F_OWNER_TID  = 0,
	linux_F_OWNER_PID  = 1,
	linux_F_OWNER_PGRP = 2,
};

enum
{
	linux_FD_CLOEXEC = 1, // actually anything with low bit set goes
};

enum
{
	linux_F_RDLCK = 0,
	linux_F_WRLCK = 1,
	linux_F_UNLCK = 2,
};

enum // File types
{
	linux_DT_UNKNOWN =  0,
	linux_DT_FIFO    =  1,
	linux_DT_CHR     =  2,
	linux_DT_DIR     =  4,
	linux_DT_BLK     =  6,
	linux_DT_REG     =  8,
	linux_DT_LNK     = 10,
	linux_DT_SOCK    = 12,
	linux_DT_WHT     = 14,
};

// Types of seals
enum
{
	linux_F_SEAL_SEAL   = 0x0001, // prevent further seals from being set
	linux_F_SEAL_SHRINK = 0x0002, // prevent file from shrinking
	linux_F_SEAL_GROW   = 0x0004, // prevent file from growing
	linux_F_SEAL_WRITE  = 0x0008, // prevent writes
	// (1u << 31) is reserved for signed error codes
};

// Valid hint values for F_{GET,SET}_RW_HINT. 0 is "not set", or can be
// used to clear any hints previously set.
enum
{
	linux_RWF_WRITE_LIFE_NOT_SET = 0,
	linux_RWH_WRITE_LIFE_NONE    = 1,
	linux_RWH_WRITE_LIFE_SHORT   = 2,
	linux_RWH_WRITE_LIFE_MEDIUM  = 3,
	linux_RWH_WRITE_LIFE_LONG    = 4,
	linux_RWH_WRITE_LIFE_EXTREME = 5,
};

// Types of directory notifications that may be requested.
enum
{
	linux_DN_ACCESS    = 0x00000001, // File accessed
	linux_DN_MODIFY    = 0x00000002, // File modified
	linux_DN_CREATE    = 0x00000004, // File created
	linux_DN_DELETE    = 0x00000008, // File removed
	linux_DN_RENAME    = 0x00000010, // File renamed
	linux_DN_ATTRIB    = 0x00000020, // File changed attibutes
	linux_DN_MULTISHOT = INT_MIN, // Don't remove notifier // Workaround for the value 0x80000000u as a signed int.
};

// operations for bsd flock(), also used by the kernel implementation
enum
{
	linux_LOCK_SH    =   1, // shared lock
	linux_LOCK_EX    =   2, // exclusive lock
	linux_LOCK_NB    =   4, // or'd with one of the above to prevent blocking
	linux_LOCK_UN    =   8, // remove lock

	linux_LOCK_MAND  =  32, // This is a mandatory flock ...
	linux_LOCK_READ  =  64, // which allows concurrent read operations
	linux_LOCK_WRITE = 128, // which allows concurrent write operations
	linux_LOCK_RW    = 192, // which allows concurrent read & write ops
};

enum
{
	linux_S_IFMT   = 00170000,
	linux_S_IFSOCK =  0140000,
	linux_S_IFLNK  =  0120000,
	linux_S_IFREG  =  0100000,
	linux_S_IFBLK  =  0060000,
	linux_S_IFDIR  =  0040000,
	linux_S_IFCHR  =  0020000,
	linux_S_IFIFO  =  0010000,
	linux_S_ISUID  =  0004000,
	linux_S_ISGID  =  0002000,
	linux_S_ISVTX  =  0001000,

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
	// 0x54 is just a magic number to make these relatively unique ('T')
	linux_TCGETS          = 0x5401,
	linux_TCSETS          = 0x5402,
	linux_TCSETSW         = 0x5403,
	linux_TCSETSF         = 0x5404,
	linux_TCGETA          = 0x5405,
	linux_TCSETA          = 0x5406,
	linux_TCSETAW         = 0x5407,
	linux_TCSETAF         = 0x5408,
	linux_TCSBRK          = 0x5409,
	linux_TCXONC          = 0x540A,
	linux_TCFLSH          = 0x540B,
	linux_TIOCEXCL        = 0x540C,
	linux_TIOCNXCL        = 0x540D,
	linux_TIOCSCTTY       = 0x540E,
	linux_TIOCGPGRP       = 0x540F,
	linux_TIOCSPGRP       = 0x5410,
	linux_TIOCOUTQ        = 0x5411,
	linux_TIOCSTI         = 0x5412,
	linux_TIOCGWINSZ      = 0x5413,
	linux_TIOCSWINSZ      = 0x5414,
	linux_TIOCMGET        = 0x5415,
	linux_TIOCMBIS        = 0x5416,
	linux_TIOCMBIC        = 0x5417,
	linux_TIOCMSET        = 0x5418,
	linux_TIOCGSOFTCAR    = 0x5419,
	linux_TIOCSSOFTCAR    = 0x541A,
	linux_FIONREAD        = 0x541B,
	linux_TIOCINQ         = linux_FIONREAD,
	linux_TIOCLINUX       = 0x541C,
	linux_TIOCCONS        = 0x541D,
	linux_TIOCGSERIAL     = 0x541E,
	linux_TIOCSSERIAL     = 0x541F,
	linux_TIOCPKT         = 0x5420,
	linux_FIONBIO         = 0x5421,
	linux_TIOCNOTTY       = 0x5422,
	linux_TIOCSETD        = 0x5423,
	linux_TIOCGETD        = 0x5424,
	linux_TCSBRKP         = 0x5425, // Needed for POSIX tcsendbreak()
	linux_TIOCSBRK        = 0x5427, // BSD compatibility
	linux_TIOCCBRK        = 0x5428, // BSD compatibility
	linux_TIOCGSID        = 0x5429, // Return the session ID of FD
#define linux_TCGETS2         = (2u << 30) | ('T' << 8) | 0x2A | (sizeof(struct linux_termios2_t) << 16),
	linux_TCSETS2         = (1u << 30) | ('T' << 8) | 0x2B | (sizeof(struct linux_termios2_t) << 16),
	linux_TCSETSW2        = (1u << 30) | ('T' << 8) | 0x2C | (sizeof(struct linux_termios2_t) << 16),
	linux_TCSETSF2        = (1u << 30) | ('T' << 8) | 0x2D | (sizeof(struct linux_termios2_t) << 16),
	linux_TIOCGRS485      = 0x542E,
	linux_TIOCSRS485      = 0x542F,
#define linux_TIOCGPTN        = ((2u << 30) | ('T' << 8) | 0x30 | (sizeof(unsigned int) << 16)), // Get Pty Number (of pty-mux device)
	linux_TIOCSPTLCK      = ((1u << 30) | ('T' << 8) | 0x31 | (sizeof(int) << 16)), // Lock/unlock Pty
#define linux_TIOCGDEV        = ((2u << 30) | ('T' << 8) | 0x32 | (sizeof(unsigned int) << 16)), // Get primary device node of /dev/console
	linux_TCGETX          = 0x5432, // SYS5 TCGETX compatibility
	linux_TCSETX          = 0x5433,
	linux_TCSETXF         = 0x5434,
	linux_TCSETXW         = 0x5435,
	linux_TIOCSIG         = (1u << 30) | ('T' << 8) | 0x36 | (sizeof(int) << 16), // pty: generate signal
	linux_TIOCVHANGUP     = 0x5437,
#define linux_TIOCGPKT        = (2u << 30) | ('T' << 8) | 0x38 | (sizeof(int) << 16), // Get packet mode state
#define linux_TIOCGPTLCK      = (2u << 30) | ('T' << 8) | 0x39 | (sizeof(int) << 16), // Get Pty lock state
#define linux_TIOCGEXCL       = (2u << 30) | ('T' << 8) | 0x40 | (sizeof(int) << 16), // Get exclusive mode state

	linux_FIONCLEX        = 0x5450,
	linux_FIOCLEX         = 0x5451,
	linux_FIOASYNC        = 0x5452,
	linux_TIOCSERCONFIG   = 0x5453,
	linux_TIOCSERGWILD    = 0x5454,
	linux_TIOCSERSWILD    = 0x5455,
	linux_TIOCGLCKTRMIOS  = 0x5456,
	linux_TIOCSLCKTRMIOS  = 0x5457,
	linux_TIOCSERGSTRUCT  = 0x5458, // For debugging only
	linux_TIOCSERGETLSR   = 0x5459, // Get line status register
	linux_TIOCSERGETMULTI = 0x545A, // Get multiport config
	linux_TIOCSERSETMULTI = 0x545B, // Set multiport config

	linux_TIOCMIWAIT      = 0x545C, // wait for a change on serial input line(s)
	linux_TIOCGICOUNT     = 0x545D, // read serial port inline interrupt counts

	linux_FIOQSIZE        = 0x5460,
};

enum
{
	// Used for packet mode
	linux_TIOCPKT_DATA       =  0,
	linux_TIOCPKT_FLUSHREAD  =  1,
	linux_TIOCPKT_FLUSHWRITE =  2,
	linux_TIOCPKT_STOP       =  4,
	linux_TIOCPKT_START      =  8,
	linux_TIOCPKT_NOSTOP     = 16,
	linux_TIOCPKT_DOSTOP     = 32,
	linux_TIOCPKT_IOCTL      = 64,
};

enum
{
	linux_TIOCSER_TEMT = 0x01, // Transmitter physically empty
};

enum
{
	linux_FP_XSTATE_MAGIC1      = 0x46505853u,
	linux_FP_XSTATE_MAGIC2      = 0x46505845u,
};
#define linux_FP_XSTATE_MAGIC2_SIZE (sizeof linux_FP_XSTATE_MAGIC2)

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

// semop flags
enum
{
	linux_SEM_UNDO = 0x1000, // undo the operation on exit
};

enum
{
	// semctl Command Definitions.
	linux_GETPID   = 11, // get sempid
	linux_GETVAL   = 12, // get semval
	linux_GETALL   = 13, // get all semval's
	linux_GETNCNT  = 14, // get semncnt
	linux_GETZCNT  = 15, // get semzcnt
	linux_SETVAL   = 16, // set semval
	linux_SETALL   = 17, // set all semval's

	// ipcs ctl cmds
	linux_SEM_STAT = 18,
	linux_SEM_INFO = 19,
};

enum
{
	linux_SEMMNI = 32000, // <= IPCMNI  max # of semaphore identifiers
	linux_SEMMSL = 32000, // <= INT_MAX max num of semaphores per id
	linux_SEMMNS = (linux_SEMMNI * linux_SEMMSL), // <= INT_MAX max # of semaphores in system
	linux_SEMOPM = 500, // <= 1 000 max num of ops per semop call
	linux_SEMVMX = 32767, // <= 32767 semaphore maximum value
	linux_SEMAEM = linux_SEMVMX, // adjust on exit max value

	// unused
	linux_SEMUME = linux_SEMOPM, // max num of undo entries per process
	linux_SEMMNU = linux_SEMMNS, // num of undo structures system wide
	linux_SEMMAP = linux_SEMMNS, // # of entries in semaphore map
	linux_SEMUSZ = 20, // sizeof struct sem_undo
};

enum
{
	// ipcs ctl commands
	linux_MSG_STAT = 11,
	linux_MSG_INFO = 12,
};

enum
{
	// msgrcv options
	linux_MSG_NOERROR = 010000, // no error if message is too big
	linux_MSG_EXCEPT  = 020000, // recv any msg except of specified type.
	linux_MSG_COPY    = 040000, // copy (not remove) all queue messages
};

enum
{
	linux_MSGMNI = 32000, // <= IPCMNI. Max # of msg queue identifiers
	linux_MSGMAX = 8192, // <= INT_MAX. Max size of message (bytes)
	linux_MSGMNB = 16384, // <= INT_MAX. Default max size of a message queue

	// unused
	linux_MSGPOOL = linux_MSGMNI * linux_MSGMNB / 1024, // size in kbytes of message pool
	linux_MSGTQL = linux_MSGMNB, // number of system message headers
	linux_MSGMAP = linux_MSGMNB, // number of entries in message map
	linux_MSGSSZ = 16, // message segment size
	linux_MSGSEG_ = ((linux_MSGPOOL * 1024) / linux_MSGSSZ), // max no. of segments
	linux_MSGSEG = (linux_MSGSEG_ <= 0xffff ? linux_MSGSEG_ : 0xffff),
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

enum
{
	linux_WNOHANG    = 0x00000001,
	linux_WUNTRACED  = 0x00000002,
	linux_WSTOPPED   = linux_WUNTRACED,
	linux_WEXITED    = 0x00000004,
	linux_WCONTINUED = 0x00000008,
	linux_WNOWAIT    = 0x01000000, // Don't reap, just poll status.
	linux_WNOTHREAD  = 0x20000000, // Don't wait on children of other threads in this group
	linux_WALL       = 0x40000000, // Wait on all children, regardless of type
	linux_WCLONE     = INT_MIN, // Wait only on non-SIGCHLD children. INT_MIN is a workaround for the value 0x80000000 as a signed int.
};

enum
{
	linux_P_ALL  = 0,
	linux_P_PID  = 1,
	linux_P_PGID = 2,
};

enum
{
	linux_AF_UNSPEC     =  0,
	linux_AF_UNIX       =  1, // Unix domain sockets
	linux_AF_LOCAL      =  1, // POSIX name for AF_UNIX
	linux_AF_INET       =  2, // Internet IP Protocol
	linux_AF_AX25       =  3, // Amateur Radio AX.25
	linux_AF_IPX        =  4, // Novell IPX
	linux_AF_APPLETALK  =  5, // AppleTalk DDP
	linux_AF_NETROM     =  6, // Amateur Radio NET/ROM
	linux_AF_BRIDGE     =  7, // Multiprotocol bridge
	linux_AF_ATMPVC     =  8, // ATM PVCs
	linux_AF_X25        =  9, // Reserved for X.25 project
	linux_AF_INET6      = 10, // IP version 6
	linux_AF_ROSE       = 11, // Amateur Radio X.25 PLP
	linux_AF_DECnet     = 12, // Reserved for DECnet project
	linux_AF_NETBEUI    = 13, // Reserved for 802.2LLC project
	linux_AF_SECURITY   = 14, // Security callback pseudo AF
	linux_AF_KEY        = 15, // PF_KEY key management API
	linux_AF_NETLINK    = 16,
	linux_AF_ROUTE      = linux_AF_NETLINK, // Alias to emulate 4.4BSD
	linux_AF_PACKET     = 17, // Packet family
	linux_AF_ASH        = 18, // Ash
	linux_AF_ECONET     = 19, // Acorn Econet
	linux_AF_ATMSVC     = 20, // ATM SVCs
	linux_AF_RDS        = 21, // RDS sockets
	linux_AF_SNA        = 22, // Linux SNA Project (nutters!)
	linux_AF_IRDA       = 23, // IRDA sockets
	linux_AF_PPPOX      = 24, // PPPoX sockets
	linux_AF_WANPIPE    = 25, // Wanpipe API Sockets
	linux_AF_LLC        = 26, // Linux LLC
	linux_AF_IB         = 27, // Native InfiniBand address
	linux_AF_MPLS       = 28, // MPLS
	linux_AF_CAN        = 29, // Controller Area Network
	linux_AF_TIPC       = 30, // TIPC sockets
	linux_AF_BLUETOOTH  = 31, // Bluetooth sockets
	linux_AF_IUCV       = 32, // IUCV sockets
	linux_AF_RXRPC      = 33, // RxRPC sockets
	linux_AF_ISDN       = 34, // mISDN sockets
	linux_AF_PHONET     = 35, // Phonet sockets
	linux_AF_IEEE802154 = 36, // IEEE802154 sockets
	linux_AF_CAIF       = 37, // CAIF sockets
	linux_AF_ALG        = 38, // Algorithm sockets
	linux_AF_NFC        = 39, // NFC sockets
	linux_AF_VSOCK      = 40, // vSockets
	linux_AF_KCM        = 41, // Kernel Connection Multiplexo
	linux_AF_QIPCRTR    = 42, // Qualcomm IPC Router
	linux_AF_SMC        = 43, // smc sockets: reserve number for
	                          //     PF_SMC protocol family that
	                          //     reuses AF_INET address family

	linux_AF_MAX        = 44, // For now..
};

enum
{
	linux_PF_UNSPEC     = linux_AF_UNSPEC,
	linux_PF_UNIX       = linux_AF_UNIX,
	linux_PF_LOCAL      = linux_AF_LOCAL,
	linux_PF_INET       = linux_AF_INET,
	linux_PF_AX25       = linux_AF_AX25,
	linux_PF_IPX        = linux_AF_IPX,
	linux_PF_APPLETALK  = linux_AF_APPLETALK,
	linux_PF_NETROM     = linux_AF_NETROM,
	linux_PF_BRIDGE     = linux_AF_BRIDGE,
	linux_PF_ATMPVC     = linux_AF_ATMPVC,
	linux_PF_X25        = linux_AF_X25,
	linux_PF_INET6      = linux_AF_INET6,
	linux_PF_ROSE       = linux_AF_ROSE,
	linux_PF_DECnet     = linux_AF_DECnet,
	linux_PF_NETBEUI    = linux_AF_NETBEUI,
	linux_PF_SECURITY   = linux_AF_SECURITY,
	linux_PF_KEY        = linux_AF_KEY,
	linux_PF_NETLINK    = linux_AF_NETLINK,
	linux_PF_ROUTE      = linux_AF_ROUTE,
	linux_PF_PACKET     = linux_AF_PACKET,
	linux_PF_ASH        = linux_AF_ASH,
	linux_PF_ECONET     = linux_AF_ECONET,
	linux_PF_ATMSVC     = linux_AF_ATMSVC,
	linux_PF_RDS        = linux_AF_RDS,
	linux_PF_SNA        = linux_AF_SNA,
	linux_PF_IRDA       = linux_AF_IRDA,
	linux_PF_PPPOX      = linux_AF_PPPOX,
	linux_PF_WANPIPE    = linux_AF_WANPIPE,
	linux_PF_LLC        = linux_AF_LLC,
	linux_PF_IB         = linux_AF_IB,
	linux_PF_MPLS       = linux_AF_MPLS,
	linux_PF_CAN        = linux_AF_CAN,
	linux_PF_TIPC       = linux_AF_TIPC,
	linux_PF_BLUETOOTH  = linux_AF_BLUETOOTH,
	linux_PF_IUCV       = linux_AF_IUCV,
	linux_PF_RXRPC      = linux_AF_RXRPC,
	linux_PF_ISDN       = linux_AF_ISDN,
	linux_PF_PHONET     = linux_AF_PHONET,
	linux_PF_IEEE802154 = linux_AF_IEEE802154,
	linux_PF_CAIF       = linux_AF_CAIF,
	linux_PF_ALG        = linux_AF_ALG,
	linux_PF_NFC        = linux_AF_NFC,
	linux_PF_VSOCK      = linux_AF_VSOCK,
	linux_PF_KCM        = linux_AF_KCM,
	linux_PF_QIPCRTR    = linux_AF_QIPCRTR,
	linux_PF_SMC        = linux_AF_SMC,
	linux_PF_MAX        = linux_AF_MAX,
};

enum
{
	linux_SOCK_STREAM    =  1,
	linux_SOCK_DGRAM     =  2,
	linux_SOCK_RAW       =  3,
	linux_SOCK_RDM       =  4,
	linux_SOCK_SEQPACKET =  5,
	linux_SOCK_DCCP      =  6,
	linux_SOCK_PACKET    = 10,

	linux_SOCK_CLOEXEC   = linux_O_CLOEXEC,
	linux_SOCK_NONBLOCK  = linux_O_NONBLOCK,
};

enum
{
	linux_SOL_SOCKET = 1,
};

enum
{
	linux_SO_DEBUG                         =  1,
	linux_SO_REUSEADDR                     =  2,
	linux_SO_TYPE                          =  3,
	linux_SO_ERROR                         =  4,
	linux_SO_DONTROUTE                     =  5,
	linux_SO_BROADCAST                     =  6,
	linux_SO_SNDBUF                        =  7,
	linux_SO_RCVBUF                        =  8,
	linux_SO_KEEPALIVE                     =  9,
	linux_SO_OOBINLINE                     = 10,
	linux_SO_NO_CHECK                      = 11,
	linux_SO_PRIORITY                      = 12,
	linux_SO_LINGER                        = 13,
	linux_SO_BSDCOMPAT                     = 14,
	linux_SO_REUSEPORT                     = 15,
	linux_SO_PASSCRED                      = 16,
	linux_SO_PEERCRED                      = 17,
	linux_SO_RCVLOWAT                      = 18,
	linux_SO_SNDLOWAT                      = 19,
	linux_SO_RCVTIMEO                      = 20,
	linux_SO_SNDTIMEO                      = 21,

	// Security levels - as per NRL IPv6 - don't actually do anything
	linux_SO_SECURITY_AUTHENTICATION       = 22,
	linux_SO_SECURITY_ENCRYPTION_TRANSPORT = 23,
	linux_SO_SECURITY_ENCRYPTION_NETWORK   = 24,

	linux_SO_BINDTODEVICE                  = 25,

	// Socket filtering
	linux_SO_ATTACH_FILTER                 = 26,
	linux_SO_DETACH_FILTER                 = 27,
	linux_SO_GET_FILTER                    = linux_SO_ATTACH_FILTER,

	linux_SO_PEERNAME                      = 28,
	linux_SO_TIMESTAMP                     = 29,
	linux_SCM_TIMESTAMP                    = linux_SO_TIMESTAMP,
	linux_SO_ACCEPTCONN                    = 30,
	linux_SO_PEERSEC                       = 31,
	linux_SO_SNDBUFFORCE                   = 32,
	linux_SO_RCVBUFFORCE                   = 33,
	linux_SO_PASSSEC                       = 34,
	linux_SO_TIMESTAMPNS                   = 35,
	linux_SCM_TIMESTAMPNS                  = linux_SO_TIMESTAMPNS,
	linux_SO_MARK                          = 36,
	linux_SO_TIMESTAMPING                  = 37,
	linux_SCM_TIMESTAMPING                 = linux_SO_TIMESTAMPING,
	linux_SO_PROTOCOL                      = 38,
	linux_SO_DOMAIN                        = 39,
	linux_SO_RXQ_OVFL                      = 40,
	linux_SO_WIFI_STATUS                   = 41,
	linux_SCM_WIFI_STATUS                  = linux_SO_WIFI_STATUS,
	linux_SO_PEEK_OFF                      = 42,

	// Instruct lower device to use last 4-bytes of skb data as FCS
	linux_SO_NOFCS                         = 43,

	linux_SO_LOCK_FILTER                   = 44,
	linux_SO_SELECT_ERR_QUEUE              = 45,
	linux_SO_BUSY_POLL                     = 46,
	linux_SO_MAX_PACING_RATE               = 47,
	linux_SO_BPF_EXTENSIONS                = 48,
	linux_SO_INCOMING_CPU                  = 49,
	linux_SO_ATTACH_BPF                    = 50,
	linux_SO_DETACH_BPF                    = linux_SO_DETACH_FILTER,
	linux_SO_ATTACH_REUSEPORT_CBPF         = 51,
	linux_SO_ATTACH_REUSEPORT_EBPF         = 52,
	linux_SO_CNX_ADVICE                    = 53,
	linux_SCM_TIMESTAMPING_OPT_STATS       = 54,
	linux_SO_MEMINFO                       = 55,
	linux_SO_INCOMING_NAPI_ID              = 56,
	linux_SO_COOKIE                        = 57,
};

// Socket-level I/O control calls.
enum
{
	linux_FIOSETOWN    = 0x8901,
	linux_SIOCSPGRP    = 0x8902,
	linux_FIOGETOWN    = 0x8903,
	linux_SIOCGPGRP    = 0x8904,
	linux_SIOCATMARK   = 0x8905,
	linux_SIOCGSTAMP   = 0x8906, // Get stamp (timeval)
	linux_SIOCGSTAMPNS = 0x8907, // Get stamp (timespec)
};

enum
{
	// Linux-specific socket ioctls
	linux_SIOCINQ                = linux_FIONREAD,
	linux_SIOCOUTQ               = linux_TIOCOUTQ, // output queue size (not sent + not acked)

	linux_SOCK_IOC_TYPE          = 0x89,

	// Routing table calls.
	linux_SIOCADDRT              = 0x890B, // add routing table entry
	linux_SIOCDELRT              = 0x890C, // delete routing table entry
	linux_SIOCRTMSG              = 0x890D, // unused

	// Socket configuration controls.
	linux_SIOCGIFNAME            = 0x8910, // get iface name
	linux_SIOCSIFLINK            = 0x8911, // set iface channel
	linux_SIOCGIFCONF            = 0x8912, // get iface list
	linux_SIOCGIFFLAGS           = 0x8913, // get flags
	linux_SIOCSIFFLAGS           = 0x8914, // set flags
	linux_SIOCGIFADDR            = 0x8915, // get PA address
	linux_SIOCSIFADDR            = 0x8916, // set PA address
	linux_SIOCGIFDSTADDR         = 0x8917, // get remote PA address
	linux_SIOCSIFDSTADDR         = 0x8918, // set remote PA address
	linux_SIOCGIFBRDADDR         = 0x8919, // get broadcast PA address
	linux_SIOCSIFBRDADDR         = 0x891a, // set broadcast PA address
	linux_SIOCGIFNETMASK         = 0x891b, // get network PA mask
	linux_SIOCSIFNETMASK         = 0x891c, // set network PA mask
	linux_SIOCGIFMETRIC          = 0x891d, // get metric
	linux_SIOCSIFMETRIC          = 0x891e, // set metric
	linux_SIOCGIFMEM             = 0x891f, // get memory address (BSD)
	linux_SIOCSIFMEM             = 0x8920, // set memory address (BSD)
	linux_SIOCGIFMTU             = 0x8921, // get MTU size
	linux_SIOCSIFMTU             = 0x8922, // set MTU size
	linux_SIOCSIFNAME            = 0x8923, // set interface name
	linux_SIOCSIFHWADDR          = 0x8924, // set hardware address
	linux_SIOCGIFENCAP           = 0x8925, // get/set encapsulations
	linux_SIOCSIFENCAP           = 0x8926,
	linux_SIOCGIFHWADDR          = 0x8927, // Get hardware address
	linux_SIOCGIFSLAVE           = 0x8929, // Driver slaving support
	linux_SIOCSIFSLAVE           = 0x8930,
	linux_SIOCADDMULTI           = 0x8931, // Multicast address lists
	linux_SIOCDELMULTI           = 0x8932,
	linux_SIOCGIFINDEX           = 0x8933, // name -> if_index mapping
	linux_SIOGIFINDEX            = linux_SIOCGIFINDEX, // misprint compatibility :-)
	linux_SIOCSIFPFLAGS          = 0x8934, // set/get extended flags set
	linux_SIOCGIFPFLAGS          = 0x8935,
	linux_SIOCDIFADDR            = 0x8936, // delete PA address
	linux_SIOCSIFHWBROADCAST     = 0x8937, // set hardware broadcast addr
	linux_SIOCGIFCOUNT           = 0x8938, // get number of devices

	linux_SIOCGIFBR              = 0x8940, // Bridging support
	linux_SIOCSIFBR              = 0x8941, // Set bridging options

	linux_SIOCGIFTXQLEN          = 0x8942, // Get the tx queue length
	linux_SIOCSIFTXQLEN          = 0x8943, // Set the tx queue length

	// SIOCGIFDIVERT was:          0x8944 // Frame diversion support
	// SIOCSIFDIVERT was:          0x8945 // Set frame diversion options

	linux_SIOCETHTOOL            = 0x8946, // Ethtool interface

	linux_SIOCGMIIPHY            = 0x8947, // Get address of MII PHY in use.
	linux_SIOCGMIIREG            = 0x8948, // Read MII PHY register.
	linux_SIOCSMIIREG            = 0x8949, // Write MII PHY register.

	linux_SIOCWANDEV             = 0x894A, // get/set netdev parameters

	linux_SIOCOUTQNSD            = 0x894B, // output queue size (not sent only)
	linux_SIOCGSKNS              = 0x894C, // get socket network namespace

	// ARP cache control calls.
	//                    0x8950 - 0x8952 // obsolete calls, don't re-use
	linux_SIOCDARP               = 0x8953, // delete ARP table entry
	linux_SIOCGARP               = 0x8954, // get ARP table entry
	linux_SIOCSARP               = 0x8955, // set ARP table entry

	// RARP cache control calls.
	linux_SIOCDRARP              = 0x8960, // delete RARP table entry
	linux_SIOCGRARP              = 0x8961, // get RARP table entry
	linux_SIOCSRARP              = 0x8962, // set RARP table entry

	// Driver configuration calls
	linux_SIOCGIFMAP             = 0x8970, // Get device parameters
	linux_SIOCSIFMAP             = 0x8971, // Set device parameters

	// DLCI configuration calls
	linux_SIOCADDDLCI            = 0x8980, // Create new DLCI device
	linux_SIOCDELDLCI            = 0x8981, // Delete DLCI device

	linux_SIOCGIFVLAN            = 0x8982, // 802.1Q VLAN support
	linux_SIOCSIFVLAN            = 0x8983, // Set 802.1Q VLAN options

	// bonding calls

	linux_SIOCBONDENSLAVE        = 0x8990, // enslave a device to the bond
	linux_SIOCBONDRELEASE        = 0x8991, // release a slave from the bond
	linux_SIOCBONDSETHWADDR      = 0x8992, // set the hw addr of the bond
	linux_SIOCBONDSLAVEINFOQUERY = 0x8993, // rtn info about slave state
	linux_SIOCBONDINFOQUERY      = 0x8994, // rtn info about bond state
	linux_SIOCBONDCHANGEACTIVE   = 0x8995, // update to a new active slave

	// bridge calls
	linux_SIOCBRADDBR            = 0x89a0, // create new bridge device
	linux_SIOCBRDELBR            = 0x89a1, // remove bridge device
	linux_SIOCBRADDIF            = 0x89a2, // add interface to bridge
	linux_SIOCBRDELIF            = 0x89a3, // remove interface from bridge

	// hardware time stamping: parameters in linux/net_tstamp.h
	linux_SIOCSHWTSTAMP          = 0x89b0, // set and get config
	linux_SIOCGHWTSTAMP          = 0x89b1, // get config

	// Device private ioctl calls
	linux_SIOCDEVPRIVATE         = 0x89F0, // to 89FF

	// These 16 ioctl calls are protocol private
	linux_SIOCPROTOPRIVATE       = 0x89E0, // to 89EF
};

#define linux_MSG_OOB              1u
#define linux_MSG_PEEK             2u
#define linux_MSG_DONTROUTE        4u
#define linux_MSG_TRYHARD          4u // Synonym for MSG_DONTROUTE for DECnet
#define linux_MSG_CTRUNC           8u
#define linux_MSG_PROBE            0x10u // Do not send. Only probe path f.e. for MTU
#define linux_MSG_TRUNC            0x20u
#define linux_MSG_DONTWAIT         0x40u // Nonblocking io
#define linux_MSG_EOR              0x80u // End of record
#define linux_MSG_WAITALL          0x100u // Wait for a full request
#define linux_MSG_FIN              0x200u
#define linux_MSG_SYN              0x400u
#define linux_MSG_CONFIRM          0x800u // Confirm path validity
#define linux_MSG_RST              0x1000u
#define linux_MSG_ERRQUEUE         0x2000u // Fetch message from error queue
#define linux_MSG_NOSIGNAL         0x4000u // Do not generate SIGPIPE
#define linux_MSG_MORE             0x8000u // Sender will send more
#define linux_MSG_WAITFORONE       0x10000u // recvmmsg(): block until 1+ packets avail
#define linux_MSG_SENDPAGE_NOTLAST 0x20000u // sendpage() internal : not the last page
#define linux_MSG_BATCH            0x40000u // sendmmsg(): more messages coming
#define linux_MSG_EOF              linux_MSG_FIN
#define linux_MSG_FASTOPEN         0x20000000u // Send data in TCP SYN
#define linux_MSG_CMSG_CLOEXEC     0x40000000u // Set close_on_exec for file descriptor received through SCM_RIGHTS
#define linux_MSG_CMSG_COMPAT      0x80000000u // This message needs 32 bit fixups

enum
{
	linux_SHUT_RD = 0,
	linux_SHUT_WR = 1,
	linux_SHUT_RDWR = 2,
};

enum
{
	linux_INET_ADDRSTRLEN  = 16,
	linux_INET6_ADDRSTRLEN = 48,
};

enum
{
	linux_IPPROTO_IP      =   0, // Dummy protocol for TCP
	linux_IPPROTO_ICMP    =   1, // Internet Control Message Protocol
	linux_IPPROTO_IGMP    =   2, // Internet Group Management Protocol
	linux_IPPROTO_IPIP    =   4, // IPIP tunnels (older KA9Q tunnels use 94)
	linux_IPPROTO_TCP     =   6, // Transmission Control Protocol
	linux_IPPROTO_EGP     =   8, // Exterior Gateway Protocol
	linux_IPPROTO_PUP     =  12, // PUP protocol
	linux_IPPROTO_UDP     =  17, // User Datagram Protocol
	linux_IPPROTO_IDP     =  22, // XNS IDP protocol
	linux_IPPROTO_TP      =  29, // SO Transport Protocol Class 4
	linux_IPPROTO_DCCP    =  33, // Datagram Congestion Control Protocol
	linux_IPPROTO_IPV6    =  41, // IPv6-in-IPv4 tunnelling
	linux_IPPROTO_RSVP    =  46, // RSVP Protocol
	linux_IPPROTO_GRE     =  47, // Cisco GRE tunnels (rfc 1701,1702)
	linux_IPPROTO_ESP     =  50, // Encapsulation Security Payload protocol
	linux_IPPROTO_AH      =  51, // Authentication Header protocol
	linux_IPPROTO_MTP     =  92, // Multicast Transport Protocol
	linux_IPPROTO_BEETPH  =  94, // IP option pseudo header for BEET
	linux_IPPROTO_ENCAP   =  98, // Encapsulation Header
	linux_IPPROTO_PIM     = 103, // Protocol Independent Multicast
	linux_IPPROTO_COMP    = 108, // Compression Header Protocol
	linux_IPPROTO_SCTP    = 132, // Stream Control Transport Protocol
	linux_IPPROTO_UDPLITE = 136, // UDP-Lite (RFC 3828)
	linux_IPPROTO_MPLS    = 137, // MPLS in IP (RFC 4023)
	linux_IPPROTO_RAW     = 255, // Raw IP packets
	linux_IPPROTO_MAX
};

enum
{
	linux_IPPROTO_HOPOPTS  =   0, // IPv6 hop-by-hop options
	linux_IPPROTO_ROUTING  =  43, // IPv6 routing header
	linux_IPPROTO_FRAGMENT =  44, // IPv6 fragmentation header
	linux_IPPROTO_ICMPV6   =  58, // ICMPv6
	linux_IPPROTO_NONE     =  59, // IPv6 no next header
	linux_IPPROTO_DSTOPTS  =  60, // IPv6 destination options
	linux_IPPROTO_MH       = 135, // IPv6 mobility header
};

enum
{
	linux_IP_TOS                  =  1,
	linux_IP_TTL                  =  2,
	linux_IP_HDRINCL              =  3,
	linux_IP_OPTIONS              =  4,
	linux_IP_ROUTER_ALERT         =  5,
	linux_IP_RECVOPTS             =  6,
	linux_IP_RETOPTS              =  7,
	linux_IP_PKTINFO              =  8,
	linux_IP_PKTOPTIONS           =  9,
	linux_IP_MTU_DISCOVER         = 10,
	linux_IP_RECVERR              = 11,
	linux_IP_RECVTTL              = 12,
	linux_IP_RECVTOS              = 13,
	linux_IP_MTU                  = 14,
	linux_IP_FREEBIND             = 15,
	linux_IP_IPSEC_POLICY         = 16,
	linux_IP_XFRM_POLICY          = 17,
	linux_IP_PASSSEC              = 18,
	linux_IP_TRANSPARENT          = 19,

	// BSD compatibility
	linux_IP_RECVRETOPTS          = linux_IP_RETOPTS,

	// TProxy original addresses
	linux_IP_ORIGDSTADDR          = 20,
	linux_IP_RECVORIGDSTADDR      = linux_IP_ORIGDSTADDR,

	linux_IP_MINTTL               = 21,
	linux_IP_NODEFRAG             = 22,
	linux_IP_CHECKSUM             = 23,
	linux_IP_BIND_ADDRESS_NO_PORT = 24,
	linux_IP_RECVFRAGSIZE         = 25,
};

enum
{
	// IP_MTU_DISCOVER values
	linux_IP_PMTUDISC_DONT      = 0, // Never send DF frames
	linux_IP_PMTUDISC_WANT      = 1, // Use per route hints
	linux_IP_PMTUDISC_DO        = 2, // Always DF
	linux_IP_PMTUDISC_PROBE     = 3, // Ignore dst pmtu
	/*
	 * Always use interface mtu (ignores dst pmtu) but don't set DF flag.
	 * Also incoming ICMP frag_needed notifications will be ignored on
	 * this socket to prevent accepting spoofed ones.
	 */
	linux_IP_PMTUDISC_INTERFACE = 4,
	// weaker version of IP_PMTUDISC_INTERFACE, which allos packets to get fragmented if they exeed the interface mtu
	linux_IP_PMTUDISC_OMIT      = 5,
};

enum
{
	linux_IP_MULTICAST_IF           = 32,
	linux_IP_MULTICAST_TTL          = 33,
	linux_IP_MULTICAST_LOOP         = 34,
	linux_IP_ADD_MEMBERSHIP         = 35,
	linux_IP_DROP_MEMBERSHIP        = 36,
	linux_IP_UNBLOCK_SOURCE         = 37,
	linux_IP_BLOCK_SOURCE           = 38,
	linux_IP_ADD_SOURCE_MEMBERSHIP  = 39,
	linux_IP_DROP_SOURCE_MEMBERSHIP = 40,
	linux_IP_MSFILTER               = 41,
	linux_MCAST_JOIN_GROUP          = 42,
	linux_MCAST_BLOCK_SOURCE        = 43,
	linux_MCAST_UNBLOCK_SOURCE      = 44,
	linux_MCAST_LEAVE_GROUP         = 45,
	linux_MCAST_JOIN_SOURCE_GROUP   = 46,
	linux_MCAST_LEAVE_SOURCE_GROUP  = 47,
	linux_MCAST_MSFILTER            = 48,
	linux_IP_MULTICAST_ALL          = 49,
	linux_IP_UNICAST_IF             = 50,
};

enum
{
	linux_MCAST_EXCLUDE = 0,
	linux_MCAST_INCLUDE = 1,
};

enum
{
	// These need to appear somewhere around here
	linux_IP_DEFAULT_MULTICAST_TTL  = 1,
	linux_IP_DEFAULT_MULTICAST_LOOP = 1,
};

#define	linux_IN_CLASSA_NET          UINT32_C(0xFF000000)
#define	linux_IN_CLASSA_NSHIFT       24
#define	linux_IN_CLASSA_HOST         (UINT32_C(0xFFFFFFFF) & ~linux_IN_CLASSA_NET)
#define	linux_IN_CLASSA_MAX          128

#define	linux_IN_CLASSB_NET          UINT32_C(0xFFFF0000)
#define	linux_IN_CLASSB_NSHIFT       16
#define	linux_IN_CLASSB_HOST         (UINT32_C(0xFFFFFFFF) & ~linux_IN_CLASSB_NET)
#define	linux_IN_CLASSB_MAX          65536

#define	linux_IN_CLASSC_NET          UINT32_C(0xFFFFFF00)
#define	linux_IN_CLASSC_NSHIFT       8
#define	linux_IN_CLASSC_HOST         (UINT32_C(0xFFFFFFFF) & ~linux_IN_CLASSC_NET)

#define linux_IN_MULTICAST_NET       UINT32_C(0xF0000000)

// Address to accept any incoming messages.
#define linux_INADDR_ANY             UINT32_C(0x00000000) // Address to accept any incoming messages.

// Address to send to all hosts.
#define linux_INADDR_BROADCAST       UINT32_C(0xFFFFFFFF) // Address to send to all hosts.

// Address indicating an error return.
#define linux_INADDR_NONE            UINT32_C(0xFFFFFFFF) // Address indicating an error return.

// Network number for local host loopback.
#define	linux_IN_LOOPBACKNET         127 // Network number for local host loopback.

// Address to loopback in software to local host.
#define linux_INADDR_LOOPBACK        UINT32_C(0x7F000001) // 127.0.0.1

// Defines for Multicast INADDR
#define linux_INADDR_UNSPEC_GROUP    UINT32_C(0xE0000000) // 224.0.0.0
#define linux_INADDR_ALLHOSTS_GROUP  UINT32_C(0xE0000001) // 224.0.0.1
#define linux_INADDR_ALLRTRS_GROUP   UINT32_C(0xE0000002) // 224.0.0.2
#define linux_INADDR_MAX_LOCAL_GROUP UINT32_C(0xE00000FF) // 224.0.0.255

enum
{
	// IPv6 TLV options.
	linux_IPV6_TLV_PAD1        =   0,
	linux_IPV6_TLV_PADN        =   1,
	linux_IPV6_TLV_ROUTERALERT =   5,
	linux_IPV6_TLV_CALIPSO     =   7, // RFC 5570
	linux_IPV6_TLV_JUMBO       = 194,
	linux_IPV6_TLV_HAO         = 201, // home address option
};

enum
{
	// IPV6 socket options
	linux_IPV6_ADDRFORM               =  1,
	linux_IPV6_2292PKTINFO            =  2,
	linux_IPV6_2292HOPOPTS            =  3,
	linux_IPV6_2292DSTOPTS            =  4,
	linux_IPV6_2292RTHDR              =  5,
	linux_IPV6_2292PKTOPTIONS         =  6,
	linux_IPV6_CHECKSUM               =  7,
	linux_IPV6_2292HOPLIMIT           =  8,
	linux_IPV6_NEXTHOP                =  9,
	linux_IPV6_AUTHHDR                = 10, // obsolete
	linux_IPV6_FLOWINFO               = 11,

	linux_IPV6_UNICAST_HOPS           = 16,
	linux_IPV6_MULTICAST_IF           = 17,
	linux_IPV6_MULTICAST_HOPS         = 18,
	linux_IPV6_MULTICAST_LOOP         = 19,
	linux_IPV6_ADD_MEMBERSHIP         = 20,
	linux_IPV6_DROP_MEMBERSHIP        = 21,
	linux_IPV6_ROUTER_ALERT           = 22,
	linux_IPV6_MTU_DISCOVER           = 23,
	linux_IPV6_MTU                    = 24,
	linux_IPV6_RECVERR                = 25,
	linux_IPV6_V6ONLY                 = 26,
	linux_IPV6_JOIN_ANYCAST           = 27,
	linux_IPV6_LEAVE_ANYCAST          = 28,

	// Flowlabel
	linux_IPV6_FLOWLABEL_MGR          = 32,
	linux_IPV6_FLOWINFO_SEND          = 33,

	linux_IPV6_IPSEC_POLICY           = 34,
	linux_IPV6_XFRM_POLICY            = 35,
	linux_IPV6_HDRINCL                = 36,

	// Multicast:
	// Following socket options are shared between IPv4 and IPv6.
	//linux_MCAST_JOIN_GROUP            = 42,
	//linux_MCAST_BLOCK_SOURCE          = 43,
	//linux_MCAST_UNBLOCK_SOURCE        = 44,
	//linux_MCAST_LEAVE_GROUP           = 45,
	//linux_MCAST_JOIN_SOURCE_GROUP     = 46,
	//linux_MCAST_LEAVE_SOURCE_GROUP    = 47,
	//linux_MCAST_MSFILTER              = 48,

	linux_IPV6_RECVPKTINFO            = 49, // Note: IPV6_RECVRTHDRDSTOPTS does not exist.
	linux_IPV6_PKTINFO                = 50,
	linux_IPV6_RECVHOPLIMIT           = 51,
	linux_IPV6_HOPLIMIT               = 52,
	linux_IPV6_RECVHOPOPTS            = 53,
	linux_IPV6_HOPOPTS                = 54,
	linux_IPV6_RTHDRDSTOPTS           = 55,
	linux_IPV6_RECVRTHDR              = 56,
	linux_IPV6_RTHDR                  = 57,
	linux_IPV6_RECVDSTOPTS            = 58,
	linux_IPV6_DSTOPTS                = 59,
	linux_IPV6_RECVPATHMTU            = 60,
	linux_IPV6_PATHMTU                = 61,
	linux_IPV6_DONTFRAG               = 62,

	// Netfilter
	// Following socket options are used in ip6_tables;
	//linux_IP6T_SO_SET_REPLACE         = 64,
	//linux_IP6T_SO_GET_INFO            = 64,
	//linux_IP6T_SO_SET_ADD_COUNTERS    = 65,
	//linux_IP6T_SO_GET_ENTRIES         = 65,

	// Advanced API (RFC3542)
	linux_IPV6_RECVTCLASS             = 66,
	linux_IPV6_TCLASS                 = 67,

	// Netfilter
	// Following socket options are used in ip6_tables;
	// see include/linux/netfilter_ipv6/ip6_tables.h.
	//linux_IP6T_SO_GET_REVISION_MATCH  = 68,
	//linux_IP6T_SO_GET_REVISION_TARGET = 69,
	//linux_IP6T_SO_ORIGINAL_DST        = 80,

	linux_IPV6_AUTOFLOWLABEL          = 70,
	// RFC5014: Source address selection
	linux_IPV6_ADDR_PREFERENCES       = 72,

	// RFC5082: Generalized Ttl Security Mechanism
	linux_IPV6_MINHOPCOUNT            = 73,

	linux_IPV6_ORIGDSTADDR            = 74,
	linux_IPV6_RECVORIGDSTADDR        = linux_IPV6_ORIGDSTADDR,
	linux_IPV6_TRANSPARENT            = 75,
	linux_IPV6_UNICAST_IF             = 76,
	linux_IPV6_RECVFRAGSIZE           = 77,
};

enum
{
	// IPV6_MTU_DISCOVER values
	linux_IPV6_PMTUDISC_DONT      = 0,
	linux_IPV6_PMTUDISC_WANT      = 1,
	linux_IPV6_PMTUDISC_DO        = 2,
	linux_IPV6_PMTUDISC_PROBE     = 3,
	// same as IPV6_PMTUDISC_PROBE, provided for symetry with IPv4 also see comments on IP_PMTUDISC_INTERFACE
	linux_IPV6_PMTUDISC_INTERFACE = 4,
	// weaker version of IPV6_PMTUDISC_INTERFACE, which allows packets to get fragmented if they exceed the interface mtu
	linux_IPV6_PMTUDISC_OMIT      = 5,
};

enum
{
	linux_IPV6_PREFER_SRC_TMP            = 0x0001,
	linux_IPV6_PREFER_SRC_PUBLIC         = 0x0002,
	linux_IPV6_PREFER_SRC_PUBTMP_DEFAULT = 0x0100,
	linux_IPV6_PREFER_SRC_COA            = 0x0004,
	linux_IPV6_PREFER_SRC_HOME           = 0x0400,
	linux_IPV6_PREFER_SRC_CGA            = 0x0008,
	linux_IPV6_PREFER_SRC_NONCGA         = 0x0800,
};

#define linux_IN6ADDR_ANY_INIT                       { { {    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define linux_IN6ADDR_LOOPBACK_INIT                  { { {    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define linux_IN6ADDR_LINKLOCAL_ALLNODES_INIT        { { { 0xFF,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define linux_IN6ADDR_LINKLOCAL_ALLROUTERS_INIT      { { { 0xFF,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define linux_IN6ADDR_INTERFACELOCAL_ALLNODES_INIT   { { { 0xFF,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define linux_IN6ADDR_INTERFACELOCAL_ALLROUTERS_INIT { { { 0xFF,1,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define linux_IN6ADDR_SITELOCAL_ALLROUTERS_INIT      { { { 0xFF,5,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }

enum
{
	linux_SIOCUNIXFILE = linux_SIOCPROTOPRIVATE + 0, // open a socket file with O_PATH
};

// cloning flags
#define linux_CSIGNAL              0x000000FFul // signal mask to be sent at exit
#define linux_CLONE_VM             0x00000100ul // set if VM shared between processes
#define linux_CLONE_FS             0x00000200ul // set if fs info shared between processes
#define linux_CLONE_FILES          0x00000400ul // set if open files shared between processes
#define linux_CLONE_SIGHAND        0x00000800ul // set if signal handlers and blocked signals shared
//#define linux_CLONE_PID            0x00001000ul
#define linux_CLONE_PTRACE         0x00002000ul // set if we want to let tracing continue on the child too
#define linux_CLONE_VFORK          0x00004000ul // set if the parent wants the child to wake it up on mm_release
#define linux_CLONE_PARENT         0x00008000ul // set if we want to have the same parent as the cloner
#define linux_CLONE_THREAD         0x00010000ul // Same thread group?
#define linux_CLONE_NEWNS          0x00020000ul // New mount namespace group
#define linux_CLONE_SYSVSEM        0x00040000ul // share system V SEM_UNDO semantics
#define linux_CLONE_SETTLS         0x00080000ul // create a new TLS for the child
#define linux_CLONE_PARENT_SETTID  0x00100000ul // set the TID in the parent
#define linux_CLONE_CHILD_CLEARTID 0x00200000ul // clear the TID in the child
#define linux_CLONE_DETACHED       0x00400000ul // Unused, ignored
#define linux_CLONE_UNTRACED       0x00800000ul // set if the tracing process can't force CLONE_PTRACE on this clone
#define linux_CLONE_CHILD_SETTID   0x01000000ul // set the TID in the child
#define linux_CLONE_NEWCGROUP      0x02000000ul // New cgroup namespace
#define linux_CLONE_NEWUTS         0x04000000ul // New utsname namespace
#define linux_CLONE_NEWIPC         0x08000000ul // New ipc namespace
#define linux_CLONE_NEWUSER        0x10000000ul // New user namespace
#define linux_CLONE_NEWPID         0x20000000ul // New pid namespace
#define linux_CLONE_NEWNET         0x40000000ul // New network namespace
#define linux_CLONE_IO             0x80000000ul // Clone io context

// Resource limit IDs
enum
{
	linux_RLIMIT_CPU        =  0, // PU time in sec
	linux_RLIMIT_FSIZE      =  1, // aximum filesize
	linux_RLIMIT_DATA       =  2, // ax data size
	linux_RLIMIT_STACK      =  3, // ax stack size
	linux_RLIMIT_CORE       =  4, // ax core file size
	linux_RLIMIT_RSS        =  5, // ax resident set size
	linux_RLIMIT_NPROC      =  6, // ax number of processes
	linux_RLIMIT_NOFILE     =  7, // ax number of open files
	linux_RLIMIT_MEMLOCK    =  8, // ax locked-in-memory address space
	linux_RLIMIT_AS         =  9, // ddress space limit
	linux_RLIMIT_LOCKS      = 10, // aximum file locks held
	linux_RLIMIT_SIGPENDING = 11, // ax number of pending signals
	linux_RLIMIT_MSGQUEUE   = 12, // aximum bytes in POSIX mqueues
	linux_RLIMIT_NICE       = 13, // ax nice prio allowed to raise to 0-39 for nice level 19 .. -20
	linux_RLIMIT_RTPRIO     = 14, // aximum realtime priority
	linux_RLIMIT_RTTIME     = 15, // timeout for RT tasks in us
	linux_RLIM_NLIMITS      = 16,
};
#define linux_RLIM_INFINITY (~0ul)

enum
{
	linux_RUSAGE_SELF     =  0,
	linux_RUSAGE_CHILDREN = -1,
	linux_RUSAGE_BOTH     = -2, // sys_wait4() uses this
	linux_RUSAGE_THREAD   =  1, // only the calling thread
};

// arch_prctl options
enum
{
	linux_ARCH_SET_GS       = 0x1001,
	linux_ARCH_SET_FS       = 0x1002,
	linux_ARCH_GET_FS       = 0x1003,
	linux_ARCH_GET_GS       = 0x1004,

	linux_ARCH_GET_CPUID    = 0x1011,
	linux_ARCH_SET_CPUID    = 0x1012,

	linux_ARCH_MAP_VDSO_X32 = 0x2001,
	linux_ARCH_MAP_VDSO_32  = 0x2002,
	linux_ARCH_MAP_VDSO_64  = 0x2003,
};

// ptrace requests
enum
{
	linux_PTRACE_TRACEME            =  0,
	linux_PTRACE_PEEKTEXT           =  1,
	linux_PTRACE_PEEKDATA           =  2,
	linux_PTRACE_PEEKUSR            =  3,
	linux_PTRACE_POKETEXT           =  4,
	linux_PTRACE_POKEDATA           =  5,
	linux_PTRACE_POKEUSR            =  6,
	linux_PTRACE_CONT               =  7,
	linux_PTRACE_KILL               =  8,
	linux_PTRACE_SINGLESTEP         =  9,

	linux_PTRACE_GETREGS            = 12,
	linux_PTRACE_SETREGS            = 13,
	linux_PTRACE_GETFPREGS          = 14,
	linux_PTRACE_SETFPREGS          = 15,
	linux_PTRACE_ATTACH             = 16,
	linux_PTRACE_DETACH             = 17,
	linux_PTRACE_GETFPXREGS         = 18,
	linux_PTRACE_SETFPXREGS         = 19,

	linux_PTRACE_OLDSETOPTIONS      = 21,

	linux_PTRACE_SYSCALL            = 24,
	linux_PTRACE_GET_THREAD_AREA    = 25,
	linux_PTRACE_SET_THREAD_AREA    = 26,

	linux_PTRACE_ARCH_PRCTL         = 30,
	linux_PTRACE_SYSEMU             = 31,
	linux_PTRACE_SYSEMU_SINGLESTEP  = 32,
	linux_PTRACE_SINGLEBLOCK        = 33,

	linux_PTRACE_SETOPTIONS         = 0x4200,
	linux_PTRACE_GETEVENTMSG        = 0x4201,
	linux_PTRACE_GETSIGINFO         = 0x4202,
	linux_PTRACE_SETSIGINFO         = 0x4203,
	linux_PTRACE_GETREGSET          = 0x4204,
	linux_PTRACE_SETREGSET          = 0x4205,
	linux_PTRACE_SEIZE              = 0x4206,
	linux_PTRACE_INTERRUPT          = 0x4207,
	linux_PTRACE_LISTEN             = 0x4208,
	linux_PTRACE_PEEKSIGINFO        = 0x4209,
	linux_PTRACE_GETSIGMASK         = 0x420A,
	linux_PTRACE_SETSIGMASK         = 0x420B,
	linux_PTRACE_SECCOMP_GET_FILTER = 0x420C,
};

// struct linux_ptrace_peeksiginfo_args_t flags
enum
{
	linux_PTRACE_PEEKSIGINFO_SHARED = (1 << 0),
};

// ptrace events
enum
{
	linux_PTRACE_EVENT_FORK       =   1,
	linux_PTRACE_EVENT_VFORK      =   2,
	linux_PTRACE_EVENT_CLONE      =   3,
	linux_PTRACE_EVENT_EXEC       =   4,
	linux_PTRACE_EVENT_VFORK_DONE =   5,
	linux_PTRACE_EVENT_EXIT       =   6,
	linux_PTRACE_EVENT_SECCOMP    =   7,

	linux_PTRACE_EVENT_STOP       = 128,
};

// ptrace options
enum
{
	linux_PTRACE_O_TRACESYSGOOD    = 1,
	linux_PTRACE_O_TRACEFORK       = 1 << linux_PTRACE_EVENT_FORK,
	linux_PTRACE_O_TRACEVFORK      = 1 << linux_PTRACE_EVENT_VFORK,
	linux_PTRACE_O_TRACECLONE      = 1 << linux_PTRACE_EVENT_CLONE,
	linux_PTRACE_O_TRACEEXEC       = 1 << linux_PTRACE_EVENT_EXEC,
	linux_PTRACE_O_TRACEVFORKDONE  = 1 << linux_PTRACE_EVENT_VFORK_DONE,
	linux_PTRACE_O_TRACEEXIT       = 1 << linux_PTRACE_EVENT_EXIT,
	linux_PTRACE_O_TRACESECCOMP    = 1 << linux_PTRACE_EVENT_SECCOMP,

	linux_PTRACE_O_EXITKILL        = 1 << 20,
	linux_PTRACE_O_SUSPEND_SECCOMP = 1 << 21,

	linux_PTRACE_O_MASK = 0x000000FF | linux_PTRACE_O_EXITKILL | linux_PTRACE_O_SUSPEND_SECCOMP,
};

// syslog types
enum
{
	linux_SYSLOG_ACTION_CLOSE         =  0,
	linux_SYSLOG_ACTION_OPEN          =  1,
	linux_SYSLOG_ACTION_READ          =  2,
	linux_SYSLOG_ACTION_READ_ALL      =  3,
	linux_SYSLOG_ACTION_READ_CLEAR    =  4,
	linux_SYSLOG_ACTION_CLEAR         =  5,
	linux_SYSLOG_ACTION_CONSOLE_OFF   =  6,
	linux_SYSLOG_ACTION_CONSOLE_ON    =  7,
	linux_SYSLOG_ACTION_CONSOLE_LEVEL =  8,
	linux_SYSLOG_ACTION_SIZE_UNREAD   =  9,
	linux_SYSLOG_ACTION_SIZE_BUFFER   = 10,
};

// capabilities
enum
{
	linux_LINUX_CAPABILITY_VERSION_1 = 0x19980330,
	linux_LINUX_CAPABILITY_U32S_1    = 1,

	linux_LINUX_CAPABILITY_VERSION_2 = 0x20071026,
	linux_LINUX_CAPABILITY_U32S_2    = 2,

	linux_LINUX_CAPABILITY_VERSION_3 = 0x20080522,
	linux_LINUX_CAPABILITY_U32S_3    = 2,
};
enum
{
	linux_CAP_CHOWN            =  0,
	linux_CAP_DAC_OVERRIDE     =  1,
	linux_CAP_DAC_READ_SEARCH  =  2,
	linux_CAP_FOWNER           =  3,
	linux_CAP_FSETID           =  4,
	linux_CAP_KILL             =  5,
	linux_CAP_SETGID           =  6,
	linux_CAP_SETUID           =  7,
	linux_CAP_SETPCAP          =  8,
	linux_CAP_LINUX_IMMUTABLE  =  9,
	linux_CAP_NET_BIND_SERVICE = 10,
	linux_CAP_NET_BROADCAST    = 11,
	linux_CAP_NET_ADMIN        = 12,
	linux_CAP_NET_RAW          = 13,
	linux_CAP_IPC_LOCK         = 14,
	linux_CAP_IPC_OWNER        = 15,
	linux_CAP_SYS_MODULE       = 16,
	linux_CAP_SYS_RAWIO        = 17,
	linux_CAP_SYS_CHROOT       = 18,
	linux_CAP_SYS_PTRACE       = 19,
	linux_CAP_SYS_PACCT        = 20,
	linux_CAP_SYS_ADMIN        = 21,
	linux_CAP_SYS_BOOT         = 22,
	linux_CAP_SYS_NICE         = 23,
	linux_CAP_SYS_RESOURCE     = 24,
	linux_CAP_SYS_TIME         = 25,
	linux_CAP_SYS_TTY_CONFIG   = 26,
	linux_CAP_MKNOD            = 27,
	linux_CAP_LEASE            = 28,
	linux_CAP_AUDIT_WRITE      = 29,
	linux_CAP_AUDIT_CONTROL    = 30,
	linux_CAP_SETFCAP          = 31,
	linux_CAP_MAC_OVERRIDE     = 32,
	linux_CAP_MAC_ADMIN        = 33,
	linux_CAP_SYSLOG           = 34,
	linux_CAP_WAKE_ALARM       = 35,
	linux_CAP_BLOCK_SUSPEND    = 36,
	linux_CAP_AUDIT_READ       = 37,
	linux_CAP_LAST_CAP         = linux_CAP_AUDIT_READ,
};

// struct linux_siginfo_t si_code values
enum
{
	linux_SI_USER     =    0,
	linux_SI_KERNEL   = 0x80,
	linux_SI_QUEUE    =   -1,
	linux_SI_TIMER    =   -2,
	linux_SI_MESGQ    =   -3,
	linux_SI_ASYNCIO  =   -4,
	linux_SI_SIGIO    =   -5,
	linux_SI_TKILL    =   -6,
	linux_SI_DETHREAD =   -7,
};

// Sigaltstack constants
enum
{
	linux_MINSIGSTKSZ = 2048,
	linux_SIGSTKSZ    = 8192,
};

// Sigaltstack flags
enum
{
	linux_SS_ONSTACK    = 1,
	linux_SS_DISABLE    = 2,

	linux_SS_AUTODISARM = INT_MIN,
	linux_SS_FLAG_BITS  = linux_SS_AUTODISARM,
};

// Personality flags
enum
{
	linux_UNAME26            = 0x0020000,
	linux_ADDR_NO_RANDOMIZE  = 0x0040000,
	linux_FDPIC_FUNCPTRS     = 0x0080000,
	linux_MMAP_PAGE_ZERO     = 0x0100000,
	linux_ADDR_COMPAT_LAYOUT = 0x0200000,
	linux_READ_IMPLIES_EXEC  = 0x0400000,
	linux_ADDR_LIMIT_32BIT   = 0x0800000,
	linux_SHORT_INODE        = 0x1000000,
	linux_WHOLE_SECONDS      = 0x2000000,
	linux_STICKY_TIMEOUTS    = 0x4000000,
	linux_ADDR_LIMIT_3GB     = 0x8000000,
};

// Personality types
enum
{
	linux_PER_LINUX       = 0x0000,
	linux_PER_LINUX_32BIT = 0x0000 | linux_ADDR_LIMIT_32BIT,
	linux_PER_LINUX_FDPIC = 0x0000 | linux_FDPIC_FUNCPTRS,
	linux_PER_SVR4        = 0x0001 | linux_STICKY_TIMEOUTS | linux_MMAP_PAGE_ZERO,
	linux_PER_SVR3        = 0x0002 | linux_STICKY_TIMEOUTS | linux_SHORT_INODE,
	linux_PER_SCOSVR3     = 0x0003 | linux_STICKY_TIMEOUTS | linux_WHOLE_SECONDS | linux_SHORT_INODE,
	linux_PER_OSR5        = 0x0003 | linux_STICKY_TIMEOUTS | linux_WHOLE_SECONDS,
	linux_PER_WYSEV386    = 0x0004 | linux_STICKY_TIMEOUTS | linux_SHORT_INODE,
	linux_PER_ISCR4       = 0x0005 | linux_STICKY_TIMEOUTS,
	linux_PER_BSD         = 0x0006,
	linux_PER_SUNOS       = 0x0006 | linux_STICKY_TIMEOUTS,
	linux_PER_XENIX       = 0x0007 | linux_STICKY_TIMEOUTS | linux_SHORT_INODE,
	linux_PER_LINUX32     = 0x0008,
	linux_PER_LINUX32_3GB = 0x0008 | linux_ADDR_LIMIT_3GB,
	linux_PER_IRIX32      = 0x0009 | linux_STICKY_TIMEOUTS,
	linux_PER_IRIXN32     = 0x000A | linux_STICKY_TIMEOUTS,
	linux_PER_IRIX64      = 0x000B | linux_STICKY_TIMEOUTS,
	linux_PER_RISCOS      = 0x000C,
	linux_PER_SOLARIS     = 0x000D | linux_STICKY_TIMEOUTS,
	linux_PER_UW7         = 0x000E | linux_STICKY_TIMEOUTS | linux_MMAP_PAGE_ZERO,
	linux_PER_OSF4        = 0x000F,
	linux_PER_HPUX        = 0x0010,
	linux_PER_MASK        = 0x00FF,
};

// statfs and fstatfs flags
enum
{
	linux_ST_RDONLY      = 0x0001,
	linux_ST_NOSUID      = 0x0002,
	linux_ST_NODEV       = 0x0004,
	linux_ST_NOEXEC      = 0x0008,
	linux_ST_SYNCHRONOUS = 0x0010,
	linux_ST_VALID       = 0x0020,
	linux_ST_MANDLOCK    = 0x0040,
	// 0x0080 used for ST_WRITE in glibc
	// 0x0100 used for ST_APPEND in glibc
	// 0x0200 used for ST_IMMUTABLE in glibc
	linux_ST_NOATIME     = 0x0400,
	linux_ST_NODIRATIME  = 0x0800,
	linux_ST_RELATIME    = 0x1000,
};

// statfs and fstatfs types
enum
{
	linux_ADFS_SUPER_MAGIC      = 0xADF5,
	linux_AFFS_SUPER_MAGIC      = 0xADFF,
	linux_AFS_SUPER_MAGIC       = 0x5346414F,
	linux_AUTOFS_SUPER_MAGIC    = 0x0187,
	linux_CODA_SUPER_MAGIC      = 0x73757245,
	linux_CRAMFS_MAGIC          = 0x28CD3D45,
	linux_CRAMFS_MAGIC_WEND     = 0x453DCD28,
	linux_DEBUGFS_MAGIC         = 0x64626720,
	linux_SECURITYFS_MAGIC      = 0x73636673,
	linux_SELINUX_MAGIC         = -109248628, // 0xF97CFF8C
	linux_SMACK_MAGIC           = 0x43415D53,
	linux_RAMFS_MAGIC           = -2054924042, // 0x858458F6
	linux_TMPFS_MAGIC           = 0x01021994,
	linux_HUGETLBFS_MAGIC       = -109248628, // 0x958458F6
	linux_SQUASHFS_MAGIC        = 0x73717368,
	linux_ECRYPTFS_SUPER_MAGIC  = 0xF15F,
	linux_EFS_SUPER_MAGIC       = 0x414a53,
	linux_EXT2_SUPER_MAGIC      = 0xEF53,
	linux_EXT3_SUPER_MAGIC      = 0xEF53,
	linux_XENFS_SUPER_MAGIC     = -1413867148, // 0xABBA1974
	linux_EXT4_SUPER_MAGIC      = 0xEF53,
	linux_BTRFS_SUPER_MAGIC     = -1859950530, // 0x9123683E
	linux_NILFS_SUPER_MAGIC     = 0x3434,
	linux_F2FS_SUPER_MAGIC      = -218816496, // 0xF2F52010
	linux_HPFS_SUPER_MAGIC      = -107616183, // 0xF995E849
	linux_ISOFS_SUPER_MAGIC     = 0x9660,
	linux_JFFS2_SUPER_MAGIC     = 0x72B6,
	linux_PSTOREFS_MAGIC        = 0x6165676C,
	linux_EFIVARFS_MAGIC        = -564231708, // 0xDE5E81E4
	linux_HOSTFS_SUPER_MAGIC    = 0x00C0FFEE,
	linux_OVERLAYFS_SUPER_MAGIC = 0x794C7630,

	linux_MINIX_SUPER_MAGIC     = 0x137F,
	linux_MINIX_SUPER_MAGIC2    = 0x138F,
	linux_MINIX2_SUPER_MAGIC    = 0x2468,
	linux_MINIX2_SUPER_MAGIC2   = 0x2478,
	linux_MINIX3_SUPER_MAGIC    = 0x4D5A,

	linux_MSDOS_SUPER_MAGIC     = 0x4D44,
	linux_NCP_SUPER_MAGIC       = 0x564C,
	linux_NFS_SUPER_MAGIC       = 0x6969,
	linux_OCFS2_SUPER_MAGIC     = 0x7461636F,
	linux_OPENPROM_SUPER_MAGIC  = 0x9FA1,
	linux_QNX4_SUPER_MAGIC      = 0x002F,
	linux_QNX6_SUPER_MAGIC      = 0x68191122,
	linux_AFS_FS_MAGIC          = 0x6B414653,

	linux_REISERFS_SUPER_MAGIC  = 0x52654973,

	linux_SMB_SUPER_MAGIC       = 0x517B,
	linux_CGROUP_SUPER_MAGIC    = 0x27E0EB,
	linux_CGROUP2_SUPER_MAGIC   = 0x63677270,

	linux_RDTGROUP_SUPER_MAGIC  = 0x7655821,

	linux_STACK_END_MAGIC       = 0x57AC6E9D,

	linux_TRACEFS_MAGIC         = 0x74726163,

	linux_V9FS_MAGIC            = 0x01021997,

	linux_BDEVFS_MAGIC          = 0x62646576,
	linux_DAXFS_MAGIC           = 0x64646178,
	linux_BINFMTFS_MAGIC        = 0x42494E4D,
	linux_DEVPTS_SUPER_MAGIC    = 0x1CD1,
	linux_FUTEXFS_SUPER_MAGIC   = 0xBAD1DEA,
	linux_PIPEFS_MAGIC          = 0x50495045,
	linux_PROC_SUPER_MAGIC      = 0x9FA0,
	linux_SOCKFS_MAGIC          = 0x534F434B,
	linux_SYSFS_MAGIC           = 0x62656572,
	linux_USBDEVICE_SUPER_MAGIC = 0x9FA2,
	linux_MTD_INODE_FS_MAGIC    = 0x11307854,
	linux_ANON_INODE_FS_MAGIC   = 0x09041934,
	linux_BTRFS_TEST_MAGIC      = 0x73727279,
	linux_NSFS_MAGIC            = 0x6E736673,
	linux_BPF_FS_MAGIC          = -889304559, // 0xCAFE4A11
	linux_AAFS_MAGIC            = 0x5A3C69F0,

	linux_UDF_SUPER_MAGIC       = 0x15013346,
	linux_BALLOON_KVM_MAGIC     = 0x13661366,
	linux_ZSMALLOC_MAGIC        = 0x58295829,
};

// getpriority and setpriority constants
enum
{
	linux_PRIO_MIN   = -20,
	linux_PRIO_MAX   =  20,

	linux_MAX_NICE   =  19,
	linux_MIN_NICE   = -20,
	linux_NICE_WIDTH = linux_MAX_NICE - linux_MIN_NICE + 1,
};
enum
{
	linux_PRIO_PROCESS = 0,
	linux_PRIO_PGRP    = 1,
	linux_PRIO_USER    = 2,
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

static inline bool linux_IN_CLASSA(uint32_t const addr)
{
	return (addr & 0x80000000) == 0;
}

static inline bool linux_IN_CLASSB(uint32_t const addr)
{
	return (addr & 0xC0000000) == 0x80000000;
}

static inline bool linux_IN_CLASSC(uint32_t const addr)
{
	return (addr & 0xE0000000) == 0xC0000000;
}

static inline bool linux_IN_CLASSD(uint32_t const addr)
{
	return (addr & 0xF0000000) == 0xE0000000;
}

static inline bool linux_IN_MULTICAST(uint32_t const addr)
{
	return linux_IN_CLASSD(addr);
}

static inline bool linux_IN_EXPERIMENTAL(uint32_t const addr)
{
	return (addr & 0xF0000000) == 0xF0000000;
}

static inline bool linux_IN_BADCLASS(uint32_t const addr)
{
	return linux_IN_EXPERIMENTAL(addr);
}

// Status bits
// -----------
// Bits  1– 7: signal number
// Bit      8: core dump
// Bits  9–16: exit code
// Bits 17–32: unknown

static inline uint8_t linux_WEXITSTATUS(int const status)
{
	return (status & 0xFF00) >> 8;
}
static inline uint8_t linux_WTERMSIG(int const status)
{
	return status & 0x7F;
}
static inline uint8_t linux_WSTOPSIG(int const status)
{
	return linux_WEXITSTATUS(status);
}
static inline bool linux_WIFEXITED(int const status)
{
	return !linux_WTERMSIG(status);
}
static inline bool linux_WIFSTOPPED(int const status)
{
	return (status & 0xFF) == 0x7F;
}
static inline bool linux_WIFSIGNALED(int const status)
{
	return (status & 0xFFFF) - 1u < 0xFFu;
}
static inline bool linux_WCOREDUMP(int const status)
{
	return status & 0x80;
}
static inline bool linux_WIFCONTINUED(int const status)
{
	return status == 0xFFFF;
}

static inline bool linux_cap_valid(int const cap)
{
	return cap >= 0 && cap <= linux_CAP_LAST_CAP;
}

static inline int linux_cap_to_index(int const cap)
{
	return cap >> 5;
}

static inline int linux_cap_to_mask(int const cap)
{
	return 1 << (cap & 31);
}

static inline bool linux_si_fromuser(struct linux_siginfo_t const* const siptr)
{
	return siptr->si_code <= 0;
}

static inline bool linux_si_fromkernel(struct linux_siginfo_t const* const siptr)
{
	return siptr->si_code > 0;
}

static inline uint32_t linux_major(linux_dev_t const dev)
{
	return (dev & 0xFFF00) >> 8;
}

static inline uint32_t linux_minor(linux_dev_t const dev)
{
	return (dev & 0xFF) | ((dev >> 12) & 0xFFF00);
}

static inline linux_dev_t linux_makedev(uint32_t major, uint32_t minor)
{
	major &= 0xFFF;
	minor &= 0xFFFFF;
	return (minor & 0xFF) | (major << 8) | ((minor & ~UINT32_C(0xFF)) << 12);
}

// Helper functions
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Syscalls

static inline LINUX_DEFINE_SYSCALL3_RET(read, linux_fd_t, fd, void*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(write, linux_fd_t, fd, void const*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(open, char const*, filename, int, flags, linux_umode_t, mode, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(close, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL2_NORET(newstat, char const*, filename, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(newfstat, linux_fd_t, fd, struct linux_stat_t*, statbuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(newlstat, char const*, filename, struct linux_stat_t*, statbuf)
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
static inline LINUX_DEFINE_SYSCALL3_RET(shmget, linux_key_t, key, size_t, size, int, flag, linux_shmid_t)
static inline LINUX_DEFINE_SYSCALL3_RET(shmat, linux_shmid_t, shmid, void LINUX_SAFE_CONST*, shmaddr, int, shmflg, void*)
static inline LINUX_DEFINE_SYSCALL3_RET(shmctl, linux_shmid_t, shmid, int, cmd, struct linux_shmid64_ds_t*, buf, int)
static inline LINUX_DEFINE_SYSCALL1_RET(dup, linux_fd_t, fildes, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_RET(dup2, linux_fd_t, oldfd, linux_fd_t, newfd, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL0_NORET(pause)
static inline LINUX_DEFINE_SYSCALL2_NORET(nanosleep, struct linux_timespec_t LINUX_SAFE_CONST*, rqtp, struct linux_timespec_t*, rmtp)
static inline LINUX_DEFINE_SYSCALL2_NORET(getitimer, int, which, struct linux_itimerval_t*, value)
static inline LINUX_DEFINE_SYSCALL1_RET(alarm, unsigned int, seconds, unsigned int)
static inline LINUX_DEFINE_SYSCALL3_NORET(setitimer, int, which, struct linux_itimerval_t  LINUX_SAFE_CONST*, value, struct linux_itimerval_t*, ovalue)
static inline LINUX_DEFINE_SYSCALL0_RET(getpid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL4_RET(sendfile64, linux_fd_t, out_fd, linux_fd_t, in_fd, linux_loff_t, offset, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(socket, int, family, int, type, int, protocol, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_NORET(connect, linux_fd_t, fd, struct linux_sockaddr_t LINUX_SAFE_CONST*, uservaddr, int, addrlen)
static inline LINUX_DEFINE_SYSCALL3_RET(accept, linux_fd_t, fd, struct linux_sockaddr_t*, upeer_sockaddr, int*, upeer_addrlen, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL6_RET(sendto, linux_fd_t, fd, void LINUX_SAFE_CONST*, buff, size_t, len, unsigned int, flags, struct linux_sockaddr_t LINUX_SAFE_CONST*, addr, int, addr_len, size_t)
static inline LINUX_DEFINE_SYSCALL6_RET(recvfrom, linux_fd_t, fd, void*, ubuf, size_t, size, unsigned int, flags, struct linux_sockaddr_t*, addr, int*, addr_len, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(sendmsg, linux_fd_t, fd, struct linux_user_msghdr_t LINUX_SAFE_CONST*, msg, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(recvmsg, linux_fd_t, fd, struct linux_user_msghdr_t*, msg, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(shutdown, linux_fd_t, fd, int, how)
static inline LINUX_DEFINE_SYSCALL3_NORET(bind, linux_fd_t, fd, struct linux_sockaddr_t LINUX_SAFE_CONST*, umyaddr, int, addrlen)
static inline LINUX_DEFINE_SYSCALL2_NORET(listen, linux_fd_t, fd, int, backlog)
static inline LINUX_DEFINE_SYSCALL3_NORET(getsockname, linux_fd_t, fd, struct linux_sockaddr_t*, usockaddr, int*, usockaddr_len)
static inline LINUX_DEFINE_SYSCALL3_NORET(getpeername, linux_fd_t, fd, struct linux_sockaddr_t*, usockaddr, int*, usockaddr_len)
static inline LINUX_DEFINE_SYSCALL4_NORET(socketpair, int, family, int, type, int, protocol, linux_fd_t*, usockvec)
static inline LINUX_DEFINE_SYSCALL5_NORET(setsockopt, linux_fd_t, fd, int, level, int, optname, void LINUX_SAFE_CONST*, optval, int, optlen)
static inline LINUX_DEFINE_SYSCALL5_NORET(getsockopt, linux_fd_t, fd, int, level, int, optname, void*, optval, int*, optlen)
static inline LINUX_DEFINE_SYSCALL5_RET(clone, unsigned long, clone_flags, void*, newsp, linux_pid_t*, parent_tidptr, linux_pid_t*, child_tidptr, unsigned long, tls, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL0_RET(fork, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL0_RET(vfork, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL3_NORET(execve, char const*, filename, char const* const*, argv, char const* const*, envp)
//exit
static inline LINUX_DEFINE_SYSCALL4_RET(wait4, linux_pid_t, pid, int*, stat_addr, int, options, struct linux_rusage_t*, ru, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(kill, linux_pid_t, pid, int, sig)
static inline LINUX_DEFINE_SYSCALL1_NORET(newuname, struct linux_new_utsname_t*, name)
static inline LINUX_DEFINE_SYSCALL3_RET(semget, linux_key_t, key, int, nsems, int, semflg, linux_semid_t)
static inline LINUX_DEFINE_SYSCALL3_NORET(semop, linux_semid_t, semid, struct linux_sembuf_t LINUX_SAFE_CONST*, sops, unsigned, nsops)
static inline LINUX_DEFINE_SYSCALL4_RET(semctl, linux_semid_t, semid, int, semnum, int, cmd, unsigned long, arg, int)
static inline LINUX_DEFINE_SYSCALL1_NORET(shmdt, void LINUX_SAFE_CONST*, shmaddr)
static inline LINUX_DEFINE_SYSCALL2_RET(msgget, linux_key_t, key, int, msgflg, linux_msgid_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(msgsnd, linux_msgid_t, msqid, struct linux_msgbuf_t LINUX_SAFE_CONST*, msgp, size_t, msgsz, int, msgflg)
static inline LINUX_DEFINE_SYSCALL5_RET(msgrcv, linux_msgid_t, msqid, struct linux_msgbuf_t*, msgp, size_t, msgsz, long, msgtyp, int, msgflg, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(msgctl, linux_msgid_t, msqid, int, cmd, struct linux_msqid64_ds_t*, buf, int)
static inline LINUX_DEFINE_SYSCALL3_RET(fcntl, linux_fd_t, fd, unsigned int, cmd, uintptr_t, arg, int)
static inline LINUX_DEFINE_SYSCALL2_NORET(flock, linux_fd_t, fd, unsigned int, cmd)
static inline LINUX_DEFINE_SYSCALL1_NORET(fsync, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL1_NORET(fdatasync, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL2_NORET(truncate, char LINUX_SAFE_CONST*, path, long, length)
static inline LINUX_DEFINE_SYSCALL2_NORET(ftruncate, linux_fd_t, fd, unsigned long, length)
static inline LINUX_DEFINE_SYSCALL3_RET(getdents, linux_fd_t, fd, struct linux_dirent_t*, dirent, unsigned int, count, unsigned int)
static inline LINUX_DEFINE_SYSCALL2_RET(getcwd, char*, buf, unsigned long, size, int)
static inline LINUX_DEFINE_SYSCALL1_NORET(chdir, char const*, filename)
static inline LINUX_DEFINE_SYSCALL1_NORET(fchdir, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL2_NORET(rename, char const*, oldname, char const*, newname)
static inline LINUX_DEFINE_SYSCALL2_NORET(mkdir, char const*, pathname, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL1_NORET(rmdir, char const*, pathname)
static inline LINUX_DEFINE_SYSCALL2_RET(creat, char const*, pathname, linux_umode_t, mode, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(link, char const*, oldname, char const*, newname)
static inline LINUX_DEFINE_SYSCALL1_NORET(unlink, char const*, pathname)
static inline LINUX_DEFINE_SYSCALL2_NORET(symlink, char const*, oldname, char const*, newname)
static inline LINUX_DEFINE_SYSCALL3_RET(readlink, char const*, path, char*, buf, int, bufsiz, int)
static inline LINUX_DEFINE_SYSCALL2_NORET(chmod, char const*, filename, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL2_NORET(fchmod, linux_fd_t, fd, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL3_NORET(chown, char const*, filename, linux_uid_t, user, linux_gid_t, group)
static inline LINUX_DEFINE_SYSCALL3_NORET(fchown, linux_fd_t, fd, linux_uid_t, user, linux_gid_t, group)
static inline LINUX_DEFINE_SYSCALL3_NORET(lchown, char const*, filename, linux_uid_t, user, linux_gid_t, group)
static inline LINUX_DEFINE_SYSCALL1_RET(umask, linux_umode_t, mask, linux_umode_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(gettimeofday, struct linux_timeval_t*, tv, struct linux_timezone_t*, tz)
static inline LINUX_DEFINE_SYSCALL2_NORET(getrlimit, unsigned int, resource, struct linux_rlimit_t*, rlim)
static inline LINUX_DEFINE_SYSCALL2_NORET(getrusage, int, who, struct linux_rusage_t*, ru)
static inline LINUX_DEFINE_SYSCALL1_NORET(sysinfo, struct linux_sysinfo_t*, info)
static inline LINUX_DEFINE_SYSCALL1_RET(times, struct linux_tms_t*, tbuf, linux_clock_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(ptrace, int, request, linux_pid_t, pid, void*, addr, uintptr_t, data)
static inline LINUX_DEFINE_SYSCALL0_RET(getuid, linux_uid_t)
static inline LINUX_DEFINE_SYSCALL3_RET(syslog, int, type, char*, buf, int, len, int)
static inline LINUX_DEFINE_SYSCALL0_RET(getgid, linux_gid_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(setuid, linux_uid_t, uid)
static inline LINUX_DEFINE_SYSCALL1_NORET(setgid, linux_gid_t, gid)
static inline LINUX_DEFINE_SYSCALL0_RET(geteuid, linux_uid_t)
static inline LINUX_DEFINE_SYSCALL0_RET(getegid, linux_gid_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(setpgid, linux_pid_t, pid, linux_pid_t, pgid)
static inline LINUX_DEFINE_SYSCALL0_RET(getppid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL0_RET(getpgrp, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL0_RET(setsid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(setreuid, linux_uid_t, ruid, linux_uid_t, euid)
static inline LINUX_DEFINE_SYSCALL2_NORET(setregid, linux_gid_t, rgid, linux_gid_t, egid)
static inline LINUX_DEFINE_SYSCALL2_RET(getgroups, int, gidsetsize, linux_gid_t*, grouplist, int)
static inline LINUX_DEFINE_SYSCALL2_NORET(setgroups, int, gidsetsize, linux_gid_t LINUX_SAFE_CONST*, grouplist)
static inline LINUX_DEFINE_SYSCALL3_NORET(setresuid, linux_uid_t, ruid, linux_uid_t, euid, linux_uid_t, suid)
static inline LINUX_DEFINE_SYSCALL3_NORET(getresuid, linux_uid_t*, ruid, linux_uid_t*, euid, linux_uid_t*, suid)
static inline LINUX_DEFINE_SYSCALL3_NORET(setresgid, linux_gid_t, rgid, linux_gid_t, egid, linux_gid_t, sgid)
static inline LINUX_DEFINE_SYSCALL3_NORET(getresgid, linux_gid_t*, rgid, linux_gid_t*, egid, linux_gid_t*, sgid)
static inline LINUX_DEFINE_SYSCALL1_RET(getpgid, linux_pid_t, pid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL1_RET(setfsuid, linux_uid_t, uid, linux_uid_t)
static inline LINUX_DEFINE_SYSCALL1_RET(setfsgid, linux_gid_t, gid, linux_gid_t)
static inline LINUX_DEFINE_SYSCALL1_RET(getsid, linux_pid_t, pid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(capget, struct linux_user_cap_header_struct_t*, header, struct linux_user_cap_data_struct_t*, dataptr)
static inline LINUX_DEFINE_SYSCALL2_NORET(capset, struct linux_user_cap_header_struct_t*, header, struct linux_user_cap_data_struct_t const*, data)
static inline LINUX_DEFINE_SYSCALL2_NORET(rt_sigpending, linux_sigset_t*, set, size_t, sigsetsize)
static inline LINUX_DEFINE_SYSCALL4_RET(rt_sigtimedwait, linux_sigset_t const*, uthese, struct linux_siginfo_t*, uinfo, struct linux_timespec_t const*, uts, size_t, sigsetsize, int)
static inline LINUX_DEFINE_SYSCALL3_NORET(rt_sigqueueinfo, linux_pid_t, pid, int, sig, struct linux_siginfo_t*, uinfo)
static inline LINUX_DEFINE_SYSCALL2_NORET(rt_sigsuspend, linux_sigset_t LINUX_SAFE_CONST*, unewset, size_t, sigsetsize)
static inline LINUX_DEFINE_SYSCALL2_NORET(sigaltstack, struct linux_sigaltstack_t const*, uss, struct linux_sigaltstack_t*, uoss)
static inline LINUX_DEFINE_SYSCALL2_NORET(utime, char LINUX_SAFE_CONST*, filename, struct linux_utimbuf_t LINUX_SAFE_CONST*, times)
static inline LINUX_DEFINE_SYSCALL3_NORET(mknod, char const*, filename, linux_umode_t, mode, linux_dev_t, dev)
static inline LINUX_DEFINE_SYSCALL1_RET(personality, unsigned int, personality, unsigned int)
static inline LINUX_DEFINE_SYSCALL2_NORET(ustat, linux_dev_t, dev, struct linux_ustat_t*, ubuf)
static inline LINUX_DEFINE_SYSCALL2_NORET(statfs, char const*, path, struct linux_statfs_t*, buf)
static inline LINUX_DEFINE_SYSCALL2_NORET(fstatfs, linux_fd_t, fd, struct linux_statfs_t*, buf)
static inline LINUX_DEFINE_SYSCALL3_RET(sysfs, int, option, uintptr_t, arg1, uintptr_t, arg2, int)
static inline LINUX_DEFINE_SYSCALL2_RET(getpriority, int, which, int, who, long)
static inline LINUX_DEFINE_SYSCALL3_NORET(setpriority, int, which, int, who, int, niceval)
// TODO: Add more syscalls here first.
static inline LINUX_DEFINE_SYSCALL2_NORET(arch_prctl, int, option, uintptr_t, arg2)

// Syscalls
//------------------------------------------------------------------------------

#endif // HEADER_LIBLINUX_LINUX_H_INCLUDED
