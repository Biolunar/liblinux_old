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
 * =======
 * Make sure all type replacements are exactly the same size! There is no
 * standard that defines if values get sign extended or not.
 *
 * char
 * signed char, unsigned char -> (u)int8_t
 * signed short, unsigned short -> (u)int16_t
 * signed int, unsigned int -> (u)int32_t
 * signed long, unsigned long -> (u)intptr_t, size_t
 * signed long long, unsigned long long -> (u)int64_t
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
typedef int32_t linux_wd_t;
typedef int linux_pkey_t;

// Custom types
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Kernel types

#if defined(__x86_64__) && defined(__ILP32__)
typedef long long linux_kernel_long_t;
typedef unsigned long long linux_kernel_ulong_t;
#else
typedef long linux_kernel_long_t;
typedef unsigned long linux_kernel_ulong_t;
#endif
typedef int linux_kernel_rwf_t;
typedef linux_kernel_long_t linux_kernel_time_t;
struct linux_timespec_t
{
	linux_kernel_time_t tv_sec;
	long tv_nsec;
};

#include "aio.h"

typedef unsigned short linux_kernel_mode_t;
typedef unsigned short linux_umode_t;
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
typedef linux_kernel_long_t linux_kernel_suseconds_t;
typedef int linux_kernel_key_t;
typedef linux_kernel_key_t linux_key_t;
typedef unsigned short linux_kernel_sa_family_t;
typedef linux_kernel_sa_family_t linux_sa_family_t;
typedef linux_kernel_time_t linux_time_t;
typedef int linux_kernel_clockid_t;
typedef linux_kernel_clockid_t linux_clockid_t;
typedef linux_kernel_timer_t linux_timer_t;
typedef int linux_kernel_mqd_t;
typedef linux_kernel_mqd_t linux_mqd_t;
typedef int32_t linux_key_serial_t;
typedef linux_kernel_rwf_t linux_rwf_t;
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
struct linux_dirent64_t
{
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char _pad[5];
	char d_name[];
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
struct linux_sched_param_t
{
	int sched_priority;
};
struct linux_sched_attr_t
{
	uint32_t size;
	uint32_t sched_policy;
	uint64_t sched_flags;
	int32_t sched_nice;
	uint32_t sched_priority;
	uint64_t sched_runtime;
	uint64_t sched_deadline;
	uint64_t sched_period;
};
struct linux_user_desc_t
{
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit:1;
	unsigned int contents:2;
	unsigned int read_exec_only:1;
	unsigned int limit_in_pages:1;
	unsigned int seg_not_present:1;
	unsigned int useable:1;
	unsigned int lm:1;
	char _pad[3];
};
struct linux_sysctl_args_t
{
	int* name;
	int nlen;
	char _pad1[4];
	void* oldval;
	size_t* oldlenp;
	void* newval;
	size_t newlen;
	unsigned long _pad2[4];
};
struct linux_timex_t
{
	unsigned int modes;
	char _pad1[4];
	linux_kernel_long_t offset;
	linux_kernel_long_t freq;
	linux_kernel_long_t maxerror;
	linux_kernel_long_t esterror;
	int status;
	char _pad2[4];
	linux_kernel_long_t constant;
	linux_kernel_long_t precision;
	linux_kernel_long_t tolerance;
	struct linux_timeval_t time;
	linux_kernel_long_t tick;

	linux_kernel_long_t ppsfreq;
	linux_kernel_long_t jitter;
	int shift;
	char _pad3[4];
	linux_kernel_long_t stabil;
	linux_kernel_long_t jitcnt;
	linux_kernel_long_t calcnt;
	linux_kernel_long_t errcnt;
	linux_kernel_long_t stbcnt;

	int tai;

	int  :32; int  :32; int  :32; int  :32;
	int  :32; int  :32; int  :32; int  :32;
	int  :32; int  :32; int  :32;
};
typedef linux_kernel_uid32_t linux_qid_t;
struct linux_if_dqblk_t
{
	uint64_t dqb_bhardlimit;
	uint64_t dqb_bsoftlimit;
	uint64_t dqb_curspace;
	uint64_t dqb_ihardlimit;
	uint64_t dqb_isoftlimit;
	uint64_t dqb_curinodes;
	uint64_t dqb_btime;
	uint64_t dqb_itime;
	uint32_t dqb_valid;
	char _pad[4];
};
struct linux_if_nextdqblk_t
{
	uint64_t dqb_bhardlimit;
	uint64_t dqb_bsoftlimit;
	uint64_t dqb_curspace;
	uint64_t dqb_ihardlimit;
	uint64_t dqb_isoftlimit;
	uint64_t dqb_curinodes;
	uint64_t dqb_btime;
	uint64_t dqb_itime;
	uint32_t dqb_valid;
	uint32_t dqb_id;
};
struct linux_if_dqinfo_t
{
	uint64_t dqi_bgrace;
	uint64_t dqi_igrace;
	uint32_t dqi_flags;
	uint32_t dqi_valid;
};
struct linux_fs_disk_quota_t
{
	int8_t d_version;
	int8_t d_flags;
	uint16_t d_fieldmask;
	uint32_t d_id;
	uint64_t d_blk_hardlimit;
	uint64_t d_blk_softlimit;
	uint64_t d_ino_hardlimit;
	uint64_t d_ino_softlimit;
	uint64_t d_bcount;
	uint64_t d_icount;
	int32_t d_itimer;
	int32_t d_btimer;
	uint16_t d_iwarns;
	uint16_t d_bwarns;
	int32_t d_padding2;
	uint64_t d_rtb_hardlimit;
	uint64_t d_rtb_softlimit;
	uint64_t d_rtbcount;
	int32_t d_rtbtimer;
	uint16_t d_rtbwarns;
	int16_t d_padding3;
	char d_padding4[8];
};
struct linux_fs_qfilestat_t
{
	uint64_t qfs_ino;
	uint64_t qfs_nblks;
	uint32_t qfs_nextents;
};
struct linux_fs_quota_stat_t
{
	int8_t qs_version;
	uint16_t qs_flags;
	int8_t qs_pad;
	struct linux_fs_qfilestat_t qs_uquota;
	struct linux_fs_qfilestat_t qs_gquota;
	uint32_t qs_incoredqs;
	int32_t qs_btimelimit;
	int32_t qs_itimelimit;
	int32_t qs_rtbtimelimit;
	uint16_t qs_bwarnlimit;
	uint16_t qs_iwarnlimit;
};
struct linux_fs_qfilestatv_t
{
	uint64_t qfs_ino;
	uint64_t qfs_nblks;
	uint32_t qfs_nextents;
	uint32_t qfs_pad;
};
struct linux_fs_quota_statv_t
{
	int8_t qs_version;
	uint8_t qs_pad1;
	uint16_t qs_flags;
	uint32_t qs_incoredqs;
	struct linux_fs_qfilestatv_t qs_uquota;
	struct linux_fs_qfilestatv_t qs_gquota;
	struct linux_fs_qfilestatv_t qs_pquota;
	int32_t qs_btimelimit;
	int32_t qs_itimelimit;
	int32_t qs_rtbtimelimit;
	uint16_t qs_bwarnlimit;
	uint16_t qs_iwarnlimit;
	uint64_t qs_pad2[8];
};
struct linux_sigevent_t
{
	union linux_sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union
	{
		int _pad[(64 - (sizeof(int) * 2 + sizeof(union linux_sigval_t))) / sizeof(int)];
		int tid;

		struct
		{
			void (*function)(union linux_sigval_t);
			void* attribute;
		} sigev_thread;
	} sigev_un;
};
struct linux_itimerspec_t
{
	struct linux_timespec_t it_interval;
	struct linux_timespec_t it_value;
};
struct linux_epoll_event_t
{
	uint32_t events;

	// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
	uint32_t data_lo;
	uint32_t data_hi;
	//uint64_t data;
};
struct linux_mq_attr_t
{
	linux_kernel_long_t mq_flags;
	linux_kernel_long_t mq_maxmsg;
	linux_kernel_long_t mq_msgsize;
	linux_kernel_long_t mq_curmsgs;
	linux_kernel_long_t _reserved[4];
};
struct linux_kexec_segment_t
{
	void const* buf;
	size_t bufsz;
	void const* mem;
	size_t memsz;
};
struct linux_keyctl_dh_params_t
{
	int32_t private;
	int32_t prime;
	int32_t base;
};
struct linux_keyctl_kdf_params_t
{
	char* hashname;
	char* otherinfo;
	uint32_t otherinfolen;
	uint32_t _spare[8];
};
struct linux_inotify_event_t
{
	int32_t wd;
	uint32_t mask;
	uint32_t cookie;
	uint32_t len;
	char name[];
};
struct linux_robust_list_t
{
	struct linux_robust_list_t* next;
};
struct linux_robust_list_head_t
{
	struct linux_robust_list_t list;
	long futex_offset;
	struct linux_robust_list_t* list_op_pending;
};
struct linux_signalfd_siginfo_t
{
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint16_t ssi_addr_lsb;
	uint8_t _pad[46];
};
struct linux_perf_event_attr_t
{
	uint32_t type;
	uint32_t size;
	uint64_t config;
	union
	{
		uint64_t sample_period;
		uint64_t sample_freq;
	};
	uint64_t sample_type;
	uint64_t read_format;
	uint64_t disabled                 :  1,
	         inherit                  :  1,
	         pinned                   :  1,
	         exclusive                :  1,
	         exclude_user             :  1,
	         exclude_kernel           :  1,
	         exclude_hv               :  1,
	         exclude_idle             :  1,
	         mmap                     :  1,
	         comm                     :  1,
	         freq                     :  1,
	         inherit_stat             :  1,
	         enable_on_exec           :  1,
	         task                     :  1,
	         watermark                :  1,
	         precise_ip               :  2,
	         mmap_data                :  1,
	         sample_id_all            :  1,
	         exclude_host             :  1,
	         exclude_guest            :  1,
	         exclude_callchain_kernel :  1,
	         exclude_callchain_user   :  1,
	         mmap2                    :  1,
	         comm_exec                :  1,
	         use_clockid              :  1,
	         context_switch           :  1,
	         write_backward           :  1,
	         namespaces               :  1,
	         _reserved1               : 35;
	union
	{
		uint32_t wakeup_events;
		uint32_t wakeup_watermark;
	};
	uint32_t bp_type;
	union
	{
		uint64_t bp_addr;
		uint64_t config1;
	};
	union
	{
		uint64_t bp_len;
		uint64_t config2;
	};
	uint64_t branch_sample_type;
	uint64_t sample_regs_user;
	uint32_t sample_stack_user;
	int32_t clockid;
	uint64_t sample_regs_intr;
	uint32_t aux_watermark;
	uint16_t sample_max_stack;
	uint16_t _reserved2;
};
struct linux_perf_event_mmap_page_t
{
	uint32_t version;
	uint32_t compat_version;
	uint32_t lock;
	uint32_t index;
	int64_t offset;
	uint64_t time_enabled;
	uint64_t time_running;
	union
	{
		uint64_t capabilities;
		struct
		{
			uint64_t cap_bit0               :  1,
			         cap_bit0_is_deprecated :  1,
			         cap_user_rdpmc         :  1,
			         cap_user_time          :  1,
			         cap_user_time_zero     :  1,
			         cap__res               : 59;
		};
	};
	uint16_t pmc_width;
	uint16_t time_shift;
	uint32_t time_mult;
	uint64_t time_offset;
	uint64_t time_zero;
	uint32_t size;
	uint8_t _reserved[118*8+4];
	uint64_t data_head;
	uint64_t data_tail;
	uint64_t data_offset;
	uint64_t data_size;
	uint64_t aux_head;
	uint64_t aux_tail;
	uint64_t aux_offset;
	uint64_t aux_size;
};
struct linux_perf_event_header_t
{
	uint32_t type;
	uint16_t misc;
	uint16_t size;
};
struct linux_perf_ns_link_info_t
{
	uint64_t dev;
	uint64_t ino;
};
union linux_perf_mem_data_src_t
{
	uint64_t val;
	struct
	{
		uint64_t mem_op      : 5,
		         mem_lvl     :14,
		         mem_snoop   : 5,
		         mem_lock    : 2,
		         mem_dtlb    : 7,
		         mem_lvl_num : 4,
		         mem_remote  : 1,
		         mem_snoopx  : 2,
		         mem_rsvd    :24;
	};
};
struct linux_perf_branch_entry_t
{
	uint64_t from;
	uint64_t to;
	uint64_t mispred   :  1,
		 predicted :  1,
		 in_tx     :  1,
		 abort     :  1,
		 cycles    : 16,
		 type      :  4,
		 reserved  : 40;
};
struct linux_mmsghdr_t
{
	struct linux_user_msghdr_t msg_hdr;
	unsigned int msg_len;
	char _pad[4];
};
struct linux_fanotify_event_metadata_t
{
	uint32_t event_len;
	uint8_t vers;
	uint8_t reserved;
	uint16_t metadata_len;
	uint64_t mask;
	int32_t fd;
	int32_t pid;
};
struct linux_fanotify_response_t
{
	int32_t fd;
	uint32_t response;
};
struct linux_rlimit64_t
{
	uint64_t rlim_cur;
	uint64_t rlim_max;
};
struct linux_file_handle_t
{
	uint32_t handle_bytes;
	int handle_type;
	unsigned char f_handle[];
};
struct linux_getcpu_cache_t
{
	unsigned long blob[128 / sizeof(long)];
};
struct linux_kcmp_epoll_slot_t
{
	uint32_t efd;
	uint32_t tfd;
	uint32_t toff;
};
struct linux_seccomp_data_t
{
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};
struct linux_sock_filter_t
{
	uint16_t code;
	uint8_t jt;
	uint8_t jf;
	uint32_t k;
};
struct linux_sock_fprog_t
{
	unsigned short len;
	struct linux_sock_filter_t* filter;
};
struct linux_bpf_insn_t
{
	uint8_t code;
	uint8_t dst_reg: 4;
	uint8_t src_reg: 4;
	int16_t off;
	int32_t imm;
};
struct linux_bpf_lpm_trie_key_t
{
	uint32_t prefixlen;
	uint8_t data[];
};
enum
{
	linux_BPF_OBJ_NAME_LEN = 16,
	linux_BPF_TAG_SIZE     =  8,
};
union linux_bpf_attr_t
{
	alignas(8) struct
	{
		uint32_t map_type;
		uint32_t key_size;
		uint32_t value_size;
		uint32_t max_entries;
		uint32_t map_flags;
		uint32_t inner_map_fd;
		uint32_t numa_node;
		char map_name[linux_BPF_OBJ_NAME_LEN];
		uint32_t map_ifindex;
	};

	struct
	{
		uint32_t map_fd;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t key_lo;
		uint32_t key_hi;
		union
		{
			// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
			uint32_t value_lo;
			uint32_t value_hi;
			// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
			uint32_t next_key_lo;
			uint32_t next_key_hi;
		};
		uint64_t flags;
	};

	struct
	{
		uint32_t prog_type;
		uint32_t insn_cnt;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t insns_lo;
		uint32_t insns_hi;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t license_lo;
		uint32_t license_hi;
		uint32_t log_level;
		uint32_t log_size;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t log_buf_lo;
		uint32_t log_buf_hi;
		uint32_t kern_version;
		uint32_t prog_flags;
		char prog_name[linux_BPF_OBJ_NAME_LEN];
		uint32_t prog_ifindex;
	};

	struct
	{
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t pathname_lo;
		uint32_t pathname_hi;
		uint32_t bpf_fd;
		uint32_t file_flags;
	};

	struct
	{
		uint32_t target_fd;
		uint32_t attach_bpf_fd;
		uint32_t attach_type;
		uint32_t attach_flags;
	};

	struct
	{
		uint32_t prog_fd;
		uint32_t retval;
		uint32_t data_size_in;
		uint32_t data_size_out;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t data_in_lo;
		uint32_t data_in_hi;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t data_out_lo;
		uint32_t data_out_hi;
		uint32_t repeat;
		uint32_t duration;
	} test;

	struct
	{
		union
		{
			uint32_t start_id;
			uint32_t prog_id;
			uint32_t map_id;
		};
		uint32_t next_id;
		uint32_t open_flags;
	};

	struct
	{
		uint32_t bpf_fd;
		uint32_t info_len;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t info_lo;
		uint32_t info_hi;
	} info;

	struct
	{
		uint32_t target_fd;
		uint32_t attach_type;
		uint32_t query_flags;
		uint32_t attach_flags;
		// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
		uint32_t prog_ids_lo;
		uint32_t prog_ids_hi;
		uint32_t prog_cnt;
	} query;
};
struct linux_sk_buff_t
{
	uint32_t len;
	uint32_t pkt_type;
	uint32_t mark;
	uint32_t queue_mapping;
	uint32_t protocol;
	uint32_t vlan_present;
	uint32_t vlan_tci;
	uint32_t vlan_proto;
	uint32_t priority;
	uint32_t ingress_ifindex;
	uint32_t ifindex;
	uint32_t tc_index;
	uint32_t cb[5];
	uint32_t hash;
	uint32_t tc_classid;
	uint32_t data;
	uint32_t data_end;
	uint32_t napi_id;

	uint32_t family;
	uint32_t remote_ip4;
	uint32_t local_ip4;
	uint32_t remote_ip6[4];
	uint32_t local_ip6[4];
	uint32_t remote_port;
	uint32_t local_port;

	uint32_t data_meta;
};
struct linux_bpf_tunnel_key_t
{
	uint32_t tunnel_id;
	union
	{
		uint32_t remote_ipv4;
		uint32_t remote_ipv6[4];
	};
	uint8_t tunnel_tos;
	uint8_t tunnel_ttl;
	uint16_t tunnel_ext;
	uint32_t tunnel_label;
};
struct linux_bpf_sock_t
{
	uint32_t bound_dev_if;
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
	uint32_t mark;
	uint32_t priority;
};
struct linux_xdp_md_t
{
	uint32_t data;
	uint32_t data_end;
	uint32_t data_meta;
	uint32_t ingress_ifindex;
	uint32_t rx_queue_index;
};
struct linux_bpf_prog_info_t
{
	alignas(8) uint32_t type;
	uint32_t id;
	uint8_t tag[linux_BPF_TAG_SIZE];
	uint32_t jited_prog_len;
	uint32_t xlated_prog_len;
	// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
	uint32_t jited_prog_insns_lo;
	uint32_t jited_prog_insns_hi;
	// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
	uint32_t xlated_prog_insns_lo;
	uint32_t xlated_prog_insns_hi;
	uint64_t load_time;
	uint32_t created_by_uid;
	uint32_t nr_map_ids;
	// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
	uint32_t map_ids_lo;
	uint32_t map_ids_hi;
	char name[linux_BPF_OBJ_NAME_LEN];
	uint32_t ifindex;
	uint64_t netns_dev;
	uint64_t netns_ino;
};
struct linux_bpf_map_info_t
{
	alignas(8) uint32_t type;
	uint32_t id;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t map_flags;
	char name[linux_BPF_OBJ_NAME_LEN];
	uint32_t ifindex;
	uint64_t netns_dev;
	uint64_t netns_ino;
};
struct linux_bpf_sock_ops_t
{
	uint32_t op;
	union
	{
		uint32_t args[4];
		uint32_t reply;
		uint32_t replylong[4];
	};
	uint32_t family;
	uint32_t remote_ip4;
	uint32_t local_ip4;
	uint32_t remote_ip6[4];
	uint32_t local_ip6[4];
	uint32_t remote_port;
	uint32_t local_port;
	uint32_t is_fullsock;
	uint32_t snd_cwnd;
	uint32_t srtt_us;
	uint32_t bpf_sock_ops_cb_flags;
	uint32_t state;
	uint32_t rtt_min;
	uint32_t snd_ssthresh;
	uint32_t rcv_nxt;
	uint32_t snd_nxt;
	uint32_t snd_una;
	uint32_t mss_cache;
	uint32_t ecn_flags;
	uint32_t rate_delivered;
	uint32_t rate_interval_us;
	uint32_t packets_out;
	uint32_t retrans_out;
	uint32_t total_retrans;
	uint32_t segs_in;
	uint32_t data_segs_in;
	uint32_t segs_out;
	uint32_t data_segs_out;
	uint32_t lost_out;
	uint32_t sacked_out;
	uint32_t sk_txhash;
	uint64_t bytes_received;
	uint64_t bytes_acked;
};
struct linux_bpf_perf_event_value_t
{
	uint64_t counter;
	uint64_t enabled;
	uint64_t running;
};
struct linux_bpf_cgroup_dev_ctx_t
{
	uint32_t access_type;
	uint32_t major;
	uint32_t minor;
};
struct linux_uffd_msg_t
{
	uint8_t event;

	uint8_t reserved1;
	uint16_t reserved2;
	uint32_t reserved3;

	union
	{
		struct
		{
			uint64_t flags;
			uint64_t address;
			union
			{
				uint32_t ptid;
			} feat;
			char _pad[4];
		} pagefault;

		struct
		{
			uint32_t ufd;
		} fork;

		struct
		{
			uint64_t from;
			uint64_t to;
			uint64_t len;
		} remap;

		struct {
			uint64_t start;
			uint64_t end;
		} remove;

		struct {
			uint64_t reserved1;
			uint64_t reserved2;
			uint64_t reserved3;
		} reserved;
	} arg;
};
struct linux_uffdio_api_t
{
	uint64_t api;
	uint64_t features;
	uint64_t ioctls;
};
struct linux_uffdio_range_t
{
	uint64_t start;
	uint64_t len;
};
struct linux_uffdio_register_t
{
	struct linux_uffdio_range_t range;
	uint64_t mode;
	uint64_t ioctls;
};
struct linux_uffdio_copy_t
{
	uint64_t dst;
	uint64_t src;
	uint64_t len;
	uint64_t mode;
	int64_t copy;
};
struct linux_uffdio_zeropage_t
{
	struct linux_uffdio_range_t range;
	uint64_t mode;
	int64_t zeropage;
};
struct linux_statx_timestamp_t
{
	int64_t tv_sec;
	uint32_t tv_nsec;
	int32_t _reserved;
};
struct linux_statx_t
{
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t _spare0[1];
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	struct linux_statx_timestamp_t stx_atime;
	struct linux_statx_timestamp_t stx_btime;
	struct linux_statx_timestamp_t stx_ctime;
	struct linux_statx_timestamp_t stx_mtime;
	uint32_t stx_rdev_major;
	uint32_t stx_rdev_minor;
	uint32_t stx_dev_major;
	uint32_t stx_dev_minor;
	uint64_t _spare2[14];
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

// *at functions
#define linux_AT_FDCWD ((linux_fd_t)(-100))
enum
{
	linux_AT_SYMLINK_NOFOLLOW = 0x0100,
	linux_AT_REMOVEDIR        = 0x0200,
	linux_AT_SYMLINK_FOLLOW   = 0x0400,
	linux_AT_NO_AUTOMOUNT     = 0x0800,
	linux_AT_EMPTY_PATH       = 0x1000,
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

// waitid
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
#define linux_RLIM_INFINITY   (~0ul)
#define linux_RLIM64_INFINITY (~0ULL)

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

// Scheduling policies
enum
{
	linux_SCHED_NORMAL        = 0,
	linux_SCHED_FIFO          = 1,
	linux_SCHED_RR            = 2,
	linux_SCHED_BATCH         = 3,
	//linux_SCHED_ISO           = 4, // reserved but not implemented yet
	linux_SCHED_IDLE          = 5,
	linux_SCHED_DEADLINE      = 6,

	linux_SCHED_RESET_ON_FORK = 0x40000000,
};

// Flags for mlock
enum
{
	linux_MLOCK_ONFAULT = 0x01,
};

// Flags for mlockall
enum
{
	linux_MCL_CURRENT = 1,
	linux_MCL_FUTURE  = 2,
	linux_MCL_ONFAULT = 4,
};

// sysctl
enum
{
	linux_CTL_MAXNAME = 10,
};
enum // Top-level names
{
	linux_CTL_KERN    =    1,
	linux_CTL_VM      =    2,
	linux_CTL_NET     =    3,
	linux_CTL_PROC    =    4,
	linux_CTL_FS      =    5,
	linux_CTL_DEBUG   =    6,
	linux_CTL_DEV     =    7,
	linux_CTL_BUS     =    8,
	linux_CTL_ABI     =    9,
	linux_CTL_CPU     =   10,
	linux_CTL_ARLAN   =  254,
	linux_CTL_S390DBF = 5677,
	linux_CTL_SUNRPC  = 7249,
	linux_CTL_PM      = 9899,
	linux_CTL_FRV     = 9898,
};
enum // CTL_BUS names
{
	linux_CTL_BUS_ISA = 1,
};
enum // /proc/sys/fs/inotify/
{
	linux_INOTIFY_MAX_USER_INSTANCES = 1,
	linux_INOTIFY_MAX_USER_WATCHES   = 2,
	linux_INOTIFY_MAX_QUEUED_EVENTS  = 3,
};
enum // CTL_KERN names
{
	linux_KERN_OSTYPE                  =  1,
	linux_KERN_OSRELEASE               =  2,
	linux_KERN_OSREV                   =  3,
	linux_KERN_VERSION                 =  4,
	linux_KERN_SECUREMASK              =  5,
	linux_KERN_PROF                    =  6,
	linux_KERN_NODENAME                =  7,
	linux_KERN_DOMAINNAME              =  8,

	linux_KERN_PANIC                   = 15,
	linux_KERN_REALROOTDEV             = 16,

	linux_KERN_SPARC_REBOOT            = 21,
	linux_KERN_CTLALTDEL               = 22,
	linux_KERN_PRINTK                  = 23,
	linux_KERN_NAMETRANS               = 24,
	linux_KERN_PPC_HTABRECLAIM         = 25,
	linux_KERN_PPC_ZEROPAGED           = 26,
	linux_KERN_PPC_POWERSAVE_NAP       = 27,
	linux_KERN_MODPROBE                = 28,
	linux_KERN_SG_BIG_BUFF             = 29,
	linux_KERN_ACCT                    = 30,
	linux_KERN_PPC_L2CR                = 31,

	linux_KERN_RTSIGNR                 = 32,
	linux_KERN_RTSIGMAX                = 33,

	linux_KERN_SHMMAX                  = 34,
	linux_KERN_MSGMAX                  = 35,
	linux_KERN_MSGMNB                  = 36,
	linux_KERN_MSGPOOL                 = 37,
	linux_KERN_SYSRQ                   = 38,
	linux_KERN_MAX_THREADS             = 39,
	linux_KERN_RANDOM                  = 40,
	linux_KERN_SHMALL                  = 41,
	linux_KERN_MSGMNI                  = 42,
	linux_KERN_SEM                     = 43,
	linux_KERN_SPARC_STOP_A            = 44,
	linux_KERN_SHMMNI                  = 45,
	linux_KERN_OVERFLOWUID             = 46,
	linux_KERN_OVERFLOWGID             = 47,
	linux_KERN_SHMPATH                 = 48,
	linux_KERN_HOTPLUG                 = 49,
	linux_KERN_IEEE_EMULATION_WARNINGS = 50,
	linux_KERN_S390_USER_DEBUG_LOGGING = 51,
	linux_KERN_CORE_USES_PID           = 52,
	linux_KERN_TAINTED                 = 53,
	linux_KERN_CADPID                  = 54,
	linux_KERN_PIDMAX                  = 55,
	linux_KERN_CORE_PATTERN            = 56,
	linux_KERN_PANIC_ON_OOPS           = 57,
	linux_KERN_HPPA_PWRSW              = 58,
	linux_KERN_HPPA_UNALIGNED          = 59,
	linux_KERN_PRINTK_RATELIMIT        = 60,
	linux_KERN_PRINTK_RATELIMIT_BURST  = 61,
	linux_KERN_PTY                     = 62,
	linux_KERN_NGROUPS_MAX             = 63,
	linux_KERN_SPARC_SCONS_PWROFF      = 64,
	linux_KERN_HZ_TIMER                = 65,
	linux_KERN_UNKNOWN_NMI_PANIC       = 66,
	linux_KERN_BOOTLOADER_TYPE         = 67,
	linux_KERN_RANDOMIZE               = 68,
	linux_KERN_SETUID_DUMPABLE         = 69,
	linux_KERN_SPIN_RETRY              = 70,
	linux_KERN_ACPI_VIDEO_FLAGS        = 71,
	linux_KERN_IA64_UNALIGNED          = 72,
	linux_KERN_COMPAT_LOG              = 73,
	linux_KERN_MAX_LOCK_DEPTH          = 74,
	linux_KERN_NMI_WATCHDOG            = 75,
	linux_KERN_PANIC_ON_NMI            = 76,
	linux_KERN_PANIC_ON_WARN           = 77,
};
enum // CTL_VM names
{
	linux_VM_UNUSED1                  =  1,
	linux_VM_UNUSED2                  =  2,
	linux_VM_UNUSED3                  =  3,
	linux_VM_UNUSED4                  =  4,
	linux_VM_OVERCOMMIT_MEMORY        =  5,
	linux_VM_UNUSED5                  =  6,
	linux_VM_UNUSED7                  =  7,
	linux_VM_UNUSED8                  =  8,
	linux_VM_UNUSED9                  =  9,
	linux_VM_PAGE_CLUSTER             = 10,
	linux_VM_DIRTY_BACKGROUND         = 11,
	linux_VM_DIRTY_RATIO              = 12,
	linux_VM_DIRTY_WB_CS              = 13,
	linux_VM_DIRTY_EXPIRE_CS          = 14,
	linux_VM_NR_PDFLUSH_THREADS       = 15,
	linux_VM_OVERCOMMIT_RATIO         = 16,
	linux_VM_PAGEBUF                  = 17,
	linux_VM_HUGETLB_PAGES            = 18,
	linux_VM_SWAPPINESS               = 19,
	linux_VM_LOWMEM_RESERVE_RATIO     = 20,
	linux_VM_MIN_FREE_KBYTES          = 21,
	linux_VM_MAX_MAP_COUNT            = 22,
	linux_VM_LAPTOP_MODE              = 23,
	linux_VM_BLOCK_DUMP               = 24,
	linux_VM_HUGETLB_GROUP            = 25,
	linux_VM_VFS_CACHE_PRESSURE       = 26,
	linux_VM_LEGACY_VA_LAYOUT         = 27,
	linux_VM_SWAP_TOKEN_TIMEOUT       = 28,
	linux_VM_DROP_PAGECACHE           = 29,
	linux_VM_PERCPU_PAGELIST_FRACTION = 30,
	linux_VM_ZONE_RECLAIM_MODE        = 31,
	linux_VM_MIN_UNMAPPED             = 32,
	linux_VM_PANIC_ON_OOM             = 33,
	linux_VM_VDSO_ENABLED             = 34,
	linux_VM_MIN_SLAB                 = 35,
};
enum // CTL_NET names
{
	linux_NET_CORE      =   1,
	linux_NET_ETHER     =   2,
	linux_NET_802       =   3,
	linux_NET_UNIX      =   4,
	linux_NET_IPV4      =   5,
	linux_NET_IPX       =   6,
	linux_NET_ATALK     =   7,
	linux_NET_NETROM    =   8,
	linux_NET_AX25      =   9,
	linux_NET_BRIDGE    =  10,
	linux_NET_ROSE      =  11,
	linux_NET_IPV6      =  12,
	linux_NET_X25       =  13,
	linux_NET_TR        =  14,
	linux_NET_DECNET    =  15,
	linux_NET_ECONET    =  16,
	linux_NET_SCTP      =  17,
	linux_NET_LLC       =  18,
	linux_NET_NETFILTER =  19,
	linux_NET_DCCP      =  20,
	linux_NET_IRDA      = 412,
};
enum // /proc/sys/kernel/random
{
	linux_RANDOM_POOLSIZE      = 1,
	linux_RANDOM_ENTROPY_COUNT = 2,
	linux_RANDOM_READ_THRESH   = 3,
	linux_RANDOM_WRITE_THRESH  = 4,
	linux_RANDOM_BOOT_ID       = 5,
	linux_RANDOM_UUID          = 6,
};
enum // /proc/sys/kernel/pty
{
	linux_PTY_MAX = 1,
	linux_PTY_NR  = 2,
};
enum // /proc/sys/bus/isa
{
	linux_BUS_ISA_MEM_BASE   = 1,
	linux_BUS_ISA_PORT_BASE  = 2,
	linux_BUS_ISA_PORT_SHIFT = 3,
};
enum // /proc/sys/net/core
{
	linux_NET_CORE_WMEM_MAX        =  1,
	linux_NET_CORE_RMEM_MAX        =  2,
	linux_NET_CORE_WMEM_DEFAULT    =  3,
	linux_NET_CORE_RMEM_DEFAULT    =  4,
	//linux_NET_CORE_DESTROY_DELAY
	linux_NET_CORE_MAX_BACKLOG     =  6,
	linux_NET_CORE_FASTROUTE       =  7,
	linux_NET_CORE_MSG_COST        =  8,
	linux_NET_CORE_MSG_BURST       =  9,
	linux_NET_CORE_OPTMEM_MAX      = 10,
	linux_NET_CORE_HOT_LIST_LENGTH = 11,
	linux_NET_CORE_DIVERT_VERSION  = 12,
	linux_NET_CORE_NO_CONG_THRESH  = 13,
	linux_NET_CORE_NO_CONG         = 14,
	linux_NET_CORE_LO_CONG         = 15,
	linux_NET_CORE_MOD_CONG        = 16,
	linux_NET_CORE_DEV_WEIGHT      = 17,
	linux_NET_CORE_SOMAXCONN       = 18,
	linux_NET_CORE_BUDGET          = 19,
	linux_NET_CORE_AEVENT_ETIME    = 20,
	linux_NET_CORE_AEVENT_RSEQTH   = 21,
	linux_NET_CORE_WARNINGS        = 22,
};
enum // /proc/sys/net/unix
{
	linux_NET_UNIX_DESTROY_DELAY  = 1,
	linux_NET_UNIX_DELETE_DELAY   = 2,
	linux_NET_UNIX_MAX_DGRAM_QLEN = 3,
};
enum // /proc/sys/net/netfilter
{
	linux_NET_NF_CONNTRACK_MAX                            =  1,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT           =  2,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV           =  3,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED        =  4,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT           =  5,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT         =  6,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK           =  7,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT          =  8,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE              =  9,
	linux_NET_NF_CONNTRACK_UDP_TIMEOUT                    = 10,
	linux_NET_NF_CONNTRACK_UDP_TIMEOUT_STREAM             = 11,
	linux_NET_NF_CONNTRACK_ICMP_TIMEOUT                   = 12,
	linux_NET_NF_CONNTRACK_GENERIC_TIMEOUT                = 13,
	linux_NET_NF_CONNTRACK_BUCKETS                        = 14,
	linux_NET_NF_CONNTRACK_LOG_INVALID                    = 15,
	linux_NET_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS        = 16,
	linux_NET_NF_CONNTRACK_TCP_LOOSE                      = 17,
	linux_NET_NF_CONNTRACK_TCP_BE_LIBERAL                 = 18,
	linux_NET_NF_CONNTRACK_TCP_MAX_RETRANS                = 19,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED            = 20,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT       = 21,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED     = 22,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED       = 23,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT     = 24,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD     = 25,
	linux_NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT = 26,
	linux_NET_NF_CONNTRACK_COUNT                          = 27,
	linux_NET_NF_CONNTRACK_ICMPV6_TIMEOUT                 = 28,
	linux_NET_NF_CONNTRACK_FRAG6_TIMEOUT                  = 29,
	linux_NET_NF_CONNTRACK_FRAG6_LOW_THRESH               = 30,
	linux_NET_NF_CONNTRACK_FRAG6_HIGH_THRESH              = 31,
	linux_NET_NF_CONNTRACK_CHECKSUM                       = 32,
};
enum // /proc/sys/net/ipv4
{
	linux_NET_IPV4_FORWARD                           =  8,
	linux_NET_IPV4_DYNADDR                           =  9,

	linux_NET_IPV4_CONF                              = 16,
	linux_NET_IPV4_NEIGH                             = 17,
	linux_NET_IPV4_ROUTE                             = 18,
	linux_NET_IPV4_FIB_HASH                          = 19,
	linux_NET_IPV4_NETFILTER                         = 20,

	linux_NET_IPV4_TCP_TIMESTAMPS                    = 33,
	linux_NET_IPV4_TCP_WINDOW_SCALING                = 34,
	linux_NET_IPV4_TCP_SACK                          = 35,
	linux_NET_IPV4_TCP_RETRANS_COLLAPSE              = 36,
	linux_NET_IPV4_DEFAULT_TTL                       = 37,
	linux_NET_IPV4_AUTOCONFIG                        = 38,
	linux_NET_IPV4_NO_PMTU_DISC                      = 39,
	linux_NET_IPV4_TCP_SYN_RETRIES                   = 40,
	linux_NET_IPV4_IPFRAG_HIGH_THRESH                = 41,
	linux_NET_IPV4_IPFRAG_LOW_THRESH                 = 42,
	linux_NET_IPV4_IPFRAG_TIME                       = 43,
	linux_NET_IPV4_TCP_MAX_KA_PROBES                 = 44,
	linux_NET_IPV4_TCP_KEEPALIVE_TIME                = 45,
	linux_NET_IPV4_TCP_KEEPALIVE_PROBES              = 46,
	linux_NET_IPV4_TCP_RETRIES1                      = 47,
	linux_NET_IPV4_TCP_RETRIES2                      = 48,
	linux_NET_IPV4_TCP_FIN_TIMEOUT                   = 49,
	linux_NET_IPV4_IP_MASQ_DEBUG                     = 50,
	linux_NET_TCP_SYNCOOKIES                         = 51,
	linux_NET_TCP_STDURG                             = 52,
	linux_NET_TCP_RFC1337                            = 53,
	linux_NET_TCP_SYN_TAILDROP                       = 54,
	linux_NET_TCP_MAX_SYN_BACKLOG                    = 55,
	linux_NET_IPV4_LOCAL_PORT_RANGE                  = 56,
	linux_NET_IPV4_ICMP_ECHO_IGNORE_ALL              = 57,
	linux_NET_IPV4_ICMP_ECHO_IGNORE_BROADCASTS       = 58,
	linux_NET_IPV4_ICMP_SOURCEQUENCH_RATE            = 59,
	linux_NET_IPV4_ICMP_DESTUNREACH_RATE             = 60,
	linux_NET_IPV4_ICMP_TIMEEXCEED_RATE              = 61,
	linux_NET_IPV4_ICMP_PARAMPROB_RATE               = 62,
	linux_NET_IPV4_ICMP_ECHOREPLY_RATE               = 63,
	linux_NET_IPV4_ICMP_IGNORE_BOGUS_ERROR_RESPONSES = 64,
	linux_NET_IPV4_IGMP_MAX_MEMBERSHIPS              = 65,
	linux_NET_TCP_TW_RECYCLE                         = 66,
	linux_NET_IPV4_ALWAYS_DEFRAG                     = 67,
	linux_NET_IPV4_TCP_KEEPALIVE_INTVL               = 68,
	linux_NET_IPV4_INET_PEER_THRESHOLD               = 69,
	linux_NET_IPV4_INET_PEER_MINTTL                  = 70,
	linux_NET_IPV4_INET_PEER_MAXTTL                  = 71,
	linux_NET_IPV4_INET_PEER_GC_MINTIME              = 72,
	linux_NET_IPV4_INET_PEER_GC_MAXTIME              = 73,
	linux_NET_TCP_ORPHAN_RETRIES                     = 74,
	linux_NET_TCP_ABORT_ON_OVERFLOW                  = 75,
	linux_NET_TCP_SYNACK_RETRIES                     = 76,
	linux_NET_TCP_MAX_ORPHANS                        = 77,
	linux_NET_TCP_MAX_TW_BUCKETS                     = 78,
	linux_NET_TCP_FACK                               = 79,
	linux_NET_TCP_REORDERING                         = 80,
	linux_NET_TCP_ECN                                = 81,
	linux_NET_TCP_DSACK                              = 82,
	linux_NET_TCP_MEM                                = 83,
	linux_NET_TCP_WMEM                               = 84,
	linux_NET_TCP_RMEM                               = 85,
	linux_NET_TCP_APP_WIN                            = 86,
	linux_NET_TCP_ADV_WIN_SCALE                      = 87,
	linux_NET_IPV4_NONLOCAL_BIND                     = 88,
	linux_NET_IPV4_ICMP_RATELIMIT                    = 89,
	linux_NET_IPV4_ICMP_RATEMASK                     = 90,
	linux_NET_TCP_TW_REUSE                           = 91,
	linux_NET_TCP_FRTO                               = 92,
	linux_NET_TCP_LOW_LATENCY                        = 93,
	linux_NET_IPV4_IPFRAG_SECRET_INTERVAL            = 94,
	linux_NET_IPV4_IGMP_MAX_MSF                      = 96,
	linux_NET_TCP_NO_METRICS_SAVE                    = 97,
	linux_NET_TCP_DEFAULT_WIN_SCALE                  = 105,
	linux_NET_TCP_MODERATE_RCVBUF                    = 106,
	linux_NET_TCP_TSO_WIN_DIVISOR                    = 107,
	linux_NET_TCP_BIC_BETA                           = 108,
	linux_NET_IPV4_ICMP_ERRORS_USE_INBOUND_IFADDR    = 109,
	linux_NET_TCP_CONG_CONTROL                       = 110,
	linux_NET_TCP_ABC                                = 111,
	linux_NET_IPV4_IPFRAG_MAX_DIST                   = 112,
	linux_NET_TCP_MTU_PROBING                        = 113,
	linux_NET_TCP_BASE_MSS                           = 114,
	linux_NET_IPV4_TCP_WORKAROUND_SIGNED_WINDOWS     = 115,
	linux_NET_TCP_DMA_COPYBREAK                      = 116,
	linux_NET_TCP_SLOW_START_AFTER_IDLE              = 117,
	linux_NET_CIPSOV4_CACHE_ENABLE                   = 118,
	linux_NET_CIPSOV4_CACHE_BUCKET_SIZE              = 119,
	linux_NET_CIPSOV4_RBM_OPTFMT                     = 120,
	linux_NET_CIPSOV4_RBM_STRICTVALID                = 121,
	linux_NET_TCP_AVAIL_CONG_CONTROL                 = 122,
	linux_NET_TCP_ALLOWED_CONG_CONTROL               = 123,
	linux_NET_TCP_MAX_SSTHRESH                       = 124,
	linux_NET_TCP_FRTO_RESPONSE                      = 125,
};
enum
{
	linux_NET_IPV4_ROUTE_FLUSH              =  1,
	linux_NET_IPV4_ROUTE_MIN_DELAY          =  2,
	linux_NET_IPV4_ROUTE_MAX_DELAY          =  3,
	linux_NET_IPV4_ROUTE_GC_THRESH          =  4,
	linux_NET_IPV4_ROUTE_MAX_SIZE           =  5,
	linux_NET_IPV4_ROUTE_GC_MIN_INTERVAL    =  6,
	linux_NET_IPV4_ROUTE_GC_TIMEOUT         =  7,
	linux_NET_IPV4_ROUTE_GC_INTERVAL        =  8,
	linux_NET_IPV4_ROUTE_REDIRECT_LOAD      =  9,
	linux_NET_IPV4_ROUTE_REDIRECT_NUMBER    = 10,
	linux_NET_IPV4_ROUTE_REDIRECT_SILENCE   = 11,
	linux_NET_IPV4_ROUTE_ERROR_COST         = 12,
	linux_NET_IPV4_ROUTE_ERROR_BURST        = 13,
	linux_NET_IPV4_ROUTE_GC_ELASTICITY      = 14,
	linux_NET_IPV4_ROUTE_MTU_EXPIRES        = 15,
	linux_NET_IPV4_ROUTE_MIN_PMTU           = 16,
	linux_NET_IPV4_ROUTE_MIN_ADVMSS         = 17,
	linux_NET_IPV4_ROUTE_SECRET_INTERVAL    = 18,
	linux_NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS = 19,
};
enum
{
	linux_NET_PROTO_CONF_ALL     = -2,
	linux_NET_PROTO_CONF_DEFAULT = -3,
};
enum
{
	linux_NET_IPV4_CONF_FORWARDING          =  1,
	linux_NET_IPV4_CONF_MC_FORWARDING       =  2,
	linux_NET_IPV4_CONF_PROXY_ARP           =  3,
	linux_NET_IPV4_CONF_ACCEPT_REDIRECTS    =  4,
	linux_NET_IPV4_CONF_SECURE_REDIRECTS    =  5,
	linux_NET_IPV4_CONF_SEND_REDIRECTS      =  6,
	linux_NET_IPV4_CONF_SHARED_MEDIA        =  7,
	linux_NET_IPV4_CONF_RP_FILTER           =  8,
	linux_NET_IPV4_CONF_ACCEPT_SOURCE_ROUTE =  9,
	linux_NET_IPV4_CONF_BOOTP_RELAY         = 10,
	linux_NET_IPV4_CONF_LOG_MARTIANS        = 11,
	linux_NET_IPV4_CONF_TAG                 = 12,
	linux_NET_IPV4_CONF_ARPFILTER           = 13,
	linux_NET_IPV4_CONF_MEDIUM_ID           = 14,
	linux_NET_IPV4_CONF_NOXFRM              = 15,
	linux_NET_IPV4_CONF_NOPOLICY            = 16,
	linux_NET_IPV4_CONF_FORCE_IGMP_VERSION  = 17,
	linux_NET_IPV4_CONF_ARP_ANNOUNCE        = 18,
	linux_NET_IPV4_CONF_ARP_IGNORE          = 19,
	linux_NET_IPV4_CONF_PROMOTE_SECONDARIES = 20,
	linux_NET_IPV4_CONF_ARP_ACCEPT          = 21,
	linux_NET_IPV4_CONF_ARP_NOTIFY          = 22,
};
enum // /proc/sys/net/ipv4/netfilter
{
	linux_NET_IPV4_NF_CONNTRACK_MAX                            =  1,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT           =  2,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV           =  3,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED        =  4,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT           =  5,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT         =  6,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK           =  7,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT          =  8,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE              =  9,
	linux_NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT                    = 10,
	linux_NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT_STREAM             = 11,
	linux_NET_IPV4_NF_CONNTRACK_ICMP_TIMEOUT                   = 12,
	linux_NET_IPV4_NF_CONNTRACK_GENERIC_TIMEOUT                = 13,
	linux_NET_IPV4_NF_CONNTRACK_BUCKETS                        = 14,
	linux_NET_IPV4_NF_CONNTRACK_LOG_INVALID                    = 15,
	linux_NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS        = 16,
	linux_NET_IPV4_NF_CONNTRACK_TCP_LOOSE                      = 17,
	linux_NET_IPV4_NF_CONNTRACK_TCP_BE_LIBERAL                 = 18,
	linux_NET_IPV4_NF_CONNTRACK_TCP_MAX_RETRANS                = 19,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED            = 20,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT       = 21,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED     = 22,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED       = 23,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT     = 24,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD     = 25,
	linux_NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT = 26,
	linux_NET_IPV4_NF_CONNTRACK_COUNT                          = 27,
	linux_NET_IPV4_NF_CONNTRACK_CHECKSUM                       = 28,
};
enum // /proc/sys/net/ipv6
{
	linux_NET_IPV6_CONF                    = 16,
	linux_NET_IPV6_NEIGH                   = 17,
	linux_NET_IPV6_ROUTE                   = 18,
	linux_NET_IPV6_ICMP                    = 19,
	linux_NET_IPV6_BINDV6ONLY              = 20,
	linux_NET_IPV6_IP6FRAG_HIGH_THRESH     = 21,
	linux_NET_IPV6_IP6FRAG_LOW_THRESH      = 22,
	linux_NET_IPV6_IP6FRAG_TIME            = 23,
	linux_NET_IPV6_IP6FRAG_SECRET_INTERVAL = 24,
	linux_NET_IPV6_MLD_MAX_MSF             = 25,
};
enum
{
	linux_NET_IPV6_ROUTE_FLUSH              =  1,
	linux_NET_IPV6_ROUTE_GC_THRESH          =  2,
	linux_NET_IPV6_ROUTE_MAX_SIZE           =  3,
	linux_NET_IPV6_ROUTE_GC_MIN_INTERVAL    =  4,
	linux_NET_IPV6_ROUTE_GC_TIMEOUT         =  5,
	linux_NET_IPV6_ROUTE_GC_INTERVAL        =  6,
	linux_NET_IPV6_ROUTE_GC_ELASTICITY      =  7,
	linux_NET_IPV6_ROUTE_MTU_EXPIRES        =  8,
	linux_NET_IPV6_ROUTE_MIN_ADVMSS         =  9,
	linux_NET_IPV6_ROUTE_GC_MIN_INTERVAL_MS = 10,
};
enum
{
	linux_NET_IPV6_FORWARDING                 =  1,
	linux_NET_IPV6_HOP_LIMIT                  =  2,
	linux_NET_IPV6_MTU                        =  3,
	linux_NET_IPV6_ACCEPT_RA                  =  4,
	linux_NET_IPV6_ACCEPT_REDIRECTS           =  5,
	linux_NET_IPV6_AUTOCONF                   =  6,
	linux_NET_IPV6_DAD_TRANSMITS              =  7,
	linux_NET_IPV6_RTR_SOLICITS               =  8,
	linux_NET_IPV6_RTR_SOLICIT_INTERVAL       =  9,
	linux_NET_IPV6_RTR_SOLICIT_DELAY          = 10,
	linux_NET_IPV6_USE_TEMPADDR               = 11,
	linux_NET_IPV6_TEMP_VALID_LFT             = 12,
	linux_NET_IPV6_TEMP_PREFERED_LFT          = 13,
	linux_NET_IPV6_REGEN_MAX_RETRY            = 14,
	linux_NET_IPV6_MAX_DESYNC_FACTOR          = 15,
	linux_NET_IPV6_MAX_ADDRESSES              = 16,
	linux_NET_IPV6_FORCE_MLD_VERSION          = 17,
	linux_NET_IPV6_ACCEPT_RA_DEFRTR           = 18,
	linux_NET_IPV6_ACCEPT_RA_PINFO            = 19,
	linux_NET_IPV6_ACCEPT_RA_RTR_PREF         = 20,
	linux_NET_IPV6_RTR_PROBE_INTERVAL         = 21,
	linux_NET_IPV6_ACCEPT_RA_RT_INFO_MAX_PLEN = 22,
	linux_NET_IPV6_PROXY_NDP                  = 23,
	linux_NET_IPV6_ACCEPT_SOURCE_ROUTE        = 25,
	linux_NET_IPV6_ACCEPT_RA_FROM_LOCAL       = 26,
	linux_NET_IPV6_ACCEPT_RA_RT_INFO_MIN_PLEN = 27,
};
enum // /proc/sys/net/ipv6/icmp
{
	linux_NET_IPV6_ICMP_RATELIMIT = 1,
};
enum // /proc/sys/net/<protocol>/neigh/<dev>
{
	linux_NET_NEIGH_MCAST_SOLICIT     =  1,
	linux_NET_NEIGH_UCAST_SOLICIT     =  2,
	linux_NET_NEIGH_APP_SOLICIT       =  3,
	linux_NET_NEIGH_RETRANS_TIME      =  4,
	linux_NET_NEIGH_REACHABLE_TIME    =  5,
	linux_NET_NEIGH_DELAY_PROBE_TIME  =  6,
	linux_NET_NEIGH_GC_STALE_TIME     =  7,
	linux_NET_NEIGH_UNRES_QLEN        =  8,
	linux_NET_NEIGH_PROXY_QLEN        =  9,
	linux_NET_NEIGH_ANYCAST_DELAY     = 10,
	linux_NET_NEIGH_PROXY_DELAY       = 11,
	linux_NET_NEIGH_LOCKTIME          = 12,
	linux_NET_NEIGH_GC_INTERVAL       = 13,
	linux_NET_NEIGH_GC_THRESH1        = 14,
	linux_NET_NEIGH_GC_THRESH2        = 15,
	linux_NET_NEIGH_GC_THRESH3        = 16,
	linux_NET_NEIGH_RETRANS_TIME_MS   = 17,
	linux_NET_NEIGH_REACHABLE_TIME_MS = 18,
};
enum // /proc/sys/net/dccp
{
	linux_NET_DCCP_DEFAULT = 1,
};
enum // /proc/sys/net/ipx
{
	linux_NET_IPX_PPROP_BROADCASTING = 1,
	linux_NET_IPX_FORWARDING         = 2,
};
enum // /proc/sys/net/llc
{
	linux_NET_LLC2        = 1,
	linux_NET_LLC_STATION = 2,
};
enum // /proc/sys/net/llc/llc2
{
	linux_NET_LLC2_TIMEOUT = 1,
};
enum // /proc/sys/net/llc/station
{
	linux_NET_LLC_STATION_ACK_TIMEOUT = 1,
};
enum // /proc/sys/net/llc/llc2/timeout
{
	linux_NET_LLC2_ACK_TIMEOUT  = 1,
	linux_NET_LLC2_P_TIMEOUT    = 2,
	linux_NET_LLC2_REJ_TIMEOUT  = 3,
	linux_NET_LLC2_BUSY_TIMEOUT = 4,
};
enum // /proc/sys/net/appletalk
{
	linux_NET_ATALK_AARP_EXPIRY_TIME      = 1,
	linux_NET_ATALK_AARP_TICK_TIME        = 2,
	linux_NET_ATALK_AARP_RETRANSMIT_LIMIT = 3,
	linux_NET_ATALK_AARP_RESOLVE_TIME     = 4,
};
enum // /proc/sys/net/netrom
{
	linux_NET_NETROM_DEFAULT_PATH_QUALITY            =  1,
	linux_NET_NETROM_OBSOLESCENCE_COUNT_INITIALISER  =  2,
	linux_NET_NETROM_NETWORK_TTL_INITIALISER         =  3,
	linux_NET_NETROM_TRANSPORT_TIMEOUT               =  4,
	linux_NET_NETROM_TRANSPORT_MAXIMUM_TRIES         =  5,
	linux_NET_NETROM_TRANSPORT_ACKNOWLEDGE_DELAY     =  6,
	linux_NET_NETROM_TRANSPORT_BUSY_DELAY            =  7,
	linux_NET_NETROM_TRANSPORT_REQUESTED_WINDOW_SIZE =  8,
	linux_NET_NETROM_TRANSPORT_NO_ACTIVITY_TIMEOUT   =  9,
	linux_NET_NETROM_ROUTING_CONTROL                 = 10,
	linux_NET_NETROM_LINK_FAILS_COUNT                = 11,
	linux_NET_NETROM_RESET                           = 12,
};
enum // /proc/sys/net/ax25
{
	linux_NET_AX25_IP_DEFAULT_MODE    =  1,
	linux_NET_AX25_DEFAULT_MODE       =  2,
	linux_NET_AX25_BACKOFF_TYPE       =  3,
	linux_NET_AX25_CONNECT_MODE       =  4,
	linux_NET_AX25_STANDARD_WINDOW    =  5,
	linux_NET_AX25_EXTENDED_WINDOW    =  6,
	linux_NET_AX25_T1_TIMEOUT         =  7,
	linux_NET_AX25_T2_TIMEOUT         =  8,
	linux_NET_AX25_T3_TIMEOUT         =  9,
	linux_NET_AX25_IDLE_TIMEOUT       = 10,
	linux_NET_AX25_N2                 = 11,
	linux_NET_AX25_PACLEN             = 12,
	linux_NET_AX25_PROTOCOL           = 13,
	linux_NET_AX25_DAMA_SLAVE_TIMEOUT = 14
};
enum // /proc/sys/net/rose
{
	linux_NET_ROSE_RESTART_REQUEST_TIMEOUT =  1,
	linux_NET_ROSE_CALL_REQUEST_TIMEOUT    =  2,
	linux_NET_ROSE_RESET_REQUEST_TIMEOUT   =  3,
	linux_NET_ROSE_CLEAR_REQUEST_TIMEOUT   =  4,
	linux_NET_ROSE_ACK_HOLD_BACK_TIMEOUT   =  5,
	linux_NET_ROSE_ROUTING_CONTROL         =  6,
	linux_NET_ROSE_LINK_FAIL_TIMEOUT       =  7,
	linux_NET_ROSE_MAX_VCS                 =  8,
	linux_NET_ROSE_WINDOW_SIZE             =  9,
	linux_NET_ROSE_NO_ACTIVITY_TIMEOUT     = 10
};
enum // /proc/sys/net/x25
{
	linux_NET_X25_RESTART_REQUEST_TIMEOUT = 1,
	linux_NET_X25_CALL_REQUEST_TIMEOUT    = 2,
	linux_NET_X25_RESET_REQUEST_TIMEOUT   = 3,
	linux_NET_X25_CLEAR_REQUEST_TIMEOUT   = 4,
	linux_NET_X25_ACK_HOLD_BACK_TIMEOUT   = 5,
	linux_NET_X25_FORWARD                 = 6,
};
enum // /proc/sys/net/token-ring
{
	linux_NET_TR_RIF_TIMEOUT = 1,
};
enum // /proc/sys/net/decnet/
{
	linux_NET_DECNET_NODE_TYPE       =   1,
	linux_NET_DECNET_NODE_ADDRESS    =   2,
	linux_NET_DECNET_NODE_NAME       =   3,
	linux_NET_DECNET_DEFAULT_DEVICE  =   4,
	linux_NET_DECNET_TIME_WAIT       =   5,
	linux_NET_DECNET_DN_COUNT        =   6,
	linux_NET_DECNET_DI_COUNT        =   7,
	linux_NET_DECNET_DR_COUNT        =   8,
	linux_NET_DECNET_DST_GC_INTERVAL =   9,
	linux_NET_DECNET_CONF            =  10,
	linux_NET_DECNET_NO_FC_MAX_CWND  =  11,
	linux_NET_DECNET_MEM             =  12,
	linux_NET_DECNET_RMEM            =  13,
	linux_NET_DECNET_WMEM            =  14,
	linux_NET_DECNET_DEBUG_LEVEL     = 255,
};
enum // /proc/sys/net/decnet/conf/<dev>
{
	linux_NET_DECNET_CONF_LOOPBACK = -2,
	linux_NET_DECNET_CONF_DDCMP    = -3,
	linux_NET_DECNET_CONF_PPP      = -4,
	linux_NET_DECNET_CONF_X25      = -5,
	linux_NET_DECNET_CONF_GRE      = -6,
	linux_NET_DECNET_CONF_ETHER    = -7,
};
enum // /proc/sys/net/decnet/conf/<dev>/
{
	linux_NET_DECNET_CONF_DEV_PRIORITY   = 1,
	linux_NET_DECNET_CONF_DEV_T1         = 2,
	linux_NET_DECNET_CONF_DEV_T2         = 3,
	linux_NET_DECNET_CONF_DEV_T3         = 4,
	linux_NET_DECNET_CONF_DEV_FORWARDING = 5,
	linux_NET_DECNET_CONF_DEV_BLKSIZE    = 6,
	linux_NET_DECNET_CONF_DEV_STATE      = 7,
};
enum // /proc/sys/net/sctp
{
	linux_NET_SCTP_RTO_INITIAL             =  1,
	linux_NET_SCTP_RTO_MIN                 =  2,
	linux_NET_SCTP_RTO_MAX                 =  3,
	linux_NET_SCTP_RTO_ALPHA               =  4,
	linux_NET_SCTP_RTO_BETA                =  5,
	linux_NET_SCTP_VALID_COOKIE_LIFE       =  6,
	linux_NET_SCTP_ASSOCIATION_MAX_RETRANS =  7,
	linux_NET_SCTP_PATH_MAX_RETRANS        =  8,
	linux_NET_SCTP_MAX_INIT_RETRANSMITS    =  9,
	linux_NET_SCTP_HB_INTERVAL             = 10,
	linux_NET_SCTP_PRESERVE_ENABLE         = 11,
	linux_NET_SCTP_MAX_BURST               = 12,
	linux_NET_SCTP_ADDIP_ENABLE		 = 13,
	linux_NET_SCTP_PRSCTP_ENABLE		 = 14,
	linux_NET_SCTP_SNDBUF_POLICY		 = 15,
	linux_NET_SCTP_SACK_TIMEOUT		 = 16,
	linux_NET_SCTP_RCVBUF_POLICY		 = 17,
};
enum // /proc/sys/net/bridge
{
	linux_NET_BRIDGE_NF_CALL_ARPTABLES      = 1,
	linux_NET_BRIDGE_NF_CALL_IPTABLES       = 2,
	linux_NET_BRIDGE_NF_CALL_IP6TABLES      = 3,
	linux_NET_BRIDGE_NF_FILTER_VLAN_TAGGED  = 4,
	linux_NET_BRIDGE_NF_FILTER_PPPOE_TAGGED = 5,
};
enum // proc/sys/net/irda
{
	linux_NET_IRDA_DISCOVERY          =  1,
	linux_NET_IRDA_DEVNAME            =  2,
	linux_NET_IRDA_DEBUG              =  3,
	linux_NET_IRDA_FAST_POLL          =  4,
	linux_NET_IRDA_DISCOVERY_SLOTS    =  5,
	linux_NET_IRDA_DISCOVERY_TIMEOUT  =  6,
	linux_NET_IRDA_SLOT_TIMEOUT       =  7,
	linux_NET_IRDA_MAX_BAUD_RATE      =  8,
	linux_NET_IRDA_MIN_TX_TURN_TIME   =  9,
	linux_NET_IRDA_MAX_TX_DATA_SIZE   = 10,
	linux_NET_IRDA_MAX_TX_WINDOW      = 11,
	linux_NET_IRDA_MAX_NOREPLY_TIME   = 12,
	linux_NET_IRDA_WARN_NOREPLY_TIME  = 13,
	linux_NET_IRDA_LAP_KEEPALIVE_TIME = 14,
};
enum // CTL_FS names
{
	linux_FS_NRINODE     =   1,
	linux_FS_STATINODE   =   2,
	linux_FS_MAXINODE    =   3,
	linux_FS_NRDQUOT     =   4,
	linux_FS_MAXDQUOT    =   5,
	linux_FS_NRFILE      =   6,
	linux_FS_MAXFILE     =   7,
	linux_FS_DENTRY      =   8,
	linux_FS_NRSUPER     =   9,
	linux_FS_MAXSUPER    =  10,
	linux_FS_OVERFLOWUID =  11,
	linux_FS_OVERFLOWGID =  12,
	linux_FS_LEASES      =  13,
	linux_FS_DIR_NOTIFY  =  14,
	linux_FS_LEASE_TIME  =  15,
	linux_FS_DQSTATS     =  16,
	linux_FS_XFS         =  17,
	linux_FS_AIO_NR      =  18,
	linux_FS_AIO_MAX_NR  =  19,
	linux_FS_INOTIFY     =  20,
	linux_FS_OCFS2       = 988,
};
enum // /proc/sys/fs/quota/
{
	linux_FS_DQ_LOOKUPS    = 1,
	linux_FS_DQ_DROPS      = 2,
	linux_FS_DQ_READS      = 3,
	linux_FS_DQ_WRITES     = 4,
	linux_FS_DQ_CACHE_HITS = 5,
	linux_FS_DQ_ALLOCATED  = 6,
	linux_FS_DQ_FREE       = 7,
	linux_FS_DQ_SYNCS      = 8,
	linux_FS_DQ_WARNINGS   = 9,
};
enum // CTL_DEV names
{
	linux_DEV_CDROM   = 1,
	linux_DEV_HWMON   = 2,
	linux_DEV_PARPORT = 3,
	linux_DEV_RAID    = 4,
	linux_DEV_MAC_HID = 5,
	linux_DEV_SCSI    = 6,
	linux_DEV_IPMI    = 7,
};
enum // /proc/sys/dev/cdrom
{
	linux_DEV_CDROM_INFO        = 1,
	linux_DEV_CDROM_AUTOCLOSE   = 2,
	linux_DEV_CDROM_AUTOEJECT   = 3,
	linux_DEV_CDROM_DEBUG       = 4,
	linux_DEV_CDROM_LOCK        = 5,
	linux_DEV_CDROM_CHECK_MEDIA = 6,
};
enum // /proc/sys/dev/parport
{
	linux_DEV_PARPORT_DEFAULT = -3,
};
enum // /proc/sys/dev/raid
{
	linux_DEV_RAID_SPEED_LIMIT_MIN = 1,
	linux_DEV_RAID_SPEED_LIMIT_MAX = 2,
};
enum // /proc/sys/dev/parport/default
{
	linux_DEV_PARPORT_DEFAULT_TIMESLICE = 1,
	linux_DEV_PARPORT_DEFAULT_SPINTIME  = 2,
};
enum // /proc/sys/dev/parport/parport n
{
	linux_DEV_PARPORT_SPINTIME  =  1,
	linux_DEV_PARPORT_BASE_ADDR =  2,
	linux_DEV_PARPORT_IRQ       =  3,
	linux_DEV_PARPORT_DMA       =  4,
	linux_DEV_PARPORT_MODES     =  5,
	linux_DEV_PARPORT_DEVICES   =  6,
	linux_DEV_PARPORT_AUTOPROBE = 16,
};
enum // /proc/sys/dev/parport/parport n/devices/
{
	linux_DEV_PARPORT_DEVICES_ACTIVE = -3,
};
enum // /proc/sys/dev/parport/parport n/devices/device n
{
	linux_DEV_PARPORT_DEVICE_TIMESLICE = 1,
};
enum // /proc/sys/dev/mac_hid
{
	linux_DEV_MAC_HID_KEYBOARD_SENDS_LINUX_KEYCODES = 1,
	linux_DEV_MAC_HID_KEYBOARD_LOCK_KEYCODES        = 2,
	linux_DEV_MAC_HID_MOUSE_BUTTON_EMULATION        = 3,
	linux_DEV_MAC_HID_MOUSE_BUTTON2_KEYCODE         = 4,
	linux_DEV_MAC_HID_MOUSE_BUTTON3_KEYCODE         = 5,
	linux_DEV_MAC_HID_ADB_MOUSE_SENDS_KEYCODES      = 6,
};
enum // /proc/sys/dev/scsi
{
	linux_DEV_SCSI_LOGGING_LEVEL = 1,
};
enum // /proc/sys/dev/ipmi
{
	linux_DEV_IPMI_POWEROFF_POWERCYCLE = 1,
};
enum // /proc/sys/abi
{
	linux_ABI_DEFHANDLER_COFF   = 1,
	linux_ABI_DEFHANDLER_ELF    = 2,
	linux_ABI_DEFHANDLER_LCALL7 = 3,
	linux_ABI_DEFHANDLER_LIBCSO = 4,
	linux_ABI_TRACE             = 5,
	linux_ABI_FAKE_UTSNAME      = 6,
};

// prctl
enum
{
	linux_PR_SET_PDEATHSIG            =  1,
	linux_PR_GET_PDEATHSIG            =  2,
	linux_PR_GET_DUMPABLE             =  3,
	linux_PR_SET_DUMPABLE             =  4,
	linux_PR_GET_UNALIGN              =  5,
	linux_PR_SET_UNALIGN              =  6,
	linux_PR_GET_KEEPCAPS             =  7,
	linux_PR_SET_KEEPCAPS             =  8,
	linux_PR_GET_FPEMU                =  9,
	linux_PR_SET_FPEMU                = 10,
	linux_PR_GET_FPEXC                = 11,
	linux_PR_SET_FPEXC                = 12,
	linux_PR_GET_TIMING               = 13,
	linux_PR_SET_TIMING               = 14,
	linux_PR_SET_NAME                 = 15,
	linux_PR_GET_NAME                 = 16,

	linux_PR_GET_ENDIAN               = 19,
	linux_PR_SET_ENDIAN               = 20,
	linux_PR_GET_SECCOMP              = 21,
	linux_PR_SET_SECCOMP              = 22,
	linux_PR_CAPBSET_READ             = 23,
	linux_PR_CAPBSET_DROP             = 24,
	linux_PR_GET_TSC                  = 25,
	linux_PR_SET_TSC                  = 26,
	linux_PR_GET_SECUREBITS           = 27,
	linux_PR_SET_SECUREBITS           = 28,
	linux_PR_SET_TIMERSLACK           = 29,
	linux_PR_GET_TIMERSLACK           = 30,
	linux_PR_TASK_PERF_EVENTS_DISABLE = 31,
	linux_PR_TASK_PERF_EVENTS_ENABLE  = 32,
	linux_PR_MCE_KILL                 = 33,
	linux_PR_MCE_KILL_GET             = 34,
	linux_PR_SET_MM                   = 35,
	linux_PR_SET_CHILD_SUBREAPER      = 36,
	linux_PR_GET_CHILD_SUBREAPER      = 37,
	linux_PR_SET_NO_NEW_PRIVS         = 38,
	linux_PR_GET_NO_NEW_PRIVS         = 39,
	linux_PR_GET_TID_ADDRESS          = 40,
	linux_PR_SET_THP_DISABLE          = 41,
	linux_PR_GET_THP_DISABLE          = 42,
	linux_PR_MPX_ENABLE_MANAGEMENT    = 43,
	linux_PR_MPX_DISABLE_MANAGEMENT   = 44,
	linux_PR_SET_FP_MODE              = 45,
	linux_PR_GET_FP_MODE              = 46,
	linux_PR_CAP_AMBIENT              = 47,

	linux_PR_SVE_SET_VL               = 50,
	linux_PR_SVE_GET_VL               = 51,

	linux_PR_SET_PTRACER              = 0x59616d61,
};
enum
{
	linux_PR_UNALIGN_NOPRINT = 1,
	linux_PR_UNALIGN_SIGBUS  = 2,
};
enum
{
	linux_PR_FPEMU_NOPRINT = 1,
	linux_PR_FPEMU_SIGFPE  = 2,
};
enum
{
	linux_PR_FP_EXC_SW_ENABLE = 0x80,
	linux_PR_FP_EXC_DIV       = 0x010000,
	linux_PR_FP_EXC_OVF       = 0x020000,
	linux_PR_FP_EXC_UND       = 0x040000,
	linux_PR_FP_EXC_RES       = 0x080000,
	linux_PR_FP_EXC_INV       = 0x100000,
	linux_PR_FP_EXC_DISABLED  = 0,
	linux_PR_FP_EXC_NONRECOV  = 1,
	linux_PR_FP_EXC_ASYNC     = 2,
	linux_PR_FP_EXC_PRECISE   = 3,
};
enum
{
	linux_PR_TIMING_STATISTICAL = 0,
	linux_PR_TIMING_TIMESTAMP   = 1,
};
enum
{
	linux_PR_ENDIAN_BIG        = 0,
	linux_PR_ENDIAN_LITTLE     = 1,
	linux_PR_ENDIAN_PPC_LITTLE = 2,
};
enum
{
	linux_PR_TSC_ENABLE  = 1,
	linux_PR_TSC_SIGSEGV = 2,
};
enum
{
	linux_PR_MCE_KILL_CLEAR = 0,
	linux_PR_MCE_KILL_SET   = 1,
};
enum
{
	linux_PR_MCE_KILL_LATE    = 0,
	linux_PR_MCE_KILL_EARLY   = 1,
	linux_PR_MCE_KILL_DEFAULT = 2,
};
enum
{
	linux_PR_SET_MM_START_CODE  =  1,
	linux_PR_SET_MM_END_CODE    =  2,
	linux_PR_SET_MM_START_DATA  =  3,
	linux_PR_SET_MM_END_DATA    =  4,
	linux_PR_SET_MM_START_STACK =  5,
	linux_PR_SET_MM_START_BRK   =  6,
	linux_PR_SET_MM_BRK         =  7,
	linux_PR_SET_MM_ARG_START   =  8,
	linux_PR_SET_MM_ARG_END     =  9,
	linux_PR_SET_MM_ENV_START   = 10,
	linux_PR_SET_MM_ENV_END     = 11,
	linux_PR_SET_MM_AUXV        = 12,
	linux_PR_SET_MM_EXE_FILE    = 13,
	linux_PR_SET_MM_MAP         = 14,
	linux_PR_SET_MM_MAP_SIZE    = 15,
};
#define linux_PR_SET_PTRACER_ANY ((unsigned long)-1)
enum
{
	linux_PR_FP_MODE_FR  = (1 << 0),
	linux_PR_FP_MODE_FRE = (1 << 1),
};
enum
{
	linux_PR_CAP_AMBIENT_IS_SET    = 1,
	linux_PR_CAP_AMBIENT_RAISE     = 2,
	linux_PR_CAP_AMBIENT_LOWER     = 3,
	linux_PR_CAP_AMBIENT_CLEAR_ALL = 4,
};
enum
{
	linux_PR_SVE_SET_VL_ONEXEC = 1 << 18,
	linux_PR_SVE_VL_LEN_MASK   = 0xffff,
	linux_PR_SVE_VL_INHERIT    = 1 << 17,
};

// adjtimex
enum // Mode codes (timex.mode)
{
	linux_ADJ_OFFSET            = 0x0001,
	linux_ADJ_FREQUENCY         = 0x0002,
	linux_ADJ_MAXERROR          = 0x0004,
	linux_ADJ_ESTERROR          = 0x0008,
	linux_ADJ_STATUS            = 0x0010,
	linux_ADJ_TIMECONST         = 0x0020,
	linux_ADJ_TAI               = 0x0080,
	linux_ADJ_SETOFFSET         = 0x0100,
	linux_ADJ_MICRO             = 0x1000,
	linux_ADJ_NANO              = 0x2000,
	linux_ADJ_TICK              = 0x4000,

	linux_ADJ_OFFSET_SINGLESHOT = 0x8001,
	linux_ADJ_OFFSET_SS_READ    = 0xa001,
};
enum // NTP userland likes the MOD_ prefix better
{
	linux_MOD_OFFSET    = linux_ADJ_OFFSET,
	linux_MOD_FREQUENCY = linux_ADJ_FREQUENCY,
	linux_MOD_MAXERROR  = linux_ADJ_MAXERROR,
	linux_MOD_ESTERROR  = linux_ADJ_ESTERROR,
	linux_MOD_STATUS    = linux_ADJ_STATUS,
	linux_MOD_TIMECONST = linux_ADJ_TIMECONST,
	linux_MOD_TAI       = linux_ADJ_TAI,
	linux_MOD_MICRO     = linux_ADJ_MICRO,
	linux_MOD_NANO      = linux_ADJ_NANO,
};
enum // Status codes (timex.status)
{
	linux_STA_PLL       = 0x0001,
	linux_STA_PPSFREQ   = 0x0002,
	linux_STA_PPSTIME   = 0x0004,
	linux_STA_FLL       = 0x0008,

	linux_STA_INS       = 0x0010,
	linux_STA_DEL       = 0x0020,
	linux_STA_UNSYNC    = 0x0040,
	linux_STA_FREQHOLD  = 0x0080,

	linux_STA_PPSSIGNAL = 0x0100,
	linux_STA_PPSJITTER = 0x0200,
	linux_STA_PPSWANDER = 0x0400,
	linux_STA_PPSERROR  = 0x0800,

	linux_STA_CLOCKERR  = 0x1000,
	linux_STA_NANO      = 0x2000,
	linux_STA_MODE      = 0x4000,
	linux_STA_CLK       = 0x8000,

	linux_STA_RONLY     = linux_STA_PPSSIGNAL | linux_STA_PPSJITTER | linux_STA_PPSWANDER | linux_STA_PPSERROR | linux_STA_CLOCKERR | linux_STA_NANO | linux_STA_MODE | linux_STA_CLK,
};
enum // Clock states (time_state)
{
	linux_TIME_OK    = 0,
	linux_TIME_INS   = 1,
	linux_TIME_DEL   = 2,
	linux_TIME_OOP   = 3,
	linux_TIME_WAIT  = 4,
	linux_TIME_ERROR = 5,
	linux_TIME_BAD   = linux_TIME_ERROR,
};

// mount flags
enum
{
	linux_MS_RDONLY      =     1,
	linux_MS_NOSUID      =     2,
	linux_MS_NODEV       =     4,
	linux_MS_NOEXEC      =     8,
	linux_MS_SYNCHRONOUS =    16,
	linux_MS_REMOUNT     =    32,
	linux_MS_MANDLOCK    =    64,
	linux_MS_DIRSYNC     =   128,
	linux_MS_NOATIME     =  1024,
	linux_MS_NODIRATIME  =  2048,
	linux_MS_BIND        =  4096,
	linux_MS_MOVE        =  8192,
	linux_MS_REC         = 16384,
	linux_MS_VERBOSE     = 32768,
	linux_MS_SILENT      = 32768,
	linux_MS_POSIXACL    = 1 << 16,
	linux_MS_UNBINDABLE  = 1 << 17,
	linux_MS_PRIVATE     = 1 << 18,
	linux_MS_SLAVE       = 1 << 19,
	linux_MS_SHARED      = 1 << 20,
	linux_MS_RELATIME    = 1 << 21,
	linux_MS_KERNMOUNT   = 1 << 22,
	linux_MS_I_VERSION   = 1 << 23,
	linux_MS_STRICTATIME = 1 << 24,
	linux_MS_LAZYTIME    = 1 << 25,

	linux_MS_RMT_MASK    = linux_MS_RDONLY | linux_MS_SYNCHRONOUS | linux_MS_MANDLOCK | linux_MS_I_VERSION | linux_MS_LAZYTIME,

	linux_MS_MGC_VAL     = -1058209792, // 0xC0ED0000
	linux_MS_MGC_MSK     = -65536, // 0xFFFF0000
};

// Umount options
enum
{
	linux_MNT_FORCE       = 0x00000001,
	linux_MNT_DETACH      = 0x00000002,
	linux_MNT_EXPIRE      = 0x00000004,
	linux_UMOUNT_NOFOLLOW = 0x00000008,
	linux_UMOUNT_UNUSED   = INT_MIN, // 0x80000000
};

// swap flags
enum
{
	linux_SWAP_FLAG_PREFER        = 0x8000,
	linux_SWAP_FLAG_PRIO_MASK     = 0x7fff,
	linux_SWAP_FLAG_PRIO_SHIFT    = 0,
	linux_SWAP_FLAG_DISCARD       = 0x10000,
	linux_SWAP_FLAG_DISCARD_ONCE  = 0x20000,
	linux_SWAP_FLAG_DISCARD_PAGES = 0x40000,

	linux_SWAP_FLAGS_VALID        = linux_SWAP_FLAG_PRIO_MASK | linux_SWAP_FLAG_PREFER | linux_SWAP_FLAG_DISCARD | linux_SWAP_FLAG_DISCARD_ONCE | linux_SWAP_FLAG_DISCARD_PAGES,
	linux_SWAP_BATCH              = 64,
};

// reboot
enum
{
	linux_LINUX_REBOOT_MAGIC1  = -18751827, // 0xFEE1DEAD
	linux_LINUX_REBOOT_MAGIC2  = 672274793,
	linux_LINUX_REBOOT_MAGIC2A =  85072278,
	linux_LINUX_REBOOT_MAGIC2B = 369367448,
	linux_LINUX_REBOOT_MAGIC2C = 537993216,
};
enum
{
	linux_LINUX_REBOOT_CMD_RESTART    = 0x01234567,
	linux_LINUX_REBOOT_CMD_HALT       = -839974621, // 0xCDEF0123
	linux_LINUX_REBOOT_CMD_CAD_ON     = -1985229329, // 0x89ABCDEF
	linux_LINUX_REBOOT_CMD_CAD_OFF    = 0x00000000,
	linux_LINUX_REBOOT_CMD_POWER_OFF  = 0x4321FEDC,
	linux_LINUX_REBOOT_CMD_RESTART2   = -1582119980, // 0xA1B2C3D4
	linux_LINUX_REBOOT_CMD_SW_SUSPEND = -805241630, // 0xD000FCE2
	linux_LINUX_REBOOT_CMD_KEXEC      = 0x45584543,
};

// quotactl
enum
{
	linux_MAXQUOTAS = 3,
	linux_USRQUOTA  = 0,
	linux_GRPQUOTA  = 1,
	linux_PRJQUOTA  = 2,
};
enum
{
	linux_SUBCMDMASK  = 0x00FF,
	linux_SUBCMDSHIFT = 8,
};
enum
{
	linux_Q_SYNC         = 0x800001,
	linux_Q_QUOTAON      = 0x800002,
	linux_Q_QUOTAOFF     = 0x800003,
	linux_Q_GETFMT       = 0x800004,
	linux_Q_GETINFO      = 0x800005,
	linux_Q_SETINFO      = 0x800006,
	linux_Q_GETQUOTA     = 0x800007,
	linux_Q_SETQUOTA     = 0x800008,
	linux_Q_GETNEXTQUOTA = 0x800009,
};
enum // Quota format type IDs
{
	linux_QFMT_VFS_OLD = 1,
	linux_QFMT_VFS_V0  = 2,
	linux_QFMT_OCFS2   = 3,
	linux_QFMT_VFS_V1  = 4,
};
enum // Size of block in which space limits are passed through the quota interface
{
	linux_QIF_DQBLKSIZE_BITS = 10,
	linux_QIF_DQBLKSIZE      = 1 << linux_QIF_DQBLKSIZE_BITS,
};
enum
{
	linux_QIF_BLIMITS_B = 0,
	linux_QIF_SPACE_B,
	linux_QIF_ILIMITS_B,
	linux_QIF_INODES_B,
	linux_QIF_BTIME_B,
	linux_QIF_ITIME_B,
};
enum
{
	linux_QIF_BLIMITS = 1 << linux_QIF_BLIMITS_B,
	linux_QIF_SPACE   = 1 << linux_QIF_SPACE_B,
	linux_QIF_ILIMITS = 1 << linux_QIF_ILIMITS_B,
	linux_QIF_INODES  = 1 << linux_QIF_INODES_B,
	linux_QIF_BTIME   = 1 << linux_QIF_BTIME_B,
	linux_QIF_ITIME   = 1 << linux_QIF_ITIME_B,
	linux_QIF_LIMITS  = linux_QIF_BLIMITS | linux_QIF_ILIMITS,
	linux_QIF_USAGE   = linux_QIF_SPACE | linux_QIF_INODES,
	linux_QIF_TIMES   = linux_QIF_BTIME | linux_QIF_ITIME,
	linux_QIF_ALL     = linux_QIF_LIMITS | linux_QIF_USAGE | linux_QIF_TIMES,
};
enum
{
	linux_IIF_BGRACE = 1,
	linux_IIF_IGRACE = 2,
	linux_IIF_FLAGS  = 4,
	linux_IIF_ALL    = linux_IIF_BGRACE | linux_IIF_IGRACE | linux_IIF_FLAGS,
};
enum
{
	linux_DQF_ROOT_SQUASH_B =  0,
	linux_DQF_SYS_FILE_B    = 16,
};
enum // Definitions for quota netlink interface
{
	linux_QUOTA_NL_NOWARN        =  0,
	linux_QUOTA_NL_IHARDWARN     =  1,
	linux_QUOTA_NL_ISOFTLONGWARN =  2,
	linux_QUOTA_NL_ISOFTWARN     =  3,
	linux_QUOTA_NL_BHARDWARN     =  4,
	linux_QUOTA_NL_BSOFTLONGWARN =  5,
	linux_QUOTA_NL_BSOFTWARN     =  6,
	linux_QUOTA_NL_IHARDBELOW    =  7,
	linux_QUOTA_NL_ISOFTBELOW    =  8,
	linux_QUOTA_NL_BHARDBELOW    =  9,
	linux_QUOTA_NL_BSOFTBELOW    = 10,
};
enum
{
	linux_QUOTA_NL_C_UNSPEC,
	linux_QUOTA_NL_C_WARNING,
	linux_QUOTA_NL_C_MAX = linux_QUOTA_NL_C_WARNING,
};
enum
{
	linux_QUOTA_NL_A_UNSPEC,
	linux_QUOTA_NL_A_QTYPE,
	linux_QUOTA_NL_A_EXCESS_ID,
	linux_QUOTA_NL_A_WARNING,
	linux_QUOTA_NL_A_DEV_MAJOR,
	linux_QUOTA_NL_A_DEV_MINOR,
	linux_QUOTA_NL_A_CAUSED_ID,
	linux_QUOTA_NL_A_PAD,
	linux_QUOTA_NL_A_MAX = linux_QUOTA_NL_A_PAD,
};
#define linux_XQM_CMD(x)     (('X' << 8) + (x))
#define linux_XQM_COMMAND(x) (((x) & (0xFF << 8)) == ('X' << 8))
enum // quotactl for the XFS Quota Manager
{
	linux_XQM_USRQUOTA  = 0,
	linux_XQM_GRPQUOTA  = 1,
	linux_XQM_PRJQUOTA  = 2,
	linux_XQM_MAXQUOTAS = 3,
};
enum
{
	linux_Q_XQUOTAON      = linux_XQM_CMD(1),
	linux_Q_XQUOTAOFF     = linux_XQM_CMD(2),
	linux_Q_XGETQUOTA     = linux_XQM_CMD(3),
	linux_Q_XSETQLIM      = linux_XQM_CMD(4),
	linux_Q_XGETQSTAT     = linux_XQM_CMD(5),
	linux_Q_XQUOTARM      = linux_XQM_CMD(6),
	linux_Q_XQUOTASYNC    = linux_XQM_CMD(7),
	linux_Q_XGETQSTATV    = linux_XQM_CMD(8),
	linux_Q_XGETNEXTQUOTA = linux_XQM_CMD(9),
};
enum
{
	linux_FS_DQUOT_VERSION = 1,
};
enum
{
	linux_FS_DQ_ISOFT      = 1 << 0,
	linux_FS_DQ_IHARD      = 1 << 1,
	linux_FS_DQ_BSOFT      = 1 << 2,
	linux_FS_DQ_BHARD      = 1 << 3,
	linux_FS_DQ_RTBSOFT    = 1 << 4,
	linux_FS_DQ_RTBHARD    = 1 << 5,
	linux_FS_DQ_LIMIT_MASK = linux_FS_DQ_ISOFT | linux_FS_DQ_IHARD | linux_FS_DQ_BSOFT | linux_FS_DQ_BHARD | linux_FS_DQ_RTBSOFT | linux_FS_DQ_RTBHARD,
};
enum
{
	linux_FS_DQ_BTIMER     = 1 << 6,
	linux_FS_DQ_ITIMER     = 1 << 7,
	linux_FS_DQ_RTBTIMER   = 1 << 8,
	linux_FS_DQ_TIMER_MASK = linux_FS_DQ_BTIMER | linux_FS_DQ_ITIMER | linux_FS_DQ_RTBTIMER,
};
enum
{
	linux_FS_DQ_BWARNS     = 1 <<  9,
	linux_FS_DQ_IWARNS     = 1 << 10,
	linux_FS_DQ_RTBWARNS   = 1 << 11,
	linux_FS_DQ_WARNS_MASK = linux_FS_DQ_BWARNS | linux_FS_DQ_IWARNS | linux_FS_DQ_RTBWARNS,
};
enum
{
	linux_FS_DQ_BCOUNT    = 1 << 12,
	linux_FS_DQ_ICOUNT    = 1 << 13,
	linux_FS_DQ_RTBCOUNT  = 1 << 14,
	linux_FS_DQ_ACCT_MASK = linux_FS_DQ_BCOUNT | linux_FS_DQ_ICOUNT | linux_FS_DQ_RTBCOUNT,
};
enum
{
	linux_FS_QUOTA_UDQ_ACCT = 1 << 0,
	linux_FS_QUOTA_UDQ_ENFD = 1 << 1,
	linux_FS_QUOTA_GDQ_ACCT = 1 << 2,
	linux_FS_QUOTA_GDQ_ENFD = 1 << 3,
	linux_FS_QUOTA_PDQ_ACCT = 1 << 4,
	linux_FS_QUOTA_PDQ_ENFD = 1 << 5,
};
enum
{
	linux_FS_USER_QUOTA  = 1 << 0,
	linux_FS_PROJ_QUOTA  = 1 << 1,
	linux_FS_GROUP_QUOTA = 1 << 2,
};
enum
{
	linux_FS_QSTAT_VERSION = 1,
};
enum
{
	linux_FS_QSTATV_VERSION1 = 1,
};

// xattr
enum
{
	linux_XATTR_CREATE  = 0x1,
	linux_XATTR_REPLACE = 0x2,
};
// Namespaces
#define linux_XATTR_OS2_PREFIX "os2."
#define linux_XATTR_MAC_OSX_PREFIX "osx."
#define linux_XATTR_BTRFS_PREFIX "btrfs."
#define linux_XATTR_SECURITY_PREFIX	"security."
#define linux_XATTR_SYSTEM_PREFIX "system."
#define linux_XATTR_TRUSTED_PREFIX "trusted."
#define linux_XATTR_USER_PREFIX "user."
enum
{
	linux_XATTR_OS2_PREFIX_LEN      = sizeof(linux_XATTR_OS2_PREFIX) - 1,
	linux_XATTR_MAC_OSX_PREFIX_LEN  = sizeof(linux_XATTR_MAC_OSX_PREFIX) - 1,
	linux_XATTR_BTRFS_PREFIX_LEN    = sizeof(linux_XATTR_BTRFS_PREFIX) - 1,
	linux_XATTR_SECURITY_PREFIX_LEN = sizeof(linux_XATTR_SECURITY_PREFIX) - 1,
	linux_XATTR_SYSTEM_PREFIX_LEN   = sizeof(linux_XATTR_SYSTEM_PREFIX) - 1,
	linux_XATTR_TRUSTED_PREFIX_LEN  = sizeof(linux_XATTR_TRUSTED_PREFIX) - 1,
	linux_XATTR_USER_PREFIX_LEN     = sizeof(linux_XATTR_USER_PREFIX) - 1,
};
// Security namespace
#define linux_XATTR_EVM_SUFFIX             "evm"
#define linux_XATTR_NAME_EVM               linux_XATTR_SECURITY_PREFIX linux_XATTR_EVM_SUFFIX
#define linux_XATTR_IMA_SUFFIX             "ima"
#define linux_XATTR_NAME_IMA               linux_XATTR_SECURITY_PREFIX linux_XATTR_IMA_SUFFIX
#define linux_XATTR_SELINUX_SUFFIX         "selinux"
#define linux_XATTR_NAME_SELINUX           linux_XATTR_SECURITY_PREFIX linux_XATTR_SELINUX_SUFFIX
#define linux_XATTR_SMACK_SUFFIX           "SMACK64"
#define linux_XATTR_SMACK_IPIN             "SMACK64IPIN"
#define linux_XATTR_SMACK_IPOUT            "SMACK64IPOUT"
#define linux_XATTR_SMACK_EXEC             "SMACK64EXEC"
#define linux_XATTR_SMACK_TRANSMUTE        "SMACK64TRANSMUTE"
#define linux_XATTR_SMACK_MMAP             "SMACK64MMAP"
#define linux_XATTR_NAME_SMACK             linux_XATTR_SECURITY_PREFIX linux_XATTR_SMACK_SUFFIX
#define linux_XATTR_NAME_SMACKIPIN         linux_XATTR_SECURITY_PREFIX linux_XATTR_SMACK_IPIN
#define linux_XATTR_NAME_SMACKIPOUT        linux_XATTR_SECURITY_PREFIX linux_XATTR_SMACK_IPOUT
#define linux_XATTR_NAME_SMACKEXEC         linux_XATTR_SECURITY_PREFIX linux_XATTR_SMACK_EXEC
#define linux_XATTR_NAME_SMACKTRANSMUTE    linux_XATTR_SECURITY_PREFIX linux_XATTR_SMACK_TRANSMUTE
#define linux_XATTR_NAME_SMACKMMAP         linux_XATTR_SECURITY_PREFIX linux_XATTR_SMACK_MMAP
#define linux_XATTR_APPARMOR_SUFFIX        "apparmor"
#define linux_XATTR_NAME_APPARMOR          linux_XATTR_SECURITY_PREFIX linux_XATTR_APPARMOR_SUFFIX
#define linux_XATTR_CAPS_SUFFIX            "capability"
#define linux_XATTR_NAME_CAPS              linux_XATTR_SECURITY_PREFIX linux_XATTR_CAPS_SUFFIX
#define linux_XATTR_POSIX_ACL_ACCESS       "posix_acl_access"
#define linux_XATTR_NAME_POSIX_ACL_ACCESS  linux_XATTR_SYSTEM_PREFIX linux_XATTR_POSIX_ACL_ACCESS
#define linux_XATTR_POSIX_ACL_DEFAULT      "posix_acl_default"
#define linux_XATTR_NAME_POSIX_ACL_DEFAULT linux_XATTR_SYSTEM_PREFIX linux_XATTR_POSIX_ACL_DEFAULT

// Futex
enum
{
	linux_FUTEX_WAIT                    =   0,
	linux_FUTEX_WAKE                    =   1,
	linux_FUTEX_FD                      =   2,
	linux_FUTEX_REQUEUE                 =   3,
	linux_FUTEX_CMP_REQUEUE             =   4,
	linux_FUTEX_WAKE_OP                 =   5,
	linux_FUTEX_LOCK_PI                 =   6,
	linux_FUTEX_UNLOCK_PI               =   7,
	linux_FUTEX_TRYLOCK_PI              =   8,
	linux_FUTEX_WAIT_BITSET             =   9,
	linux_FUTEX_WAKE_BITSET             =  10,
	linux_FUTEX_WAIT_REQUEUE_PI         =  11,
	linux_FUTEX_CMP_REQUEUE_PI          =  12,

	linux_FUTEX_PRIVATE_FLAG            = 128,
	linux_FUTEX_CLOCK_REALTIME          = 256,
	linux_FUTEX_CMD_MASK                = ~(linux_FUTEX_PRIVATE_FLAG | linux_FUTEX_CLOCK_REALTIME),

	linux_FUTEX_WAIT_PRIVATE            = linux_FUTEX_WAIT | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_WAKE_PRIVATE            = linux_FUTEX_WAKE | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_REQUEUE_PRIVATE         = linux_FUTEX_REQUEUE | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_CMP_REQUEUE_PRIVATE     = linux_FUTEX_CMP_REQUEUE | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_WAKE_OP_PRIVATE         = linux_FUTEX_WAKE_OP | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_LOCK_PI_PRIVATE         = linux_FUTEX_LOCK_PI | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_UNLOCK_PI_PRIVATE       = linux_FUTEX_UNLOCK_PI | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_TRYLOCK_PI_PRIVATE      = linux_FUTEX_TRYLOCK_PI | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_WAIT_BITSET_PRIVATE     = linux_FUTEX_WAIT_BITSET | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_WAKE_BITSET_PRIVATE     = linux_FUTEX_WAKE_BITSET | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_WAIT_REQUEUE_PI_PRIVATE = linux_FUTEX_WAIT_REQUEUE_PI | linux_FUTEX_PRIVATE_FLAG,
	linux_FUTEX_CMP_REQUEUE_PI_PRIVATE  = linux_FUTEX_CMP_REQUEUE_PI | linux_FUTEX_PRIVATE_FLAG,
};
enum
{
	linux_FUTEX_WAITERS          = INT_MIN, // 0x80000000
	linux_FUTEX_OWNER_DIED       = 0x40000000,
	linux_FUTEX_TID_MASK         = 0x3FFFFFFF,

	linux_ROBUST_LIST_LIMIT      = 2048,

	linux_FUTEX_BITSET_MATCH_ANY = -1, // 0xFFFFFFFF
};
enum
{
	linux_FUTEX_OP_SET         = 0,
	linux_FUTEX_OP_ADD         = 1,
	linux_FUTEX_OP_OR          = 2,
	linux_FUTEX_OP_ANDN        = 3,
	linux_FUTEX_OP_XOR         = 4,

	linux_FUTEX_OP_OPARG_SHIFT = 8,

	linux_FUTEX_OP_CMP_EQ      = 0,
	linux_FUTEX_OP_CMP_NE      = 1,
	linux_FUTEX_OP_CMP_LT      = 2,
	linux_FUTEX_OP_CMP_LE      = 3,
	linux_FUTEX_OP_CMP_GT      = 4,
	linux_FUTEX_OP_CMP_GE      = 5,
};

// aio
enum
{
	linux_IOCB_CMD_PREAD   = 0,
	linux_IOCB_CMD_PWRITE  = 1,
	linux_IOCB_CMD_FSYNC   = 2,
	linux_IOCB_CMD_FDSYNC  = 3,
	//linux_IOCB_CMD_PREADX  = 4,
	//linux_IOCB_CMD_POLL    = 5,
	linux_IOCB_CMD_NOOP    = 6,
	linux_IOCB_CMD_PREADV  = 7,
	linux_IOCB_CMD_PWRITEV = 8,
};
enum
{
	linux_IOCB_FLAG_RESFD = 1 << 0,
};

// epoll
enum
{
	linux_EPOLL_CLOEXEC = linux_O_CLOEXEC,
};
enum
{
	linux_EPOLL_CTL_ADD = 1,
	linux_EPOLL_CTL_DEL = 2,
	linux_EPOLL_CTL_MOD = 3,
};
enum
{
	linux_EPOLLIN        = 0x00000001,
	linux_EPOLLPRI       = 0x00000002,
	linux_EPOLLOUT       = 0x00000004,
	linux_EPOLLERR       = 0x00000008,
	linux_EPOLLHUP       = 0x00000010,
	linux_EPOLLRDNORM    = 0x00000040,
	linux_EPOLLRDBAND    = 0x00000080,
	linux_EPOLLWRNORM    = 0x00000100,
	linux_EPOLLWRBAND    = 0x00000200,
	linux_EPOLLMSG       = 0x00000400,
	linux_EPOLLRDHUP     = 0x00002000,
	linux_EPOLLEXCLUSIVE = 1u << 28,
	linux_EPOLLWAKEUP    = 1u << 29,
	linux_EPOLLONESHOT   = 1u << 30,
	linux_EPOLLET        = INT_MIN, // 1u << 31
};

// fadvise
enum
{
	linux_POSIX_FADV_NORMAL     = 0,
	linux_POSIX_FADV_RANDOM     = 1,
	linux_POSIX_FADV_SEQUENTIAL = 2,
	linux_POSIX_FADV_WILLNEED   = 3,
	linux_POSIX_FADV_DONTNEED   = 4,
	linux_POSIX_FADV_NOREUSE    = 5,
};

// sigevent
enum
{
	linux_SIGEV_SIGNAL    = 0,
	linux_SIGEV_NONE      = 1,
	linux_SIGEV_THREAD    = 2,
	linux_SIGEV_THREAD_ID = 4,
};

// POSIX timer
enum
{
	linux_CLOCK_REALTIME           = 0,
	linux_CLOCK_MONOTONIC          = 1,
	linux_CLOCK_PROCESS_CPUTIME_ID = 2,
	linux_CLOCK_THREAD_CPUTIME_ID  = 3,
	linux_CLOCK_MONOTONIC_RAW      = 4,
	linux_CLOCK_REALTIME_COARSE    = 5,
	linux_CLOCK_MONOTONIC_COARSE   = 6,
	linux_CLOCK_BOOTTIME           = 7,
	linux_CLOCK_REALTIME_ALARM     = 8,
	linux_CLOCK_BOOTTIME_ALARM     = 9,

	// The driver implementing this got removed. The clock ID is kept as a place holder. Do not reuse!
	linux_CLOCK_SGI_CYCLE          = 10,
	linux_CLOCK_TAI                = 11,
};
enum
{
	linux_TIMER_ABSTIME = 0x01,
};

// mbind
enum
{
	linux_MPOL_DEFAULT,
	linux_MPOL_PREFERRED,
	linux_MPOL_BIND,
	linux_MPOL_INTERLEAVE,
	linux_MPOL_LOCAL,
	linux_MPOL_MAX,
};
enum
{
	linux_MPOL_F_STATIC_NODES   = 1 << 15,
	linux_MPOL_F_RELATIVE_NODES = 1 << 14,

	linux_MPOL_MODE_FLAGS       = linux_MPOL_F_STATIC_NODES | linux_MPOL_F_RELATIVE_NODES,
};
enum
{
	linux_MPOL_F_NODE         = 1 << 0,
	linux_MPOL_F_ADDR         = 1 << 1,
	linux_MPOL_F_MEMS_ALLOWED = 1 << 2,
};
enum
{
	linux_MPOL_MF_STRICT   = 1 << 0,
	linux_MPOL_MF_MOVE     = 1 << 1,
	linux_MPOL_MF_MOVE_ALL = 1 << 2,
	linux_MPOL_MF_LAZY     = 1 << 3,
	linux_MPOL_MF_VALID    = linux_MPOL_MF_STRICT | linux_MPOL_MF_MOVE | linux_MPOL_MF_MOVE_ALL,
};

// message queue
enum
{
	linux_MQ_PRIO_MAX  =  32768,
	linux_MQ_BYTES_MAX = 819200,
};

// kexec_load and kexec_file_load
enum
{
	linux_KEXEC_ON_CRASH         = 0x00000001,
	linux_KEXEC_PRESERVE_CONTEXT = 0x00000002,
	linux_KEXEC_ARCH_MASK        = -65536, // 0xFFFF0000
};
enum
{
	linux_KEXEC_FILE_UNLOAD       = 0x00000001,
	linux_KEXEC_FILE_ON_CRASH     = 0x00000002,
	linux_KEXEC_FILE_NO_INITRAMFS = 0x00000004,
};
enum
{
	linux_KEXEC_ARCH_DEFAULT =   0 << 16,
	linux_KEXEC_ARCH_386     =   3 << 16,
	linux_KEXEC_ARCH_68K     =   4 << 16,
	linux_KEXEC_ARCH_X86_64  =  62 << 16,
	linux_KEXEC_ARCH_PPC     =  20 << 16,
	linux_KEXEC_ARCH_PPC64   =  21 << 16,
	linux_KEXEC_ARCH_IA_64   =  50 << 16,
	linux_KEXEC_ARCH_ARM     =  40 << 16,
	linux_KEXEC_ARCH_S390    =  22 << 16,
	linux_KEXEC_ARCH_SH      =  42 << 16,
	linux_KEXEC_ARCH_MIPS_LE =  10 << 16,
	linux_KEXEC_ARCH_MIPS    =   8 << 16,
	linux_KEXEC_ARCH_AARCH64 = 183 << 16,
};
enum
{
	linux_KEXEC_SEGMENT_MAX = 16,
};

// keyrings
enum
{
	linux_KEY_SPEC_THREAD_KEYRING       = -1,
	linux_KEY_SPEC_PROCESS_KEYRING      = -2,
	linux_KEY_SPEC_SESSION_KEYRING      = -3,
	linux_KEY_SPEC_USER_KEYRING         = -4,
	linux_KEY_SPEC_USER_SESSION_KEYRING = -5,
	linux_KEY_SPEC_GROUP_KEYRING        = -6,
	linux_KEY_SPEC_REQKEY_AUTH_KEY      = -7,
	linux_KEY_SPEC_REQUESTOR_KEYRING    = -8,
};
enum
{
	linux_KEY_REQKEY_DEFL_NO_CHANGE            = -1,
	linux_KEY_REQKEY_DEFL_DEFAULT              =  0,
	linux_KEY_REQKEY_DEFL_THREAD_KEYRING       =  1,
	linux_KEY_REQKEY_DEFL_PROCESS_KEYRING      =  2,
	linux_KEY_REQKEY_DEFL_SESSION_KEYRING      =  3,
	linux_KEY_REQKEY_DEFL_USER_KEYRING         =  4,
	linux_KEY_REQKEY_DEFL_USER_SESSION_KEYRING =  5,
	linux_KEY_REQKEY_DEFL_GROUP_KEYRING        =  6,
	linux_KEY_REQKEY_DEFL_REQUESTOR_KEYRING    =  7,
};
enum
{
	linux_KEYCTL_GET_KEYRING_ID       =  0,
	linux_KEYCTL_JOIN_SESSION_KEYRING =  1,
	linux_KEYCTL_UPDATE               =  2,
	linux_KEYCTL_REVOKE               =  3,
	linux_KEYCTL_CHOWN                =  4,
	linux_KEYCTL_SETPERM              =  5,
	linux_KEYCTL_DESCRIBE             =  6,
	linux_KEYCTL_CLEAR                =  7,
	linux_KEYCTL_LINK                 =  8,
	linux_KEYCTL_UNLINK               =  9,
	linux_KEYCTL_SEARCH               = 10,
	linux_KEYCTL_READ                 = 11,
	linux_KEYCTL_INSTANTIATE          = 12,
	linux_KEYCTL_NEGATE               = 13,
	linux_KEYCTL_SET_REQKEY_KEYRING   = 14,
	linux_KEYCTL_SET_TIMEOUT          = 15,
	linux_KEYCTL_ASSUME_AUTHORITY     = 16,
	linux_KEYCTL_GET_SECURITY         = 17,
	linux_KEYCTL_SESSION_TO_PARENT    = 18,
	linux_KEYCTL_REJECT               = 19,
	linux_KEYCTL_INSTANTIATE_IOV      = 20,
	linux_KEYCTL_INVALIDATE           = 21,
	linux_KEYCTL_GET_PERSISTENT       = 22,
	linux_KEYCTL_DH_COMPUTE           = 23,
	linux_KEYCTL_RESTRICT_KEYRING     = 29,
};

// ioprio
enum
{
	linux_IOPRIO_WHO_PROCESS = 1,
	linux_IOPRIO_WHO_PGRP,
	linux_IOPRIO_WHO_USER,
};
enum
{
	linux_IOPRIO_CLASS_NONE,
	linux_IOPRIO_CLASS_RT,
	linux_IOPRIO_CLASS_BE,
	linux_IOPRIO_CLASS_IDLE,
};

// inotify
enum
{
	linux_IN_CLOEXEC  = linux_O_CLOEXEC,
	linux_IN_NONBLOCK = linux_O_NONBLOCK,
};
enum
{
linux_IN_ACCESS        = 0x00000001,
linux_IN_MODIFY        = 0x00000002,
linux_IN_ATTRIB        = 0x00000004,
linux_IN_CLOSE_WRITE   = 0x00000008,
linux_IN_CLOSE_NOWRITE = 0x00000010,
linux_IN_OPEN          = 0x00000020,
linux_IN_MOVED_FROM    = 0x00000040,
linux_IN_MOVED_TO      = 0x00000080,
linux_IN_CREATE        = 0x00000100,
linux_IN_DELETE        = 0x00000200,
linux_IN_DELETE_SELF   = 0x00000400,
linux_IN_MOVE_SELF     = 0x00000800,

linux_IN_UNMOUNT       = 0x00002000,
linux_IN_Q_OVERFLOW    = 0x00004000,
linux_IN_IGNORED       = 0x00008000,

linux_IN_CLOSE         = linux_IN_CLOSE_WRITE | linux_IN_CLOSE_NOWRITE,
linux_IN_MOVE          = linux_IN_MOVED_FROM | linux_IN_MOVED_TO,

linux_IN_ONLYDIR       = 0x01000000,
linux_IN_DONT_FOLLOW   = 0x02000000,
linux_IN_EXCL_UNLINK   = 0x04000000,
linux_IN_MASK_ADD      = 0x20000000,
linux_IN_ISDIR         = 0x40000000,
linux_IN_ONESHOT       = INT_MIN, // 0x80000000

linux_IN_ALL_EVENTS    = linux_IN_ACCESS | linux_IN_MODIFY | linux_IN_ATTRIB | linux_IN_CLOSE_WRITE | linux_IN_CLOSE_NOWRITE | linux_IN_OPEN | linux_IN_MOVED_FROM | linux_IN_MOVED_TO | linux_IN_DELETE | linux_IN_CREATE | linux_IN_DELETE_SELF | linux_IN_MOVE_SELF,
};

// splice, tee, vmsplice
enum
{
	linux_SPLICE_F_MOVE     = 0x01,
	linux_SPLICE_F_NONBLOCK = 0x02,
	linux_SPLICE_F_MORE     = 0x04,
	linux_SPLICE_F_GIFT     = 0x08,

	linux_SPLICE_F_ALL      = linux_SPLICE_F_MOVE | linux_SPLICE_F_NONBLOCK | linux_SPLICE_F_MORE | linux_SPLICE_F_GIFT,
};

// sync_file_range
enum
{
	linux_SYNC_FILE_RANGE_WAIT_BEFORE = 1,
	linux_SYNC_FILE_RANGE_WRITE       = 2,
	linux_SYNC_FILE_RANGE_WAIT_AFTER  = 4,
};

// utimensat
enum
{
	linux_UTIME_NOW  = (1l << 30) - 1l,
	linux_UTIME_OMIT = (1l << 30) - 2l,
};

// signalfd4
enum
{
	linux_SFD_CLOEXEC  = linux_O_CLOEXEC,
	linux_SFD_NONBLOCK = linux_O_NONBLOCK,
};

// timerfd_*
enum
{
	linux_TFD_TIMER_ABSTIME       = 1 << 0,
	linux_TFD_TIMER_CANCEL_ON_SET = 1 << 1,
	linux_TFD_CLOEXEC             = linux_O_CLOEXEC,
	linux_TFD_NONBLOCK            = linux_O_NONBLOCK,

	linux_TFD_IOC_SET_TICKS       = (1u << 30) | ('T' << 8) | (sizeof(uint64_t) << 16),
};

// eventfd
enum
{
	linux_EFD_SEMAPHORE          = 1 << 0,
	linux_EFD_CLOEXEC            = linux_O_CLOEXEC,
	linux_EFD_NONBLOCK           = linux_O_NONBLOCK,

	linux_EFD_SHARED_FCNTL_FLAGS = linux_O_CLOEXEC | linux_O_NONBLOCK,
	linux_EFD_FLAGS_SET          = linux_EFD_SHARED_FCNTL_FLAGS | linux_EFD_SEMAPHORE,
};

// fallocate
enum
{
	linux_FALLOC_FL_KEEP_SIZE      = 0x01,
	linux_FALLOC_FL_PUNCH_HOLE     = 0x02,
	linux_FALLOC_FL_NO_HIDE_STALE  = 0x04,
	linux_FALLOC_FL_COLLAPSE_RANGE = 0x08,
	linux_FALLOC_FL_ZERO_RANGE     = 0x10,
	linux_FALLOC_FL_INSERT_RANGE   = 0x20,
	linux_FALLOC_FL_UNSHARE_RANGE  = 0x40,
};

// preadv2, pwritev2
enum
{
	linux_RWF_HIPRI     = 0x00000001,
	linux_RWF_DSYNC     = 0x00000002,
	linux_RWF_SYNC      = 0x00000004,
	linux_RWF_NOWAIT    = 0x00000008,
	linux_RWF_SUPPORTED = linux_RWF_HIPRI | linux_RWF_DSYNC | linux_RWF_SYNC | linux_RWF_NOWAIT,
};

// perf_event_open
enum linux_perf_type_id_t
{
	linux_PERF_TYPE_HARDWARE   = 0,
	linux_PERF_TYPE_SOFTWARE   = 1,
	linux_PERF_TYPE_TRACEPOINT = 2,
	linux_PERF_TYPE_HW_CACHE   = 3,
	linux_PERF_TYPE_RAW        = 4,
	linux_PERF_TYPE_BREAKPOINT = 5,
};
enum linux_perf_hw_id_t
{
	linux_PERF_COUNT_HW_CPU_CYCLES              = 0,
	linux_PERF_COUNT_HW_INSTRUCTIONS            = 1,
	linux_PERF_COUNT_HW_CACHE_REFERENCES        = 2,
	linux_PERF_COUNT_HW_CACHE_MISSES            = 3,
	linux_PERF_COUNT_HW_BRANCH_INSTRUCTIONS     = 4,
	linux_PERF_COUNT_HW_BRANCH_MISSES           = 5,
	linux_PERF_COUNT_HW_BUS_CYCLES              = 6,
	linux_PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
	linux_PERF_COUNT_HW_STALLED_CYCLES_BACKEND  = 8,
	linux_PERF_COUNT_HW_REF_CPU_CYCLES          = 9,
};
enum perf_hw_cache_id_t
{
	linux_PERF_COUNT_HW_CACHE_L1D  = 0,
	linux_PERF_COUNT_HW_CACHE_L1I  = 1,
	linux_PERF_COUNT_HW_CACHE_LL   = 2,
	linux_PERF_COUNT_HW_CACHE_DTLB = 3,
	linux_PERF_COUNT_HW_CACHE_ITLB = 4,
	linux_PERF_COUNT_HW_CACHE_BPU  = 5,
	linux_PERF_COUNT_HW_CACHE_NODE = 6,
};
enum linux_perf_hw_cache_op_id_t
{
	linux_PERF_COUNT_HW_CACHE_OP_READ     = 0,
	linux_PERF_COUNT_HW_CACHE_OP_WRITE    = 1,
	linux_PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
};
enum linux_perf_hw_cache_op_result_id_t
{
	linux_PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	linux_PERF_COUNT_HW_CACHE_RESULT_MISS   = 1,
};
enum linux_perf_sw_ids_t
{
	linux_PERF_COUNT_SW_CPU_CLOCK        =  0,
	linux_PERF_COUNT_SW_TASK_CLOCK       =  1,
	linux_PERF_COUNT_SW_PAGE_FAULTS      =  2,
	linux_PERF_COUNT_SW_CONTEXT_SWITCHES =  3,
	linux_PERF_COUNT_SW_CPU_MIGRATIONS   =  4,
	linux_PERF_COUNT_SW_PAGE_FAULTS_MIN  =  5,
	linux_PERF_COUNT_SW_PAGE_FAULTS_MAJ  =  6,
	linux_PERF_COUNT_SW_ALIGNMENT_FAULTS =  7,
	linux_PERF_COUNT_SW_EMULATION_FAULTS =  8,
	linux_PERF_COUNT_SW_DUMMY            =  9,
	linux_PERF_COUNT_SW_BPF_OUTPUT       = 10,
};
enum linux_perf_event_sample_format_t
{
	linux_PERF_SAMPLE_IP           = 1u <<  0,
	linux_PERF_SAMPLE_TID          = 1u <<  1,
	linux_PERF_SAMPLE_TIME         = 1u <<  2,
	linux_PERF_SAMPLE_ADDR         = 1u <<  3,
	linux_PERF_SAMPLE_READ         = 1u <<  4,
	linux_PERF_SAMPLE_CALLCHAIN    = 1u <<  5,
	linux_PERF_SAMPLE_ID           = 1u <<  6,
	linux_PERF_SAMPLE_CPU          = 1u <<  7,
	linux_PERF_SAMPLE_PERIOD       = 1u <<  8,
	linux_PERF_SAMPLE_STREAM_ID    = 1u <<  9,
	linux_PERF_SAMPLE_RAW          = 1u << 10,
	linux_PERF_SAMPLE_BRANCH_STACK = 1u << 11,
	linux_PERF_SAMPLE_REGS_USER    = 1u << 12,
	linux_PERF_SAMPLE_STACK_USER   = 1u << 13,
	linux_PERF_SAMPLE_WEIGHT       = 1u << 14,
	linux_PERF_SAMPLE_DATA_SRC     = 1u << 15,
	linux_PERF_SAMPLE_IDENTIFIER   = 1u << 16,
	linux_PERF_SAMPLE_TRANSACTION  = 1u << 17,
	linux_PERF_SAMPLE_REGS_INTR    = 1u << 18,
	linux_PERF_SAMPLE_PHYS_ADDR    = 1u << 19,
};
enum linux_perf_branch_sample_type_shift_t
{
	linux_PERF_SAMPLE_BRANCH_USER_SHIFT       =  0,
	linux_PERF_SAMPLE_BRANCH_KERNEL_SHIFT     =  1,
	linux_PERF_SAMPLE_BRANCH_HV_SHIFT         =  2,

	linux_PERF_SAMPLE_BRANCH_ANY_SHIFT        =  3,
	linux_PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT   =  4,
	linux_PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT =  5,
	linux_PERF_SAMPLE_BRANCH_IND_CALL_SHIFT   =  6,
	linux_PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT   =  7,
	linux_PERF_SAMPLE_BRANCH_IN_TX_SHIFT      =  8,
	linux_PERF_SAMPLE_BRANCH_NO_TX_SHIFT      =  9,
	linux_PERF_SAMPLE_BRANCH_COND_SHIFT       = 10,

	linux_PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	linux_PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT   = 12,
	linux_PERF_SAMPLE_BRANCH_CALL_SHIFT       = 13,

	linux_PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT   = 14,
	linux_PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT  = 15,

	linux_PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT  = 16,
};
enum linux_perf_branch_sample_type_t
{
	linux_PERF_SAMPLE_BRANCH_USER       = 1u << linux_PERF_SAMPLE_BRANCH_USER_SHIFT,
	linux_PERF_SAMPLE_BRANCH_KERNEL     = 1u << linux_PERF_SAMPLE_BRANCH_KERNEL_SHIFT,
	linux_PERF_SAMPLE_BRANCH_HV         = 1u << linux_PERF_SAMPLE_BRANCH_HV_SHIFT,

	linux_PERF_SAMPLE_BRANCH_ANY        = 1u << linux_PERF_SAMPLE_BRANCH_ANY_SHIFT,
	linux_PERF_SAMPLE_BRANCH_ANY_CALL   = 1u << linux_PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT,
	linux_PERF_SAMPLE_BRANCH_ANY_RETURN = 1u << linux_PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT,
	linux_PERF_SAMPLE_BRANCH_IND_CALL   = 1u << linux_PERF_SAMPLE_BRANCH_IND_CALL_SHIFT,
	linux_PERF_SAMPLE_BRANCH_ABORT_TX   = 1u << linux_PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT,
	linux_PERF_SAMPLE_BRANCH_IN_TX      = 1u << linux_PERF_SAMPLE_BRANCH_IN_TX_SHIFT,
	linux_PERF_SAMPLE_BRANCH_NO_TX      = 1u << linux_PERF_SAMPLE_BRANCH_NO_TX_SHIFT,
	linux_PERF_SAMPLE_BRANCH_COND       = 1u << linux_PERF_SAMPLE_BRANCH_COND_SHIFT,

	linux_PERF_SAMPLE_BRANCH_CALL_STACK = 1u << linux_PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT,
	linux_PERF_SAMPLE_BRANCH_IND_JUMP   = 1u << linux_PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT,
	linux_PERF_SAMPLE_BRANCH_CALL       = 1u << linux_PERF_SAMPLE_BRANCH_CALL_SHIFT,

	linux_PERF_SAMPLE_BRANCH_NO_FLAGS   = 1u << linux_PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT,
	linux_PERF_SAMPLE_BRANCH_NO_CYCLES  = 1u << linux_PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT,

	linux_PERF_SAMPLE_BRANCH_TYPE_SAVE  = 1u << linux_PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT,
};
enum
{
	linux_PERF_BR_UNKNOWN   =  0,
	linux_PERF_BR_COND      =  1,
	linux_PERF_BR_UNCOND    =  2,
	linux_PERF_BR_IND       =  3,
	linux_PERF_BR_CALL      =  4,
	linux_PERF_BR_IND_CALL  =  5,
	linux_PERF_BR_RET       =  6,
	linux_PERF_BR_SYSCALL   =  7,
	linux_PERF_BR_SYSRET    =  8,
	linux_PERF_BR_COND_CALL =  9,
	linux_PERF_BR_COND_RET  = 10,
};
enum
{
	linux_PERF_SAMPLE_BRANCH_PLM_ALL = linux_PERF_SAMPLE_BRANCH_USER | linux_PERF_SAMPLE_BRANCH_KERNEL | linux_PERF_SAMPLE_BRANCH_HV,
};
enum linux_perf_sample_regs_abi_t
{
	linux_PERF_SAMPLE_REGS_ABI_NONE = 0,
	linux_PERF_SAMPLE_REGS_ABI_32   = 1,
	linux_PERF_SAMPLE_REGS_ABI_64   = 2,
};
enum
{
	linux_PERF_TXN_ELISION        = 1 << 0,
	linux_PERF_TXN_TRANSACTION    = 1 << 1,
	linux_PERF_TXN_SYNC           = 1 << 2,
	linux_PERF_TXN_ASYNC          = 1 << 3,
	linux_PERF_TXN_RETRY          = 1 << 4,
	linux_PERF_TXN_CONFLICT       = 1 << 5,
	linux_PERF_TXN_CAPACITY_WRITE = 1 << 6,
	linux_PERF_TXN_CAPACITY_READ  = 1 << 7,

	linux_PERF_TXN_MAX            = 1 << 8,

	linux_PERF_TXN_ABORT_SHIFT    = 32,
};
#define linux_PERF_TXN_ABORT_MASK (0xFFFFFFFFull << 32) // TODO: this was inside the enum above.
enum linux_perf_event_read_format_t
{
	linux_PERF_FORMAT_TOTAL_TIME_ENABLED = 1u << 0,
	linux_PERF_FORMAT_TOTAL_TIME_RUNNING = 1u << 1,
	linux_PERF_FORMAT_ID                 = 1u << 2,
	linux_PERF_FORMAT_GROUP              = 1u << 3,
};
enum
{
	linux_PERF_ATTR_SIZE_VER0 =  64,
	linux_PERF_ATTR_SIZE_VER1 =  72,
	linux_PERF_ATTR_SIZE_VER2 =  80,
	linux_PERF_ATTR_SIZE_VER3 =  96,
	linux_PERF_ATTR_SIZE_VER4 = 104,
	linux_PERF_ATTR_SIZE_VER5 = 112,
};
enum
{
	linux_PERF_EVENT_IOC_ENABLE       = (0u << 30) | ('$' << 8) | 0 | (0 << 16),
	linux_PERF_EVENT_IOC_DISABLE      = (0u << 30) | ('$' << 8) | 1 | (0 << 16),
	linux_PERF_EVENT_IOC_REFRESH      = (0u << 30) | ('$' << 8) | 2 | (0 << 16),
	linux_PERF_EVENT_IOC_RESET        = (0u << 30) | ('$' << 8) | 3 | (0 << 16),
	linux_PERF_EVENT_IOC_PERIOD       = (1u << 30) | ('$' << 8) | 4 | (sizeof(uint64_t) << 16),
	linux_PERF_EVENT_IOC_SET_OUTPUT   = (0u << 30) | ('$' << 8) | 5 | (0 << 16),
	linux_PERF_EVENT_IOC_SET_FILTER   = (1u << 30) | ('$' << 8) | 6 | (sizeof(char*) << 16),
	linux_PERF_EVENT_IOC_ID           = -2146950137, // (2u << 30) | ('$' << 8) | 7 | (sizeof(uint64_t*) << 16)
	linux_PERF_EVENT_IOC_SET_BPF      = (1u << 30) | ('$' << 8) | 8 | (sizeof(uint32_t) << 16),
	linux_PERF_EVENT_IOC_PAUSE_OUTPUT = (1u << 30) | ('$' << 8) | 9 | (sizeof(uint32_t) << 16),
};
enum linux_perf_event_ioc_flags_t
{
	linux_PERF_IOC_FLAG_GROUP = 1u << 0,
};
enum
{
	linux_PERF_RECORD_MISC_CPUMODE_MASK           = 7 <<  0,
	linux_PERF_RECORD_MISC_CPUMODE_UNKNOWN        = 0 <<  0,
	linux_PERF_RECORD_MISC_KERNEL                 = 1 <<  0,
	linux_PERF_RECORD_MISC_USER                   = 2 <<  0,
	linux_PERF_RECORD_MISC_HYPERVISOR             = 3 <<  0,
	linux_PERF_RECORD_MISC_GUEST_KERNEL           = 4 <<  0,
	linux_PERF_RECORD_MISC_GUEST_USER             = 5 <<  0,
	linux_PERF_RECORD_MISC_PROC_MAP_PARSE_TIMEOUT = 1 << 12,
	linux_PERF_RECORD_MISC_MMAP_DATA              = 1 << 13,
	linux_PERF_RECORD_MISC_COMM_EXEC              = 1 << 13,
	linux_PERF_RECORD_MISC_SWITCH_OUT             = 1 << 13,
	linux_PERF_RECORD_MISC_EXACT_IP               = 1 << 14,
	linux_PERF_RECORD_MISC_EXT_RESERVED           = 1 << 15,
};
enum
{
	linux_NET_NS_INDEX    = 0,
	linux_UTS_NS_INDEX    = 1,
	linux_IPC_NS_INDEX    = 2,
	linux_PID_NS_INDEX    = 3,
	linux_USER_NS_INDEX   = 4,
	linux_MNT_NS_INDEX    = 5,
	linux_CGROUP_NS_INDEX = 6,

	linux_NR_NAMESPACES,
};
enum linux_perf_event_type_t
{
	linux_PERF_RECORD_MMAP            =  1,
	linux_PERF_RECORD_LOST            =  2,
	linux_PERF_RECORD_COMM            =  3,
	linux_PERF_RECORD_EXIT            =  4,
	linux_PERF_RECORD_THROTTLE        =  5,
	linux_PERF_RECORD_UNTHROTTLE      =  6,
	linux_PERF_RECORD_FORK            =  7,
	linux_PERF_RECORD_READ            =  8,
	linux_PERF_RECORD_SAMPLE          =  9,
	linux_PERF_RECORD_MMAP2           = 10,
	linux_PERF_RECORD_AUX             = 11,
	linux_PERF_RECORD_ITRACE_START    = 12,
	linux_PERF_RECORD_LOST_SAMPLES    = 13,
	linux_PERF_RECORD_SWITCH          = 14,
	linux_PERF_RECORD_SWITCH_CPU_WIDE = 15,
	linux_PERF_RECORD_NAMESPACES      = 16,
};
enum
{
	linux_PERF_MAX_STACK_DEPTH        = 127,
	linux_PERF_MAX_CONTEXTS_PER_STACK =   8,
};
//enum linux_perf_callchain_context_t // TODO: following macros were in this enum.
//{
#define linux_PERF_CONTEXT_HV           ((uint64_t)-32)
#define linux_PERF_CONTEXT_KERNEL       ((uint64_t)-128)
#define linux_PERF_CONTEXT_USER         ((uint64_t)-512)

#define linux_PERF_CONTEXT_GUEST        ((uint64_t)-2048)
#define linux_PERF_CONTEXT_GUEST_KERNEL ((uint64_t)-2176)
#define linux_PERF_CONTEXT_GUEST_USER   ((uint64_t)-2560)

#define linux_PERF_CONTEXT_MAX          ((uint64_t)-4095)
//};
enum
{
	linux_PERF_AUX_FLAG_TRUNCATED = 0x01,
	linux_PERF_AUX_FLAG_OVERWRITE = 0x02,
	linux_PERF_AUX_FLAG_PARTIAL   = 0x04,
	linux_PERF_AUX_FLAG_COLLISION = 0x08,

	linux_PERF_FLAG_FD_NO_GROUP   = 1ul << 0,
	linux_PERF_FLAG_FD_OUTPUT     = 1ul << 1,
	linux_PERF_FLAG_PID_CGROUP    = 1ul << 2,
	linux_PERF_FLAG_FD_CLOEXEC    = 1ul << 3,
};
enum
{
	linux_PERF_MEM_OP_NA     = 0x01,
	linux_PERF_MEM_OP_LOAD   = 0x02,
	linux_PERF_MEM_OP_STORE  = 0x04,
	linux_PERF_MEM_OP_PFETCH = 0x08,
	linux_PERF_MEM_OP_EXEC   = 0x10,
	linux_PERF_MEM_OP_SHIFT  = 0,
};
enum
{
	linux_PERF_MEM_LVL_NA       = 0x01,
	linux_PERF_MEM_LVL_HIT      = 0x02,
	linux_PERF_MEM_LVL_MISS     = 0x04,
	linux_PERF_MEM_LVL_L1       = 0x08,
	linux_PERF_MEM_LVL_LFB      = 0x10,
	linux_PERF_MEM_LVL_L2       = 0x20,
	linux_PERF_MEM_LVL_L3       = 0x40,
	linux_PERF_MEM_LVL_LOC_RAM  = 0x80,
	linux_PERF_MEM_LVL_REM_RAM1 = 0x100,
	linux_PERF_MEM_LVL_REM_RAM2 = 0x200,
	linux_PERF_MEM_LVL_REM_CCE1 = 0x400,
	linux_PERF_MEM_LVL_REM_CCE2 = 0x800,
	linux_PERF_MEM_LVL_IO       = 0x1000,
	linux_PERF_MEM_LVL_UNC      = 0x2000,
	linux_PERF_MEM_LVL_SHIFT    = 5,
};
enum
{
	linux_PERF_MEM_REMOTE_REMOTE = 0x01,
	linux_PERF_MEM_REMOTE_SHIFT  = 37,
};
enum
{
	linux_PERF_MEM_LVLNUM_L1        = 0x01,
	linux_PERF_MEM_LVLNUM_L2        = 0x02,
	linux_PERF_MEM_LVLNUM_L3        = 0x03,
	linux_PERF_MEM_LVLNUM_L4        = 0x04,
	linux_PERF_MEM_LVLNUM_ANY_CACHE = 0x0B,
	linux_PERF_MEM_LVLNUM_LFB       = 0x0C,
	linux_PERF_MEM_LVLNUM_RAM       = 0x0D,
	linux_PERF_MEM_LVLNUM_PMEM      = 0x0E,
	linux_PERF_MEM_LVLNUM_NA        = 0x0F,
	linux_PERF_MEM_LVLNUM_SHIFT     = 33,
};
enum
{
	linux_PERF_MEM_SNOOP_NA    = 0x01,
	linux_PERF_MEM_SNOOP_NONE  = 0x02,
	linux_PERF_MEM_SNOOP_HIT   = 0x04,
	linux_PERF_MEM_SNOOP_MISS  = 0x08,
	linux_PERF_MEM_SNOOP_HITM  = 0x10,
	linux_PERF_MEM_SNOOP_SHIFT = 19,
};
enum
{
	linux_PERF_MEM_SNOOPX_FWD   = 0x01,
	linux_PERF_MEM_SNOOPX_SHIFT = 37,
};
enum
{
	linux_PERF_MEM_LOCK_NA     = 0x01,
	linux_PERF_MEM_LOCK_LOCKED = 0x02,
	linux_PERF_MEM_LOCK_SHIFT  = 24,
};
enum
{
	linux_PERF_MEM_TLB_NA    = 0x01,
	linux_PERF_MEM_TLB_HIT   = 0x02,
	linux_PERF_MEM_TLB_MISS  = 0x04,
	linux_PERF_MEM_TLB_L1    = 0x08,
	linux_PERF_MEM_TLB_L2    = 0x10,
	linux_PERF_MEM_TLB_WK    = 0x20,
	linux_PERF_MEM_TLB_OS    = 0x40,
	linux_PERF_MEM_TLB_SHIFT = 26,
};

// fanotify
enum
{
	linux_FAN_ACCESS         = 0x00000001,
	linux_FAN_MODIFY         = 0x00000002,
	linux_FAN_CLOSE_WRITE    = 0x00000008,
	linux_FAN_CLOSE_NOWRITE  = 0x00000010,
	linux_FAN_OPEN           = 0x00000020,
	linux_FAN_Q_OVERFLOW     = 0x00004000,
	linux_FAN_OPEN_PERM      = 0x00010000,
	linux_FAN_ACCESS_PERM    = 0x00020000,
	linux_FAN_ONDIR          = 0x40000000,
	linux_FAN_EVENT_ON_CHILD = 0x08000000,

	linux_FAN_CLOSE          = linux_FAN_CLOSE_WRITE | linux_FAN_CLOSE_NOWRITE,
};
enum
{
	linux_FAN_CLOEXEC           = 0x00000001,
	linux_FAN_NONBLOCK          = 0x00000002,

	linux_FAN_CLASS_NOTIF       = 0x00000000,
	linux_FAN_CLASS_CONTENT     = 0x00000004,
	linux_FAN_CLASS_PRE_CONTENT = 0x00000008,
	linux_FAN_ALL_CLASS_BITS    = linux_FAN_CLASS_NOTIF | linux_FAN_CLASS_CONTENT | linux_FAN_CLASS_PRE_CONTENT,

	linux_FAN_UNLIMITED_QUEUE   = 0x00000010,
	linux_FAN_UNLIMITED_MARKS   = 0x00000020,
	linux_FAN_ENABLE_AUDIT      = 0x00000040,

	linux_FAN_ALL_INIT_FLAGS    = linux_FAN_CLOEXEC | linux_FAN_NONBLOCK | linux_FAN_ALL_CLASS_BITS | linux_FAN_UNLIMITED_QUEUE | linux_FAN_UNLIMITED_MARKS,
};
enum
{
	linux_FAN_MARK_ADD                 = 0x00000001,
	linux_FAN_MARK_REMOVE              = 0x00000002,
	linux_FAN_MARK_DONT_FOLLOW         = 0x00000004,
	linux_FAN_MARK_ONLYDIR             = 0x00000008,
	linux_FAN_MARK_MOUNT               = 0x00000010,
	linux_FAN_MARK_IGNORED_MASK        = 0x00000020,
	linux_FAN_MARK_IGNORED_SURV_MODIFY = 0x00000040,
	linux_FAN_MARK_FLUSH               = 0x00000080,

	linux_FAN_ALL_MARK_FLAGS           = linux_FAN_MARK_ADD | linux_FAN_MARK_REMOVE | linux_FAN_MARK_DONT_FOLLOW | linux_FAN_MARK_ONLYDIR | linux_FAN_MARK_MOUNT | linux_FAN_MARK_IGNORED_MASK | linux_FAN_MARK_IGNORED_SURV_MODIFY | linux_FAN_MARK_FLUSH,
};
enum
{
	linux_FAN_ALL_EVENTS          = linux_FAN_ACCESS | linux_FAN_MODIFY | linux_FAN_CLOSE | linux_FAN_OPEN,
	linux_FAN_ALL_PERM_EVENTS     = linux_FAN_OPEN_PERM | linux_FAN_ACCESS_PERM,
	linux_FAN_ALL_OUTGOING_EVENTS = linux_FAN_ALL_EVENTS | linux_FAN_ALL_PERM_EVENTS | linux_FAN_Q_OVERFLOW,
};
enum
{
	linux_FANOTIFY_METADATA_VERSION = 3,
};
enum
{
	linux_FAN_ALLOW = 0x01,
	linux_FAN_DENY  = 0x02,
	linux_FAN_AUDIT = 0x10,
};
enum
{
	linux_FAN_NOFD = -1,
};
enum
{
	linux_FAN_EVENT_METADATA_LEN = sizeof(struct linux_fanotify_event_metadata_t),
};

// kcmp
enum linux_kcmp_type_t
{
	linux_KCMP_FILE,
	linux_KCMP_VM,
	linux_KCMP_FILES,
	linux_KCMP_FS,
	linux_KCMP_SIGHAND,
	linux_KCMP_IO,
	linux_KCMP_SYSVSEM,
	linux_KCMP_EPOLL_TFD,
};

// finit_module
enum
{
	linux_MODULE_INIT_IGNORE_MODVERSIONS = 1,
	linux_MODULE_INIT_IGNORE_VERMAGIC    = 2,
};

// renameat2
enum
{
	linux_RENAME_NOREPLACE = 1 << 0,
	linux_RENAME_EXCHANGE  = 1 << 1,
	linux_RENAME_WHITEOUT  = 1 << 2,
};

// seccomp
enum
{
	linux_SECCOMP_SET_MODE_STRICT  = 0,
	linux_SECCOMP_SET_MODE_FILTER  = 1,
	linux_SECCOMP_GET_ACTION_AVAIL = 2,
};
enum
{
	linux_SECCOMP_FILTER_FLAG_TSYNC = 1,
	linux_SECCOMP_FILTER_FLAG_LOG   = 2,
};
enum
{
	linux_SECCOMP_RET_KILL_PROCESS = INT_MIN, // 0x80000000u,
	linux_SECCOMP_RET_KILL_THREAD  = 0x00000000u,
	linux_SECCOMP_RET_KILL         = linux_SECCOMP_RET_KILL_THREAD,
	linux_SECCOMP_RET_TRAP         = 0x00030000u,
	linux_SECCOMP_RET_ERRNO        = 0x00050000u,
	linux_SECCOMP_RET_TRACE        = 0x7FF00000u,
	linux_SECCOMP_RET_LOG          = 0x7FFC0000u,
	linux_SECCOMP_RET_ALLOW        = 0x7FFF0000u,

	linux_SECCOMP_RET_ACTION_FULL  = -65536, // 0xFFFF0000u,
	linux_SECCOMP_RET_ACTION       = 0x7FFF0000u,
	linux_SECCOMP_RET_DATA         = 0x0000FFFFu,
};

// getrandom
enum
{
	linux_GRND_NONBLOCK = 0x0001,
	linux_GRND_RANDOM   = 0x0002,
};

// memfd_create
enum
{
	linux_MFD_CLOEXEC       = 0x0001u,
	linux_MFD_ALLOW_SEALING = 0x0002u,
	linux_MFD_HUGETLB       = 0x0004u,
};
enum
{
	linux_HUGETLB_FLAG_ENCODE_SHIFT = 26,
	linux_HUGETLB_FLAG_ENCODE_MASK  = 0x3F,

	linux_HUGETLB_FLAG_ENCODE_64KB  = 16 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_512KB = 19 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_1MB   = 20 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_2MB   = 21 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_8MB   = 23 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_16MB  = 24 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_256MB = 28 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_1GB   = 30 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_2GB   = 31 << linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_HUGETLB_FLAG_ENCODE_16GB  = -2013265920, // 34 << linux_HUGETLB_FLAG_ENCODE_SHIFT
};
enum
{
	linux_MFD_HUGE_SHIFT = linux_HUGETLB_FLAG_ENCODE_SHIFT,
	linux_MFD_HUGE_MASK  = linux_HUGETLB_FLAG_ENCODE_MASK,

	linux_MFD_HUGE_64KB  = linux_HUGETLB_FLAG_ENCODE_64KB,
	linux_MFD_HUGE_512KB = linux_HUGETLB_FLAG_ENCODE_512KB,
	linux_MFD_HUGE_1MB   = linux_HUGETLB_FLAG_ENCODE_1MB,
	linux_MFD_HUGE_2MB   = linux_HUGETLB_FLAG_ENCODE_2MB,
	linux_MFD_HUGE_8MB   = linux_HUGETLB_FLAG_ENCODE_8MB,
	linux_MFD_HUGE_16MB  = linux_HUGETLB_FLAG_ENCODE_16MB,
	linux_MFD_HUGE_256MB = linux_HUGETLB_FLAG_ENCODE_256MB,
	linux_MFD_HUGE_1GB   = linux_HUGETLB_FLAG_ENCODE_1GB,
	linux_MFD_HUGE_2GB   = linux_HUGETLB_FLAG_ENCODE_2GB,
	linux_MFD_HUGE_16GB  = linux_HUGETLB_FLAG_ENCODE_16GB,
};

// bpf
enum
{
	linux_BPF_LD   = 0x00,
	linux_BPF_LDX  = 0x01,
	linux_BPF_ST   = 0x02,
	linux_BPF_STX  = 0x03,
	linux_BPF_ALU  = 0x04,
	linux_BPF_JMP  = 0x05,
	linux_BPF_RET  = 0x06,
	linux_BPF_MISC = 0x07,
};
enum
{
	linux_BPF_W  = 0x00,
	linux_BPF_H  = 0x08,
	linux_BPF_B  = 0x10,
	//linux_BPF_DW = 0x18,
};
enum
{
	linux_BPF_IMM = 0x00,
	linux_BPF_ABS = 0x20,
	linux_BPF_IND = 0x40,
	linux_BPF_MEM = 0x60,
	linux_BPF_LEN = 0x80,
	linux_BPF_MSH = 0xa0,
};
enum
{
	linux_BPF_ADD = 0x00,
	linux_BPF_SUB = 0x10,
	linux_BPF_MUL = 0x20,
	linux_BPF_DIV = 0x30,
	linux_BPF_OR  = 0x40,
	linux_BPF_AND = 0x50,
	linux_BPF_LSH = 0x60,
	linux_BPF_RSH = 0x70,
	linux_BPF_NEG = 0x80,
	linux_BPF_MOD = 0x90,
	linux_BPF_XOR = 0xa0,
};
enum
{
	linux_BPF_JA   = 0x00,
	linux_BPF_JEQ  = 0x10,
	linux_BPF_JGT  = 0x20,
	linux_BPF_JGE  = 0x30,
	linux_BPF_JSET = 0x40,
};
enum
{
	linux_BPF_K = 0x00,
	linux_BPF_X = 0x08,
};
enum
{
	linux_BPF_MAXINSNS = 4096,
};
enum
{
	linux_BPF_ALU64   = 0x07,
	linux_BPF_DW      = 0x18,
	linux_BPF_XADD    = 0xc0,
	linux_BPF_MOV     = 0xb0,
	linux_BPF_ARSH    = 0xc0,
	linux_BPF_END     = 0xd0,
	linux_BPF_TO_LE   = 0x00,
	linux_BPF_TO_BE   = 0x08,
	linux_BPF_FROM_LE = linux_BPF_TO_LE,
	linux_BPF_FROM_BE = linux_BPF_TO_BE,
	linux_BPF_JNE     = 0x50,
	linux_BPF_JLT     = 0xa0,
	linux_BPF_JLE     = 0xb0,
	linux_BPF_JSGT    = 0x60,
	linux_BPF_JSGE    = 0x70,
	linux_BPF_JSLT    = 0xc0,
	linux_BPF_JSLE    = 0xd0,
	linux_BPF_CALL    = 0x80,
	linux_BPF_EXIT    = 0x90,
};
enum
{
	linux_BPF_REG_0 = 0,
	linux_BPF_REG_1,
	linux_BPF_REG_2,
	linux_BPF_REG_3,
	linux_BPF_REG_4,
	linux_BPF_REG_5,
	linux_BPF_REG_6,
	linux_BPF_REG_7,
	linux_BPF_REG_8,
	linux_BPF_REG_9,
	linux_BPF_REG_10,
};
enum linux_bpf_cmd_t
{
	linux_BPF_MAP_CREATE,
	linux_BPF_MAP_LOOKUP_ELEM,
	linux_BPF_MAP_UPDATE_ELEM,
	linux_BPF_MAP_DELETE_ELEM,
	linux_BPF_MAP_GET_NEXT_KEY,
	linux_BPF_PROG_LOAD,
	linux_BPF_OBJ_PIN,
	linux_BPF_OBJ_GET,
	linux_BPF_PROG_ATTACH,
	linux_BPF_PROG_DETACH,
	linux_BPF_PROG_TEST_RUN,
	linux_BPF_PROG_GET_NEXT_ID,
	linux_BPF_MAP_GET_NEXT_ID,
	linux_BPF_PROG_GET_FD_BY_ID,
	linux_BPF_MAP_GET_FD_BY_ID,
	linux_BPF_OBJ_GET_INFO_BY_FD,
	linux_BPF_PROG_QUERY,
};
enum linux_bpf_map_type_t
{
	linux_BPF_MAP_TYPE_UNSPEC,
	linux_BPF_MAP_TYPE_HASH,
	linux_BPF_MAP_TYPE_ARRAY,
	linux_BPF_MAP_TYPE_PROG_ARRAY,
	linux_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	linux_BPF_MAP_TYPE_PERCPU_HASH,
	linux_BPF_MAP_TYPE_PERCPU_ARRAY,
	linux_BPF_MAP_TYPE_STACK_TRACE,
	linux_BPF_MAP_TYPE_CGROUP_ARRAY,
	linux_BPF_MAP_TYPE_LRU_HASH,
	linux_BPF_MAP_TYPE_LRU_PERCPU_HASH,
	linux_BPF_MAP_TYPE_LPM_TRIE,
	linux_BPF_MAP_TYPE_ARRAY_OF_MAPS,
	linux_BPF_MAP_TYPE_HASH_OF_MAPS,
	linux_BPF_MAP_TYPE_DEVMAP,
	linux_BPF_MAP_TYPE_SOCKMAP,
	linux_BPF_MAP_TYPE_CPUMAP,
};
enum linux_bpf_prog_type_t
{
	linux_BPF_PROG_TYPE_UNSPEC,
	linux_BPF_PROG_TYPE_SOCKET_FILTER,
	linux_BPF_PROG_TYPE_KPROBE,
	linux_BPF_PROG_TYPE_SCHED_CLS,
	linux_BPF_PROG_TYPE_SCHED_ACT,
	linux_BPF_PROG_TYPE_TRACEPOINT,
	linux_BPF_PROG_TYPE_XDP,
	linux_BPF_PROG_TYPE_PERF_EVENT,
	linux_BPF_PROG_TYPE_CGROUP_SKB,
	linux_BPF_PROG_TYPE_CGROUP_SOCK,
	linux_BPF_PROG_TYPE_LWT_IN,
	linux_BPF_PROG_TYPE_LWT_OUT,
	linux_BPF_PROG_TYPE_LWT_XMIT,
	linux_BPF_PROG_TYPE_SOCK_OPS,
	linux_BPF_PROG_TYPE_SK_SKB,
	linux_BPF_PROG_TYPE_CGROUP_DEVICE,
};
enum linux_bpf_attach_type_t
{
	linux_BPF_CGROUP_INET_INGRESS,
	linux_BPF_CGROUP_INET_EGRESS,
	linux_BPF_CGROUP_INET_SOCK_CREATE,
	linux_BPF_CGROUP_SOCK_OPS,
	linux_BPF_SK_SKB_STREAM_PARSER,
	linux_BPF_SK_SKB_STREAM_VERDICT,
	linux_BPF_CGROUP_DEVICE,

	linux_MAX_BPF_ATTACH_TYPE,
};
// A bunch of constants
enum
{
	linux_BPF_F_ALLOW_OVERRIDE   = 1u << 0,
	linux_BPF_F_ALLOW_MULTI      = 1u << 1,

	linux_BPF_F_STRICT_ALIGNMENT = 1u << 0,

	linux_BPF_PSEUDO_MAP_FD      = 1,

	linux_BPF_PSEUDO_CALL        = 1,

	linux_BPF_ANY                = 0,
	linux_BPF_NOEXIST            = 1,
	linux_BPF_EXIST              = 2,

	linux_BPF_F_NO_PREALLOC      = 1u << 0,
	linux_BPF_F_NO_COMMON_LRU    = 1u << 1,
	linux_BPF_F_NUMA_NODE        = 1u << 2,

	linux_BPF_F_QUERY_EFFECTIVE  = 1u << 0,

	linux_BPF_F_RDONLY           = 1u << 3,
	linux_BPF_F_WRONLY           = 1u << 4,
};
enum linux_bpf_func_id_t
{
	BPF_FUNC_unspec,
	BPF_FUNC_map_lookup_elem,
	BPF_FUNC_map_update_elem,
	BPF_FUNC_map_delete_elem,
	BPF_FUNC_probe_read,
	BPF_FUNC_ktime_get_ns,
	BPF_FUNC_trace_printk,
	BPF_FUNC_get_prandom_u32,
	BPF_FUNC_get_smp_processor_id,
	BPF_FUNC_skb_store_bytes,
	BPF_FUNC_l3_csum_replace,
	BPF_FUNC_l4_csum_replace,
	BPF_FUNC_tail_call,
	BPF_FUNC_clone_redirect,
	BPF_FUNC_get_current_pid_tgid,
	BPF_FUNC_get_current_uid_gid,
	BPF_FUNC_get_current_comm,
	BPF_FUNC_get_cgroup_classid,
	BPF_FUNC_skb_vlan_push,
	BPF_FUNC_skb_vlan_pop,
	BPF_FUNC_skb_get_tunnel_key,
	BPF_FUNC_skb_set_tunnel_key,
	BPF_FUNC_perf_event_read,
	BPF_FUNC_redirect,
	BPF_FUNC_get_route_realm,
	BPF_FUNC_perf_event_output,
	BPF_FUNC_skb_load_bytes,
	BPF_FUNC_get_stackid,
	BPF_FUNC_csum_diff,
	BPF_FUNC_skb_get_tunnel_opt,
	BPF_FUNC_skb_set_tunnel_opt,
	BPF_FUNC_skb_change_proto,
	BPF_FUNC_skb_change_type,
	BPF_FUNC_skb_under_cgroup,
	BPF_FUNC_get_hash_recalc,
	BPF_FUNC_get_current_task,
	BPF_FUNC_probe_write_user,
	BPF_FUNC_current_task_under_cgroup,
	BPF_FUNC_skb_change_tail,
	BPF_FUNC_skb_pull_data,
	BPF_FUNC_csum_update,
	BPF_FUNC_set_hash_invalid,
	BPF_FUNC_get_numa_node_id,
	BPF_FUNC_skb_change_head,
	BPF_FUNC_xdp_adjust_head,
	BPF_FUNC_probe_read_str,
	BPF_FUNC_get_socket_cookie,
	BPF_FUNC_get_socket_uid,
	BPF_FUNC_set_hash,
	BPF_FUNC_setsockopt,
	BPF_FUNC_skb_adjust_room,
	BPF_FUNC_redirect_map,
	BPF_FUNC_sk_redirect_map,
	BPF_FUNC_sock_map_update,
	BPF_FUNC_xdp_adjust_meta,
	BPF_FUNC_perf_event_read_value,
	BPF_FUNC_perf_prog_read_value,
	BPF_FUNC_getsockopt,
	BPF_FUNC_override_return,
	BPF_FUNC_sock_ops_cb_flags_set,
};
// eBPF helper functions flags
enum
{
	linux_BPF_F_RECOMPUTE_CSUM  = 1ull << 0,
	linux_BPF_F_INVALIDATE_HASH = 1ull << 1,

	linux_BPF_F_HDR_FIELD_MASK  = 0xFull,

	linux_BPF_F_PSEUDO_HDR      = 1ull << 4,
	linux_BPF_F_MARK_MANGLED_0  = 1ull << 5,
	linux_BPF_F_MARK_ENFORCE    = 1ull << 6,

	linux_BPF_F_INGRESS         = 1ull << 0,

	linux_BPF_F_TUNINFO_IPV6    = 1ull << 0,

	linux_BPF_F_SKIP_FIELD_MASK = 0xFFull,
	linux_BPF_F_USER_STACK      = 1ull << 8,
	linux_BPF_F_FAST_STACK_CMP  = 1ull << 9,
	linux_BPF_F_REUSE_STACKID   = 1ull << 10,

	linux_BPF_F_ZERO_CSUM_TX    = 1ull << 1,
	linux_BPF_F_DONT_FRAGMENT   = 1ull << 2,

	linux_BPF_F_INDEX_MASK      = -1, // 0xFFFFFFFFull
	linux_BPF_F_CURRENT_CPU     = linux_BPF_F_INDEX_MASK,
};
#define linux_BPF_F_CTXLEN_MASK (0xFFFFFull << 32)
enum linux_bpf_adj_room_mode_t
{
	linux_BPF_ADJ_ROOM_NET,
};
enum linux_bpf_ret_code_t
{
	linux_BPF_OK       = 0,
	linux_BPF_DROP     = 2,
	linux_BPF_REDIRECT = 7,
};
enum
{
	linux_XDP_PACKET_HEADROOM = 256,
};
enum linux_xdp_action_t
{
	linux_XDP_ABORTED = 0,
	linux_XDP_DROP,
	linux_XDP_PASS,
	linux_XDP_TX,
	linux_XDP_REDIRECT,
};
enum linux_sk_action_t
{
	linux_SK_DROP = 0,
	linux_SK_PASS,
};
enum
{
	linux_BPF_SOCK_OPS_RTO_CB_FLAG     = 1 << 0,
	linux_BPF_SOCK_OPS_RETRANS_CB_FLAG = 1 << 1,
	linux_BPF_SOCK_OPS_STATE_CB_FLAG   = 1 << 2,
	linux_BPF_SOCK_OPS_ALL_CB_FLAGS    = 0x7,
};
enum
{
	linux_BPF_SOCK_OPS_VOID,
	linux_BPF_SOCK_OPS_TIMEOUT_INIT,
	linux_BPF_SOCK_OPS_RWND_INIT,
	linux_BPF_SOCK_OPS_TCP_CONNECT_CB,
	linux_BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,
	linux_BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
	linux_BPF_SOCK_OPS_NEEDS_ECN,
	linux_BPF_SOCK_OPS_BASE_RTT,
	linux_BPF_SOCK_OPS_RTO_CB,
	linux_BPF_SOCK_OPS_RETRANS_CB,
	linux_BPF_SOCK_OPS_STATE_CB,
};
enum
{
	linux_BPF_TCP_ESTABLISHED = 1,
	linux_BPF_TCP_SYN_SENT,
	linux_BPF_TCP_SYN_RECV,
	linux_BPF_TCP_FIN_WAIT1,
	linux_BPF_TCP_FIN_WAIT2,
	linux_BPF_TCP_TIME_WAIT,
	linux_BPF_TCP_CLOSE,
	linux_BPF_TCP_CLOSE_WAIT,
	linux_BPF_TCP_LAST_ACK,
	linux_BPF_TCP_LISTEN,
	linux_BPF_TCP_CLOSING,
	linux_BPF_TCP_NEW_SYN_RECV,
};
enum
{
	linux_TCP_BPF_IW            = 1001,
	linux_TCP_BPF_SNDCWND_CLAMP = 1002,
};
enum
{
	linux_BPF_DEVCG_ACC_MKNOD = 1ull << 0,
	linux_BPF_DEVCG_ACC_READ  = 1ull << 1,
	linux_BPF_DEVCG_ACC_WRITE = 1ull << 2,

	linux_BPF_DEVCG_DEV_BLOCK = 1ull << 0,
	linux_BPF_DEVCG_DEV_CHAR  = 1ull << 1,
};
enum
{
	linux_BPF_MAJOR_VERSION = 1,
	linux_BPF_MINOR_VERSION = 1,
};
enum
{
	linux_BPF_A = 0x10,
};
enum
{
	linux_BPF_TAX = 0x00,
	linux_BPF_TXA = 0x80,
};
#define linux_BPF_STMT(code, k)         { (unsigned short)(code), 0, 0, k }
#define linux_BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
enum
{
	linux_BPF_MEMWORDS = 16,
};
enum
{
	linux_SKF_AD_OFF              = -0x1000,
	linux_SKF_AD_PROTOCOL         =  0,
	linux_SKF_AD_PKTTYPE          =  4,
	linux_SKF_AD_IFINDEX          =  8,
	linux_SKF_AD_NLATTR           = 12,
	linux_SKF_AD_NLATTR_NEST      = 16,
	linux_SKF_AD_MARK             = 20,
	linux_SKF_AD_QUEUE            = 24,
	linux_SKF_AD_HATYPE           = 28,
	linux_SKF_AD_RXHASH           = 32,
	linux_SKF_AD_CPU              = 36,
	linux_SKF_AD_ALU_XOR_X        = 40,
	linux_SKF_AD_VLAN_TAG         = 44,
	linux_SKF_AD_VLAN_TAG_PRESENT = 48,
	linux_SKF_AD_PAY_OFFSET       = 52,
	linux_SKF_AD_RANDOM           = 56,
	linux_SKF_AD_VLAN_TPID        = 60,
	linux_SKF_AD_MAX              = 64,
};
enum
{
	linux_SKF_NET_OFF = -0x100000,
	linux_SKF_LL_OFF  = -0x200000,
};
enum
{
	linux_BPF_NET_OFF = linux_SKF_NET_OFF,
	linux_BPF_LL_OFF  = linux_SKF_LL_OFF,
};

// userfaultfd
enum
{
	linux_UFFD_FEATURE_PAGEFAULT_FLAG_WP = 1 << 0,
	linux_UFFD_FEATURE_EVENT_FORK        = 1 << 1,
	linux_UFFD_FEATURE_EVENT_REMAP       = 1 << 2,
	linux_UFFD_FEATURE_EVENT_REMOVE      = 1 << 3,
	linux_UFFD_FEATURE_MISSING_HUGETLBFS = 1 << 4,
	linux_UFFD_FEATURE_MISSING_SHMEM     = 1 << 5,
	linux_UFFD_FEATURE_EVENT_UNMAP       = 1 << 6,
	linux_UFFD_FEATURE_SIGBUS            = 1 << 7,
	linux_UFFD_FEATURE_THREAD_ID         = 1 << 8,
};
enum
{
	linux__UFFDIO_REGISTER   = 0x00,
	linux__UFFDIO_UNREGISTER = 0x01,
	linux__UFFDIO_WAKE       = 0x02,
	linux__UFFDIO_COPY       = 0x03,
	linux__UFFDIO_ZEROPAGE   = 0x04,
	linux__UFFDIO_API        = 0x3F,
};
enum
{
	linux_UFFD_API          = (uint64_t)0xAA,
	linux_UFFD_API_FEATURES = linux_UFFD_FEATURE_EVENT_FORK |
	                          linux_UFFD_FEATURE_EVENT_REMAP |
	                          linux_UFFD_FEATURE_EVENT_REMOVE |
	                          linux_UFFD_FEATURE_EVENT_UNMAP |
	                          linux_UFFD_FEATURE_MISSING_HUGETLBFS |
	                          linux_UFFD_FEATURE_MISSING_SHMEM |
	                          linux_UFFD_FEATURE_SIGBUS |
	                          linux_UFFD_FEATURE_THREAD_ID,
};
#define linux_UFFD_API_IOCTLS             ((uint64_t)1 << linux__UFFDIO_REGISTER | (uint64_t)1 << linux__UFFDIO_UNREGISTER | (uint64_t)1 << linux__UFFDIO_API)
#define linux_UFFD_API_RANGE_IOCTLS       ((uint64_t)1 << linux__UFFDIO_WAKE | (uint64_t)1 << linux__UFFDIO_COPY | (uint64_t)1 << linux__UFFDIO_ZEROPAGE)
#define linux_UFFD_API_RANGE_IOCTLS_BASIC ((uint64_t)1 << linux__UFFDIO_WAKE | (uint64_t)1 << linux__UFFDIO_COPY)
enum
{
	linux_UFFDIO = 0xAA,
};
#define linux_UFFDIO_API        ((3 << 30) | (linux_UFFDIO << 8) | linux__UFFDIO_API | (sizeof(struct linux_uffdio_api_t) << 16))
#define linux_UFFDIO_REGISTER   ((3 << 30) | (linux_UFFDIO << 8) | linux__UFFDIO_REGISTER | (sizeof(struct linux_uffdio_register_t) << 16))
#define linux_UFFDIO_UNREGISTER ((2 << 30) | (linux_UFFDIO << 8) | linux__UFFDIO_UNREGISTER | (sizeof(struct linux_uffdio_range_t) << 16))
#define linux_UFFDIO_WAKE       ((2 << 30) | (linux_UFFDIO << 8) | linux__UFFDIO_WAKE | (sizeof(struct linux_uffdio_range_t) << 16))
#define linux_UFFDIO_COPY       ((3 << 30) | (linux_UFFDIO << 8) | linux__UFFDIO_COPY | (sizeof(struct linux_uffdio_copy_t) << 16))
#define linux_UFFDIO_ZEROPAGE   ((3 << 30) | (linux_UFFDIO << 8) | linux__UFFDIO_ZEROPAGE | (sizeof(struct linux_uffdio_zeropage_t) << 16))
enum
{
	linux_UFFD_EVENT_PAGEFAULT = 0x12,
	linux_UFFD_EVENT_FORK      = 0x13,
	linux_UFFD_EVENT_REMAP     = 0x14,
	linux_UFFD_EVENT_REMOVE    = 0x15,
	linux_UFFD_EVENT_UNMAP     = 0x16,
};
enum
{
	linux_UFFD_PAGEFAULT_FLAG_WRITE = 1 << 0,
	linux_UFFD_PAGEFAULT_FLAG_WP    = 1 << 1,
};
enum
{
	linux_UFFDIO_REGISTER_MODE_MISSING = (uint64_t)1 << 0,
	linux_UFFDIO_REGISTER_MODE_WP      = (uint64_t)1 << 1,
};
enum
{
	linux_UFFDIO_COPY_MODE_DONTWAKE = (uint64_t)1 << 0,
};
enum
{
	linux_UFFDIO_ZEROPAGE_MODE_DONTWAKE = (uint64_t)1 << 0,
};
enum linux_membarrier_cmd_t
{
	linux_MEMBARRIER_CMD_QUERY                                = 0,
	linux_MEMBARRIER_CMD_GLOBAL                               = 1 << 0,
	linux_MEMBARRIER_CMD_GLOBAL_EXPEDITED                     = 1 << 1,
	linux_MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED            = 1 << 2,
	linux_MEMBARRIER_CMD_PRIVATE_EXPEDITED                    = 1 << 3,
	linux_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED           = 1 << 4,
	linux_MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE          = 1 << 5,
	linux_MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE = 1 << 6,

	linux_MEMBARRIER_CMD_SHARED                               = linux_MEMBARRIER_CMD_GLOBAL,
};

// pkeys
enum
{
	linux_PKEY_DISABLE_ACCESS = 0x1,
	linux_PKEY_DISABLE_WRITE  = 0x2,
	linux_PKEY_ACCESS_MASK    = linux_PKEY_DISABLE_ACCESS | linux_PKEY_DISABLE_WRITE,
};

// statx
enum
{
	linux_STATX_TYPE        = 0x00000001u,
	linux_STATX_MODE        = 0x00000002u,
	linux_STATX_NLINK       = 0x00000004u,
	linux_STATX_UID         = 0x00000008u,
	linux_STATX_GID         = 0x00000010u,
	linux_STATX_ATIME       = 0x00000020u,
	linux_STATX_MTIME       = 0x00000040u,
	linux_STATX_CTIME       = 0x00000080u,
	linux_STATX_INO         = 0x00000100u,
	linux_STATX_SIZE        = 0x00000200u,
	linux_STATX_BLOCKS      = 0x00000400u,
	linux_STATX_BASIC_STATS = 0x000007FFu,
	linux_STATX_BTIME       = 0x00000800u,
	linux_STATX_ALL         = 0x00000FFFu,
	linux_STATX__RESERVED   = INT_MIN, // 0x80000000u
};
enum
{
	linux_STATX_ATTR_COMPRESSED = 0x00000004,
	linux_STATX_ATTR_IMMUTABLE  = 0x00000010,
	linux_STATX_ATTR_APPEND     = 0x00000020,
	linux_STATX_ATTR_NODUMP     = 0x00000040,
	linux_STATX_ATTR_ENCRYPTED  = 0x00000800,

	linux_STATX_ATTR_AUTOMOUNT  = 0x00001000,
};
enum
{
	linux_AT_STATX_SYNC_TYPE    = 0x6000,
	linux_AT_STATX_SYNC_AS_STAT = 0x0000,
	linux_AT_STATX_FORCE_SYNC   = 0x2000,
	linux_AT_STATX_DONT_SYNC    = 0x4000,
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

static inline unsigned int linux_QCMD(unsigned int const cmd, unsigned int const type)
{
	return (cmd << linux_SUBCMDSHIFT) | (type & linux_SUBCMDMASK);
}

static inline unsigned int linux_FUTEX_OP(unsigned int op, unsigned int oparg, unsigned int cmp, unsigned int cmparg)
{
	return ((op & 0xF) << 28) | ((cmp & 0xF) << 24) | ((oparg & 0xFFF) << 12) | (cmparg & 0xFFF);
}

#define linux_IOPRIO_CLASS_SHIFT (13)
#define linux_IOPRIO_PRIO_MASK   ((1 << linux_IOPRIO_CLASS_SHIFT) - 1)
static inline int linux_IOPRIO_PRIO_CLASS(int const mask)
{
	return mask >> linux_IOPRIO_CLASS_SHIFT;
}

static inline int linux_IOPRIO_PRIO_DATA(int const mask)
{
	return mask & linux_IOPRIO_PRIO_MASK;
}

static inline int linux_IOPRIO_PRIO_VALUE(int const class, int const data)
{
	return (class << linux_IOPRIO_CLASS_SHIFT) | data;
}
#undef linux_IOPRIO_CLASS_SHIFT

static inline uint64_t linux_perf_flags(struct linux_perf_event_attr_t const* const attr)
{
	return *(&attr->read_format + 1); // TODO: use offsetof()
}

#define linux_PERF_MEM_S(a, s) (((uint64_t)linux_PERF_MEM_##a##_##s) << linux_PERF_MEM_##a##_SHIFT)

static inline struct linux_fanotify_event_metadata_t const* linux_FAN_EVENT_NEXT(struct linux_fanotify_event_metadata_t const* const meta, size_t* const len)
{
	*len -= meta->event_len;
	return (struct linux_fanotify_event_metadata_t const*)(((uintptr_t)meta) + meta->event_len);
}

static inline bool linux_FAN_EVENT_OK(struct linux_fanotify_event_metadata_t const* const meta, size_t const len)
{
	return (long)len >= (long)linux_FAN_EVENT_METADATA_LEN && (long)meta->event_len >= (long)linux_FAN_EVENT_METADATA_LEN && (long)meta->event_len <= (long)len;
}

static inline int linux_BPF_CLASS(int const code)
{
	return code & 0x07;
}

static inline int linux_BPF_SIZE(int const code)
{
	return code & 0x18;
}

static inline int linux_BPF_MODE(int const code)
{
	return code & 0xe0;
}

static inline int linux_BPF_OP(int const code)
{
	return code & 0xf0;
}

static inline int linux_BPF_SRC(int const code)
{
	return code & 0x08;
}

static inline int linux_BPF_RVAL(int const code)
{
	return code & 0x18;
}

static inline int linux_BPF_MISCOP(int const code)
{
	return code & 0xf8;
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
static inline LINUX_DEFINE_SYSCALL2_NORET(sched_setparam, linux_pid_t, pid, struct linux_sched_param_t LINUX_SAFE_CONST*, param)
static inline LINUX_DEFINE_SYSCALL2_NORET(sched_getparam, linux_pid_t, pid, struct linux_sched_param_t*, param)
static inline LINUX_DEFINE_SYSCALL3_NORET(sched_setscheduler, linux_pid_t, pid, int, policy, struct linux_sched_param_t LINUX_SAFE_CONST*, param)
static inline LINUX_DEFINE_SYSCALL1_RET(sched_getscheduler, linux_pid_t, pid, int)
static inline LINUX_DEFINE_SYSCALL1_RET(sched_get_priority_max, int, policy, int)
static inline LINUX_DEFINE_SYSCALL1_RET(sched_get_priority_min, int, policy, int)
static inline LINUX_DEFINE_SYSCALL2_NORET(sched_rr_get_interval, linux_pid_t, pid, struct linux_timespec_t*, interval)
static inline LINUX_DEFINE_SYSCALL2_NORET(mlock, void const*, start, size_t, len)
static inline LINUX_DEFINE_SYSCALL2_NORET(munlock, void const*, start, size_t, len)
static inline LINUX_DEFINE_SYSCALL1_NORET(mlockall, int, flags)
static inline LINUX_DEFINE_SYSCALL0_NORET(munlockall)
static inline LINUX_DEFINE_SYSCALL0_NORET(vhangup)
static inline enum linux_error_t linux_modify_ldt(int const func, void* const ptr, unsigned long const bytecount, int* const result)
{
	int const ret = (int)linux_syscall3((intptr_t)func, (intptr_t)ptr, (intptr_t)bytecount, linux_syscall_name_modify_ldt);
	if (linux_syscall_returned_error(ret))
		return (enum linux_error_t)-ret;
	if (result)
		*result = ret;
	return linux_error_none;
}
static inline LINUX_DEFINE_SYSCALL2_NORET(pivot_root, char const*, new_root, char const*, put_old)
static inline LINUX_DEFINE_SYSCALL1_NORET(sysctl, struct linux_sysctl_args_t*, args)
static inline LINUX_DEFINE_SYSCALL5_RET(prctl, int, option, uintptr_t, arg2, uintptr_t, arg3, uintptr_t, arg4, uintptr_t, arg5, long)
static inline LINUX_DEFINE_SYSCALL2_NORET(arch_prctl, int, option, uintptr_t, arg2)
static inline LINUX_DEFINE_SYSCALL1_RET(adjtimex, struct linux_timex_t*, txc_p, int)
static inline LINUX_DEFINE_SYSCALL2_NORET(setrlimit, unsigned int, resource, struct linux_rlimit_t LINUX_SAFE_CONST*, rlim)
static inline LINUX_DEFINE_SYSCALL1_NORET(chroot, char const*, filename)
static inline LINUX_DEFINE_SYSCALL0_NORET(sync)
static inline LINUX_DEFINE_SYSCALL1_NORET(acct, char const*, name)
static inline LINUX_DEFINE_SYSCALL2_NORET(settimeofday, struct linux_timeval_t LINUX_SAFE_CONST*, tv, struct linux_timezone_t LINUX_SAFE_CONST*, tz)
static inline LINUX_DEFINE_SYSCALL5_NORET(mount, char LINUX_SAFE_CONST*, dev_name, char LINUX_SAFE_CONST*, dir_name, char LINUX_SAFE_CONST*, type, unsigned long, flags, void LINUX_SAFE_CONST*, data)
static inline LINUX_DEFINE_SYSCALL2_NORET(umount, char LINUX_SAFE_CONST*, name, int, flags)
static inline LINUX_DEFINE_SYSCALL2_NORET(swapon, char const*, specialfile, int, swap_flags)
static inline LINUX_DEFINE_SYSCALL1_NORET(swapoff, char const*, specialfile)
static inline LINUX_DEFINE_SYSCALL4_NORET(reboot, int, magic1, int, magic2, unsigned int, cmd, void LINUX_SAFE_CONST*, arg)
static inline LINUX_DEFINE_SYSCALL2_NORET(sethostname, char LINUX_SAFE_CONST*, name, int, len)
static inline LINUX_DEFINE_SYSCALL2_NORET(setdomainname, char LINUX_SAFE_CONST*, name, int, len)
static inline LINUX_DEFINE_SYSCALL1_NORET(iopl, unsigned int, level)
static inline LINUX_DEFINE_SYSCALL3_NORET(ioperm, unsigned long, from, unsigned long, num, int, on)
static inline LINUX_DEFINE_SYSCALL3_NORET(init_module, void LINUX_SAFE_CONST*, umod, size_t, len, char const*, uargs)
static inline LINUX_DEFINE_SYSCALL2_NORET(delete_module, char const*, name_user, unsigned int, flags)
static inline LINUX_DEFINE_SYSCALL4_NORET(quotactl, unsigned int, cmd, char const*, special, linux_qid_t, id, void*, addr)
static inline LINUX_DEFINE_SYSCALL0_RET(gettid, linux_pid_t)
static inline LINUX_DEFINE_SYSCALL3_NORET(readahead, linux_fd_t, fd, linux_loff_t, offset, size_t, count)
static inline LINUX_DEFINE_SYSCALL5_NORET(setxattr, char const*, path, char const*, name, void const*, value, size_t, size, int, flags)
static inline LINUX_DEFINE_SYSCALL5_NORET(lsetxattr, char const*, path, char const*, name, void const*, value, size_t, size, int, flags)
static inline LINUX_DEFINE_SYSCALL5_NORET(fsetxattr, linux_fd_t, fd, char const*, name, void const*, value, size_t, size, int, flags)
static inline LINUX_DEFINE_SYSCALL4_RET(getxattr, char const*, path, char const*, name, void*, value, size_t, size, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(lgetxattr, char const*, path, char const*, name, void*, value, size_t, size, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(fgetxattr, linux_fd_t, fd, char const*, name, void*, value, size_t, size, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(listxattr, char const*, path, char*, list, size_t, size, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(llistxattr, char const*, path, char*, list, size_t, size, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(flistxattr, linux_fd_t, fd, char*, list, size_t, size, size_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(removexattr, char const*, path, char const*, name)
static inline LINUX_DEFINE_SYSCALL2_NORET(lremovexattr, char const*, path, char const*, name)
static inline LINUX_DEFINE_SYSCALL2_NORET(fremovexattr, linux_fd_t, fd, char const*, name)
static inline LINUX_DEFINE_SYSCALL2_NORET(tkill, linux_pid_t, pid, int, sig)
static inline LINUX_DEFINE_SYSCALL1_RET(time, linux_time_t*, tloc, linux_time_t)
static inline LINUX_DEFINE_SYSCALL6_NORET(futex, uint32_t*, uaddr, int, op, uint32_t, val, struct linux_timespec_t*, utime, uint32_t*, uaddr2, uint32_t, val3)
static inline LINUX_DEFINE_SYSCALL3_NORET(sched_setaffinity, linux_pid_t, pid, unsigned int, len, unsigned long LINUX_SAFE_CONST*, user_mask_ptr)
static inline LINUX_DEFINE_SYSCALL3_NORET(sched_getaffinity, linux_pid_t, pid, unsigned int, len, unsigned long*, user_mask_ptr)
static inline LINUX_DEFINE_SYSCALL3_RET(lookup_dcookie, uint64_t, cookie64, char*, buf, size_t, len, size_t)
static inline LINUX_DEFINE_SYSCALL1_RET(epoll_create, int, size, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL5_NORET(remap_file_pages, void const*, start, size_t, size, unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
static inline LINUX_DEFINE_SYSCALL3_RET(getdents64, linux_fd_t, fd, struct linux_dirent64_t*, dirent, unsigned int, count, unsigned int)
static inline LINUX_DEFINE_SYSCALL1_RET(set_tid_address, int*, tidptr, linux_pid_t)
//restart_syscall
static inline LINUX_DEFINE_SYSCALL4_NORET(semtimedop, linux_semid_t, semid, struct linux_sembuf_t*, sops, unsigned int, nsops, struct linux_timespec_t const*, timeout)
static inline LINUX_DEFINE_SYSCALL4_NORET(fadvise64, linux_fd_t, fd, linux_loff_t, offset, size_t, len, int, advice)
static inline LINUX_DEFINE_SYSCALL3_NORET(timer_create, linux_clockid_t, which_clock, struct linux_sigevent_t*, timer_event_spec, linux_timer_t*, created_timer_id)
static inline LINUX_DEFINE_SYSCALL4_NORET(timer_settime, linux_timer_t, timer_id, int, flags, struct linux_itimerspec_t const*, new_setting, struct linux_itimerspec_t*, old_setting)
static inline LINUX_DEFINE_SYSCALL2_NORET(timer_gettime, linux_timer_t, timer_id, struct linux_itimerspec_t*, setting)
static inline LINUX_DEFINE_SYSCALL1_RET(timer_getoverrun, linux_timer_t, timer_id, int)
static inline LINUX_DEFINE_SYSCALL1_NORET(timer_delete, linux_timer_t, timer_id)
static inline LINUX_DEFINE_SYSCALL2_NORET(clock_settime, linux_clockid_t, which_clock, struct linux_timespec_t const*, tp)
static inline LINUX_DEFINE_SYSCALL2_NORET(clock_gettime, linux_clockid_t, which_clock, struct linux_timespec_t*, tp)
static inline LINUX_DEFINE_SYSCALL2_NORET(clock_getres, linux_clockid_t, which_clock, struct linux_timespec_t*, tp)
static inline LINUX_DEFINE_SYSCALL4_NORET(clock_nanosleep, linux_clockid_t, which_clock, int, flags, struct linux_timespec_t const*, rqtp, struct linux_timespec_t*, rmtp)
// exit_group
static inline LINUX_DEFINE_SYSCALL4_RET(epoll_wait, linux_fd_t, epfd, struct linux_epoll_event_t*, events, int, maxevents, int, timeout, int)
static inline LINUX_DEFINE_SYSCALL4_NORET(epoll_ctl, linux_fd_t, epfd, int, op, linux_fd_t, fd, struct linux_epoll_event_t*, event)
static inline LINUX_DEFINE_SYSCALL3_NORET(tgkill, linux_pid_t, tgid, linux_pid_t, pid, int, sig)
static inline LINUX_DEFINE_SYSCALL2_NORET(utimes, char LINUX_SAFE_CONST*, filename, struct linux_timeval_t LINUX_SAFE_CONST*, utimes)
static inline LINUX_DEFINE_SYSCALL6_NORET(mbind, void const*, start, size_t, len, unsigned long, mode, unsigned long const*, nmask, unsigned long, maxnode, unsigned int, flags)
static inline LINUX_DEFINE_SYSCALL3_NORET(set_mempolicy, int, mode, unsigned long const*, nmask, unsigned long, maxnode)
static inline LINUX_DEFINE_SYSCALL5_NORET(get_mempolicy, int*, policy, unsigned long*, nmask, unsigned long, maxnode, unsigned long, addr, unsigned long, flags)
static inline LINUX_DEFINE_SYSCALL4_RET(mq_open, char const*, name, int, oflag, linux_umode_t, mode, struct linux_mq_attr_t*, attr, linux_mqd_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(mq_unlink, char const*, name)
static inline LINUX_DEFINE_SYSCALL5_NORET(mq_timedsend, linux_mqd_t, mqdes, char const*, msg_ptr, size_t, msg_len, unsigned int, msg_prio, struct linux_timespec_t const*, abs_timeout)
static inline LINUX_DEFINE_SYSCALL5_RET(mq_timedreceive, linux_mqd_t, mqdes, char*, msg_ptr, size_t, msg_len, unsigned int*, msg_prio, struct linux_timespec_t const*, abs_timeout, size_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(mq_notify, linux_mqd_t, mqdes, struct linux_sigevent_t const*, notification)
static inline LINUX_DEFINE_SYSCALL3_NORET(mq_getsetattr, linux_mqd_t, mqdes, struct linux_mq_attr_t const*, mqstat, struct linux_mq_attr_t*, omqstat)
static inline LINUX_DEFINE_SYSCALL4_NORET(kexec_load, unsigned long, entry, unsigned long, nr_segments, struct linux_kexec_segment_t*, segments, unsigned long, flags)
static inline LINUX_DEFINE_SYSCALL5_NORET(waitid, int, which, linux_pid_t, pid, struct linux_siginfo_t*, infop, int, options, struct linux_rusage_t*, ru)
static inline LINUX_DEFINE_SYSCALL5_RET(add_key, char const*, type, char const*, description, void const*, payload, size_t, plen, linux_key_serial_t, destringid, linux_key_serial_t)
static inline LINUX_DEFINE_SYSCALL4_RET(request_key, char const*, type, char const*, description, char const*, callout_info, linux_key_serial_t, destringid, linux_key_serial_t)
static inline LINUX_DEFINE_SYSCALL5_RET(keyctl, int, cmd, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5, intptr_t)
static inline LINUX_DEFINE_SYSCALL3_NORET(ioprio_set, int, which, int, who, int, ioprio)
static inline LINUX_DEFINE_SYSCALL2_RET(ioprio_get, int, which, int, who, int)
static inline LINUX_DEFINE_SYSCALL0_RET(inotify_init, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_RET(inotify_add_watch, linux_fd_t, fd, char const*, path, uint32_t, mask, linux_wd_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(inotify_rm_watch, linux_fd_t, fd, linux_wd_t, wd)
static inline LINUX_DEFINE_SYSCALL4_RET(migrate_pages, linux_pid_t, pid, unsigned long, maxnode, unsigned long const*, from, unsigned long const*, to, int)
static inline LINUX_DEFINE_SYSCALL4_RET(openat, linux_fd_t, dfd, char const*, filename, int, flags, linux_umode_t, mode, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_NORET(mkdirat, linux_fd_t, dfd, char const*, pathname, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL4_NORET(mknodat, linux_fd_t, dfd, char const*, filename, linux_umode_t, mode, unsigned int, dev)
static inline LINUX_DEFINE_SYSCALL5_NORET(fchownat, linux_fd_t, dfd, char const*, filename, linux_uid_t, user, linux_gid_t, group, int, flag)
static inline LINUX_DEFINE_SYSCALL3_NORET(futimesat, linux_fd_t, dfd, char const*, filename, struct linux_timeval_t LINUX_SAFE_CONST*, utimes)
static inline LINUX_DEFINE_SYSCALL4_NORET(newfstatat, linux_fd_t, dfd, char const*, filename, struct linux_stat_t*, statbuf, int, flag)
static inline LINUX_DEFINE_SYSCALL3_NORET(unlinkat, linux_fd_t, dfd, char const*, pathname, int, flag)
static inline LINUX_DEFINE_SYSCALL4_NORET(renameat, linux_fd_t, olddfd, char const*, oldname, linux_fd_t, newdfd, char const*, newname)
static inline LINUX_DEFINE_SYSCALL5_NORET(linkat, linux_fd_t, olddfd, char const*, oldname, linux_fd_t, newdfd, char const*, newname, int, flags)
static inline LINUX_DEFINE_SYSCALL3_NORET(symlinkat, char const*, oldname, linux_fd_t, newdfd, char const*, newname)
static inline LINUX_DEFINE_SYSCALL4_RET(readlinkat, linux_fd_t, dfd, char const*, path, char*, buf, int, bufsiz, int)
static inline LINUX_DEFINE_SYSCALL3_NORET(fchmodat, linux_fd_t, dfd, char const*, filename, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL3_NORET(faccessat, linux_fd_t, dfd, char const*, filename, int, mode)
static inline LINUX_DEFINE_SYSCALL6_RET(pselect6, int, n, linux_fd_set_t*, inp, linux_fd_set_t*, outp, linux_fd_set_t*, exp, struct linux_timespec_t*, tsp, void*, sig, unsigned int)
static inline LINUX_DEFINE_SYSCALL5_RET(ppoll, struct linux_pollfd_t*, ufds, unsigned int, nfds, struct linux_timespec_t*, tsp, linux_sigset_t const*, sigmask, size_t, sigsetsize, unsigned int)
static inline LINUX_DEFINE_SYSCALL1_NORET(unshare, unsigned long, unshare_flags)
static inline LINUX_DEFINE_SYSCALL2_NORET(set_robust_list, struct linux_robust_list_head_t*, head, size_t, len)
static inline LINUX_DEFINE_SYSCALL3_NORET(get_robust_list, linux_pid_t, pid, struct linux_robust_list_head_t**, head_ptr, size_t*, len_ptr)
static inline LINUX_DEFINE_SYSCALL6_RET(splice, linux_fd_t, fd_in, linux_loff_t*, off_in, linux_fd_t, fd_out, linux_loff_t*, off_out, size_t, len, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(tee, linux_fd_t, fdin, linux_fd_t, fdout, size_t, len, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(sync_file_range, linux_fd_t, fd, linux_loff_t, offset, linux_loff_t, nbytes, unsigned int, flags)
static inline LINUX_DEFINE_SYSCALL4_RET(vmsplice, linux_fd_t, fd, struct linux_iovec_t const*, iov, unsigned long, nr_segs, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL6_NORET(move_pages, linux_pid_t, pid, unsigned long, nr_pages, void const**, pages, int const*, nodes, int*, status, int, flags)
static inline LINUX_DEFINE_SYSCALL4_NORET(utimensat, linux_fd_t, dfd, char const*, filename, struct linux_timespec_t LINUX_SAFE_CONST*, utimes, int, flags)
static inline LINUX_DEFINE_SYSCALL6_RET(epoll_pwait, linux_fd_t, epfd, struct linux_epoll_event_t*, events, int, maxevents, int, timeout, linux_sigset_t const*, sigmask, size_t, sigsetsize, int)
static inline LINUX_DEFINE_SYSCALL3_RET(signalfd, linux_fd_t, ufd, linux_sigset_t LINUX_SAFE_CONST*, user_mask, size_t, sizemask, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_RET(timerfd_create, int, clockid, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL1_RET(eventfd, unsigned int, count, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(fallocate, linux_fd_t, fd, int, mode, linux_loff_t, offset, linux_loff_t, len)
static inline LINUX_DEFINE_SYSCALL4_NORET(timerfd_settime, linux_fd_t, ufd, int, flags, struct linux_itimerspec_t const*, utmr, struct linux_itimerspec_t*, otmr)
static inline LINUX_DEFINE_SYSCALL2_NORET(timerfd_gettime, linux_fd_t, ufd, struct linux_itimerspec_t*, otmr)
static inline LINUX_DEFINE_SYSCALL4_RET(accept4, linux_fd_t, fd, struct linux_sockaddr_t*, upeer_sockaddr, int*, upeer_addrlen, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL4_RET(signalfd4, linux_fd_t, ufd, linux_sigset_t LINUX_SAFE_CONST*, user_mask, size_t, sizemask, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_RET(eventfd2, unsigned int, count, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL1_RET(epoll_create1, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_RET(dup3, linux_fd_t, oldfd, linux_fd_t, newfd, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(pipe2, linux_fd_t*, fildes, int, flags)
static inline LINUX_DEFINE_SYSCALL1_RET(inotify_init1, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL5_RET(preadv, linux_fd_t, fd, struct linux_iovec_t const*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h, size_t)
static inline LINUX_DEFINE_SYSCALL5_RET(pwritev, linux_fd_t, fd, struct linux_iovec_t const*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h, size_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(rt_tgsigqueueinfo, linux_pid_t, tgid, linux_pid_t, pid, int, sig, struct linux_siginfo_t*, uinfo)
static inline LINUX_DEFINE_SYSCALL5_RET(perf_event_open, struct linux_perf_event_attr_t*, attr_uptr, linux_pid_t, pid, int, cpu, linux_fd_t, group_fd, unsigned long, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL5_RET(recvmmsg, linux_fd_t, fd, struct linux_mmsghdr_t*, msg, unsigned int, vlen, unsigned int, flags, struct linux_timespec_t*, timeout, unsigned int)
static inline LINUX_DEFINE_SYSCALL2_RET(fanotify_init, unsigned int, flags, unsigned int, event_f_flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL5_NORET(fanotify_mark, linux_fd_t, fanotify_fd, unsigned int, flags, uint64_t, mask, linux_fd_t, fd, char const*, pathname)
static inline LINUX_DEFINE_SYSCALL4_NORET(prlimit64, linux_pid_t, pid, unsigned int, resource, struct linux_rlimit64_t const*, new_rlim, struct linux_rlimit64_t*, old_rlim)
static inline LINUX_DEFINE_SYSCALL5_NORET(name_to_handle_at, linux_fd_t, dfd, char const*, name, struct linux_file_handle_t*, handle, linux_fd_t*, mnt_id, int, flag)
static inline LINUX_DEFINE_SYSCALL3_RET(open_by_handle_at, linux_fd_t, mountdirfd, struct linux_file_handle_t*, handle, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_RET(clock_adjtime, linux_clockid_t, which_clock, struct linux_timex_t*, tx, int)
static inline LINUX_DEFINE_SYSCALL1_NORET(syncfs, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL4_RET(sendmmsg, linux_fd_t, fd, struct linux_mmsghdr_t*, msg, unsigned int, vlen, unsigned int, flags, unsigned int)
static inline LINUX_DEFINE_SYSCALL2_NORET(setns, linux_fd_t, fd, int, nstype)
static inline LINUX_DEFINE_SYSCALL3_NORET(getcpu, unsigned int*, cpu, unsigned int*, node, struct linux_getcpu_cache_t*, cache)
static inline LINUX_DEFINE_SYSCALL6_RET(process_vm_readv, linux_pid_t, pid, struct linux_iovec_t const*, lvec, size_t, liovcnt, struct linux_iovec_t const*, rvec, size_t, riovcnt, unsigned long, flags, size_t)
static inline LINUX_DEFINE_SYSCALL6_RET(process_vm_writev, linux_pid_t, pid, struct linux_iovec_t const*, lvec, size_t, liovcnt, struct linux_iovec_t const*, rvec, size_t, riovcnt, unsigned long, flags, size_t)
static inline LINUX_DEFINE_SYSCALL5_RET(kcmp, linux_pid_t, pid1, linux_pid_t, pid2, int, type, unsigned long, idx1, unsigned long, idx2, int)
static inline LINUX_DEFINE_SYSCALL3_NORET(finit_module, linux_fd_t, fd, char const*, uargs, int, flags)
static inline LINUX_DEFINE_SYSCALL3_NORET(sched_setattr, linux_pid_t, pid, struct linux_sched_attr_t*, attr, unsigned int, flags)
static inline LINUX_DEFINE_SYSCALL4_NORET(sched_getattr, linux_pid_t, pid, struct linux_sched_attr_t*, attr, unsigned int, size, unsigned int, flags)
static inline LINUX_DEFINE_SYSCALL5_NORET(renameat2, linux_fd_t, olddfd, char const*, oldname, linux_fd_t, newdfd, char const*, newname, unsigned int, flags)
static inline LINUX_DEFINE_SYSCALL3_RET(seccomp, unsigned int, op, unsigned int, flags, char const*, uargs, int)
static inline LINUX_DEFINE_SYSCALL3_RET(getrandom, char*, buf, size_t, count, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL2_RET(memfd_create, char const*, uname_ptr, unsigned int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL5_NORET(kexec_file_load, linux_fd_t, kernel_fd, linux_fd_t, initrd_fd, unsigned long, cmdline_len, char const*, cmdline_ptr, unsigned long, flags)
static inline LINUX_DEFINE_SYSCALL3_RET(bpf, int, cmd, union linux_bpf_attr_t*, attr, unsigned int, size, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL5_NORET(execveat, linux_fd_t, dfd, char const*, filename, char const* const*, argv, char const* const*, envp, int, flags)
static inline LINUX_DEFINE_SYSCALL1_RET(userfaultfd, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_RET(membarrier, int, cmd, int, flags, int)
static inline LINUX_DEFINE_SYSCALL3_NORET(mlock2, void const*, start, size_t, len, int, flags)
static inline LINUX_DEFINE_SYSCALL6_RET(copy_file_range, linux_fd_t, fd_in, linux_loff_t*, off_in, linux_fd_t, fd_out, linux_loff_t*, off_out, size_t, len, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL6_RET(preadv2, linux_fd_t, fd, struct linux_iovec_t const*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h, linux_rwf_t, flags, size_t)
static inline LINUX_DEFINE_SYSCALL6_RET(pwritev2, linux_fd_t, fd, struct linux_iovec_t const*, vec, unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h, linux_rwf_t, flags, size_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(pkey_mprotect, void const*, start, size_t, len, unsigned long, prot, linux_pkey_t, pkey)
static inline LINUX_DEFINE_SYSCALL2_RET(pkey_alloc, unsigned long, flags, unsigned long, init_val, linux_pkey_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(pkey_free, linux_pkey_t, pkey)
static inline LINUX_DEFINE_SYSCALL5_NORET(statx, linux_fd_t, dfd, char const*, path, unsigned int, flags, unsigned int, mask, struct linux_statx_t*, buffer)

// Syscalls
//------------------------------------------------------------------------------

#endif // HEADER_LIBLINUX_LINUX_H_INCLUDED
