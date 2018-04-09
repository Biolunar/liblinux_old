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

#ifndef HEADER_LIBLINUX_OPEN_H_INCLUDED
#define HEADER_LIBLINUX_OPEN_H_INCLUDED

#include <stdint.h>

#include <liblinux/syscall.h>

#if defined(LINUX_ARCH_ARM64) || defined(LINUX_ARCH_X86_64)
typedef linux_kernel_long_t linux_statfs_word;
#else
typedef uint32_t linux_statfs_word;
#endif
typedef struct
{
	int val[2];
} linux_kernel_fsid_t;
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

static inline LINUX_DEFINE_SYSCALL2_NORET(statfs, char const*, pathname, struct linux_statfs_t*, buf)
static inline LINUX_DEFINE_SYSCALL2_NORET(fstatfs, linux_fd_t, fd, struct linux_statfs_t*, buf)
static inline LINUX_DEFINE_SYSCALL2_NORET(truncate, char const*, path, long, length)
static inline LINUX_DEFINE_SYSCALL2_NORET(ftruncate, linux_fd_t, fd, unsigned long, length)

static inline LINUX_DEFINE_SYSCALL4_NORET(fallocate, linux_fd_t, fd, int, mode, linux_loff_t, offset, linux_loff_t, len)
static inline LINUX_DEFINE_SYSCALL3_NORET(faccessat, linux_fd_t, dfd, char const*, filename, int, mode)
static inline LINUX_DEFINE_SYSCALL1_NORET(chdir, char const*, filename)
static inline LINUX_DEFINE_SYSCALL1_NORET(fchdir, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL1_NORET(chroot, char const*, filename)
static inline LINUX_DEFINE_SYSCALL2_NORET(fchmod, linux_fd_t, fd, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL3_NORET(fchmodat, linux_fd_t, dfd, char const*, filename, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL5_NORET(fchownat, linux_fd_t, dfd, char const*, filename, linux_uid_t, user, linux_gid_t, group, int, flag)
static inline LINUX_DEFINE_SYSCALL3_NORET(fchown, linux_fd_t, fd, linux_uid_t, user, linux_gid_t, group)
static inline LINUX_DEFINE_SYSCALL4_RET(openat, linux_fd_t, dfd, char const*, filename, int, flags, linux_umode_t, mode, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL1_NORET(close, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL0_NORET(vhangup)

#endif // HEADER_LIBLINUX_OPEN_H_INCLUDED
