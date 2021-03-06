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

#ifndef HEADER_LIBLINUX_SYNC_H_INCLUDED
#define HEADER_LIBLINUX_SYNC_H_INCLUDED

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL0_NORET(sync)
static inline LINUX_DEFINE_SYSCALL1_NORET(fsync, linux_fd_t, fd)
static inline LINUX_DEFINE_SYSCALL1_NORET(fdatasync, linux_fd_t, fd)
#ifdef LINUX_ARCH_WANT_SYNC_FILE_RANGE2
static inline LINUX_DEFINE_SYSCALL4_NORET(sync_file_range2, linux_fd_t, fd, unsigned int, flags, linux_loff_t, offset, linux_loff_t, nbytes)
#else
static inline LINUX_DEFINE_SYSCALL4_NORET(sync_file_range, linux_fd_t, fd, linux_loff_t, offset, linux_loff_t, nbytes, unsigned int, flags)
#endif
#undef LINUX_ARCH_WANT_SYNC_FILE_RANGE2

#endif // HEADER_LIBLINUX_SYNC_H_INCLUDED
