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

#ifndef HEADER_LIBLINUX_NAMEI_H_INCLUDED
#define HEADER_LIBLINUX_NAMEI_H_INCLUDED

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL4_NORET(mknodat, linux_fd_t, dfd, char const*, filename, linux_umode_t, mode, unsigned int, dev)
static inline LINUX_DEFINE_SYSCALL3_NORET(mkdirat, linux_fd_t, dfd, char const*, pathname, linux_umode_t, mode)
static inline LINUX_DEFINE_SYSCALL3_NORET(unlinkat, linux_fd_t, dfd, char const*, pathname, int, flag)
static inline LINUX_DEFINE_SYSCALL3_NORET(symlinkat, char const*, oldname, linux_fd_t, newdfd, char const*, newname)
static inline LINUX_DEFINE_SYSCALL5_NORET(linkat, linux_fd_t, olddfd, char const*, oldname, linux_fd_t, newdfd, char const*, newname, int, flags)
#ifdef LINUX_ARCH_WANT_RENAMEAT
static inline LINUX_DEFINE_SYSCALL4_NORET(renameat, linux_fd_t, olddfd, char const*, oldname, linux_fd_t, newdfd, char const*, newname)
#undef LINUX_ARCH_WANT_RENAMEAT
#endif

#endif // HEADER_LIBLINUX_NAMEI_H_INCLUDED
