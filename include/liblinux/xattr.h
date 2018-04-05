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

#ifndef HEADER_LIBLINUX_XATTR_H_INCLUDED
#define HEADER_LIBLINUX_XATTR_H_INCLUDED

#include <stddef.h>

#include <liblinux/syscall.h>

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

#endif // HEADER_LIBLINUX_XATTR_H_INCLUDED
