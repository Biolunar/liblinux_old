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

#ifndef HEADER_LIBLINUX_FCNTL_H_INCLUDED
#define HEADER_LIBLINUX_FCNTL_H_INCLUDED

#include <stdint.h>

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL1_RET(dup, linux_fd_t, fildes, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_RET(dup3, linux_fd_t, oldfd, linux_fd_t, newfd, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_RET(fcntl, linux_fd_t, fd, unsigned int, cmd, uintptr_t, arg, long)

#endif // HEADER_LIBLINUX_FCNTL_H_INCLUDED
