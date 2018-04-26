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

#ifndef HEADER_LIBLINUX_STAT_H_INCLUDED
#define HEADER_LIBLINUX_STAT_H_INCLUDED

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL4_RET(readlinkat, linux_fd_t, dfd, char const*, pathname, char*, buf, int, bufsiz, unsigned int)
static inline LINUX_DEFINE_SYSCALL4_NORET(newfstatat, linux_fd_t, dfd, char const*, filename, struct linux_stat_t*, statbuf, int, flag)
static inline LINUX_DEFINE_SYSCALL2_NORET(newfstat, linux_fd_t, fd, struct linux_stat_t*, statbuf)

#endif // HEADER_LIBLINUX_STAT_H_INCLUDED
