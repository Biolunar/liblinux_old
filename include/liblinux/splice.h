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

#ifndef HEADER_LIBLINUX_SPLICE_H_INCLUDED
#define HEADER_LIBLINUX_SPLICE_H_INCLUDED

#include <stddef.h>

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL4_RET(vmsplice, linux_fd_t, fd, struct linux_iovec_t const*, iov, unsigned long, nr_segs, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL6_RET(splice, linux_fd_t, fd_in, linux_loff_t*, off_in, linux_fd_t, fd_out, linux_loff_t*, off_out, size_t, len, unsigned int, flags, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(tee, linux_fd_t, fdin, linux_fd_t, fdout, size_t, len, unsigned int, flags, unsigned int)

#endif // HEADER_LIBLINUX_SPLICE_H_INCLUDED
