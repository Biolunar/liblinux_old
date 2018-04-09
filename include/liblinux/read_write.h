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

#ifndef HEADER_LIBLINUX_READ_WRITE_H_INCLUDED
#define HEADER_LIBLINUX_READ_WRITE_H_INCLUDED

#include <stddef.h>

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL3_RET(lseek, linux_fd_t, fd, linux_off_t, offset, unsigned int, whence, linux_off_t)
static inline LINUX_DEFINE_SYSCALL3_RET(read, linux_fd_t, fd, void*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(write, linux_fd_t, fd, void const*, buf, size_t, count, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(readv, linux_fd_t, fd, struct linux_iovec_t const*, vec, size_t, vlen, size_t)
static inline LINUX_DEFINE_SYSCALL3_RET(writev, linux_fd_t, fd, struct linux_iovec_t const*, vec, size_t, vlen, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(pread64, linux_fd_t, fd, void*, buf, size_t, count, linux_loff_t, pos, size_t)
static inline LINUX_DEFINE_SYSCALL4_RET(pwrite64, linux_fd_t, fd, void const*, buf, size_t, count, linux_loff_t, pos, size_t)
static inline LINUX_DEFINE_SYSCALL5_RET(preadv, linux_fd_t, fd, struct linux_iovec_t const*, vec, size_t, vlen, unsigned long, pos_l, unsigned long, pos_h, size_t)
static inline LINUX_DEFINE_SYSCALL5_RET(pwritev, linux_fd_t, fd, struct linux_iovec_t const*, vec, size_t, vlen, unsigned long, pos_l, unsigned long, pos_h, size_t)

#endif // HEADER_LIBLINUX_READ_WRITE_H_INCLUDED
