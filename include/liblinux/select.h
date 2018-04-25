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

#ifndef HEADER_LIBLINUX_SELECT_H_INCLUDED
#define HEADER_LIBLINUX_SELECT_H_INCLUDED

#include <stddef.h>

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL6_RET(pselect6, int, n, linux_fd_set_t*, inp, linux_fd_set_t*, outp, linux_fd_set_t*, exp, struct linux_timespec_t*, tsp, void*, sig, unsigned int)
static inline LINUX_DEFINE_SYSCALL5_RET(ppoll, struct linux_pollfd_t*, ufds, unsigned int, nfds, struct linux_timespec_t*, tsp, linux_sigset_t const*, sigmask, size_t, sigsetsize, unsigned int)

#endif // HEADER_LIBLINUX_SELECT_H_INCLUDED
