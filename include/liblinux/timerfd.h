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

#ifndef HEADER_LIBLINUX_TIMERFD_H_INCLUDED
#define HEADER_LIBLINUX_TIMERFD_H_INCLUDED

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL2_RET(timerfd_create, int, clockid, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(timerfd_settime, linux_fd_t, ufd, int, flags, struct linux_itimerspec_t const*, utmr, struct linux_itimerspec_t*, otmr)
static inline LINUX_DEFINE_SYSCALL2_NORET(timerfd_gettime, linux_fd_t, ufd, struct linux_itimerspec_t*, otmr)

#endif // HEADER_LIBLINUX_TIMERFD_H_INCLUDED
