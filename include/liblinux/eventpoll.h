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

#ifndef HEADER_LIBLINUX_EVENTPOLL_H_INCLUDED
#define HEADER_LIBLINUX_EVENTPOLL_H_INCLUDED

#include <stdint.h>
#include <stddef.h>

#include <liblinux/syscall.h>

struct linux_epoll_event_t
{
	uint32_t events;

#ifdef LINUX_ARCH_X86_64
	// TODO: Following two 32 bit members should be one 64 bit memeber but with 32 bit alignment.
	uint32_t data_lo;
	uint32_t data_hi;
#else
	uint64_t data;
#endif
};
#ifdef LINUX_ARCH_X86_64
_Static_assert(sizeof(struct linux_epoll_event_t) == 4 + 8, "struct linux_epoll_event_t must have no padding on x86_64.");
#endif

static inline LINUX_DEFINE_SYSCALL1_RET(epoll_create1, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL4_NORET(epoll_ctl, linux_fd_t, epfd, int, op, linux_fd_t, fd, struct linux_epoll_event_t*, event)
static inline LINUX_DEFINE_SYSCALL6_RET(epoll_pwait, linux_fd_t, epfd, struct linux_epoll_event_t*, events, int, maxevents, int, timeout, linux_sigset_t const*, sigmask, size_t, sigsetsize, int)

#endif // HEADER_LIBLINUX_EVENTPOLL_H_INCLUDED
