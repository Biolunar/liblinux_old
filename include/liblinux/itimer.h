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

#ifndef HEADER_LIBLINUX_ITIMER_H_INCLUDED
#define HEADER_LIBLINUX_ITIMER_H_INCLUDED

#include <liblinux/syscall.h>

struct linux_itimerval_t
{
	struct linux_timeval_t it_interval;
	struct linux_timeval_t it_value;
};

static inline LINUX_DEFINE_SYSCALL2_NORET(getitimer, int, which, struct linux_itimerval_t*, value)
static inline LINUX_DEFINE_SYSCALL3_NORET(setitimer, int, which, struct linux_itimerval_t  const*, value, struct linux_itimerval_t*, ovalue)

#endif // HEADER_LIBLINUX_ITIMER_H_INCLUDED
