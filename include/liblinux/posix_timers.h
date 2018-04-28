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

#ifndef HEADER_LIBLINUX_POSIX_TIMERS_H_INCLUDED
#define HEADER_LIBLINUX_POSIX_TIMERS_H_INCLUDED

#include <liblinux/syscall.h>

typedef linux_kernel_timer_t linux_timer_t;

static inline LINUX_DEFINE_SYSCALL3_NORET(timer_create, linux_clockid_t, which_clock, struct linux_sigevent_t const*, timer_event_spec, linux_timer_t*, created_timer_id)
static inline LINUX_DEFINE_SYSCALL2_NORET(timer_gettime, linux_timer_t, timer_id, struct linux_itimerspec_t*, setting)
static inline LINUX_DEFINE_SYSCALL1_RET(timer_getoverrun, linux_timer_t, timer_id, unsigned int)
static inline LINUX_DEFINE_SYSCALL4_NORET(timer_settime, linux_timer_t, timer_id, int, flags, struct linux_itimerspec_t const*, new_setting, struct linux_itimerspec_t*, old_setting)
static inline LINUX_DEFINE_SYSCALL1_NORET(timer_delete, linux_timer_t, timer_id)
static inline LINUX_DEFINE_SYSCALL2_NORET(clock_settime, linux_clockid_t, which_clock, struct linux_timespec_t const*, tp)
static inline LINUX_DEFINE_SYSCALL2_NORET(clock_gettime, linux_clockid_t, which_clock, struct linux_timespec_t*, tp)
static inline LINUX_DEFINE_SYSCALL2_NORET(clock_getres, linux_clockid_t, which_clock, struct linux_timespec_t*, tp)
static inline LINUX_DEFINE_SYSCALL4_NORET(clock_nanosleep, linux_clockid_t, which_clock, int, flags, struct linux_timespec_t const*, rqtp, struct linux_timespec_t*, rmtp)

#endif // HEADER_LIBLINUX_POSIX_TIMERS_H_INCLUDED
