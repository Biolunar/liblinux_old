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

#ifndef HEADER_LIBLINUX_FUTEX_H_INCLUDED
#define HEADER_LIBLINUX_FUTEX_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#include <liblinux/syscall.h>

struct linux_robust_list_t
{
	struct linux_robust_list_t* next;
};
struct linux_robust_list_head_t
{
	struct linux_robust_list_t list;
	long futex_offset;
	struct linux_robust_list_t* list_op_pending;
};

static inline LINUX_DEFINE_SYSCALL6_RET(futex, uint32_t*, uaddr, int, op, uint32_t, val, struct linux_timespec_t*, utime, uint32_t*, uaddr2, uint32_t, val3, unsigned int)
static inline LINUX_DEFINE_SYSCALL2_NORET(set_robust_list, struct linux_robust_list_head_t*, head, size_t, len)
static inline LINUX_DEFINE_SYSCALL3_NORET(get_robust_list, linux_pid_t, pid, struct linux_robust_list_head_t**, head_ptr, size_t*, len_ptr)

#endif // HEADER_LIBLINUX_FUTEX_H_INCLUDED
