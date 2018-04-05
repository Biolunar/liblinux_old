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

#ifndef HEADER_LIBLINUX_CAPABILITIES_H_INCLUDED
#define HEADER_LIBLINUX_CAPABILITIES_H_INCLUDED

#include <stdint.h>

#include <liblinux/syscall.h>

typedef struct linux_user_cap_header_struct_t
{
	uint32_t version;
	linux_pid_t pid;
} *linux_cap_user_header_t;
typedef struct linux_user_cap_data_struct_t
{
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
} *linux_cap_user_data_t;

static inline LINUX_DEFINE_SYSCALL2_NORET(capget, struct linux_user_cap_header_struct_t*, header, struct linux_user_cap_data_struct_t*, dataptr)
static inline LINUX_DEFINE_SYSCALL2_NORET(capset, struct linux_user_cap_header_struct_t*, header, struct linux_user_cap_data_struct_t const*, data)

#endif // HEADER_LIBLINUX_CAPABILITIES_H_INCLUDED
