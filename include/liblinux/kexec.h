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

#ifndef HEADER_LIBLINUX_KEXEC_H_INCLUDED
#define HEADER_LIBLINUX_KEXEC_H_INCLUDED

#include <stddef.h>

#include <liblinux/syscall.h>

struct linux_kexec_segment_t
{
	void const* buf;
	size_t bufsz;
	void const* mem;
	size_t memsz;
};

static inline LINUX_DEFINE_SYSCALL4_NORET(kexec_load, unsigned long, entry, unsigned long, nr_segments, struct linux_kexec_segment_t const*, segments, unsigned long, flags)

#endif // HEADER_LIBLINUX_KEXEC_H_INCLUDED
