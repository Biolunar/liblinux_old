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

#ifndef HEADER_LIBLINUX_UTIMES_H_INCLUDED
#define HEADER_LIBLINUX_UTIMES_H_INCLUDED

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL4_NORET(utimensat, linux_fd_t, dfd, char const*, filename, struct linux_timespec_t const*, utimes, int, flags)

#endif // HEADER_LIBLINUX_UTIMES_H_INCLUDED
