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

#ifndef HEADER_LIBLINUX_NAMESPACE_H_INCLUDED
#define HEADER_LIBLINUX_NAMESPACE_H_INCLUDED

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL2_NORET(umount, char const*, name, int, flags)
static inline LINUX_DEFINE_SYSCALL5_NORET(mount, char const*, dev_name, char const*, dir_name, char const*, type, unsigned long, flags, void const*, data)
static inline LINUX_DEFINE_SYSCALL2_NORET(pivot_root, char const*, new_root, char const*, put_old)

#endif // HEADER_LIBLINUX_NAMESPACE_H_INCLUDED
