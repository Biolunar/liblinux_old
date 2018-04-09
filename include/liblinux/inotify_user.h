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

#ifndef HEADER_LIBLINUX_INOTIFY_USER_H_INCLUDED
#define HEADER_LIBLINUX_INOTIFY_USER_H_INCLUDED

#include <stdint.h>

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL1_RET(inotify_init1, int, flags, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL3_RET(inotify_add_watch, linux_fd_t, fd, char const*, path, uint32_t, mask, linux_fd_t)
static inline LINUX_DEFINE_SYSCALL2_NORET(inotify_rm_watch, linux_fd_t, fd, linux_fd_t, wd)

#endif // HEADER_LIBLINUX_INOTIFY_USER_H_INCLUDED
