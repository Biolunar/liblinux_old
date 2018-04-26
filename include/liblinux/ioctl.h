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

#ifndef HEADER_LIBLINUX_IOCTL_H_INCLUDED
#define HEADER_LIBLINUX_IOCTL_H_INCLUDED

#include <stdint.h>

#include <liblinux/syscall.h>

static inline LINUX_DEFINE_SYSCALL3_RET(ioctl, linux_fd_t, fd, unsigned int, cmd, uintptr_t, arg, int)

#if defined(LINUX_ARCH_ARM64)
#include "arm64/ioctls.h"
#elif defined(LINUX_ARCH_X86)
#include "x86/ioctls.h"
#elif defined(LINUX_ARCH_X32)
#include "x32/ioctls.h"
#elif defined(LINUX_ARCH_X86_64)
#include "x86_64/ioctls.h"
#else
#error "Unknown architecture"
#endif

#endif // HEADER_LIBLINUX_IOCTL_H_INCLUDED
