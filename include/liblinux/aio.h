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

#ifndef HEADER_LIBLINUX_AIO_H_INCLUDED
#define HEADER_LIBLINUX_AIO_H_INCLUDED

#include <stdint.h>

#include <liblinux/syscall.h>

typedef linux_kernel_ulong_t linux_aio_context_t;
struct linux_iocb_t
{
	uint64_t aio_data;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t aio_key;
	linux_kernel_rwf_t aio_rw_flags;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	linux_kernel_rwf_t aio_rw_flags;
	uint32_t aio_key;
#else
#error "Unknown byte order."
#endif
	uint16_t aio_lio_opcode;
	int16_t aio_reqprio;
	uint32_t aio_fildes;
	uint64_t aio_buf;
	uint64_t aio_nbytes;
	int64_t aio_offset;
	uint64_t aio_reserved2;
	uint32_t aio_flags;
	uint32_t aio_resfd;
};
struct linux_io_event_t
{
	uint64_t data;
	uint64_t obj;
	int64_t res;
	int64_t res2;
};

static inline LINUX_DEFINE_SYSCALL2_NORET(io_setup, unsigned int, nr_events, linux_aio_context_t*, context)
static inline LINUX_DEFINE_SYSCALL1_NORET(io_destroy, linux_aio_context_t, context)
static inline LINUX_DEFINE_SYSCALL3_RET(io_submit, linux_aio_context_t, context, long, count, struct linux_iocb_t const* const*, iocbpp, long)
static inline LINUX_DEFINE_SYSCALL3_NORET(io_cancel, linux_aio_context_t, context, struct linux_iocb_t const*, iocb, struct linux_io_event_t*, result)
static inline LINUX_DEFINE_SYSCALL5_RET(io_getevents, linux_aio_context_t, context, long, min_count, long, count, struct linux_io_event_t*, events, struct linux_timespec_t*, timeout, long)

#endif // HEADER_LIBLINUX_AIO_H_INCLUDED
