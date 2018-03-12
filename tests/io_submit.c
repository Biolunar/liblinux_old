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

#include "test.h"
#include <liblinux/linux.h>

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

static enum TestResult test_segfault(void)
{
	linux_aio_context_t context = 0;
	if (linux_io_setup(1, &context))
		return TEST_RESULT_OTHER_FAILURE;

	long ret;
	if (linux_io_submit(context, 1, 0, &ret) != linux_EFAULT)
	{
		linux_io_destroy(context);
		return TEST_RESULT_FAILURE;
	}

	linux_io_destroy(context);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_nr(void)
{
	linux_aio_context_t context = 0;
	if (linux_io_setup(1, &context))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_iocb_t iocb;
	memset(&iocb, 0, sizeof iocb);
	struct linux_iocb_t* array[] = { &iocb };
	long ret;
	if (linux_io_submit(context, -1, array, &ret) != linux_EINVAL)
	{
		linux_io_destroy(context);
		return TEST_RESULT_FAILURE;
	}

	linux_io_destroy(context);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_open("/tmp", linux_O_RDWR | linux_O_TMPFILE, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	linux_aio_context_t context = 0;
	if (linux_io_setup(1, &context))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char const msg[] = "test message";
	struct linux_iocb_t iocb =
	{
		.aio_lio_opcode = linux_IOCB_CMD_PWRITE,
		.aio_fildes = fd,
		.aio_buf = (uint64_t)msg,
		.aio_nbytes = sizeof msg,
	};
	long ret;
	if (linux_io_submit(context, 1, (struct linux_iocb_t*[]){&iocb}, &ret) || ret != 1)
	{
		linux_io_destroy(context);
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	struct linux_io_event_t event;
	long events_read;
	if (linux_io_getevents(context, 1, 1, &event, 0, &events_read) || events_read != 1)
	{
		linux_io_destroy(context);
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char buf[sizeof msg];
	size_t bytes_read;
	if (linux_pread64(fd, buf, sizeof buf, 0, &bytes_read))
	{
		linux_io_destroy(context);
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (memcmp(buf, msg, bytes_read))
		return TEST_RESULT_FAILURE;

	linux_io_destroy(context);
	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing io_submit.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_nr, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing io_submit.\n");

	return ret;
}
