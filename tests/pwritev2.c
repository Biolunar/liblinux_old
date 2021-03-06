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

#define BUFFER_SIZE 512

static enum TestResult test_invalid_fd(void)
{
	char buf[BUFFER_SIZE] = {0};
	struct linux_iovec_t vec =
	{
		.iov_base = buf,
		.iov_len = sizeof buf,
	};
	if (linux_pwritev2(linux_stderr + 1, &vec, 1, 0, 0, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	// Cannot use /dev/null, because every write to it is successful.

	linux_fd_t fd;
	if (linux_open("/tmp", linux_O_WRONLY | linux_O_TMPFILE, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_iovec_t vec =
	{
		.iov_base = 0,
		.iov_len = BUFFER_SIZE,
	};
	if (linux_pwritev2((linux_fd_t)fd, &vec, 1, 0, 0, 0, 0) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_write_zero(void)
{
	linux_fd_t fd;
	if (linux_open("/dev/null", linux_O_WRONLY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	char buf[1] = {0};
	struct linux_iovec_t vec =
	{
		.iov_base = buf,
		.iov_len = 0,
	};
	size_t result = 0;
	if (linux_pwritev2((linux_fd_t)fd, &vec, 1, 0, 0, 0, &result) || result)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pwritev2.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(write_zero, &ret);
	printf("Finished testing pwritev2.\n");

	return ret;
}
