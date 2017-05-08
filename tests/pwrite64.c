/*
 * Copyright 2017 Mahdi Khanalizadeh
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <liblinux/linux.h>

#define BUFFER_SIZE 512

static enum TestResult test_invalid_fd(void)
{
	char buf[BUFFER_SIZE] = {0};
	if (linux_write(linux_stderr + 1, buf, sizeof buf, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	// Cannot use /dev/null, because every write to it is successful.
	int const fd = open("/tmp", O_WRONLY | 020000000 | 00200000, S_IWUSR); // TODO: Use O_TMPFILE instead of 020000000 | 00200000
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_write((linux_fd_t)fd, 0, BUFFER_SIZE, 0) != linux_EFAULT)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_write_zero(void)
{
	int const fd = open("/dev/null", O_WRONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[1] = {0};
	size_t result = 0;
	if (linux_write((linux_fd_t)fd, buf, 0, &result) || result)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_write(void)
{
	int const fd = open("/tmp", O_WRONLY | 020000000 | 00200000, S_IWUSR); // TODO: Use O_TMPFILE instead of 020000000 | 00200000
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[BUFFER_SIZE] = {0};
	if (linux_write((linux_fd_t)fd, buf, sizeof buf, 0))
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pwrite64.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(write_zero, &ret);
	DO_TEST(write, &ret);
	printf("Finished testing pwrite64.\n");

	return ret;
}
