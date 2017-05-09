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
#include <liblinux/linux.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFER_SIZE 512

static enum TestResult test_invalid_fd(void)
{
	char buf[BUFFER_SIZE] = {0};
	if (linux_pread64(linux_stderr + 1, buf, sizeof buf, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	int const fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_pread64((linux_fd_t)fd, 0, BUFFER_SIZE, 0, 0) != linux_EFAULT)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_read_zero(void)
{
	int const fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[BUFFER_SIZE] = {0};
	size_t result = 0;
	if (linux_pread64((linux_fd_t)fd, buf, 0, 0, &result) || result)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_read(void)
{
	linux_loff_t const offset = 123;

	int const fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[BUFFER_SIZE] = {0};
	if (linux_pread64((linux_fd_t)fd, buf, sizeof buf, offset, 0))
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

	printf("Start testing pread64.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(read_zero, &ret);
	DO_TEST(read, &ret);
	printf("Finished testing pread64.\n");

	return ret;
}
