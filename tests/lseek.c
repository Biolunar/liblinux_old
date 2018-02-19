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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static enum TestResult test_invalid_file(void)
{
	if (linux_lseek(linux_stderr + 1, 0, linux_SEEK_SET, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	if (linux_lseek(linux_stdin, 0, linux_SEEK_SET, 0) != linux_ESPIPE)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_whence(void)
{
	int const fd = open("/proc/self/maps", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_lseek((linux_fd_t)fd, 0, linux_SEEK_MAX + 1, 0) != linux_EINVAL)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_out_of_bounds(void)
{
	int const fd = open("/proc/self/maps", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_lseek((linux_fd_t)fd, -1, linux_SEEK_SET, 0) != linux_EINVAL)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_return_value(void)
{
	int const fd = open("/proc/self/maps", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	linux_off_t ret = 0;

	if (linux_lseek((linux_fd_t)fd, 10, linux_SEEK_SET, &ret) || ret != 10)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	if (linux_lseek((linux_fd_t)fd, -5, linux_SEEK_CUR, &ret) || ret != 5)
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

	printf("Start testing lseek.\n");
	DO_TEST(invalid_file, &ret);
	DO_TEST(invalid_whence, &ret);
	DO_TEST(out_of_bounds, &ret);
	DO_TEST(return_value, &ret);
	printf("Finished testing lseek.\n");

	return ret;
}
