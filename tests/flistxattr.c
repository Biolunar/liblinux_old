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

static enum TestResult test_buffer_too_small(void)
{
	char const* const filename = "some test file";

	linux_fd_t fd;
	if (linux_open(filename, linux_O_RDWR | linux_O_CREAT, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	char const name[] = "user.liblinux";
	char const data[] = "test data";
	if (linux_setxattr(filename, name, data, sizeof data, linux_XATTR_CREATE))
	{
		linux_close(fd);
		linux_unlink(filename);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char buf[sizeof name - 1];
	size_t ret;
	if (linux_flistxattr(fd, buf, sizeof buf, &ret) != linux_ERANGE)
	{
		linux_close(fd);
		linux_unlink(filename);
		return TEST_RESULT_FAILURE;
	}


	linux_close(fd);
	linux_unlink(filename);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	char const* const filename = "some test file";

	linux_fd_t fd;
	if (linux_open(filename, linux_O_RDWR | linux_O_CREAT, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	char const name[] = "user.liblinux";
	char const data[] = "test data";
	if (linux_setxattr(filename, name, data, sizeof data, linux_XATTR_CREATE))
	{
		linux_close(fd);
		linux_unlink(filename);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char buf[512];
	size_t ret;
	if (linux_flistxattr(fd, buf, sizeof buf, &ret))
	{
		linux_close(fd);
		linux_unlink(filename);
		return TEST_RESULT_FAILURE;
	}

	if (memcmp(buf, name, ret))
	{
		linux_close(fd);
		linux_unlink(filename);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	linux_unlink(filename);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing flistxattr.\n");
	DO_TEST(buffer_too_small, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing flistxattr.\n");

	return ret;
}
