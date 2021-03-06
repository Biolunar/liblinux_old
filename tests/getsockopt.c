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

static enum TestResult test_invalid_fd(void)
{
	if  (linux_getsockopt(linux_stderr + 1, linux_SOL_SOCKET, linux_SO_REUSEADDR, &(int){0}, &(int){sizeof(int)}) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_not_socket(void)
{
	if  (linux_getsockopt(linux_stderr, linux_SOL_SOCKET, linux_SO_REUSEADDR, &(int){0}, &(int){sizeof(int)}) != linux_ENOTSOCK)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if  (linux_getsockopt(fd, linux_SOL_SOCKET, linux_SO_REUSEADDR, 0, &(int){sizeof(int)}) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	int ret = 2;
	int len = sizeof ret;
	if  (linux_getsockopt(fd, linux_SOL_SOCKET, linux_SO_REUSEADDR, &ret, &len) || len != sizeof ret)
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

	printf("Start testing getsockopt.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(not_socket, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getsockopt.\n");

	return ret;
}
