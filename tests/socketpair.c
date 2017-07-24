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

static enum TestResult test_invalid_address_family(void)
{
	linux_fd_t fds[2];
	enum linux_error_t const err = linux_socketpair(-1, linux_SOCK_STREAM, 0, fds);
	if (err != linux_EAFNOSUPPORT)
	{
		if (!err)
		{
			linux_close(fds[0]);
			linux_close(fds[1]);
		}
		return TEST_RESULT_FAILURE;
	}

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_type(void)
{
	linux_fd_t fds[2];
	enum linux_error_t const err = linux_socketpair(linux_AF_INET, -1, 0, fds);
	if (err != linux_EINVAL)
	{
		if (!err)
		{
			linux_close(fds[0]);
			linux_close(fds[1]);
		}
		return TEST_RESULT_FAILURE;
	}

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fds[2] = {(linux_fd_t)-1, (linux_fd_t)-1};
	enum linux_error_t const err = linux_socketpair(linux_AF_UNIX, linux_SOCK_STREAM, 0, fds);
	if (err || fds[0] == (linux_fd_t)-1 || fds[1] == (linux_fd_t)-1)
	{
		if (!err)
		{
			linux_close(fds[0]);
			linux_close(fds[1]);
		}
		return TEST_RESULT_FAILURE;
	}

	linux_close(fds[0]);
	linux_close(fds[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing socketpair.\n");
	DO_TEST(invalid_address_family, &ret);
	DO_TEST(invalid_type, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing socketpair.\n");

	return ret;
}
