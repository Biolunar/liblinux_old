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
	int i = 5;
	struct linux_iovec_t const vec =
	{
		.iov_base = &i,
		.iov_len = sizeof i,
	};

	size_t ret;
	if (linux_vmsplice(linux_stderr + 1, &vec, 1, 0, &ret) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t pfd[2];
	if (linux_pipe(pfd))
		return TEST_RESULT_OTHER_FAILURE;

	int i = 5;
	struct linux_iovec_t const vec =
	{
		.iov_base = &i,
		.iov_len = sizeof i,
	};

	size_t ret = 0;
	if (linux_vmsplice(pfd[1], &vec, 1, 0, &ret))
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		return TEST_RESULT_FAILURE;
	}

	linux_close(pfd[0]);
	linux_close(pfd[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing vmsplice.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing vmsplice.\n");

	return ret;
}
