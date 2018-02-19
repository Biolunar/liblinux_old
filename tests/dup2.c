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
	linux_fd_t fd;
	enum linux_error_t const err = linux_dup2(linux_stderr + 1, linux_stderr + 2, &fd);
	if (!err)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}
	if (err != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd; // Gets number 3.
	if (linux_open("/tmp", linux_O_RDWR | linux_O_TMPFILE, linux_S_IRWXU, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	linux_fd_t ret;
	if (linux_dup2(fd, fd + 1, &ret)) // Requests number 3 + 1.
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(ret);
	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing dup2.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing dup2.\n");

	return ret;
}
