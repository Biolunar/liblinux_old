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
	if  (linux_fsync(linux_stderr + 1) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_file(void)
{
	linux_fd_t pfd[2];
	if (linux_pipe2(pfd, linux_O_CLOEXEC))
		return TEST_RESULT_OTHER_FAILURE;

	if  (linux_fsync(pfd[1]) != linux_EINVAL)
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		return TEST_RESULT_FAILURE;
	}

	linux_close(pfd[0]);
	linux_close(pfd[1]);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	char const* const filename = "/tmp/liblinux_testfile";

	linux_fd_t fd;
	if (linux_open(filename, linux_O_RDWR | linux_O_CREAT, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if  (linux_fsync(fd))
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

	printf("Start testing fsync.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_file, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing fsync.\n");

	return ret;
}
