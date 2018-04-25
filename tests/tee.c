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
	unsigned int ret;
	if (linux_tee(linux_stdin, linux_stderr + 1, linux_PAGE_SIZE, 0, &ret) != linux_EBADF)
		return TEST_RESULT_FAILURE;
	if (linux_tee(linux_stderr + 1, linux_stdout, linux_PAGE_SIZE, 0, &ret) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t rnd;
	if (linux_open("/dev/urandom", linux_O_RDONLY, 0, &rnd))
		return TEST_RESULT_OTHER_FAILURE;

	linux_fd_t p1[2];
	if (linux_pipe(p1))
	{
		linux_close(rnd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (linux_splice(rnd, 0, p1[1], 0, linux_PAGE_SIZE, 0, 0))
	{
		linux_close(p1[0]);
		linux_close(p1[1]);
		linux_close(rnd);
		return TEST_RESULT_OTHER_FAILURE;
	}
	linux_close(rnd);

	linux_fd_t p2[2];
	if (linux_pipe(p2))
	{
		linux_close(p1[0]);
		linux_close(p1[1]);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (linux_tee(p1[0], p2[1], linux_PAGE_SIZE, 0, 0))
	{
		linux_close(p1[0]);
		linux_close(p1[1]);
		linux_close(p2[0]);
		linux_close(p2[1]);
		return TEST_RESULT_FAILURE;
	}

	linux_close(p1[0]);
	linux_close(p1[1]);
	linux_close(p2[0]);
	linux_close(p2[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing tee.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing tee.\n");

	return ret;
}
