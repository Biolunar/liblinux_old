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

#include <unistd.h>

static enum TestResult test_invalid_fd(void)
{
	if (linux_pipe2(0, linux_O_CLOEXEC) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_valid_function(void)
{
	linux_fd_t p[2];
	if (linux_pipe2(p, linux_O_CLOEXEC))
		return TEST_RESULT_FAILURE;

	if (p[0] != (linux_stderr + 1) || p[1] != (linux_stderr + 2))
		return TEST_RESULT_FAILURE;

	close((int)p[0]);
	close((int)p[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pipe2.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(valid_function, &ret);
	printf("Finished testing pipe2.\n");

	return ret;
}
