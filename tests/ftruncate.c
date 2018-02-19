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
	if  (linux_ftruncate(linux_stderr + 1, 1) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_file_type(void)
{
	if  (linux_ftruncate(linux_stdout, 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_open(".", linux_O_RDWR | linux_O_TMPFILE, linux_S_IRUSR | linux_S_IWUSR, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if  (linux_ftruncate(fd, 512))
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

	printf("Start testing ftruncate.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_file_type, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing ftruncate.\n");

	return ret;
}
