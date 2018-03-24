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

static char const* const filename = "some non existant file";

static enum TestResult test_segfault(void)
{
	if (linux_unlinkat(linux_AT_FDCWD, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_filename(void)
{
	if (linux_unlinkat(linux_AT_FDCWD, filename, 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd = 0;
	if (linux_creat(filename, linux_S_IRUSR | linux_S_IWUSR, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_unlinkat(linux_AT_FDCWD, filename, 0))
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	if (linux_close(fd))
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing unlinkat.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_filename, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing unlinkat.\n");

	return ret;
}
