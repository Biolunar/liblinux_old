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
	if (linux_link(0, filename) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_link(0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_filename(void)
{
	if (linux_link(filename, "some new filename") != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	char const* const old_test_file = "old test file";
	char const* const new_test_file = "new test file";

	linux_fd_t fd = 0;
	if (linux_creat(old_test_file, linux_S_IRUSR | linux_S_IWUSR, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_close(fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_link(old_test_file, new_test_file))
		return TEST_RESULT_FAILURE;

	if (linux_unlink(old_test_file))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_unlink(new_test_file))
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing link.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_filename, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing link.\n");

	return ret;
}
