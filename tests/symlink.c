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

static char const* const newname = "some non existant filename";

static enum TestResult test_segfault(void)
{
	enum linux_error_t err;

	err = linux_symlink(0, newname);
	if (!err)
	{
		linux_unlink(newname);
		return TEST_RESULT_FAILURE;
	}
	if (err != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_symlink("oldname", 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	if (linux_symlink("oldname", newname))
		return TEST_RESULT_FAILURE;

	linux_unlink(newname);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing symlink.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing symlink.\n");

	return ret;
}
