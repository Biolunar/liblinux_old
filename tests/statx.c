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

static enum TestResult test_invalid_file(void)
{
	if (linux_statx(linux_AT_FDCWD, "some very non existant name", 0, linux_STATX_ALL, 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	if (linux_statx(linux_AT_FDCWD, "", 0, linux_STATX_ALL, 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	if (linux_statx(linux_AT_FDCWD, 0, 0, linux_STATX_ALL, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_real_file(void)
{
	struct linux_statx_t stat;
	if (linux_statx(linux_AT_FDCWD, "/proc/self/maps", 0, linux_STATX_ALL, &stat))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing statx.\n");
	DO_TEST(invalid_file, &ret);
	DO_TEST(real_file, &ret);
	printf("Finished testing statx.\n");

	return ret;
}
