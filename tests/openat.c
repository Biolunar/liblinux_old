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

static enum TestResult test_opening_file(void)
{
	linux_fd_t fd = 0;
	if (linux_openat(linux_AT_FDCWD, "/dev/urandom", linux_O_RDONLY, 0, &fd))
		return TEST_RESULT_FAILURE;

	if (close((int)fd) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_creating_file(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	char const* const filename = "tmp_file";

	linux_fd_t fd = 0;
	if (linux_openat(linux_AT_FDCWD, filename, linux_O_RDWR | linux_O_CLOEXEC | linux_O_CREAT | linux_O_EXCL, linux_S_IRUSR | linux_S_IWUSR, &fd))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	if (unlink(filename) == -1)
		goto cleanup;

	ret = TEST_RESULT_SUCCESS;

cleanup:
	close((int)fd);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing openat.\n");
	DO_TEST(opening_file, &ret);
	DO_TEST(creating_file, &ret);
	printf("Finished testing openat.\n");

	return ret;
}
