/*
 * Copyright 2017 Mahdi Khanalizadeh
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
#include <sys/types.h>

static char const* const filename = "some non existant file";

static enum TestResult test_segfault(void)
{
	if (linux_chown(0, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_filename(void)
{
	if (linux_chown(filename, 0, 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd = 0;
	if (linux_open(filename, linux_O_RDWR | linux_O_CLOEXEC | linux_O_CREAT, linux_S_IRUSR | linux_S_IWUSR | linux_S_IRGRP | linux_S_IWGRP | linux_S_IROTH | linux_S_IWOTH, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_close(fd))
		return TEST_RESULT_OTHER_FAILURE;

	uid_t const uid = geteuid();
	gid_t const gid = getegid();
	if (linux_chown(filename, uid, gid))
	{
		linux_unlink(filename);
		return TEST_RESULT_FAILURE;
	}

	if (linux_unlink(filename))
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing chown.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_filename, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing chown.\n");

	return ret;
}
