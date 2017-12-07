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

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

static linux_umode_t const mode = linux_S_IRUSR | linux_S_IWUSR | linux_S_IRGRP | linux_S_IWGRP | linux_S_IROTH | linux_S_IWOTH;
static char const* const filename = "some non existant file";

static enum TestResult test_segfault(void)
{
	if (linux_chmod(0, mode) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_filename(void)
{
	if (linux_chmod(filename, mode) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static linux_umode_t get_umask(void)
{
	mode_t const ret = umask(0);
	umask(ret);
	return (linux_umode_t)ret;
}

static enum TestResult test_correct_usage(void)
{
	enum TestResult ret = TEST_RESULT_SUCCESS;

	linux_fd_t fd = 0;
	if (linux_creat(filename, mode, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	linux_umode_t const new_mode = linux_S_IRUSR | linux_S_IWUSR;
	if (linux_chmod(filename, new_mode))
	{
		ret = TEST_RESULT_FAILURE;
		goto out;
	}

	struct linux_stat_t statbuf;
	memset(&statbuf, 0, sizeof statbuf);
	if (linux_fstat(fd, &statbuf))
	{
		ret = TEST_RESULT_OTHER_FAILURE;
		goto out;
	}

	linux_umode_t const umask = get_umask();
	if ((statbuf.st_mode & (linux_S_IRWXU | linux_S_IRWXG | linux_S_IRWXO)) != (new_mode & ~umask))
	{
		ret = TEST_RESULT_FAILURE;
		goto out;
	}

out:
	linux_close(fd);
	linux_unlink(filename);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing chmod.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_filename, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing chmod.\n");

	return ret;
}
