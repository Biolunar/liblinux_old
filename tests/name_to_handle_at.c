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

static enum TestResult test_segfault(void)
{
	if (linux_name_to_handle_at(linux_AT_FDCWD, 0, 0, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	char const filename[] = "some file";

	linux_fd_t fd;
	if (linux_open(filename, linux_O_RDWR | linux_O_CREAT, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;
	linux_close(fd);

	struct linux_file_handle_t temp = { .handle_bytes = 0 };
	linux_fd_t mount;
	if (linux_name_to_handle_at(linux_AT_FDCWD, filename, &temp, &mount, 0) != linux_EOVERFLOW)
	{
		linux_unlink(filename);
		return TEST_RESULT_FAILURE;
	}

	struct linux_file_handle_t* const handle = malloc(sizeof *handle + temp.handle_bytes);
	if (!handle)
		return TEST_RESULT_OTHER_FAILURE;
	handle->handle_bytes = temp.handle_bytes;

	if (linux_name_to_handle_at(linux_AT_FDCWD, filename, handle, &mount, 0))
	{
		free(handle);
		linux_unlink(filename);
		return TEST_RESULT_FAILURE;
	}

	free(handle);
	linux_unlink(filename);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing name_to_handle_at.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing name_to_handle_at.\n");

	return ret;
}
