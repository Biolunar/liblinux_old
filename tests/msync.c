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

static enum TestResult test_invalid_alignment(void)
{
	if (linux_msync((void*)1, sizeof(int), linux_MS_SYNC) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_flags(void)
{
	if (linux_msync(0, sizeof(int), linux_MS_SYNC | linux_MS_ASYNC) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_msync(0, sizeof(int), (linux_MS_SYNC | linux_MS_ASYNC | linux_MS_INVALIDATE) + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_address(void)
{
	if (linux_msync(0, sizeof(int), linux_MS_SYNC) != linux_ENOMEM)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd = 0;
	if (linux_open("/tmp", linux_O_RDWR | linux_O_TMPFILE, linux_S_IRUSR | linux_S_IWUSR, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	char buf[512] = {0};
	if (linux_write(fd, buf, sizeof buf, 0))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	void* addr = 0;
	if (linux_mmap(0, sizeof buf, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE, fd, 0, &addr))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (linux_msync(addr, sizeof buf, linux_MS_SYNC))
	{
		linux_munmap(addr, sizeof buf);
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_munmap(addr, sizeof buf);
	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing msync.\n");
	DO_TEST(invalid_alignment, &ret);
	DO_TEST(invalid_flags, &ret);
	DO_TEST(invalid_address, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing msync.\n");

	return ret;
}
