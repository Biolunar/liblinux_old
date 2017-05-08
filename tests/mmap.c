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

#include <limits.h>

#include <liblinux/linux.h>

#include <sys/mman.h>

static enum TestResult test_invalid_file(void)
{
	int const fd = -1;
	if (linux_mmap(0, sizeof(int), linux_PROT_READ, linux_MAP_PRIVATE, (linux_fd_t)fd, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_length(void)
{
	if (linux_mmap(0, 0, linux_PROT_READ, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_visibility(void)
{
	if (linux_mmap(0, sizeof(int), linux_PROT_READ, linux_MAP_ANONYMOUS, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_mmap(0, sizeof(int), linux_PROT_READ, linux_MAP_PRIVATE | linux_MAP_SHARED | linux_MAP_ANONYMOUS, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_alloc(void)
{
	void* ret = 0;
	size_t const length = sizeof(int);
	if (linux_mmap(0, length, linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &ret))
		return TEST_RESULT_FAILURE;

	int volatile* const p = ret;
	*p = INT_MAX;

	if (munmap(ret, length) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing mmap.\n");
	DO_TEST(invalid_file, &ret);
	DO_TEST(invalid_length, &ret);
	DO_TEST(invalid_visibility, &ret);
	DO_TEST(alloc, &ret);
	printf("Finished testing mmap.\n");

	return ret;
}
