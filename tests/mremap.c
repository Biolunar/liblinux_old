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

static size_t const size = 0x1000;

static enum TestResult test_invalid_alignment(void)
{
	if (linux_mremap((void*)1, size, size * 2, linux_MREMAP_MAYMOVE, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_address(void)
{
	if (linux_mremap(0, size, size * 2, linux_MREMAP_MAYMOVE, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	void* addr = 0;
	// TODO: Using linux_mmap here because MAP_ANONYMOUS needs a feature test macro.
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	void* new_addr = 0;
	if (linux_mremap(addr, size, size * 2, linux_MREMAP_MAYMOVE, 0, &new_addr))
	{
		linux_munmap(addr, size);
		return TEST_RESULT_FAILURE;
	}
	if (!new_addr)
	{
		linux_munmap(addr, size);
		return TEST_RESULT_FAILURE;
	}

	linux_munmap(addr, size);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing mremap.\n");
	DO_TEST(invalid_alignment, &ret);
	DO_TEST(invalid_address, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing mremap.\n");

	return ret;
}
