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

static enum TestResult test_invalid_alignment(void)
{
	unsigned char vec = 0;
	if (linux_mincore((void*)1, sizeof(int), &vec) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_vector(void)
{
	size_t const size = sizeof(int);
	void* addr = 0;
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_mincore(addr, size, 0) != linux_EFAULT)
	{
		linux_munmap(addr, size);
		return TEST_RESULT_FAILURE;
	}

	linux_munmap(addr, size);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_not_mapped_address(void)
{
	unsigned char vec = 0;
	if (linux_mincore(0, sizeof(int), &vec) != linux_ENOMEM)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	size_t const size = 2 * 0x1000;
	void* addr = 0;
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	unsigned char vec[2] = {0, 0};
	if (linux_mincore(addr, size, vec))
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

	printf("Start testing mincore.\n");
	DO_TEST(invalid_alignment, &ret);
	DO_TEST(not_mapped_address, &ret);
	DO_TEST(invalid_vector, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing mincore.\n");

	return ret;
}
