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

#include <string.h>

static enum TestResult test_invalid_addr(void)
{
	if (linux_remap_file_pages(0, linux_PAGE_SIZE, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	size_t const size = linux_PAGE_SIZE * 2;

	void* mem;
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_SHARED | linux_MAP_ANONYMOUS, 0, 0, &mem))
		return TEST_RESULT_OTHER_FAILURE;
	memset(mem, 0, size);

	char const data[] = "some test data";
	memcpy((unsigned char*)mem + size / 2, data, sizeof data);

	if (linux_remap_file_pages(mem, size / 2, 0, 1, 0))
	{
		linux_munmap(mem, size);
		return TEST_RESULT_FAILURE;
	}

	if (memcmp((unsigned char*)mem, data, sizeof data))
		return TEST_RESULT_FAILURE;

	linux_munmap(mem, size);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing remap_file_pages.\n");
	DO_TEST(invalid_addr, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing remap_file_pages.\n");

	return ret;
}
