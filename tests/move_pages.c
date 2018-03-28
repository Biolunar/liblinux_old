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
	int status = 0;
	if (linux_move_pages(0, 1, 0, 0, &status, linux_MPOL_MF_MOVE) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	void* mem;
	if (linux_mmap(0, linux_PAGE_SIZE, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &mem))
		return TEST_RESULT_OTHER_FAILURE;

	void const* page = mem;
	int status = 0;

	if (linux_move_pages(0, 1, &page, 0, &status, linux_MPOL_MF_MOVE))
	{
		linux_munmap(mem, linux_PAGE_SIZE);
		return TEST_RESULT_FAILURE;
	}

	linux_munmap(mem, linux_PAGE_SIZE);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing move_pages.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing move_pages.\n");

	return ret;
}
