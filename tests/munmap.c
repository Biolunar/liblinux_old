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

static enum TestResult test_invalid_address(void)
{
	// Address 0x1 is not aligned to a page boundary.
	if (linux_munmap((void*)1, sizeof(int)) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_use(void)
{
	size_t const size = sizeof(int);
	void* addr = 0;
	// TODO: Using linux_mmap here because MAP_ANONYMOUS needs a feature test macro.
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_munmap(addr, size))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing munmap.\n");
	DO_TEST(invalid_address, &ret);
	DO_TEST(correct_use, &ret);
	printf("Finished testing munmap.\n");

	return ret;
}
