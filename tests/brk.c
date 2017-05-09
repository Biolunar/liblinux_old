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

#include <limits.h>
#include <stdint.h>

static enum TestResult test_invalid_address(void)
{
	void* base = 0;
	if (linux_brk(0, &base))
		return TEST_RESULT_FAILURE;

	void* ret = 0;
	if (linux_brk((void*)UINTPTR_MAX, &ret) || base != ret)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_alloc(void)
{
	void* base = 0;
	if (linux_brk(0, &base))
		return TEST_RESULT_FAILURE;

	size_t const size = sizeof(int);
	void* ret = 0;
	if (linux_brk((char*)base + size, &ret) || ret != ((char*)base + size))
		return TEST_RESULT_FAILURE;

	int volatile* const p = ret;
	*p = INT_MAX;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing brk.\n");
	DO_TEST(invalid_address, &ret);
	DO_TEST(alloc, &ret);
	printf("Finished testing brk.\n");

	return ret;
}
