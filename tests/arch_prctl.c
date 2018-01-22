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

static enum TestResult test_segfault(void)
{
	if (linux_arch_prctl(linux_ARCH_GET_FS, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_operation(void)
{
	void* addr;
	if (linux_arch_prctl(0x1000, (uintptr_t)&addr) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	void* addr;
	if (linux_arch_prctl(linux_ARCH_GET_FS, (uintptr_t)&addr))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing arch_prctl.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_operation, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing arch_prctl.\n");

	return ret;
}
