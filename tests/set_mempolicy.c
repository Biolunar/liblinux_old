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

static enum TestResult test_segfault(void)
{
	if (linux_set_mempolicy(linux_MPOL_BIND, (unsigned long const*)-1, 1000) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_mask(void)
{
	unsigned long mask[100];
	memset(mask, 0, sizeof mask);
	mask[0] = 0x1;
	if (linux_set_mempolicy(linux_MPOL_DEFAULT, mask, 100) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	if (linux_set_mempolicy(linux_MPOL_DEFAULT, 0, 0))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing set_mempolicy.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_mask, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing set_mempolicy.\n");

	return ret;
}
