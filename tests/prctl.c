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

static enum TestResult test_correct_usage(void)
{
	char const name[] = "the name";

	if (linux_prctl(linux_PR_SET_NAME, (uintptr_t)name, 0, 0, 0, 0))
		return TEST_RESULT_FAILURE;

	char buf[16];
	if (linux_prctl(linux_PR_GET_NAME, (uintptr_t)buf, 0, 0, 0, 0))
		return TEST_RESULT_FAILURE;

	if (strcmp(name, buf))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing prctl.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing prctl.\n");

	return ret;
}
