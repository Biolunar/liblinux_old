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
	if  (linux_getcwd(0, linux_PATH_MAX, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_insufficient_size(void)
{
	char buf = 0;

	if  (linux_getcwd(&buf, 1, 0) != linux_ERANGE)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	char buf[linux_PATH_MAX];
	memset(buf, 0, sizeof buf);

	int ret = 0;
	if  (linux_getcwd(buf, sizeof buf, &ret))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing getcwd.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(insufficient_size, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getcwd.\n");

	return ret;
}
