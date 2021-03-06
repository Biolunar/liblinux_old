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
	if (linux_setrlimit(linux_RLIMIT_NOFILE, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_resource(void)
{
	struct linux_rlimit_t const rlim =
	{
		.rlim_cur = 0,
		.rlim_max = 0,
	};
	if (linux_setrlimit(linux_RLIM_NLIMITS, &rlim) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_rlimit_t rlim;
	if (linux_getrlimit(linux_RLIMIT_NOFILE, &rlim))
		return TEST_RESULT_OTHER_FAILURE;

	rlim.rlim_cur = rlim.rlim_max;
	if (linux_setrlimit(linux_RLIMIT_NOFILE, &rlim))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing setrlimit.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_resource, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing setrlimit.\n");

	return ret;
}
