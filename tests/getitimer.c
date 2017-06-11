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

static enum TestResult test_invalid_pointer(void)
{
	if (linux_getitimer(linux_ITIMER_REAL, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_getitimer(linux_ITIMER_VIRTUAL, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_getitimer(linux_ITIMER_PROF, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_value(void)
{
	struct linux_itimerval_t value;
	if (linux_getitimer(linux_ITIMER_PROF + 1, &value) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_itimerval_t value;
	if (linux_getitimer(linux_ITIMER_REAL, &value))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing getitimer.\n");
	DO_TEST(invalid_pointer, &ret);
	DO_TEST(invalid_value, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getitimer.\n");

	return ret;
}
