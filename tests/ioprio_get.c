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

static enum TestResult test_invalid_which(void)
{
	int ret;
	if (linux_ioprio_get(linux_IOPRIO_WHO_PROCESS - 1, 0, &ret) != linux_EINVAL)
		return TEST_RESULT_FAILURE;
	if (linux_ioprio_get(linux_IOPRIO_WHO_USER + 1, 0, &ret) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	int ret;
	if (linux_ioprio_get(linux_IOPRIO_WHO_PROCESS, 0, &ret))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing ioprio_get.\n");
	DO_TEST(invalid_which, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing ioprio_get.\n");

	return ret;
}
