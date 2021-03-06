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

static char const name[] = "liblinux";
static char const data[] = "some test data";

static enum TestResult test_invalid_mqd(void)
{
	if (linux_mq_timedsend(0, data, sizeof data, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_mqd_t mqd;
	if (linux_mq_open(name, linux_O_RDWR | linux_O_CLOEXEC | linux_O_CREAT, 0666, 0, &mqd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_mq_timedsend(mqd, data, sizeof data, 0, 0))
	{
		linux_mq_unlink(name);
		return TEST_RESULT_FAILURE;
	}

	linux_mq_unlink(name);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing mq_timedsend.\n");
	DO_TEST(invalid_mqd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing mq_timedsend.\n");

	return ret;
}
