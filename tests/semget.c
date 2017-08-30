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

static enum TestResult test_invalid_number(void)
{
	enum linux_error_t err = linux_error_none;

	int id = 0;
	err = linux_semget(linux_IPC_PRIVATE, -1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id);
	if (!err)
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}
	else if (err == linux_EINVAL)
		return TEST_RESULT_SUCCESS;

	return TEST_RESULT_FAILURE;
}

static enum TestResult test_correct_usage(void)
{
	int id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_FAILURE;

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing semget.\n");
	DO_TEST(invalid_number, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing semget.\n");

	return ret;
}
