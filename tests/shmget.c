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

static enum TestResult test_invalid_size(void)
{
	enum linux_error_t err = linux_error_none;
	linux_shmid_t id = 0;

	err = linux_shmget(linux_IPC_PRIVATE, linux_SHMMIN - 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id);
	if (!err)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}
	if (err != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	err = linux_shmget(linux_IPC_PRIVATE, linux_SHMMAX + 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id);
	if (!err)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}
	if (err != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_key(void)
{
	linux_shmid_t id = 0;

	enum linux_error_t const err = linux_shmget(-1, linux_SHMMIN, linux_S_IRWXU, &id);
	if (!err)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}
	if (err != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_shmid_t id = 0;
	if (linux_shmget(linux_IPC_PRIVATE, linux_SHMMIN, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_FAILURE;

	linux_shmctl(id, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing shmget.\n");
	DO_TEST(invalid_size, &ret);
	DO_TEST(invalid_key, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing shmget.\n");

	return ret;
}
