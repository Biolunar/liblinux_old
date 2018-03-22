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

static char const data[] = "some test payload";

static enum TestResult test_segfault(void)
{
	linux_key_serial_t key;
	if (linux_add_key((char const*)-1, "liblinux", data, sizeof data, linux_KEY_SPEC_THREAD_KEYRING, &key) != linux_EFAULT)
		return TEST_RESULT_FAILURE;
	if (linux_add_key("user", (char const*)-1, data, sizeof data, linux_KEY_SPEC_THREAD_KEYRING, &key) != linux_EFAULT)
		return TEST_RESULT_FAILURE;
	if (linux_add_key("user", "liblinux", (char const*)-1, sizeof data, linux_KEY_SPEC_THREAD_KEYRING, &key) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_key_serial_t key;
	if (linux_add_key("user", "liblinux", data, sizeof data, linux_KEY_SPEC_THREAD_KEYRING, &key))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing add_key.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing add_key.\n");

	return ret;
}
