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

static enum TestResult test_correct_usage(void)
{
	linux_umode_t const new_mode = linux_S_IWOTH;

	linux_umode_t old_mode;
	if (linux_umask(new_mode, &old_mode))
		return TEST_RESULT_FAILURE;

	linux_umode_t mode;
	if (linux_umask(old_mode, &mode) || mode != new_mode)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing umask.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing umask.\n");

	return ret;
}
