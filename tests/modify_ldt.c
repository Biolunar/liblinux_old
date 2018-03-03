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
	if (linux_modify_ldt(1, 0, sizeof(struct linux_user_desc_t), 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_size(void)
{
	char buf[sizeof(struct linux_user_desc_t) - 1];
	if (linux_modify_ldt(1, buf, sizeof buf, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_user_desc_t ud;
	memset(&ud, 0, sizeof ud);
	ud.read_exec_only = 1;
	ud.seg_not_present = 1;

	if (linux_modify_ldt(1, &ud, sizeof ud, 0))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing modify_ldt.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_size, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing modify_ldt.\n");

	return ret;
}
