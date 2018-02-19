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

#include <string.h>

static enum TestResult test_invalid_type(void)
{
	if (!linux_syslog(-1, 0, 0, 0))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_arg(void)
{
	if (linux_syslog(linux_SYSLOG_ACTION_READ_ALL, 0, 1, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	char buf;
	if (linux_syslog(linux_SYSLOG_ACTION_READ_ALL, &buf, -1, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	int len;
	if (linux_syslog(linux_SYSLOG_ACTION_SIZE_BUFFER, 0, 0, &len) || len <= 0)
		return TEST_RESULT_FAILURE;

	char* const buf = malloc((unsigned)len);
	if (!buf)
		return TEST_RESULT_OTHER_FAILURE;
	memset(buf, 'x', (unsigned)len);

	int ret;
	if (linux_syslog(linux_SYSLOG_ACTION_READ_ALL, buf, len, &ret) || ret < 0)
		return TEST_RESULT_FAILURE;

	free(buf);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing syslog.\n");
	DO_TEST(invalid_type, &ret);
	DO_TEST(invalid_arg, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing syslog.\n");

	return ret;
}
