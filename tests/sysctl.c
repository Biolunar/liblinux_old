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

static enum TestResult test_corret_usage(void)
{
	char osname[512];
	size_t osname_size = sizeof osname;

	int name[] =
	{
		linux_CTL_KERN,
		linux_KERN_OSTYPE,
	};

	struct linux_sysctl_args_t args =
	{
		.name = name,
		.nlen = sizeof name / sizeof name[0],
		.oldval = osname,
		.oldlenp = &osname_size,
	};

	if (linux_sysctl(&args))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing sysctl.\n");
	DO_TEST(corret_usage, &ret);
	printf("Finished testing sysctl.\n");

	return ret;
}
