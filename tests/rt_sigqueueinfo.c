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

#include <stdbool.h>

static bool volatile g_success = false;

static void signal_handler(int const sig, struct linux_siginfo_t* const info, struct linux_ucontext_t* const context)
{
	(void)sig;
	(void)context;

	if (info->sifields.rt.si_value.sival_int == 42)
		g_success = true;
}

static bool install_signal_handler(void)
{
	g_success = false;

	struct linux_sigaction_t sa =
	{
		.sa_handler = (linux_sighandler_t)&signal_handler,
		.sa_flags = linux_SA_RESTORER | linux_SA_SIGINFO,
		.sa_restorer = &linux_rt_sigreturn,
	};
	linux_sigemptyset(&sa.sa_mask);
	if (linux_rt_sigaction(linux_SIGUSR1, &sa, 0, sizeof(linux_sigset_t)))
		return false;

	return true;
}

static enum TestResult test_invalid_pid(void)
{
	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	linux_uid_t uid;
	if (linux_getuid(&uid))
		return TEST_RESULT_OTHER_FAILURE;

	if (!install_signal_handler())
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_siginfo_t info =
	{
		.si_code = linux_SI_QUEUE,
		.sifields.rt.si_pid = pid,
		.sifields.rt.si_uid = uid,
		.sifields.rt.si_value = { .sival_int = 42 },
	};
	if (linux_rt_sigqueueinfo((linux_pid_t)-1, linux_SIGUSR1, &info) != linux_ESRCH || g_success == true)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	linux_uid_t uid;
	if (linux_getuid(&uid))
		return TEST_RESULT_OTHER_FAILURE;

	if (!install_signal_handler())
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_siginfo_t info =
	{
		.si_code = linux_SI_QUEUE,
		.sifields.rt.si_pid = pid,
		.sifields.rt.si_uid = uid,
		.sifields.rt.si_value = { .sival_int = 42 },
	};
	if (linux_rt_sigqueueinfo(pid, linux_SIGUSR1, &info) || g_success == false)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing rt_sigqueueinfo.\n");
	DO_TEST(invalid_pid, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing rt_sigqueueinfo.\n");

	return ret;
}
