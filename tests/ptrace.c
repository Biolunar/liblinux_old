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

#include <stdnoreturn.h>
#include <sys/types.h>
#include <unistd.h>

static enum TestResult test_no_tracee(void)
{
	pid_t const pid = getpid();

	linux_siginfo_t info;
	if (linux_ptrace(linux_PTRACE_GETSIGINFO, pid, 0, (uintptr_t)&info) != linux_ESRCH)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static noreturn void child(void)
{
	if (linux_ptrace(linux_PTRACE_TRACEME, 0, 0, 0))
		linux_exit(1);

	if (linux_kill(getpid(), linux_SIGSTOP))
		linux_exit(1);

	linux_exit(0);
}

static enum TestResult test_segfault(void)
{
	linux_pid_t pid;
	if (linux_fork(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	if (pid) // Parent
	{
		int status;
		if (linux_wait4(pid, &status, linux_WSTOPPED, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;

		uintptr_t word;
		if (linux_ptrace(linux_PTRACE_PEEKTEXT, pid, 0, (uintptr_t)&word) == 0)
			return TEST_RESULT_FAILURE;

		if (linux_ptrace(linux_PTRACE_CONT, pid, 0, 0))
			return TEST_RESULT_FAILURE;

		if (linux_wait4(pid, &status, 0, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;
	}
	else // Child
		child();

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_pid_t pid;
	if (linux_fork(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	if (pid) // Parent
	{
		int status;
		if (linux_wait4(pid, &status, linux_WSTOPPED, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;

		struct linux_user_regs_struct_t regs;
		if (linux_ptrace(linux_PTRACE_GETREGS, pid, 0, (uintptr_t)&regs))
			return TEST_RESULT_FAILURE;

		if (linux_ptrace(linux_PTRACE_CONT, pid, 0, 0))
			return TEST_RESULT_FAILURE;

		if (linux_wait4(pid, &status, 0, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;
	}
	else // Child
		child();

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing ptrace.\n");
	DO_TEST(no_tracee, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing ptrace.\n");

	return ret;
}
