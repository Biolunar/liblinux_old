#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <liblinux/linux.h>

#define BUFFER_SIZE 512

static enum TestResult test_random_write(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int p[2] = {-1, -1};
	FILE* file = 0;

	if (pipe(p) == -1)
		goto cleanup;

	if (p[0] == -1 || p[1] == -1)
		goto cleanup;

	file = fopen("/dev/urandom", "r");
	if (!file)
		goto cleanup;

	char in_buf[BUFFER_SIZE] = {0};
	if (fread(in_buf, 1, sizeof in_buf, file) != sizeof in_buf)
		goto cleanup;

	if (linux_write((linux_fd_t)p[1], in_buf, sizeof in_buf, 0))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	char out_buf[sizeof in_buf] = {0};
	size_t to_read = sizeof out_buf;
	while (to_read)
	{
		ssize_t const bytes_read = read(p[0], out_buf + (sizeof out_buf - to_read), to_read);
		if (bytes_read < 0)
			goto cleanup;
		to_read -= (size_t)bytes_read;
	}

	if (memcmp(out_buf, in_buf, sizeof out_buf))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (file)
		fclose(file);
	if (p[0] != -1)
		close(p[0]);
	if (p[1] != -1)
		close(p[1]);
	return ret;
}

static enum TestResult test_write_zero(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int fd = -1;
	
	fd = open("/dev/null", O_WRONLY, 0);
	if (fd == -1)
		goto cleanup;

	char buf[1] = {0};
	size_t result = 0;
	if (linux_write((linux_fd_t)fd, buf, 0, &result) || result)
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (fd != -1)
		close(fd);
	return ret;
}

static enum TestResult test_invalid_fd(void)
{
	char buf[8] = {0};
	if (linux_write(3, buf, sizeof buf, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int fd = -1;
	
	// Cannot use /dev/null, because every write to it is successful.
	fd = open(".", O_WRONLY | 020000000 | 00200000, S_IWUSR); // 020000000 | 00200000  == O_TMPFILE
	if (fd == -1)
		goto cleanup;

	if (linux_write((linux_fd_t)fd, 0, BUFFER_SIZE, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (fd != -1)
		close(fd);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing write.\n");
	DO_TEST(write_zero, &ret);
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(random_write, &ret);
	printf("Finished testing write.\n");

	return ret;
}
