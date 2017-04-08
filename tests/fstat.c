#include "test.h"

#include <liblinux/linux.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static enum TestResult test_invalid_file(void)
{
	if (linux_fstat(linux_stderr + 1, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_real_file(void)
{
	int const fd = open("/proc/self/maps", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_stat_t stat;
	if (linux_fstat((linux_fd_t)fd, &stat))
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing fstat.\n");
	DO_TEST(invalid_file, &ret);
	DO_TEST(real_file, &ret);
	printf("Finished testing fstat.\n");

	return ret;
}
