// SPDX-License-Identifier: GPL-2.0
// Real syscall regressions for the 64-bit Droidspaces GKI IPC port.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ipc.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Raw syscalls keep the test usable with Bionic, which lacks SysV libc APIs.
#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "FAIL line %d: %s: %s\n", __LINE__, #x, strerror(errno)); \
	exit(1); } } while (0)

struct test_message { long type; char text[32]; };
struct test_mq_attr {
	long flags, maxmsg, msgsize, curmsgs;
	long reserved[4];
};

static int sem_value(int id)
{
	return syscall(SYS_semctl, id, 0, GETVAL, 0UL);
}

static int sem_decrement(void *arg)
{
	struct sembuf op = { .sem_num = 0, .sem_op = -1, .sem_flg = SEM_UNDO };
	return syscall(SYS_semop, *(int *)arg, &op, 1) ? 1 : 0;
}

static void wait_ok(pid_t child)
{
	int status;
	CHECK(child > 0);
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void sem_undo(void)
{
	int id = syscall(SYS_semget, IPC_PRIVATE, 1, IPC_CREAT | 0600);
	CHECK(id >= 0);
	CHECK(syscall(SYS_semctl, id, 0, SETVAL, 1UL) == 0);
	pid_t child = fork();
	if (!child)
		_exit(sem_decrement(&id));
	wait_ok(child);
	CHECK(sem_value(id) == 1); // A normal fork owns independent undo state.

	const size_t bytes = 1024 * 1024;
	char *stack = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(stack != MAP_FAILED);
	child = clone(sem_decrement, stack + bytes, CLONE_SYSVSEM | SIGCHLD, &id);
	wait_ok(child);
	CHECK(sem_value(id) == 0); // Shared undo must survive the child's exit.
	CHECK(unshare(CLONE_SYSVSEM) == 0);
	CHECK(sem_value(id) == 1); // Last-owner detach applies the adjustment.
	CHECK(munmap(stack, bytes) == 0);
	CHECK(syscall(SYS_semctl, id, 0, IPC_RMID, 0UL) == 0);
}

static void shared_memory(void)
{
	int id = syscall(SYS_shmget, IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	CHECK(id >= 0);
	char *memory = (char *)syscall(SYS_shmat, id, NULL, 0);
	CHECK(memory != (char *)-1);
	strcpy(memory, "before");
	pid_t child = fork();
	if (!child) {
		char *other = (char *)syscall(SYS_shmat, id, NULL, 0);
		CHECK(other != (char *)-1);
		CHECK(!strcmp(other, "before"));
		strcpy(other, "after");
		CHECK(syscall(SYS_shmdt, other) == 0);
		_exit(0);
	}
	wait_ok(child);
	CHECK(!strcmp(memory, "after"));
	CHECK(syscall(SYS_shmctl, id, IPC_RMID, NULL) == 0);
	CHECK(!strcmp(memory, "after")); // Removed segments remain until detach.
	CHECK(syscall(SYS_shmdt, memory) == 0);

	// Remove segments after their creator was reaped: list/state lifetime test.
	for (int round = 0; round < 64; round++) {
		int pipefd[2];
		CHECK(pipe(pipefd) == 0);
		child = fork();
		if (!child) {
			close(pipefd[0]);
			int owned = syscall(SYS_shmget, IPC_PRIVATE, 4096, IPC_CREAT | 0600);
			CHECK(owned >= 0);
			CHECK(write(pipefd[1], &owned, sizeof(owned)) == sizeof(owned));
			_exit(0);
		}
		CHECK(child > 0);
		close(pipefd[1]);
		CHECK(read(pipefd[0], &id, sizeof(id)) == sizeof(id));
		close(pipefd[0]);
		wait_ok(child);
		CHECK(syscall(SYS_shmctl, id, IPC_RMID, NULL) == 0);
	}
}

static void ipc_isolation(void)
{
	const int key = 0x618001;
	int shmid = syscall(SYS_shmget, key, 4096, IPC_CREAT | IPC_EXCL | 0600);
	int semid = syscall(SYS_semget, key, 1, IPC_CREAT | IPC_EXCL | 0600);
	int msgid = syscall(SYS_msgget, key, IPC_CREAT | IPC_EXCL | 0600);
	CHECK(shmid >= 0 && semid >= 0 && msgid >= 0);
	struct test_message msg = { .type = 1, .text = "message" };
	CHECK(syscall(SYS_msgsnd, msgid, &msg, sizeof(msg.text), 0) == 0);
	memset(msg.text, 0, sizeof(msg.text));
	CHECK(syscall(SYS_msgrcv, msgid, &msg, sizeof(msg.text), 1, 0) == sizeof(msg.text));
	CHECK(!strcmp(msg.text, "message"));

	struct test_mq_attr attr = { .maxmsg = 2, .msgsize = 32 };
	int mq = syscall(SYS_mq_open, "droidspaces-check", O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK,
			 0600, &attr);
	CHECK(mq >= 0);
	CHECK(syscall(SYS_mq_timedsend, mq, "queue", 6, 0, NULL) == 0);
	char receive[32];
	CHECK(syscall(SYS_mq_timedreceive, mq, receive, sizeof(receive), NULL, NULL) == 6);
	CHECK(!strcmp(receive, "queue"));

	pid_t child = fork();
	if (!child) {
		struct stat before, after;
		CHECK(stat("/proc/self/ns/ipc", &before) == 0);
		CHECK(unshare(CLONE_NEWIPC) == 0);
		CHECK(stat("/proc/self/ns/ipc", &after) == 0);
		CHECK(before.st_ino != after.st_ino);
		errno = 0;
		CHECK(syscall(SYS_shmget, key, 0, 0) == -1 && errno == ENOENT);
		errno = 0;
		CHECK(syscall(SYS_semget, key, 0, 0) == -1 && errno == ENOENT);
		errno = 0;
		CHECK(syscall(SYS_msgget, key, 0) == -1 && errno == ENOENT);
		errno = 0;
		CHECK(syscall(SYS_mq_open, "droidspaces-check", O_RDWR, 0, NULL) == -1 && errno == ENOENT);
		_exit(0);
	}
	wait_ok(child);
	CHECK(close(mq) == 0);
	CHECK(syscall(SYS_mq_unlink, "droidspaces-check") == 0);
	CHECK(syscall(SYS_shmctl, shmid, IPC_RMID, NULL) == 0);
	CHECK(syscall(SYS_semctl, semid, 0, IPC_RMID, 0UL) == 0);
	CHECK(syscall(SYS_msgctl, msgid, IPC_RMID, NULL) == 0);
}

static void namespace_probe(int flag, const char *name)
{
	pid_t child = fork();
	if (!child) {
		char path[64];
		struct stat before, after;
		snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
		CHECK(stat(path, &before) == 0);
		CHECK(unshare(flag) == 0);
		CHECK(stat(path, &after) == 0);
		CHECK(before.st_ino != after.st_ino);
		_exit(0);
	}
	wait_ok(child);
}

static void pid_namespace(void)
{
	pid_t child = fork();
	if (!child) {
		CHECK(unshare(CLONE_NEWPID) == 0);
		pid_t inner = fork();
		if (!inner)
			_exit(getpid() == 1 ? 0 : 1);
		wait_ok(inner);
		_exit(0);
	}
	wait_ok(child);
}

int main(void)
{
	if (sizeof(void *) != 8) {
		fputs("SKIP: this regression binary targets 64-bit GKI\n", stderr);
		return 77;
	}
	// All IPC objects and sysctl state belong to a disposable namespace.
	if (unshare(CLONE_NEWIPC)) {
		fprintf(stderr, "SKIP: initial IPC unshare requires the new kernel and root: %s\n", strerror(errno));
		return 77;
	}
	sem_undo();
	shared_memory();
	ipc_isolation();
	namespace_probe(CLONE_NEWNS, "mnt");
	namespace_probe(CLONE_NEWUTS, "uts");
	namespace_probe(CLONE_NEWNET, "net");
	namespace_probe(CLONE_NEWCGROUP, "cgroup");
	namespace_probe(CLONE_NEWUSER, "user");
	pid_namespace();
	puts("PASS: IPC isolation, SysV message/shm, SEM_UNDO fork/share/unshare, creator exit/reap, POSIX mqueue, mount/UTS/network/cgroup/user/PID namespaces");
	return 0;
}
