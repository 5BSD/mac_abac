/*
 * test_audit.c - Test audit event reading from /dev/vlabel
 *
 * Compile: cc -o test_audit test_audit.c
 * Run: ./test_audit
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Audit entry structure - must match kernel definition
 */
#define VLABEL_AUDIT_LABEL_LEN	64
#define VLABEL_AUDIT_PATH_LEN	256

struct vlabel_audit_entry {
	uint64_t	vae_timestamp;
	uint32_t	vae_type;
	uint32_t	vae_operation;
	int32_t		vae_result;
	int32_t		vae_pid;
	uint32_t	vae_uid;
	int32_t		vae_jailid;
	char		vae_subject_label[VLABEL_AUDIT_LABEL_LEN];
	char		vae_object_label[VLABEL_AUDIT_LABEL_LEN];
	char		vae_path[VLABEL_AUDIT_PATH_LEN];
};

/* Operation names */
static const char *op_names[] = {
	"EXEC", "READ", "WRITE", "MMAP", "LINK", "RENAME", "UNLINK",
	"CHDIR", "STAT", "READDIR", "CREATE", "SETEXTATTR", "GETEXTATTR",
	"LOOKUP", "OPEN", "ACCESS"
};

static volatile sig_atomic_t running = 1;

static void
sighandler(int sig)
{
	running = 0;
}

static const char *
op_to_string(uint32_t op)
{
	static char buf[32];
	int i;

	for (i = 0; i < 16; i++) {
		if (op & (1 << i)) {
			if (i < sizeof(op_names)/sizeof(op_names[0]))
				return op_names[i];
			break;
		}
	}
	snprintf(buf, sizeof(buf), "OP(0x%x)", op);
	return buf;
}

int
main(int argc, char *argv[])
{
	struct vlabel_audit_entry entry;
	struct pollfd pfd;
	char timebuf[64];
	time_t ts;
	int fd, ret;

	printf("=== vLabel Audit Monitor ===\n\n");

	fd = open("/dev/vlabel", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/vlabel");
		return 1;
	}

	printf("Opened /dev/vlabel, waiting for audit events...\n");
	printf("(Press Ctrl+C to stop)\n\n");

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (running) {
		ret = poll(&pfd, 1, 1000);  /* 1 second timeout */
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		if (ret == 0)
			continue;  /* timeout, no events */

		if (pfd.revents & POLLIN) {
			ret = read(fd, &entry, sizeof(entry));
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				perror("read");
				break;
			}

			if (ret != sizeof(entry)) {
				fprintf(stderr, "short read: %d bytes\n", ret);
				continue;
			}

			/* Format timestamp */
			ts = (time_t)entry.vae_timestamp;
			strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
			    localtime(&ts));

			/* Print event */
			printf("[%s] %s %s\n",
			    timebuf,
			    op_to_string(entry.vae_operation),
			    entry.vae_result == 0 ? "ALLOWED" : "DENIED");
			printf("  PID: %d  UID: %u  Jail: %d\n",
			    entry.vae_pid, entry.vae_uid, entry.vae_jailid);
			printf("  Subject: %s\n",
			    entry.vae_subject_label[0] ? entry.vae_subject_label : "(none)");
			printf("  Object:  %s\n",
			    entry.vae_object_label[0] ? entry.vae_object_label : "(none)");
			if (entry.vae_path[0])
				printf("  Path:    %s\n", entry.vae_path);
			printf("\n");
		}
	}

	printf("\nShutting down...\n");
	close(fd);
	return 0;
}
