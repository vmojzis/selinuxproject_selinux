/*
 * Reproducer for RHEL-217307: Symlink-following in fgetfilecon()/
 * fsetfilecon() O_PATH fallback via /proc/self/fd.
 *
 * fgetfilecon_raw()/fsetfilecon_raw() first try fgetxattr(2)/fsetxattr(2)
 * directly on the given fd. On Linux those syscalls always fail with EBADF
 * on an O_PATH descriptor, so the library falls back to
 * getxattr(2)/setxattr(2) on "/proc/self/fd/<n>". That fallback path
 * dereferences symlinks, unlike the fd it was supposed to represent.
 *
 * This program opens a symlink with O_PATH|O_NOFOLLOW (the standard,
 * portable way to get a non-following handle on a symlink object), gives
 * the symlink and its target deliberately different SELinux contexts, and
 * then compares what fgetfilecon_raw()/fsetfilecon_raw() actually operate
 * on:
 *   - correct behavior: the fd represents the symlink itself, so
 *     fgetfilecon_raw() should report the symlink's own context (matching
 *     lgetfilecon_raw()) or fail outright - not silently return the
 *     target's context.
 *   - vulnerable behavior: fgetfilecon_raw() returns the target's context,
 *     and fsetfilecon_raw() relabels the target instead of the symlink.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <selinux/selinux.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <symlink-path> <target-path>\n", argv[0]);
		return 2;
	}

	const char *link_path = argv[1];
	const char *target_path = argv[2];
	char *link_ctx = NULL, *target_ctx = NULL, *fd_ctx = NULL;
	int rc = 2;

	if (lgetfilecon_raw(link_path, &link_ctx) < 0) {
		perror("lgetfilecon_raw(link)");
		goto out;
	}
	if (getfilecon_raw(target_path, &target_ctx) < 0) {
		perror("getfilecon_raw(target)");
		goto out;
	}

	if (strcmp(link_ctx, target_ctx) == 0) {
		fprintf(stderr,
			"test setup invalid: symlink and target already share the same context (%s)\n",
			link_ctx);
		goto out;
	}

	int fd = open(link_path, O_PATH | O_NOFOLLOW);
	if (fd < 0) {
		perror("open(O_PATH|O_NOFOLLOW)");
		goto out;
	}

	int gr = fgetfilecon_raw(fd, &fd_ctx);

	printf("symlink's own context : %s\n", link_ctx);
	printf("target's own context  : %s\n", target_ctx);
	if (gr < 0) {
		printf("fgetfilecon_raw(O_PATH fd) failed: %s\n", strerror(errno));
	} else {
		printf("fgetfilecon_raw(O_PATH fd) returned: %s\n", fd_ctx);
	}

	if (gr >= 0 && strcmp(fd_ctx, link_ctx) == 0) {
		printf("NOT VULNERABLE: fgetfilecon_raw() correctly reported the "
		       "symlink's own context (RHEL-217307 fixed)\n");
		rc = 0;
	} else if (gr >= 0 && strcmp(fd_ctx, target_ctx) == 0) {
		printf("VULNERABLE: fgetfilecon_raw() on an O_PATH|O_NOFOLLOW fd "
		       "for a symlink returned the target's context, not the "
		       "symlink's own context (RHEL-217307)\n");
		rc = 1;
	} else if (gr < 0) {
		printf("NOT VULNERABLE: fgetfilecon_raw() failed instead of "
		       "silently following the symlink (RHEL-217307 fixed)\n");
		rc = 0;
	} else {
		printf("INCONCLUSIVE: fgetfilecon_raw() returned a context that "
		       "matches neither the symlink nor the target\n");
		rc = 2;
	}

	/* Now probe the write path: fsetfilecon_raw() on the same O_PATH fd
	 * should only ever be able to relabel the symlink itself, never the
	 * target. */
	{
		static const char new_ctx[] = "unconfined_u:object_r:samba_share_t:s0";
		char *target_ctx_after = NULL, *link_ctx_after = NULL;

		int sr = fsetfilecon_raw(fd, new_ctx);
		if (sr < 0) {
			printf("fsetfilecon_raw(O_PATH fd) failed: %s\n", strerror(errno));
		} else {
			printf("fsetfilecon_raw(O_PATH fd) succeeded\n");
		}

		if (getfilecon_raw(target_path, &target_ctx_after) < 0) {
			perror("getfilecon_raw(target, after)");
		} else {
			printf("target's context after set : %s\n", target_ctx_after);
		}
		if (lgetfilecon_raw(link_path, &link_ctx_after) < 0) {
			perror("lgetfilecon_raw(link, after)");
		} else {
			printf("symlink's context after set: %s\n", link_ctx_after);
		}

		if (target_ctx_after && strcmp(target_ctx_after, target_ctx) != 0) {
			printf("VULNERABLE: fsetfilecon_raw() on an O_PATH|O_NOFOLLOW fd "
			       "for a symlink relabeled the target object "
			       "(RHEL-217307)\n");
			rc = 1;
		} else {
			printf("NOT VULNERABLE: fsetfilecon_raw() did not touch the "
			       "target's context (RHEL-217307 fixed)\n");
			if (rc != 1)
				rc = 0;
		}

		free(target_ctx_after);
		free(link_ctx_after);
	}

	close(fd);
out:
	free(link_ctx);
	free(target_ctx);
	free(fd_ctx);
	return rc;
}
