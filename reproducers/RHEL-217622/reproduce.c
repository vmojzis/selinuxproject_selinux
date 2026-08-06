/*
 * Reproducer for RHEL-217622: Use-after-free in libselinux
 * selinux_restorecon_xattr() via stale static global xattr list state.
 *
 * selinux_restorecon_xattr(3) documents that "xattr_list must be set to
 * NULL before calling selinux_restorecon_xattr(3). The caller is
 * responsible for freeing the returned xattr_list entries." This program
 * follows that contract exactly: it calls the function, frees the
 * returned list as documented, then calls the function again in the same
 * process. If the library retains stale head/tail pointers in static
 * globals across calls, the second call writes through freed memory.
 *
 * Build with -fsanitize=address so the use-after-free is caught reliably
 * instead of relying on it corrupting the heap silently.
 */
#include <stdio.h>
#include <stdlib.h>
#include <selinux/restorecon.h>

static void free_xattr_list(struct dir_xattr *list)
{
	struct dir_xattr *cur = list, *next;

	while (cur) {
		next = cur->next;
		free(cur->directory);
		free(cur->digest);
		free(cur);
		cur = next;
	}
}

int main(int argc, char **argv)
{
	struct dir_xattr **list1 = NULL;
	struct dir_xattr **list2 = NULL;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <dir1-with-sehash> <dir2-with-sehash>\n",
			argv[0]);
		return 2;
	}

	if (selinux_restorecon_xattr(argv[1], SELINUX_RESTORECON_XATTR_RECURSE,
				     &list1) < 0) {
		perror("selinux_restorecon_xattr(dir1)");
		return 2;
	}
	if (!list1 || !*list1) {
		fprintf(stderr,
			"no security.sehash entries found under %s - test setup invalid\n",
			argv[1]);
		return 2;
	}

	/* Free the list exactly as documented by the API contract. */
	free_xattr_list(*list1);

	/*
	 * Second, independent call in the same process. If the static
	 * dir_xattr_list/dir_xattr_last globals were left pointing at the
	 * just-freed nodes, add_xattr_entry() will dereference/write
	 * through freed memory here.
	 */
	if (selinux_restorecon_xattr(argv[2], SELINUX_RESTORECON_XATTR_RECURSE,
				     &list2) < 0) {
		perror("selinux_restorecon_xattr(dir2)");
		return 2;
	}

	printf("second call completed without a detected use-after-free\n");

	if (list2 && *list2)
		free_xattr_list(*list2);

	return 0;
}
