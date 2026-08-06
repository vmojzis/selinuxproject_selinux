# RHEL-217622

Use-after-free in libselinux `selinux_restorecon_xattr()` via stale static
global xattr list state.

## Running

```
mkdir -p dir1 dir2
touch dir1/f dir2/f
restorecon -R -D dir1 dir2   # populate security.sehash xattrs
gcc -fsanitize=address -g -O0 -o reproduce reproduce.c -lselinux
ASAN_OPTIONS=detect_leaks=0 ./reproduce dir1 dir2
```

`dir1` and `dir2` must be directories with a `security.sehash` extended
attribute set (written by `restorecon -D`; not supported on tmpfs/ramfs, so
use a persistent filesystem such as `/var/tmp` on a non-tmpfs mount).

`dir1`/`dir2` must live under a path prefix that file_contexts actually has
a spec for (e.g. `/root`, matched by `/root(/.*)?`) - otherwise `restorecon
-D` has no default label to apply and silently skips writing the digest
xattr entirely, which surfaces as "no security.sehash entries found" from
this reproducer rather than as a false negative.

## Result

Verified on both:
- RHEL 10.3 Beta (libselinux-3.11-1.el10): vulnerable
- RHEL 10.2 (libselinux-3.10-1.el10): vulnerable

Same crash on both versions, since the code path exercised here was never
touched by the one fix that did land for this function.

On libselinux-3.11:

```
==7157==ERROR: AddressSanitizer: heap-use-after-free on address ...
READ of size 8 at ... thread T0
    #0 ... in free_xattr_list reproduce.c:25
    #1 ... in main reproduce.c:74
...
previously allocated by thread T0 here:
    #0 ... in malloc
    #1 ... in add_xattr_entry (/lib64/libselinux.so.1+0x15439)
```

**Still vulnerable.** Upstream commit `b5a23d7f30c1` ("libselinux:
restorecon_xattr: clear dir_xattr_* after freeing") only resets the
`dir_xattr_list`/`dir_xattr_last` statics on the internal error-cleanup path
of the recursive walk. It does not reset them on the normal success path,
which is exactly the documented usage pattern this reproducer follows: call
the function, free the returned list as the API contract requires, then
call it again in the same process. The second call appends through
`dir_xattr_last->next`, a dangling pointer left over from the first call's
now-freed list, corrupting the heap.
