# RHEL-217307

Reported as: symlink-following in `fgetfilecon*`/`fsetfilecon*` `O_PATH`
fallback via `/proc/self/fd`.

## Running

```
mkdir -p symtest
touch symtest/target
ln -s target symtest/link
chcon -t etc_t symtest/target
chcon -h -t tmp_t symtest/link
gcc -g -O0 -o reproduce reproduce.c -lselinux
./reproduce symtest/link symtest/target
```

## Result

Verified on both:
- RHEL 10.3 Beta (libselinux-3.11-1.el10, kernel 6.12.0-254.el10): not vulnerable
- RHEL 10.2 (libselinux-3.10-1.el10, kernel 6.12.0-211.40.1.el10_2): not vulnerable

Identical result on both versions, which is expected: the behavior in
question is determined by the kernel's handling of `/proc/self/fd/N` magic
symlinks, not by anything in libselinux itself, and both machines run
kernel 6.12.

On libselinux-3.11:

```
symlink's own context : unconfined_u:object_r:tmp_t:s0
target's own context  : unconfined_u:object_r:etc_t:s0
fgetfilecon_raw(O_PATH fd) returned: unconfined_u:object_r:tmp_t:s0
NOT VULNERABLE: fgetfilecon_raw() correctly reported the symlink's own context (RHEL-217307 fixed)
fsetfilecon_raw(O_PATH fd) succeeded
target's context after set : unconfined_u:object_r:etc_t:s0
symlink's context after set: unconfined_u:object_r:samba_share_t:s0
NOT VULNERABLE: fsetfilecon_raw() did not touch the target's context (RHEL-217307 fixed)
```

**Not vulnerable, and there is no code fix for this in git history.** Strace
confirms the `EBADF` fallback to `getxattr(2)`/`setxattr(2)` on
`/proc/self/fd/<n>` is actually taken:

```
openat(AT_FDCWD, "symtest/link", O_RDONLY|O_NOFOLLOW|O_PATH) = 3
fgetxattr(3, "security.selinux", ...) = -1 EBADF (Bad file descriptor)
getxattr("/proc/self/fd/3", "security.selinux", "...tmp_t:s0", 255) = 31
```

But the kernel's magic `/proc/self/fd/N` symlink for an fd opened with
`O_PATH|O_NOFOLLOW` on a symlink resolves to the symlink object itself, not
its target — it honors the `O_NOFOLLOW` recorded at open time rather than
re-resolving the path. The vulnerability report's premise (that this
fallback dereferences the symlink) does not hold on this kernel; this
appears to be a false positive in the original AI-generated report rather
than a real, fixed bug.
