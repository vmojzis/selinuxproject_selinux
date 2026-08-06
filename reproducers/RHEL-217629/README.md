# RHEL-217629

TOCTOU vulnerability in libselinux recursive `restorecon` allows relabeling
of files outside the intended directory tree via symlink swapping.

## Running

```
./reproduce.sh
```

Must be run as root on an SELinux-enabled system with `restorecon` and
`chcon` available. Only touches files under private, randomly-named
directories in `/var/tmp`. Set `ITER` to change the number of race
iterations (default 500).

## Result

Verified on RHEL 10.3 Beta (libselinux-3.11-1.el10, kernel 6.12.0-254.el10):

```
canary context before: unconfined_u:object_r:httpd_sys_content_t:s0
canary context after:  unconfined_u:object_r:httpd_sys_content_t:s0
NOT VULNERABLE: canary file context unchanged (RHEL-217629 fixed)
```

Ran with `ITER=3000` (~25s) with the same result. This matches upstream
commit `67bc978bfaf9` ("libselinux: restorecon: revisit pinning files to
avoid TOCTOU issues"), which pins each directory/file via an `O_PATH` fd
opened once during the tree walk instead of re-resolving pathnames.
