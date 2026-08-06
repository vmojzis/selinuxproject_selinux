# RHEL-217629

TOCTOU vulnerability in libselinux recursive `restorecon` allows relabeling
of files outside the intended directory tree via symlink swapping.

## Running

```
./reproduce.sh
```

Must be run as root on an SELinux-enabled system with `gdb`, `restorecon`
and `chcon` available. Only touches files under private, randomly-named
directories in `/root`.

This is a deterministic, GDB-driven reproducer rather than a pure timing
race: a plain background-loop-swaps-a-symlink-while-restorecon-runs race did
not land within thousands of iterations even against genuinely vulnerable
code, consistent with the report's own `AC:H` ("high attack complexity")
rating - the real window is an in-process gap between one call reading a
file's current context and another writing its new one, far too narrow to
hit by chance from an external, unsynchronized process. The script instead
runs `restorecon -R` under GDB, breaks on the read side of that gap for the
exact target path, and performs the symlink swap synchronously the instant
it's hit.

## Result

Verified on both:
- RHEL 10.2 (libselinux-3.10-1.el10, kernel 6.12.0-211.40.1.el10_2): **vulnerable**
- RHEL 10.3 Beta (libselinux-3.11-1.el10, kernel 6.12.0-254.el10): **not vulnerable**

On libselinux-3.10:

```
canary context before: unconfined_u:object_r:httpd_sys_content_t:s0
canary context after:  unconfined_u:object_r:admin_home_t:s0
VULNERABLE: canary file outside the relabeled tree was modified (RHEL-217629)
```

The canary file (outside the tree passed to `restorecon -R`) picked up
`/root`'s default type, proving `restorecon` wrote through the raced
symlink to a file it was never asked to touch.

On libselinux-3.11, the `lgetfilecon_raw` breakpoint is never hit at all -
`restorecon` runs to completion without ever calling it - and the canary is
untouched:

```
canary context before: unconfined_u:object_r:httpd_sys_content_t:s0
canary context after:  unconfined_u:object_r:httpd_sys_content_t:s0
NOT VULNERABLE: canary file context unchanged (RHEL-217629 fixed)
```

This matches upstream commit `67bc978bfaf9` ("libselinux: restorecon:
revisit pinning files to avoid TOCTOU issues"), which replaced the
path-string-based `lgetfilecon_raw()`/`lsetfilecon()` pair with fd-pinned
operations on an `O_PATH` descriptor opened once per entry during the walk,
eliminating the vulnerable call pattern entirely rather than just closing
the specific race window.
