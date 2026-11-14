# ebury-fix

One script that detects and removes the Ebury variant which replaces `libkeyutils.so.1`
with a hidden setuid library.

The implant ships a userland rootkit hooking `readlink`, `__readlink_chk`, `stat`, `lstat`,
`readdir`, `realpath` and `openat`. Because of that, `ls`, `stat`, `readlink`, `rpm -V`,
`sha256sum` and a plain read of `/proc/<pid>/maps` all report an infected host as clean, and
`rm` and `ln` cannot touch the implant. Everything here goes around the hooks with raw
syscalls. A clean result from ordinary tooling means nothing on this malware.

## What it checks

Two stages, because they fail independently:

**disk** — the symlink's hidden target (raw `readlinkat` vs `os.readlink`), the implant's
size, mode, setuid bit, sha256 and planted `ctime`, directory entries visible to
`getdents64` but hidden from `readdir`, `/etc/ld.so.preload`.

**memory** — the daemon forked from the backdoored `sshd` (argv and `comm` faked, but the
cgroup still says `ssh.service` and `exe` points at a deleted copy of a legitimate binary),
the abstract `@tmp-*` socket it listens on for credentials harvested from `sshd` and its
holder (resolved by matching `/proc/net/unix` inodes against `/proc/*/fd/*` with raw
`readlinkat`), shared objects unlinked from world-writable directories, which `libkeyutils`
the listening `sshd` has mapped, and root's `authorized_keys` read raw.

A host with a clean symlink can still be carrying the implant in memory: that daemon
survives deletion of the file and puts it back.

## Usage

```bash
# scan, changes nothing
python3 ebury-fix.py                            # this host
python3 ebury-fix.py host1 host2 ...            # over ssh as root, with a summary table

# through a jump host
scp ebury-fix.py root@jump:/tmp/
ssh root@jump 'python3 /tmp/ebury-fix.py host1 host2 ...'

# remove the implant from disk
python3 ebury-fix.py --apply [hosts ...]

# also unload the in-memory daemon, so a reboot is not required
python3 ebury-fix.py --apply --kill-daemon [hosts ...]

# exercise the removal path against a fake implant, system paths untouched
python3 ebury-fix.py --sandbox /tmp/sbx --apply
```

Exit codes: `0` clean, `1` findings or fix applied, `2` error or manual review needed.

## Removal

Order of operations is deliberate: the symlink is repointed to the legitimate library
**first**, atomically via `symlinkat` + `renameat`. Deleting the implant first leaves
`libkeyutils.so.1` dangling, new `sshd` sessions fail to start, and an interrupted run locks
you out of the host. Keep a second multiplexed session open while applying:

```bash
ssh -M -S /tmp/sock -fN root@host
```

A copy of the implant (mode 400) and a state file go to `/root/backup/` before anything
changes. `ldconfig` runs after the implant is unlinked, never before — otherwise it picks the
implant's version back up as the newest one.

The script refuses rather than guess: it will not touch a hidden target that is not the
expected `<legit>.2` shape, will not proceed when the legitimate library is missing from the
directory, and will not act on an implant it cannot read.

`--kill-daemon` unloads the in-memory stage live: it kills the masquerading daemon and any
process still mapping the implant, skipping pid 1 and its own session chain. Observed
masquerade names so far: `rsyslogd`, `arpd`, `systemd-udevd`.

## After cleanup

Every credential that passed through the host is compromised: SSH keys, root and user
passwords, anything typed into an SSH session. Rotate them, and assume exfiltration from the
moment the symlink's `ctime` shows.

Re-run the scan to confirm: `real == shown` on the symlink, no hidden dirents, no `@tmp-*`
socket, no process mapping the implant.

## Notes

- Implant builds are randomized per host, so comparing against known SHA-256 values is
  useless. Size 64600 bytes and setuid root are the stable traits.
- Cross-distribution: seen on RHEL-family `/usr/lib64` and on Debian 13
  `/usr/lib/x86_64-linux-gnu`.
- Run it as root. Without root, other processes' `maps`, `fd` and `environ` are unreadable
  and the memory stage is incomplete; the script says so.
- Offline inspection of a mounted disk from rescue mode stays reliable — the hooks are not
  loaded there.
