# ebury-fix

Detection and removal for the Ebury variant that replaces `libkeyutils.so.1` with a hidden
setuid library and ships a userland rootkit.

The rootkit hooks `readlink`, `__readlink_chk`, `stat`, `lstat`, `readdir`, `realpath` and
`openat`, so `ls`, `stat`, `readlink`, `rpm -V`, `sha256sum` and a plain read of
`/proc/<pid>/maps` all report an infected host as clean. Everything here goes around the
hooks with raw syscalls. A "clean" result from ordinary tooling means nothing on this malware.

## Scripts

| script | what it does | writes |
|---|---|---|
| `ebury-probe.py` | disk stage: `libkeyutils` symlink via libc vs `os.readlink`, hidden dirents (`getdents64` vs `readdir`), implant size/mode/sha256, `/etc/ld.so.preload` | no |
| `ebury-probe2.py` | in-memory stage: `@tmp-*` abstract credential sockets and their holder, unlinked `.so` in world-writable dirs, `PPid=1` daemons whose name disagrees with their cgroup, which `libkeyutils` the listening `sshd` has mapped, raw read of root `authorized_keys` | no |
| `ebury-fix.py` | repoints the symlink to the legitimate library (`symlinkat` + `renameat`, atomic), then unlinks the implant; backs it up to `/root/backup/` first | yes, with `--apply` |

Run both probes. A host can have a clean symlink on disk and still be carrying the implant in
memory — the daemon forked from the backdoored `sshd` survives deletion of the file and
reinstalls it.

```bash
# on the host
python3 ebury-probe.py
python3 ebury-probe2.py

# from your own machine: copies itself over ssh as root, prints a summary table
python3 ebury-probe.py host1 host2 ...

# through a jump host
scp ebury-probe.py root@jump:/tmp/
ssh root@jump 'python3 /tmp/ebury-probe.py host1 host2 ...'
```

Exit codes: `0` clean, `1` infected, `2` probe error.

## Removal

```bash
python3 ebury-fix.py host1 host2 ...            # dry run, changes nothing
python3 ebury-fix.py --apply host1 host2 ...    # repoint symlink, unlink implant
```

Order of operations is deliberate: the symlink is repointed to the legitimate library
**first**. Deleting the implant first leaves `libkeyutils.so.1` dangling, new `sshd` sessions
fail to start, and an interrupted run locks you out of the host. Keep a second multiplexed
session open (`ssh -M -S sock -fN`) while applying.

Run `ldconfig` after the implant is unlinked, not before — otherwise it picks the implant's
version back up as the newest one.

## Removing the file is not the end

The implant stays mapped in every process that already loaded it, and a daemon forked from
the backdoored `sshd` will put it back. Rebooting clears both. If a reboot is not an option,
the daemon can be unloaded live: check the listening `sshd` does not map the implant
(`grep keyutils /proc/<sshd pid>/maps`), then kill the masquerading daemon that `ebury-probe2.py`
reports, and then any remaining session with the implant mapped. Observed masquerade names so
far: `rsyslogd`, `arpd`, `systemd-udevd` — argv and `comm` are faked, but the cgroup still says
`ssh.service` and `exe` points at a deleted copy of a legitimate binary.

## After cleanup

Every credential that passed through the host is compromised: SSH keys, root and user
passwords, and anything typed into an SSH session. Rotate them. The implant collects
credentials from `sshd` and hands them to the abstract socket, so assume exfiltration
happened from the moment the symlink's `ctime` shows.

Verify with both probes: `real == shown` on the symlink, no hidden dirents, no `@tmp-*`
socket, no process mapping the implant.

## Notes

- Implant builds are randomized per host, so comparing against known SHA-256 values is
  useless. Size 64600 bytes and setuid root are the stable traits.
- Cross-distribution: seen on RHEL-family `/usr/lib64` and on Debian 13
  `/usr/lib/x86_64-linux-gnu`.
- Offline inspection of a mounted disk from rescue mode stays reliable — the hooks are not
  loaded there.
