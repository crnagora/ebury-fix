#!/usr/bin/env python3
"""
Ebury probe, second pass: the in-memory stage.

ebury-probe.py checks the disk side (libkeyutils symlink, hidden dirents, ld.so.preload).
This pass looks for what survives a clean disk: the masquerading daemon forked from the
backdoored sshd, the abstract @tmp-* credential socket it listens on, and deleted
mappings/binaries. All /proc reads and link resolutions go through raw syscalls, because
the rootkit hooks readlink/readdir/stat.

Read-only. Exit 0 clean, 1 suspicious findings, 2 probe error.
"""
import ctypes, os, struct, sys, subprocess, datetime

SYS_OPENAT, SYS_NEWFSTATAT, SYS_GETDENTS64, SYS_READLINKAT = 257, 262, 217, 267
AT_FDCWD, O_DIRECTORY = -100, 0o200000

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def raw_read(path, limit=1 << 22):
    fd = libc.syscall(SYS_OPENAT, AT_FDCWD, path.encode(), 0, 0)
    if fd < 0:
        return None
    chunks, total = [], 0
    try:
        while total < limit:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
            total += len(b)
    except OSError:
        pass
    finally:
        os.close(fd)
    return b"".join(chunks)


def raw_readlink(path):
    buf = ctypes.create_string_buffer(4096)
    n = libc.syscall(SYS_READLINKAT, AT_FDCWD, path.encode(), buf, 4096)
    return buf.raw[:n].decode(errors="replace") if n > 0 else None


def raw_listdir(path):
    fd = libc.syscall(SYS_OPENAT, AT_FDCWD, path.encode(), O_DIRECTORY, 0)
    if fd < 0:
        return []
    buf = ctypes.create_string_buffer(1 << 20)
    names = []
    while True:
        n = libc.syscall(SYS_GETDENTS64, fd, buf, 1 << 20)
        if n <= 0:
            break
        off = 0
        while off < n:
            reclen = struct.unpack_from("<H", buf.raw, off + 16)[0]
            if reclen == 0:
                break
            name = buf.raw[off + 19:off + reclen].split(b"\x00")[0].decode(errors="replace")
            if name not in (".", ".."):
                names.append(name)
            off += reclen
    os.close(fd)
    return names


def btime():
    stat = raw_read("/proc/stat") or b""
    for line in stat.decode(errors="replace").splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return 0


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def pids():
    return [p for p in raw_listdir("/proc") if p.isdigit()]


def proc(pid):
    """Everything about one pid, gathered through raw syscalls."""
    st = raw_read("/proc/%s/status" % pid)
    if not st:
        return None
    d = {"pid": pid}
    for line in st.decode(errors="replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k in ("Name", "PPid", "Uid"):
                d[k] = v.strip()
    d["cmdline"] = (raw_read("/proc/%s/cmdline" % pid) or b"").replace(b"\x00", b" ").decode(errors="replace").strip()
    d["environ_len"] = len(raw_read("/proc/%s/environ" % pid) or b"")
    d["cgroup"] = (raw_read("/proc/%s/cgroup" % pid) or b"").decode(errors="replace").strip().split(":")[-1]
    d["exe"] = raw_readlink("/proc/%s/exe" % pid) or ""
    d["maps"] = (raw_read("/proc/%s/maps" % pid) or b"").decode(errors="replace")
    stat = (raw_read("/proc/%s/stat" % pid) or b"").decode(errors="replace")
    try:
        d["start"] = int(stat.rsplit(")", 1)[1].split()[19]) // os.sysconf("SC_CLK_TCK")
    except Exception:
        d["start"] = 0
    fds = {}
    for f in raw_listdir("/proc/%s/fd" % pid):
        t = raw_readlink("/proc/%s/fd/%s" % (pid, f))
        if t:
            fds[f] = t
    d["fds"] = fds
    return d


def main():
    host = (subprocess.run(["hostname", "-f"], stdout=subprocess.PIPE).stdout or b"").decode().strip() or os.uname()[1]
    bt = btime()
    print("HOST : %s" % host)
    print("BOOT : %s" % utc(bt))
    bad = False

    print("\n=== abstract unix sockets @tmp-* (Ebury credential drop)")
    unix = (raw_read("/proc/net/unix") or b"").decode(errors="replace")
    tmp_inodes = {}
    for line in unix.splitlines():
        if "@tmp-" in line:
            f = line.split()
            tmp_inodes[f[6]] = f[-1]
            print("  inode=%s name=%s" % (f[6], f[-1]))
    if not tmp_inodes:
        print("  none")

    procs = [p for p in (proc(x) for x in pids()) if p]

    if tmp_inodes:
        print("\n  holders (fd -> socket inode, resolved with raw readlinkat):")
        for p in procs:
            for fd, t in p["fds"].items():
                for ino in tmp_inodes:
                    if t == "socket:[%s]" % ino:
                        print("    pid=%s name=%s cmdline=%r exe=%s cgroup=%s"
                              % (p["pid"], p.get("Name"), p["cmdline"], p["exe"], p["cgroup"]))
                        bad = True

    print("\n=== deleted mappings in suspicious locations / deleted exe")
    # A package upgrade leaves plenty of legitimate "(deleted)" library mappings behind,
    # so only unlinked keyutils or files from world-writable dirs count as a finding.
    def is_hot(path):
        # keyutils unlinked at all, or a shared object unlinked from a world-writable dir.
        # Chrome and Python map plenty of deleted scratch files from /tmp; those are not it.
        if "keyutils" in path:
            return True
        so = ".so" in path.rsplit("/", 1)[-1]
        return so and any(h in path for h in ("/tmp/", "/dev/shm", "/var/tmp"))
    noise = 0
    for p in procs:
        dele = sorted({l.split()[-2] for l in p["maps"].splitlines() if l.endswith("(deleted)")})
        hot = [x for x in dele if is_hot(x)]
        if hot:
            print("  SUSPECT pid=%s %s exe=%s" % (p["pid"], p.get("Name"), p["exe"]))
            for x in hot:
                print("      %s (deleted)" % x)
            bad = True
        elif p["exe"].endswith("(deleted)"):
            print("  INFO    pid=%s %s exe=%s  <- binary unlinked (also normal after an upgrade)"
                  % (p["pid"], p.get("Name"), p["exe"]))
        noise += len(dele) - len(hot)
    print("  (%d other (deleted) library mappings ignored as upgrade leftovers)" % noise)

    print("\n=== PPid=1 daemons not belonging to their cgroup")
    # The Ebury daemon is forked from the backdoored sshd and reparented to init, so it
    # keeps ssh.service's cgroup while pretending to be something else. A legitimate
    # service shares its name with its unit, so only a name/unit clash is reported.
    ALIAS = {"ssh": "sshd", "dbus": "dbus-daemon", "postfix@-": "master",
             "console-getty": "agetty", "container-getty@1": "agetty",
             "container-getty@2": "agetty", "getty@tty1": "agetty", "serial-getty@ttyS0": "agetty",
             "cron": "cron", "systemd-journald": "systemd-journal"}
    for p in procs:
        if p.get("PPid") != "1":
            continue
        cg = p["cgroup"].rstrip("/")
        # only system daemons: a user session legitimately holds unrelated processes
        if not (cg.startswith("/system.slice") or cg.startswith("/init.scope")):
            continue
        name = (p.get("Name") or "").lower()
        unit = cg.split("/")[-1].replace(".service", "").replace(".scope", "").replace("\\x2d", "-").lower()
        if not unit or unit in ("init", "-.slice"):
            continue
        if "getty" in unit and name == "agetty":
            continue
        if ALIAS.get(unit) == name or unit.startswith(name[:6]) or name[:6] in unit:
            continue
        flag = "SUSPECT" if (unit == "ssh" or p["exe"].endswith("(deleted)") or p["environ_len"] == 0) else "INFO   "
        print("  %s pid=%s name=%s cmdline=%r cgroup=%s" % (flag, p["pid"], p.get("Name"), p["cmdline"], cg))
        print("      exe=%s environ=%dB start=%s fd0-2=%s"
              % (p["exe"], p["environ_len"], utc(bt + p["start"]), [p["fds"].get(x) for x in ("0", "1", "2")]))
        if flag.strip() == "SUSPECT":
            bad = True

    print("\n=== keyutils mapped by sshd / listening sshd")
    for p in procs:
        if "sshd" in (p.get("Name") or "") and "keyutils" in p["maps"]:
            for l in p["maps"].splitlines():
                if "keyutils" in l:
                    print("  pid=%s %s" % (p["pid"], l.split()[-1]))
                    break

    print("\n=== root authorized_keys (raw read, hooks bypassed)")
    for path in ("/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"):
        data = raw_read(path)
        if data:
            for line in data.decode(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    print("  %s: %s ... %s" % (path, parts[0][:20], parts[-1] if len(parts) > 2 else ""))

    print("\nPASS2 VERDICT: %s" % ("SUSPECT" if bad else "CLEAN"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
