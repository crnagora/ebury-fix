#!/usr/bin/env python3
"""
Ebury rootkit probe.

Why this exists: the Ebury variant seen in the October 2026 wave ships a
userland rootkit that hooks readlink/__readlink_chk/stat/lstat/readdir/openat/realpath.
Because of that, ls, stat, readlink, rpm -V, sha256sum and a plain read of
/proc/<pid>/maps all report the host as clean while the implant is loaded and active.

The reliable test is to call readlink through libc directly and compare it with what the
usual tooling reports. If they disagree, the libkeyutils symlink points at a hidden
implant. Everything else here (raw getdents vs readdir, raw openat, raw stat) exists for
the same reason: go around the hooks.

Usage
  On the host:        python3 ebury-probe.py
  From your machine:  python3 ebury-probe.py host1 host2 ...
                      (copies itself over ssh as root, prints a summary table)

Exit codes: 0 all clean, 1 at least one host infected, 2 probe error.
Read-only: this script never writes or changes anything.
"""
import ctypes, os, struct, hashlib, datetime, sys, subprocess, glob

SYS_OPENAT, SYS_NEWFSTATAT, SYS_GETDENTS64 = 257, 262, 217
AT_FDCWD, AT_SYMLINK_NOFOLLOW, O_DIRECTORY = -100, 0x100, 0o200000

CANDIDATES = [
    "/usr/lib64/libkeyutils.so.1",
    "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1",
    "/lib/x86_64-linux-gnu/libkeyutils.so.1",
    "/usr/lib/aarch64-linux-gnu/libkeyutils.so.1",
    "/usr/lib/libkeyutils.so.1",
]
SCAN_DIRS = ["/usr/lib64", "/lib64", "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
             "/usr/bin", "/usr/sbin", "/etc", "/etc/cron.d", "/root", "/tmp", "/var/tmp", "/dev/shm"]

_libc = None


def libc_handle():
    """Loaded lazily: in remote mode this script also runs on the operator's machine,
    which may be macOS and has no libc.so.6."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return _libc


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + "Z"


def raw_read(path):
    fd = libc_handle().syscall(SYS_OPENAT, AT_FDCWD, path.encode(), 0, 0)
    if fd < 0:
        return None
    chunks = []
    while True:
        b = os.read(fd, 65536)
        if not b:
            break
        chunks.append(b)
    os.close(fd)
    return b"".join(chunks)


def raw_lstat(path):
    buf = ctypes.create_string_buffer(144)
    if libc_handle().syscall(SYS_NEWFSTATAT, AT_FDCWD, path.encode(), buf, AT_SYMLINK_NOFOLLOW) != 0:
        return None
    r = buf.raw
    return {"mode": struct.unpack_from("<I", r, 24)[0],
            "uid": struct.unpack_from("<I", r, 28)[0],
            "size": struct.unpack_from("<q", r, 48)[0],
            "mtime": struct.unpack_from("<q", r, 88)[0],
            "ctime": struct.unpack_from("<q", r, 104)[0]}


def raw_readlink(path):
    buf = ctypes.create_string_buffer(4096)
    n = libc_handle().readlink(path.encode(), buf, 4096)
    return buf.raw[:n].decode(errors="replace") if n > 0 else None


def raw_listdir(path):
    fd = libc_handle().syscall(SYS_OPENAT, AT_FDCWD, path.encode(), O_DIRECTORY, 0)
    if fd < 0:
        return []
    buf = ctypes.create_string_buffer(1 << 20)
    names = []
    while True:
        n = libc_handle().syscall(SYS_GETDENTS64, fd, buf, 1 << 20)
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


def probe():
    host = (subprocess.run(["hostname", "-f"], stdout=subprocess.PIPE).stdout or b"").decode().strip() or os.uname()[1]
    print("HOST : %s" % host)
    rel = ""
    for f in glob.glob("/etc/*release"):
        try:
            for line in open(f):
                if line.startswith("PRETTY_NAME"):
                    rel = line.split("=", 1)[1].strip().strip('"')
                    break
        except Exception:
            pass
        if rel:
            break
    print("OS   : %s" % (rel or "unknown"))
    print("KERN : %s" % os.uname()[2])

    links = [p for p in CANDIDATES if os.path.lexists(p)]
    if not links:
        links = glob.glob("/usr/lib*/**/libkeyutils.so.1", recursive=True)
    if not links:
        print("\nlibkeyutils.so.1 not found - nothing to compare")
        return 2

    print("\n=== libkeyutils symlink: direct syscall vs what tooling reports")
    infected, targets = False, set()
    for sl in links:
        real = raw_readlink(sl)
        try:
            shown = os.readlink(sl)
        except OSError:
            shown = "<unreadable>"
        bad = real != shown
        infected = infected or bad
        print("  %s" % sl)
        print("    real  (syscall)  : %s" % real)
        print("    shown (stat/ls)  : %s" % shown)
        print("    => %s" % ("INFECTED, hidden target" if bad else "consistent"))
        st = raw_lstat(sl)
        if st:
            print("    symlink ctime    : %s" % utc(st["ctime"]))
        if bad and real:
            targets.add(real)
            imp = os.path.dirname(sl) + "/" + real
            data, si = raw_read(imp), raw_lstat(imp)
            if data and si:
                print("    implant          : %s" % imp)
                print("      visible to ls  : %s" % ("yes" if os.path.exists(imp) else "NO, hidden"))
                print("      size           : %d" % len(data))
                print("      mode           : %s  setuid=%s  uid=%d"
                      % (oct(si["mode"])[-4:], bool(si["mode"] & 0o4000), si["uid"]))
                print("      sha256         : %s" % hashlib.sha256(data).hexdigest())
                print("      mtime (faked)  : %s" % utc(si["mtime"]))
                print("      ctime (planted): %s" % utc(si["ctime"]))

    print("\n=== hidden directory entries: raw getdents vs readdir")
    any_hidden = False
    for d in SCAN_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            visible = set(os.listdir(d))
        except OSError:
            continue
        hidden = sorted(set(raw_listdir(d)) - visible)
        if hidden:
            print("  %-30s HIDDEN: %s" % (d, hidden))
            any_hidden = True
            infected = True
    if not any_hidden:
        print("  none")

    print("\n=== processes with the implant mapped")
    count = 0
    if targets:
        needles = [t.encode() for t in targets]
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            maps = raw_read("/proc/%s/maps" % pid)
            if maps and any(nd in maps for nd in needles):
                count += 1
    print("  %d%s" % (count, "  (a reboot is required to unload it)" if count else ""))

    print("\n=== /etc/ld.so.preload")
    pre = raw_read("/etc/ld.so.preload")
    print("  %s" % (repr(pre) if pre else "absent or empty"))
    if pre and pre.strip():
        infected = True

    print("\nVERDICT: %s" % ("INFECTED" if infected else "CLEAN"))
    return 1 if infected else 0


def remote(hosts):
    src = open(os.path.abspath(__file__), "rb").read()
    results = []
    for h in hosts:
        target = h if "@" in h else "root@" + h
        print("=" * 72)
        print("### %s" % target)
        print("=" * 72)
        p = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=20",
                            target, "python3 -"], input=src,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode(errors="replace")
        print(out.rstrip())
        if "VERDICT: INFECTED" in out:
            verdict = "INFECTED"
        elif "VERDICT: CLEAN" in out:
            verdict = "CLEAN"
        else:
            verdict = "ERROR"
        results.append((target, verdict))
        print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    for t, v in results:
        print("  %-40s %s" % (t, v))
    inf = sum(1 for _, v in results if v == "INFECTED")
    err = sum(1 for _, v in results if v == "ERROR")
    print("\n  infected=%d  clean=%d  error=%d" % (inf, len(results) - inf - err, err))
    return 1 if inf else (2 if err else 0)


if __name__ == "__main__":
    sys.exit(remote(sys.argv[1:]) if len(sys.argv) > 1 else probe())
