#!/usr/bin/env python3
"""
Ebury implant removal.

The implant is a replaced libkeyutils symlink pointing at a hidden setuid library
(e.g. libkeyutils.so.1.10 -> libkeyutils.so.1.10.2). Its userland rootkit hooks
readlink/stat/readdir/openat, so ls, rm, ln and rpm cannot see or touch the implant.
Everything here therefore goes through raw syscalls.

Order of operations matters and is deliberate:
  1. the symlink is repointed to the legitimate library FIRST, atomically via
     symlinkat + renameat. If the implant were deleted first, libkeyutils.so.1
     would dangle, new sshd sessions would fail to start, and an interrupted
     session would lock you out of the host.
  2. only then is the implant unlinked.
A copy of the implant is saved to /root/backup/ before anything is changed.

The host stays infected in memory until it is rebooted: the implant remains mapped
into every process that already loaded it. This script never reboots; it tells you to.

Usage
  Dry run (default, changes nothing):
      python3 ebury-fix.py host1 host2 ...
  Apply:
      python3 ebury-fix.py --apply host1 host2 ...
  On the host itself:
      python3 ebury-fix.py [--apply]

Exit codes: 0 nothing to do / dry run fine, 1 implant found (dry run) or fix failed, 2 error.
"""
import ctypes, os, sys, struct, hashlib, datetime, subprocess

SYS_OPENAT, SYS_NEWFSTATAT, SYS_UNLINKAT = 257, 262, 263
SYS_SYMLINKAT, SYS_RENAMEAT, SYS_GETDENTS64 = 266, 264, 217
AT_FDCWD, AT_SYMLINK_NOFOLLOW, O_DIRECTORY = -100, 0x100, 0o200000

CANDIDATES = [
    "/usr/lib64/libkeyutils.so.1",
    "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1",
    "/usr/lib/aarch64-linux-gnu/libkeyutils.so.1",
    "/usr/lib/libkeyutils.so.1",
]
BACKUP = "/root/backup"
_libc = None


def libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return _libc


def raw_read(path):
    fd = libc().syscall(SYS_OPENAT, AT_FDCWD, path.encode(), 0, 0)
    if fd < 0:
        return None
    out = []
    while True:
        b = os.read(fd, 65536)
        if not b:
            break
        out.append(b)
    os.close(fd)
    return b"".join(out)


def raw_lstat(path):
    buf = ctypes.create_string_buffer(144)
    if libc().syscall(SYS_NEWFSTATAT, AT_FDCWD, path.encode(), buf, AT_SYMLINK_NOFOLLOW) != 0:
        return None
    r = buf.raw
    return {"mode": struct.unpack_from("<I", r, 24)[0],
            "size": struct.unpack_from("<q", r, 48)[0],
            "mtime": struct.unpack_from("<q", r, 88)[0],
            "ctime": struct.unpack_from("<q", r, 104)[0]}


def raw_readlink(path):
    buf = ctypes.create_string_buffer(4096)
    n = libc().readlink(path.encode(), buf, 4096)
    return buf.raw[:n].decode(errors="replace") if n > 0 else None


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + "Z"


def mapped_count(target):
    n = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        m = raw_read("/proc/%s/maps" % pid)
        if m and target.encode() in m:
            n += 1
    return n


def hidden_in(d):
    fd = libc().syscall(SYS_OPENAT, AT_FDCWD, d.encode(), O_DIRECTORY, 0)
    if fd < 0:
        return []
    buf = ctypes.create_string_buffer(1 << 20)
    names = []
    while True:
        n = libc().syscall(SYS_GETDENTS64, fd, buf, 1 << 20)
        if n <= 0:
            break
        off = 0
        while off < n:
            reclen = struct.unpack_from("<H", buf.raw, off + 16)[0]
            if reclen == 0:
                break
            nm = buf.raw[off + 19:off + reclen].split(b"\x00")[0].decode(errors="replace")
            if nm not in (".", ".."):
                names.append(nm)
            off += reclen
    os.close(fd)
    try:
        return sorted(set(names) - set(os.listdir(d)))
    except OSError:
        return []


def fix(apply_changes):
    host = os.popen("hostname -f 2>/dev/null || hostname").read().strip()
    print("HOST : %s" % host)
    print("MODE : %s" % ("APPLY" if apply_changes else "DRY RUN (nothing will be changed)"))

    links = [p for p in CANDIDATES if os.path.lexists(p)]
    if not links:
        print("libkeyutils.so.1 not found; nothing to do")
        return 0

    # /lib64 and /lib are usually symlinks to /usr/lib64 and /usr/lib: same inode, fix once.
    seen, work = set(), []
    for sl in links:
        key = os.path.realpath(os.path.dirname(sl)) + "/" + os.path.basename(sl)
        if key in seen:
            continue
        seen.add(key)
        work.append(sl)

    rc = 0
    for sl in work:
        real, shown = raw_readlink(sl), os.readlink(sl)
        print("\n%s" % sl)
        print("  real  (syscall) : %s" % real)
        print("  shown (stat/ls) : %s" % shown)
        if real == shown:
            print("  => consistent, nothing to fix")
            continue
        if real != shown + ".2":
            print("  => UNEXPECTED hidden target; refusing to touch it. Review manually.")
            rc = 2
            continue

        libdir = os.path.dirname(sl)
        implant, legit = libdir + "/" + real, shown
        data, st = raw_read(implant), raw_lstat(implant)
        if not data or not st:
            print("  => cannot read implant %s; aborting this path" % implant)
            rc = 2
            continue
        sha = hashlib.sha256(data).hexdigest()
        print("  => INFECTED")
        print("     implant : %s" % implant)
        print("     size=%d mode=%s setuid=%s" % (len(data), oct(st["mode"])[-4:], bool(st["mode"] & 0o4000)))
        print("     sha256  : %s" % sha)
        print("     mtime   : %s (faked)" % utc(st["mtime"]))
        print("     ctime   : %s (planted)" % utc(st["ctime"]))
        print("     will repoint symlink to: %s" % legit)
        if not os.path.exists(libdir + "/" + legit):
            print("     legitimate library %s/%s is MISSING; refusing to proceed" % (libdir, legit))
            rc = 2
            continue

        if not apply_changes:
            print("     [dry run] would save a copy, repoint the symlink, then unlink the implant")
            rc = rc or 1
            continue

        os.makedirs(BACKUP, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        sample = "%s/implant-%s-%s.bin" % (BACKUP, real, stamp)
        with open(sample, "wb") as f:
            f.write(data)
        os.chmod(sample, 0o400)
        with open("%s/ebury-state-%s.txt" % (BACKUP, stamp), "w") as f:
            f.write("host=%s\nsymlink=%s\nreal=%s\nshown=%s\nimplant=%s\nsize=%d\nsha256=%s\nlegit=%s\nctime=%s\n"
                    % (host, sl, real, shown, implant, len(data), sha, legit, utc(st["ctime"])))
        print("     saved: %s (mode 400)" % sample)

        tmp = libdir + "/.libkeyutils.swap.%d" % os.getpid()
        libc().syscall(SYS_UNLINKAT, AT_FDCWD, tmp.encode(), 0)
        if libc().syscall(SYS_SYMLINKAT, legit.encode(), AT_FDCWD, tmp.encode()) != 0:
            print("     symlinkat failed errno=%d; nothing changed" % ctypes.get_errno())
            rc = 2
            continue
        if libc().syscall(SYS_RENAMEAT, AT_FDCWD, tmp.encode(), AT_FDCWD, sl.encode()) != 0:
            print("     renameat failed errno=%d" % ctypes.get_errno())
            libc().syscall(SYS_UNLINKAT, AT_FDCWD, tmp.encode(), 0)
            print("     temp removed, original symlink untouched")
            rc = 2
            continue
        print("     symlink repointed -> %s" % raw_readlink(sl))
        if libc().syscall(SYS_UNLINKAT, AT_FDCWD, implant.encode(), 0) != 0:
            print("     unlinkat failed errno=%d (symlink is already fixed)" % ctypes.get_errno())
            rc = 2
            continue
        print("     implant removed; still present: %s" % (raw_lstat(implant) is not None))

    print("\n--- post-state ---")
    for sl in work:
        print("  %s  real=%s shown=%s" % (sl, raw_readlink(sl), os.readlink(sl)))
    for d in ["/usr/lib64", "/usr/lib/x86_64-linux-gnu"]:
        if os.path.isdir(d):
            h = hidden_in(d)
            print("  hidden in %-28s %s" % (d, h if h else "none"))
    live = 0
    for sl in work:
        r = raw_readlink(sl)
        if r:
            live = max(live, mapped_count(r + ".2"))
    if apply_changes:
        print("\n  processes still holding the implant in memory: %d" % live)
        print("  >>> REBOOT REQUIRED. Until then this host is still compromised.")
    return rc


def remote(hosts, apply_changes):
    src = open(os.path.abspath(__file__), "rb").read()
    results = []
    for h in hosts:
        target = h if "@" in h else "root@" + h
        print("=" * 72)
        print("### %s" % target)
        print("=" * 72)
        args = "--apply" if apply_changes else ""
        p = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=25",
                            target, "python3 - %s" % args], input=src,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode(errors="replace")
        print(out.rstrip())
        if "REBOOT REQUIRED" in out:
            v = "FIXED, NEEDS REBOOT"
        elif "nothing to fix" in out and "INFECTED" not in out:
            v = "CLEAN"
        elif "[dry run]" in out:
            v = "INFECTED (dry run)"
        elif "refusing" in out.lower():
            v = "NEEDS REVIEW"
        else:
            v = "ERROR"
        results.append((target, v))
        print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    for t, v in results:
        print("  %-40s %s" % (t, v))
    return 1 if any(v != "CLEAN" for _, v in results) else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--apply"]
    ap = "--apply" in sys.argv[1:]
    sys.exit(remote(args, ap) if args else fix(ap))
  
