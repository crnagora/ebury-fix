#!/usr/bin/env python3
"""
Ebury: detection and removal in one script.

The implant is a replaced libkeyutils symlink pointing at a hidden setuid library
(e.g. libkeyutils.so.1.10 -> libkeyutils.so.1.10.2). Its userland rootkit hooks
readlink/__readlink_chk/stat/lstat/readdir/realpath/openat, so ls, stat, readlink, rpm -V,
sha256sum, rm and ln all report an infected host as clean and cannot touch the implant.
Everything here goes around the hooks with raw syscalls.

Two stages are checked, because they fail independently:

  disk    the symlink's hidden target, the implant's size/mode/sha256, directory entries
          visible to getdents64 but not to readdir, /etc/ld.so.preload
  memory  the daemon forked from the backdoored sshd (argv and comm faked, cgroup still
          ssh.service, exe a deleted copy of a legitimate binary), the abstract @tmp-*
          socket it listens on for credentials harvested from sshd, unlinked shared objects
          in world-writable dirs, which libkeyutils the listening sshd has mapped

A host with a clean symlink can still carry the implant in memory: that daemon survives
deletion of the file and puts it back.

Removal order is deliberate. The symlink is repointed to the legitimate library FIRST,
atomically via symlinkat + renameat; deleting the implant first leaves libkeyutils.so.1
dangling, new sshd sessions fail to start, and an interrupted run locks you out. Keep a
second multiplexed session open (ssh -M -S sock -fN) while applying. A copy of the implant
and a state file are written to /root/backup/ before anything changes.

Usage
  Scan only (default, changes nothing):
      python3 ebury-fix.py                       # this host
      python3 ebury-fix.py host1 host2 ...       # over ssh as root, with a summary table
  Remove the implant from disk:
      python3 ebury-fix.py --apply [hosts ...]
  Also unload the in-memory daemon (so a reboot is not required):
      python3 ebury-fix.py --apply --kill-daemon [hosts ...]
  Prove the removal path against a fake implant instead of a real one:
      python3 ebury-fix.py --sandbox /tmp/sbx [--apply]

Exit codes: 0 clean, 1 findings (scan) or fix applied, 2 error or manual review needed.
"""
import ctypes, os, sys, re, struct, hashlib, datetime, subprocess, signal

SYS_OPENAT, SYS_NEWFSTATAT, SYS_UNLINKAT = 257, 262, 263
SYS_SYMLINKAT, SYS_RENAMEAT, SYS_GETDENTS64, SYS_READLINKAT = 266, 264, 217, 267
AT_FDCWD, AT_SYMLINK_NOFOLLOW, O_DIRECTORY = -100, 0x100, 0o200000

CANDIDATES = [
    "/usr/lib64/libkeyutils.so.1",
    "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1",
    "/lib/x86_64-linux-gnu/libkeyutils.so.1",
    "/lib64/libkeyutils.so.1",
    "/usr/lib/aarch64-linux-gnu/libkeyutils.so.1",
    "/usr/lib/libkeyutils.so.1",
]
SCAN_DIRS = ["/usr/lib64", "/lib64", "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
             "/usr/bin", "/usr/sbin", "/etc", "/etc/cron.d", "/root", "/tmp", "/var/tmp", "/dev/shm"]
BACKUP = "/root/backup"
_libc = None


def libc():
    """Loaded lazily: in remote mode this also runs on the operator's machine, which may be
    macOS and has no libc.so.6."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return _libc


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


# --------------------------------------------------------------------------- raw syscalls

def raw_read(path, limit=1 << 22):
    fd = libc().syscall(SYS_OPENAT, AT_FDCWD, path.encode(), 0, 0)
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


def raw_lstat(path):
    buf = ctypes.create_string_buffer(144)
    if libc().syscall(SYS_NEWFSTATAT, AT_FDCWD, path.encode(), buf, AT_SYMLINK_NOFOLLOW) != 0:
        return None
    r = buf.raw
    return {"mode": struct.unpack_from("<I", r, 24)[0],
            "uid": struct.unpack_from("<I", r, 28)[0],
            "size": struct.unpack_from("<q", r, 48)[0],
            "mtime": struct.unpack_from("<q", r, 88)[0],
            "ctime": struct.unpack_from("<q", r, 104)[0]}


def raw_readlink(path):
    buf = ctypes.create_string_buffer(4096)
    n = libc().syscall(SYS_READLINKAT, AT_FDCWD, path.encode(), buf, 4096)
    return buf.raw[:n].decode(errors="replace") if n > 0 else None


def raw_listdir(path):
    fd = libc().syscall(SYS_OPENAT, AT_FDCWD, path.encode(), O_DIRECTORY, 0)
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
    return names


def shown_readlink(path):
    """What ordinary tooling sees: this one is deliberately NOT a raw syscall."""
    try:
        return os.readlink(path)
    except OSError:
        return None


# ------------------------------------------------------------------------------ disk stage

def links_to_check(sandbox=None):
    if sandbox:
        return [sandbox.rstrip("/") + "/libkeyutils.so.1"]
    present = [p for p in CANDIDATES if raw_lstat(p)]
    # /lib64 and /lib are usually symlinks to /usr/lib64 and /usr/lib: same inode, handle once
    seen, work = set(), []
    for sl in present:
        key = os.path.realpath(os.path.dirname(sl)) + "/" + os.path.basename(sl)
        if key not in seen:
            seen.add(key)
            work.append(sl)
    return work


def scan_disk(work, sandbox=None):
    """Returns (findings, infections) where an infection is a dict describing one symlink.

    In sandbox mode the rootkit is not there to lie, so raw and reported targets agree; the
    fake infection is recognised by the implant-shaped target instead."""
    print("\n=== disk: libkeyutils symlink, raw syscall vs what tooling reports")
    findings, infections = [], []
    if not work:
        print("  libkeyutils.so.1 not found in the usual paths - nothing to compare")
        return ["libkeyutils.so.1 absent"], []
    for sl in work:
        real, shown = raw_readlink(sl), shown_readlink(sl)
        st = raw_lstat(sl)
        print("  %s" % sl)
        print("    real  (syscall)  : %s" % real)
        print("    shown (stat/ls)  : %s" % shown)
        if st:
            print("    symlink ctime    : %s" % utc(st["ctime"]))
        # the implant carries one numeric component more than the library it hides behind:
        # libkeyutils.so.1.10 is a normal soname, libkeyutils.so.1.10.2 is not
        if sandbox and real and re.search(r"\.so(\.\d+){3,}$", real):
            # no rootkit here to lie, so the fake infection is recognised by its target and
            # the legitimate name is derived from it; repair() still validates both
            shown = real[:-2]
            print("    => sandbox: treating %s as the implant, legitimate name would be %s"
                  % (real, shown))
        elif real == shown:
            print("    => consistent")
            continue
        else:
            print("    => INFECTED, hidden target")
        findings.append("hidden symlink target at %s" % sl)
        libdir = os.path.dirname(sl)
        implant = libdir + "/" + (real or "")
        data, si = raw_read(implant), raw_lstat(implant)
        inf = {"symlink": sl, "real": real, "shown": shown, "implant": implant,
               "libdir": libdir, "sha256": None, "size": None}
        if data and si:
            inf["sha256"] = hashlib.sha256(data).hexdigest()
            inf["size"] = len(data)
            inf["data"] = data
            print("    implant          : %s" % implant)
            print("      visible to ls  : %s" % ("yes" if os.path.exists(implant) else "NO, hidden"))
            print("      size           : %d" % len(data))
            print("      mode           : %s  setuid=%s  uid=%d"
                  % (oct(si["mode"])[-4:], bool(si["mode"] & 0o4000), si["uid"]))
            print("      sha256         : %s" % inf["sha256"])
            print("      mtime (faked)  : %s" % utc(si["mtime"]))
            print("      ctime (planted): %s" % utc(si["ctime"]))
        else:
            print("    implant %s cannot be read" % implant)
        infections.append(inf)
    return findings, infections


def scan_hidden(dirs):
    print("\n=== disk: directory entries hidden from readdir (getdents64 vs readdir)")
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            visible = set(os.listdir(d))
        except OSError:
            continue
        hidden = sorted(set(raw_listdir(d)) - visible)
        if hidden:
            print("  %-30s HIDDEN: %s" % (d, hidden))
            findings.append("hidden entries in %s: %s" % (d, hidden))
    if not findings:
        print("  none")
    return findings


def scan_preload():
    print("\n=== disk: /etc/ld.so.preload")
    pre = raw_read("/etc/ld.so.preload")
    body = (pre or b"").decode(errors="replace").strip()
    print("  %s" % (repr(body) if body else "absent or empty"))
    return ["/etc/ld.so.preload is not empty"] if body else []


# ---------------------------------------------------------------------------- memory stage

def btime():
    for line in (raw_read("/proc/stat") or b"").decode(errors="replace").splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return 0


def read_procs():
    out = []
    for pid in raw_listdir("/proc"):
        if not pid.isdigit():
            continue
        st = raw_read("/proc/%s/status" % pid)
        if not st:
            continue
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
        d["fds"] = {}
        for f in raw_listdir("/proc/%s/fd" % pid):
            t = raw_readlink("/proc/%s/fd/%s" % (pid, f))
            if t:
                d["fds"][f] = t
        out.append(d)
    return out


def scan_memory(procs, bt):
    """Returns (findings, suspect_pids)."""
    findings, suspects = [], set()

    print("\n=== memory: abstract unix sockets @tmp-* (Ebury credential drop)")
    inodes = {}
    for line in (raw_read("/proc/net/unix") or b"").decode(errors="replace").splitlines():
        if "@tmp-" in line:
            f = line.split()
            inodes[f[6]] = f[-1]
            print("  inode=%s name=%s" % (f[6], f[-1]))
    if not inodes:
        print("  none")
    else:
        findings.append("%d @tmp-* abstract socket(s)" % len(inodes))
        print("  holders (fd -> socket inode, resolved with raw readlinkat):")
        held = False
        for p in procs:
            for t in p["fds"].values():
                if any(t == "socket:[%s]" % i for i in inodes):
                    print("    pid=%s name=%s cmdline=%r exe=%s cgroup=%s"
                          % (p["pid"], p.get("Name"), p["cmdline"], p["exe"], p["cgroup"]))
                    suspects.add(int(p["pid"]))
                    held = True
                    break
        if not held:
            print("    none found (holder may be outside this namespace)")

    print("\n=== memory: unlinked shared objects and deleted binaries")
    # A package upgrade leaves plenty of legitimate "(deleted)" library mappings behind,
    # so only unlinked keyutils, or a .so unlinked from a world-writable dir, is a finding.
    def hot(path):
        if "keyutils" in path:
            return True
        so = ".so" in path.rsplit("/", 1)[-1]
        return so and any(h in path for h in ("/tmp/", "/dev/shm", "/var/tmp"))

    noise = 0
    for p in procs:
        dele = sorted({l.split()[-2] for l in p["maps"].splitlines() if l.endswith("(deleted)")})
        bad = [x for x in dele if hot(x)]
        if bad:
            print("  SUSPECT pid=%s %s exe=%s" % (p["pid"], p.get("Name"), p["exe"]))
            for x in bad:
                print("      %s (deleted)" % x)
            findings.append("pid %s maps unlinked %s" % (p["pid"], bad[0]))
            suspects.add(int(p["pid"]))
        elif p["exe"].endswith("(deleted)"):
            print("  INFO    pid=%s %s exe=%s  <- binary unlinked (also normal after an upgrade)"
                  % (p["pid"], p.get("Name"), p["exe"]))
        noise += len(dele) - len(bad)
    print("  (%d other (deleted) library mappings ignored as upgrade leftovers)" % noise)

    print("\n=== memory: PPid=1 daemons not belonging to their cgroup")
    # The Ebury daemon is forked from the backdoored sshd and reparented to init, so it keeps
    # ssh.service's cgroup while pretending to be something else. A legitimate service shares
    # its name with its unit, so only a name/unit clash is reported.
    ALIAS = {"ssh": "sshd", "dbus": "dbus-daemon", "postfix@-": "master", "cron": "cron",
             "systemd-journald": "systemd-journal"}
    for p in procs:
        if p.get("PPid") != "1":
            continue
        cg = p["cgroup"].rstrip("/")
        if not (cg.startswith("/system.slice") or cg.startswith("/init.scope")):
            continue  # a user session legitimately holds unrelated processes
        name = (p.get("Name") or "").lower()
        # the unit is not always the last cgroup segment: systemd-udevd.service has a /udev
        # child, user units nest under .slice
        segs = [x for x in cg.split("/") if x]
        unit = next((x for x in reversed(segs) if x.endswith((".service", ".scope"))), segs[-1] if segs else "")
        unit = unit.replace(".service", "").replace(".scope", "").replace("\\x2d", "-").lower()
        if not unit or unit in ("init", "-.slice"):
            continue
        if "getty" in unit and name == "agetty":
            continue
        if ALIAS.get(unit) == name or unit.startswith(name[:6]) or name[:6] in unit:
            continue
        # a unit frequently shares only one word with the process it runs
        # (pm2-uptimekuma.service -> "PM2 v7.0.4: God Daemon")
        haystack = " ".join((name, p["exe"].lower(), p["cmdline"].lower()))
        if any(len(t) >= 3 and t in haystack for t in unit.replace("@", "-").replace("_", "-").split("-")):
            continue
        # without root we cannot read other processes' environ, so an empty one proves nothing
        hard = unit == "ssh" or p["exe"].endswith("(deleted)") or (p["environ_len"] == 0 and os.geteuid() == 0)
        print("  %s pid=%s name=%s cmdline=%r cgroup=%s"
              % ("SUSPECT" if hard else "INFO   ", p["pid"], p.get("Name"), p["cmdline"], cg))
        print("      exe=%s environ=%dB start=%s fd0-2=%s"
              % (p["exe"], p["environ_len"], utc(bt + p["start"]),
                 [p["fds"].get(x) for x in ("0", "1", "2")]))
        if hard:
            findings.append("pid %s (%s) runs outside its unit, cgroup %s" % (p["pid"], p.get("Name"), cg))
            suspects.add(int(p["pid"]))
    print("\n=== memory: libkeyutils mapped by sshd")
    for p in procs:
        if "sshd" in (p.get("Name") or "") and "keyutils" in p["maps"]:
            for l in p["maps"].splitlines():
                if "keyutils" in l:
                    print("  pid=%-8s %s" % (p["pid"], l.split()[-1]))
                    break
    return findings, suspects


def mapped_by(procs, needle):
    return [int(p["pid"]) for p in procs if needle in p["maps"]]


def scan_authkeys():
    print("\n=== root authorized_keys (raw read, hooks bypassed)")
    for path in ("/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"):
        data = raw_read(path)
        if not data:
            continue
        for line in data.decode(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                f = line.split()
                print("  %s: %s...%s  %s" % (path, f[0], f[1][-12:] if len(f) > 1 else "",
                                             f[-1] if len(f) > 2 else ""))


# ----------------------------------------------------------------------------------- repair

def repair(inf, sandbox=None):
    """Repoint the symlink at the legitimate library, then unlink the implant. Raw syscalls
    only: ln and rm are hooked. Returns 0 on success, 2 on refusal or failure."""
    sl, real, shown, libdir = inf["symlink"], inf["real"], inf["shown"], inf["libdir"]
    implant, legit = inf["implant"], shown
    print("\n--- repair %s" % sl)
    if not real or not shown:
        print("  cannot resolve both targets; refusing")
        return 2
    if real != shown + ".2":
        print("  hidden target %r is not the expected '%s.2' shape; refusing to touch it. "
              "Review manually." % (real, shown))
        return 2
    if not inf.get("data"):
        print("  implant %s cannot be read; refusing" % implant)
        return 2
    if not raw_lstat(libdir + "/" + legit):
        print("  legitimate library %s/%s is MISSING; refusing (the symlink would dangle)"
              % (libdir, legit))
        return 2

    backup = (sandbox.rstrip("/") + "/backup") if sandbox else BACKUP
    os.makedirs(backup, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    sample = "%s/implant-%s-%s.bin" % (backup, real, stamp)
    with open(sample, "wb") as f:
        f.write(inf["data"])
    os.chmod(sample, 0o400)
    with open("%s/ebury-state-%s.txt" % (backup, stamp), "w") as f:
        f.write("symlink=%s\nreal=%s\nshown=%s\nimplant=%s\nsize=%s\nsha256=%s\nlegit=%s\n"
                % (sl, real, shown, implant, inf["size"], inf["sha256"], legit))
    print("  saved %s (mode 400) and the state file" % sample)

    tmp = libdir + "/.libkeyutils.swap.%d" % os.getpid()
    libc().syscall(SYS_UNLINKAT, AT_FDCWD, tmp.encode(), 0)
    if libc().syscall(SYS_SYMLINKAT, legit.encode(), AT_FDCWD, tmp.encode()) != 0:
        print("  symlinkat failed errno=%d; nothing changed" % ctypes.get_errno())
        return 2
    if libc().syscall(SYS_RENAMEAT, AT_FDCWD, tmp.encode(), AT_FDCWD, sl.encode()) != 0:
        print("  renameat failed errno=%d" % ctypes.get_errno())
        libc().syscall(SYS_UNLINKAT, AT_FDCWD, tmp.encode(), 0)
        print("  temp removed, original symlink untouched")
        return 2
    print("  symlink repointed -> %s" % raw_readlink(sl))
    if libc().syscall(SYS_UNLINKAT, AT_FDCWD, implant.encode(), 0) != 0:
        print("  unlinkat failed errno=%d (the symlink is already fixed)" % ctypes.get_errno())
        return 2
    print("  implant unlinked; still on disk: %s" % (raw_lstat(implant) is not None))
    if not sandbox:
        # after the file is gone, so ldconfig cannot pick the implant's version as newest
        r = subprocess.run(["ldconfig"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print("  ldconfig rc=%d %s" % (r.returncode, r.stdout.decode(errors="replace").strip()[:200]))
    return 0


def own_session_pids():
    """Our own process chain and ssh session: never kill these."""
    keep = {os.getpid(), os.getppid(), 1}
    try:
        keep.add(os.getsid(0))
        keep.add(os.getpgid(0))
    except OSError:
        pass
    pid = os.getppid()
    for _ in range(12):  # walk up to init
        st = raw_read("/proc/%d/status" % pid)
        if not st:
            break
        ppid = None
        for line in st.decode(errors="replace").splitlines():
            if line.startswith("PPid:"):
                ppid = int(line.split()[1])
        if not ppid or ppid <= 1:
            break
        keep.add(ppid)
        pid = ppid
    return keep


def kill_daemon(suspects, procs):
    """Unload the in-memory stage without a reboot: kill the masquerading daemon and any
    process still mapping the implant. Never touches our own session or pid 1."""
    keep = own_session_pids()
    print("\n--- unloading the in-memory stage")
    print("  protected pids (our own chain): %s" % sorted(keep))
    live_sshd = [p for p in procs if p["cmdline"].startswith("sshd: /usr/sbin/sshd -D")]
    for p in live_sshd:
        if "keyutils" in p["maps"]:
            tgt = [l.split()[-1] for l in p["maps"].splitlines() if "keyutils" in l]
            print("  listening sshd pid=%s maps %s" % (p["pid"], tgt))
    rc = 0
    for pid in sorted(suspects):
        if pid in keep:
            print("  pid=%d is our own session; skipped" % pid)
            continue
        info = next((p for p in procs if int(p["pid"]) == pid), None)
        label = "%s %r" % (info.get("Name"), info["cmdline"]) if info else "?"
        try:
            os.kill(pid, signal.SIGKILL)
            print("  killed pid=%d %s" % (pid, label))
        except OSError as e:
            print("  pid=%d %s: kill failed (%s)" % (pid, label, e))
            rc = 2
    return rc


# -------------------------------------------------------------------------------- sandbox

def make_sandbox(root):
    """Build a fake infection so the removal path can be exercised without a real one:
    libkeyutils.so.1 -> libkeyutils.so.1.10.2 (the 'implant'), next to a legitimate
    libkeyutils.so.1.10. Nothing outside `root` is touched."""
    root = root.rstrip("/")
    os.makedirs(root, exist_ok=True)
    legit, implant, link = root + "/libkeyutils.so.1.10", root + "/libkeyutils.so.1.10.2", root + "/libkeyutils.so.1"
    if os.path.lexists(link):
        print("sandbox %s already set up, using it as it is" % root)
        print("  %s -> %s" % (link, os.readlink(link)))
        return root
    with open(legit, "wb") as f:
        f.write(b"\x7fELF" + b"legit" * 100)
    with open(implant, "wb") as f:
        f.write(b"\x7fELF" + os.urandom(64600 - 4))
    os.chmod(implant, 0o4755)
    os.symlink("libkeyutils.so.1.10.2", link)
    print("sandbox ready in %s" % root)
    print("  %s -> %s" % (link, os.readlink(link)))
    return root


# ----------------------------------------------------------------------------------- driver

def run(apply_changes, kill_mem, sandbox):
    host = os.popen("hostname -f 2>/dev/null || hostname").read().strip() or os.uname()[1]
    rel = ""
    for f in ("/etc/os-release", "/usr/lib/os-release"):
        for line in (raw_read(f) or b"").decode(errors="replace").splitlines():
            if line.startswith("PRETTY_NAME"):
                rel = line.split("=", 1)[1].strip().strip('"')
    print("HOST : %s" % host)
    print("OS   : %s   KERNEL: %s" % (rel or "unknown", os.uname()[2]))
    print("MODE : %s%s" % ("APPLY" if apply_changes else "SCAN ONLY (nothing is changed)",
                           ", --kill-daemon" if kill_mem else ""))
    if os.geteuid() != 0:
        print("WARN : not running as root - other processes' maps, fd and environ are "
              "unreadable, so the memory stage is incomplete and its findings are unreliable")
    if sandbox:
        print("SANDBOX: %s (the real system is not touched)" % sandbox)

    work = links_to_check(sandbox)
    findings, infections = scan_disk(work, sandbox)
    if not sandbox:
        findings += scan_hidden(SCAN_DIRS)
        findings += scan_preload()
        bt = btime()
        procs = read_procs()
        mem_findings, suspects = scan_memory(procs, bt)
        findings += mem_findings
        scan_authkeys()
    else:
        procs, suspects = [], set()

    print("\nVERDICT: %s" % ("INFECTED / SUSPECT" if findings else "CLEAN"))
    for f in findings:
        print("  - %s" % f)
    if not findings:
        return 0
    if not apply_changes:
        if infections:
            print("\n[scan only] run again with --apply to repoint the symlink and unlink the implant")
        return 1

    rc = 0
    for inf in infections:
        rc = repair(inf, sandbox) or rc
    if sandbox:
        link = work[0]
        print("\n--- post-state")
        print("  %s -> real=%s shown=%s" % (link, raw_readlink(link), shown_readlink(link)))
        for inf in infections:
            print("  implant %s on disk: %s" % (inf["implant"], raw_lstat(inf["implant"]) is not None))
        return rc

    procs = read_procs()  # re-read: the symlink changed under them
    holders = set()
    for inf in infections:
        holders |= set(mapped_by(procs, inf["real"]))
    holders -= own_session_pids()
    print("\n--- post-state")
    for sl in links_to_check():
        print("  %s  real=%s shown=%s" % (sl, raw_readlink(sl), shown_readlink(sl)))
    for d in ("/usr/lib64", "/usr/lib/x86_64-linux-gnu"):
        if os.path.isdir(d):
            try:
                h = sorted(set(raw_listdir(d)) - set(os.listdir(d)))
            except OSError:
                h = []
            print("  hidden in %-28s %s" % (d, h if h else "none"))
    print("  processes still holding the implant in memory: %d %s"
          % (len(holders), sorted(holders) if holders else ""))
    if kill_mem:
        rc = kill_daemon(suspects | holders, procs) or rc
        print("\n  re-run the scan to confirm: no @tmp-* socket, no process mapping the implant")
    else:
        print("\n  >>> the implant is still mapped in memory and the daemon can put it back.")
        print("  >>> reboot, or re-run with --apply --kill-daemon to unload it live.")
    print("\n  >>> rotate every credential that passed through this host: ssh keys, root and")
    print("  >>> user passwords, anything typed into an ssh session.")
    return rc or 1


def remote(hosts, apply_changes, kill_mem):
    src = open(os.path.abspath(__file__), "rb").read()
    args = " ".join(x for x in (("--apply" if apply_changes else ""),
                                ("--kill-daemon" if kill_mem else "")) if x)
    results = []
    for h in hosts:
        target = h if "@" in h else "root@" + h
        print("=" * 72)
        print("### %s" % target)
        print("=" * 72)
        p = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=25",
                            target, "python3 - %s" % args], input=src,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode(errors="replace")
        print(out.rstrip())
        if "VERDICT: CLEAN" in out:
            v = "CLEAN"
        elif "refusing" in out.lower():
            v = "NEEDS REVIEW"
        elif "implant unlinked" in out:
            v = "FIXED" + ("" if kill_mem else ", NEEDS REBOOT")
        elif "VERDICT: INFECTED" in out:
            v = "INFECTED"
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
    argv = sys.argv[1:]
    apply_changes = "--apply" in argv
    kill_mem = "--kill-daemon" in argv
    sandbox = None
    if "--sandbox" in argv:
        i = argv.index("--sandbox")
        if i + 1 >= len(argv):
            sys.exit("--sandbox needs a directory")
        sandbox = make_sandbox(argv[i + 1])
        del argv[i:i + 2]
    hosts = [a for a in argv if not a.startswith("--")]
    if kill_mem and not apply_changes:
        sys.exit("--kill-daemon only makes sense together with --apply")
    sys.exit(remote(hosts, apply_changes, kill_mem) if hosts
             else run(apply_changes, kill_mem, sandbox))
