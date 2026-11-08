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
