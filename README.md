# fimd

A small host-based file integrity monitor for Linux. It compares the filesystem against an Ed25519-signed baseline, watches for changes with inotify, and records every finding in a hash-chained append-only log so that after-the-fact edits are detectable.

C++17, OpenSSL 3 (SHA-256 and Ed25519 via EVP), no other dependencies.

## Build and test

    cmake -S . -B build && cmake --build build -j
    ./tests/smoke.sh build/fimd

## Usage

    fimd keygen --priv fimd.key --pub fimd.pub          # run once, off the monitored host
    fimd init -w /etc -w /usr/local/bin -x /etc/mtab \
         --baseline /var/lib/fimd/base --key fimd.key    # sign on a trusted machine
    fimd check --baseline /var/lib/fimd/base --pub fimd.pub --log /var/lib/fimd/log
    fimd watch --baseline /var/lib/fimd/base --pub fimd.pub --log /var/lib/fimd/log \
         --syslog --rescan 3600
    fimd verify-log --log /var/lib/fimd/log [--expect-head HEX] [--expect-count N]
    fimd head --log /var/lib/fimd/log                    # print records and head hash to ship off-box

`check` exits 0 when clean, 1 on differences, 2 on error. Event kinds are ADDED, MODIFIED, DELETED and ATTRIB (mode, uid or gid changed with identical content), plus START, STOP, CHECK_START, CHECK_END, RESCAN_OVERFLOW and RESCAN_PERIODIC markers. START and CHECK_START records carry the SHA-256 of the baseline file, binding the log to the exact baseline in force.

## Design

The baseline is a sorted text manifest (mode, uid, gid, size, SHA-256, escaped path) with a detached raw Ed25519 signature in `<baseline>.sig`. The watched roots and exclusions live inside the signed manifest, so an attacker cannot shrink the monitored scope without invalidating the signature. The daemon holds only the public key; re-baselining after legitimate changes happens with the private key on another machine.

Each log record is `seq, timestamp, kind, path, old_sha256, new_sha256, prev_hash, entry_hash`, where `entry_hash` is SHA-256 over a domain-separated, newline-joined encoding of the other fields. Editing, removing or reordering any record breaks every hash after it. The log is opened 0600 with an exclusive flock and is fully verified on every open; the daemon refuses to extend a chain that does not verify. Every append is followed by fdatasync.

The watcher arms inotify on every directory before the seeding scan, so nothing falls between scanning and watching. Newly created directories are watched and then walked, which covers files that appeared before the watch existed. Renamed or deleted directories have their watches torn down and their subtree re-examined, because a watch descriptor tracks an inode and its stored path goes stale on rename. Bursts are debounced (default 300 ms, forced after 2 s of continuous activity) and then reported as state differences against the last known state, so a file created and removed inside one window produces no event. On IN_Q_OVERFLOW the daemon re-arms all watches and performs a full diff scan, and `--rescan` adds a periodic full scan as a backstop against anything inotify cannot see.

Hashing is TOCTOU-resistant: paths are lstat-ed, opened with O_NOFOLLOW and O_NONBLOCK, type-checked on the open descriptor (so a swap to a FIFO or device is rejected), and fstat-ed before and after the read; if mtime, ctime or size moved, the file is re-read.

## Threat model and limits

fimd detects tampering by an attacker who can modify files but cannot also forge the Ed25519 signature or silently rewrite your off-box log anchor. It does not prevent tampering.

Root on the monitored host can stop the daemon, rewrite the whole log with a fresh valid chain, or truncate its tail; a hash chain alone cannot expose either. The defence is to periodically copy `fimd head` output (and count) to another system and verify with `--expect-head` and `--expect-count`, and to forward events with `--syslog` to a collector the host cannot rewrite. Setting the append-only attribute on the log (`chattr +a`) raises the bar further.

Other known limits: only regular files and symlinks are recorded (devices, sockets and FIFOs are skipped); extended attributes, ACLs, SELinux labels and file capabilities are not hashed yet; changes made through mmap on an already open file may only surface on the next close or periodic rescan; the watch limit is `fs.inotify.max_user_watches`, and the daemon warns when it is hit; log verification at startup is linear in log size.

## Roadmap

Signing key on a FIDO2 token (libfido2 or `ssh-keygen -Y sign` with a security-key identity), checkpoint records signed with a separate log key, xattr/ACL/capability coverage, fanotify backend for mount-wide coverage, webhook and journald sinks, a systemd unit with a hardened sandbox, and a libFuzzer harness for the baseline parser.
