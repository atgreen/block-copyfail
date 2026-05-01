# block-copyfail

Runtime mitigation for [CVE-2026-31431](https://copy.fail/) ("Copy Fail") — a Linux kernel privilege escalation via the `authencesn` cryptographic template in `algif_aead`.

Unlike module blacklisting, this **requires no reboot**. A BPF LSM program hooks `socket_bind` and blocks only the vulnerable `authencesn` algorithm. All other AF_ALG usage (dm-crypt, OpenSSL afalg engine, hash, skcipher) is unaffected.

Blocked attempts are logged in real time with PID, process name, and timestamp.

## Prerequisites

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y` and `lsm=bpf` in boot parameters
- [SBCL](http://www.sbcl.org/) 2.0+
- [Whistler](https://github.com/atgreen/whistler) (Common Lisp eBPF compiler)

```
make doctor   # check all prerequisites
```

## Quick start

```
git clone https://github.com/atgreen/whistler.git ~/git/whistler
git clone https://github.com/atgreen/block-copyfail.git
cd block-copyfail
sudo make run
```

The blocker stays active until you press Ctrl-C, then cleanly detaches.

## Build a standalone binary

```
make build
sudo ./block-copyfail
```

## Testing

With the blocker running in one terminal, trigger a test in another:

```
python3 trigger-test.py
```

The test script attempts an `authencesn` AF_ALG bind (no exploit is performed).

**Expected output in the test terminal:**

```
BLOCKED: [Errno 1] Operation not permitted
```

**Expected output in the blocker terminal:**

```
Copy Fail blocker active — authencesn bind blocked.
Other AF_ALG usage (dm-crypt, hash, skcipher) unaffected.
Watching for blocked attempts. Press Ctrl-C to exit.

TIME                  PID       COMMAND
----                  ---       -------
06:38:12               31337  python3
```

Without the blocker running, the test script prints:

```
FAIL: bind succeeded (blocker not working)
```

## How it works

The BPF program reads 34 bytes of `struct sockaddr_alg` from the `socket_bind` arguments via `bpf_probe_read_kernel`, checks `salg_family == AF_ALG` and `salg_name` starts with `"authencesn"`, and returns `-EPERM` on match. Events are sent to userspace via a ring buffer.

Written in [Whistler](https://github.com/atgreen/whistler), a Common Lisp dialect that compiles directly to eBPF bytecode — no C, clang, or LLVM required.

## License

MIT
