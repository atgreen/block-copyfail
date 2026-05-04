# block-copyfail

**Proof of concept** runtime mitigation for [CVE-2026-31431](https://copy.fail/) ("Copy Fail") — a Linux kernel privilege escalation via the `authencesn` cryptographic template in `algif_aead`.

Unlike module blacklisting, this **requires no reboot**. A BPF LSM program hooks `socket_bind` and blocks all AF_ALG AEAD binds — the subsystem exploited by Copy Fail. This prevents bypasses via crypto template nesting (e.g. `pcrypt(authencesn(...))`). Other AF_ALG usage (hash, skcipher) is unaffected.

Blocked attempts are logged in real time with PID, process name, and timestamp.

## Prerequisites

- Linux kernel 5.7+ with `CONFIG_BPF_LSM=y` and `lsm=bpf` in boot parameters
- [SBCL](http://www.sbcl.org/) 2.0+
- [Whistler](https://github.com/atgreen/whistler) (Common Lisp eBPF compiler)

```sh
make doctor   # check all prerequisites
```

## Quick start

```sh
git clone https://github.com/atgreen/block-copyfail.git
cd block-copyfail
```

```sh
make ubi8-build
sudo ./block-copyfail
```

### OpenShift quick start

```sh
oc apply -k ocp
```

The blocker stays active until you press Ctrl-C, then cleanly detaches.

## Build locally

To build on your own machine you need SBCL and [Whistler](https://github.com/atgreen/whistler) (the Common Lisp eBPF compiler):

```sh
git clone https://github.com/atgreen/whistler.git ~/git/whistler
make build
sudo ./block-copyfail
```

## Build a portable binary (EL8+)

Build inside a UBI8 container to produce a binary that runs on RHEL/CentOS/Alma/Rocky 8+, Fedora, Ubuntu 20.04+, and any Linux with glibc 2.28 or newer. No SBCL or Whistler needed on the target system — just copy the binary and run it.

```sh
make ubi8-build
scp block-copyfail root@server:
ssh root@server ./block-copyfail
```

## Compile to ELF object

Produces a standard `.bpf.o` file loadable by `bpftool`, `libbpf`, or any BPF loader:

```sh
make elf
sudo mkdir -p /sys/fs/bpf/copyfail
sudo bpftool prog loadall block-copyfail.bpf.o /sys/fs/bpf/copyfail autoattach
```

To detach and remove:

```sh
sudo rm -rf /sys/fs/bpf/copyfail
```

## Testing

With the blocker running in one terminal, trigger a test in another:

```sh
python3 trigger-test.py
```

The test script attempts an AF_ALG AEAD bind (no exploit is performed).

**Expected output in the test terminal:**

```sh
BLOCKED: aead/authencesn(hmac(sha256),cbc(aes)) — [Errno 1] Operation not permitted
BLOCKED: aead/gcm(aes) — [Errno 1] Operation not permitted
ALLOWED: hash/sha256
ALLOWED: skcipher/cbc(aes)
```

**Expected output in the blocker terminal:**

```sh
Copy Fail blocker active — all AF_ALG AEAD binds blocked.
Other AF_ALG usage (hash, skcipher) unaffected.
Watching for blocked attempts. Press Ctrl-C to exit.

TIME                  PID       COMMAND
----                  ---       -------
06:38:12               31337  python3
```

Without the blocker running, the test script prints `ALLOWED` for all four algorithms.

## How it works

The BPF program reads 7 bytes of `struct sockaddr_alg` from the `socket_bind` arguments via `bpf_probe_read_kernel`, checks `salg_family == AF_ALG` and `salg_type == "aead"`, and returns `-EPERM` on match. This blocks all AEAD algorithm binds regardless of template nesting. Events are sent to userspace via a ring buffer.

Written in [Whistler](https://github.com/atgreen/whistler), a Common Lisp dialect that compiles directly to eBPF bytecode — no C, clang, or LLVM required.

## License

MIT
