#!/bin/bash

set -euo pipefail

echo "===== RESOURCE LIMITS ====="

ulimit -t 20
ulimit -v 1048576
ulimit -u 64
ulimit -f 10240
ulimit -c 0

echo "CPU seconds per process: $(ulimit -t)"
echo "Virtual memory KB per process: $(ulimit -v)"
echo "Processes: $(ulimit -u)"
echo "File size blocks: $(ulimit -f)"
echo "Core dumps: $(ulimit -c)"

echo "NOTE: ulimit values are not aggregate cgroup limits."

echo "===== IDENTITY AND SECURITY STATUS ====="

id

STATUS="$(cat /proc/self/status)"

CAP_EFF="$(printf '%s\n' "$STATUS" | awk '/^CapEff:/ {print $2}')"
NO_NEW_PRIVS="$(printf '%s\n' "$STATUS" | awk '/^NoNewPrivs:/ {print $2}')"
SECCOMP="$(printf '%s\n' "$STATUS" | awk '/^Seccomp:/ {print $2}')"

printf 'CapEff=%s\n' "$CAP_EFF"
printf 'NoNewPrivs=%s\n' "$NO_NEW_PRIVS"
printf 'Seccomp=%s\n' "$SECCOMP"

if [[ ! "$CAP_EFF" =~ ^0+$ ]]; then
    echo "FAIL: effective capabilities are not zero"
    exit 1
fi

if [[ "$NO_NEW_PRIVS" != "1" ]]; then
    echo "FAIL: NoNewPrivs is not enabled"
    exit 1
fi

if [[ "$SECCOMP" != "2" ]]; then
    echo "FAIL: seccomp filter is not active"
    exit 1
fi

echo "PASS: security status checks"

echo "===== SECCOMP ENFORCEMENT TEST ====="

python3 - <<'SECCOMP_TEST'
import ctypes

libc = ctypes.CDLL(None, use_errno=True)

result = libc.ptrace(0, 0, 0, 0)
error = ctypes.get_errno()

print("PTRACE_RESULT", result)
print("PTRACE_ERRNO", error)

if result != -1 or error != 99:
    raise SystemExit("FAIL: expected seccomp errno 99")

print("PASS: ptrace blocked by the diagnostic filter")
SECCOMP_TEST

echo "===== NAMESPACE TEST ====="

check_namespace() {
    name="$1"
    host="$2"
    current="$(readlink "/proc/self/ns/$name")"

    printf '%s: host=%s sandbox=%s\n' "$name" "$host" "$current"

    if [[ "$host" == "$current" ]]; then
        echo "FAIL: $name namespace not isolated"
        exit 1
    fi

    echo "PASS: $name namespace"
}

check_namespace user "$HOST_USER_NS"
check_namespace pid "$HOST_PID_NS"
check_namespace net "$HOST_NET_NS"
check_namespace mnt "$HOST_MNT_NS"

echo "===== FILESYSTEM TEST ====="

if [[ -e "$HOST_MARKER" ]]; then
    echo "FAIL: host marker visible"
    exit 1
fi

if [[ -e /home/runner ]]; then
    echo "FAIL: runner home unexpectedly present in minimal rootfs"
    exit 1
fi

if [[ -e /var/run/docker.sock || -e /run/docker.sock ]]; then
    echo "FAIL: Docker socket unexpectedly present in minimal rootfs"
    exit 1
fi

touch /work/test-file
touch /tmp/test-file

if touch /etc/sandbox-write-test 2>/dev/null; then
    echo "FAIL: root filesystem is writable"
    exit 1
fi

echo "PASS: minimal filesystem and write restrictions"

echo "===== ENVIRONMENT TEST ====="

if env | grep -qiE 'TOKEN|SECRET|PASSWORD|API_KEY|GITHUB'; then
    echo "FAIL: sensitive environment variable detected"
    exit 1
fi

echo "PASS: inherited environment cleared"

echo "===== PROCESS VISIBILITY TEST ====="

python3 - <<'PROCESS'
import glob
import os

marker = os.environ["HOST_PROCESS_MARKER"].encode()
paths = glob.glob("/proc/[0-9]*/cmdline")

if not paths:
    raise SystemExit("FAIL: process table could not be inspected")

hits = []

for path in paths:
    try:
        with open(path, "rb") as handle:
            content = handle.read()
    except FileNotFoundError:
        continue

    if marker in content:
        hits.append(path)

print("HOST_SENTINEL_VISIBLE", hits)

if hits:
    raise SystemExit("FAIL: host process sentinel is visible")

print("PASS: host process sentinel not visible")
PROCESS

echo "===== NETWORK TEST ====="

ip -brief link

INTERFACES="$(
    ip -o link show |
    awk -F': ' '{print $2}' |
    cut -d@ -f1
)"

if [[ "$INTERFACES" != "lo" ]]; then
    echo "FAIL: unexpected network interface: $INTERFACES"
    exit 1
fi

ROUTES4="$(ip -4 route show default)"
ROUTES6="$(ip -6 route show default)"

if [[ -n "$ROUTES4" || -n "$ROUTES6" ]]; then
    echo "FAIL: default network route exists"
    printf '%s\n%s\n' "$ROUTES4" "$ROUTES6"
    exit 1
fi

echo "PASS: only loopback interface and no default routes"

python3 - <<'NETWORK'
import errno
import socket

targets = [
    (socket.AF_INET, "1.1.1.1"),
    (socket.AF_INET6, "2606:4700:4700::1111"),
]

for family, address in targets:
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        if family == socket.AF_INET6 and error.errno in (
            errno.EAFNOSUPPORT,
            errno.EPROTONOSUPPORT,
        ):
            print("IPv6 unavailable; no IPv6 socket")
            continue
        raise

    sock.settimeout(3)

    try:
        result = sock.connect_ex((address, 80))
    finally:
        sock.close()

    print("NETWORK_CONNECT_RESULT", address, result)

    if result == 0:
        raise SystemExit("FAIL: external connection succeeded")

print("PASS: direct external IPv4/IPv6 connections blocked")
NETWORK

echo "===== NESTED USER NAMESPACE TEST ====="

if unshare -Ur true 2>/dev/null; then
    echo "FAIL: nested user namespace creation succeeded"
    exit 1
fi

echo "PASS: nested user namespaces blocked"

echo "===== PYTHON EXECUTION TEST ====="

python3 -c 'print("PASS: Python executes inside isolated filesystem")'

echo "===== HARDENING TESTS PASSED ====="
