"""Pure-stdlib `SCMP_ARCH_X86_64` classic BPF compiler and pure-Python BPF VM."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import struct
from types import MappingProxyType
from typing import Any, Final

from tools.governance import gov1_sandbox
from tools.governance.gov1_sandbox import verify_seccomp_profile

AUDIT_ARCH_X86_64: Final[int] = 0xC000003E
SECCOMP_RET_ALLOW: Final[int] = 0x7FFF0000
SECCOMP_RET_ERRNO_EPERM: Final[int] = 0x00050001
SECCOMP_RET_KILL_PROCESS: Final[int] = 0x80000000
SECCOMP_RET_KILL_THREAD: Final[int] = 0x00000000
BPF_MAXINSNS: Final[int] = 4096

_LD_IMM: Final[int] = 0x00
_LD_ABS: Final[int] = 0x20
_LD_LEN: Final[int] = 0x80
_ALU_ADD_K: Final[int] = 0x04
_ALU_SUB_K: Final[int] = 0x14
_ALU_MUL_K: Final[int] = 0x24
_ALU_DIV_K: Final[int] = 0x34
_ALU_OR_K: Final[int] = 0x44
_ALU_AND_K: Final[int] = 0x54
_ALU_LSH_K: Final[int] = 0x64
_ALU_RSH_K: Final[int] = 0x74
_ALU_NEG: Final[int] = 0x84
_ALU_XOR_K: Final[int] = 0xA4
_JMP_JA: Final[int] = 0x05
_JMP_JEQ_K: Final[int] = 0x15
_JMP_JGT_K: Final[int] = 0x25
_JMP_JGE_K: Final[int] = 0x35
_JMP_JSET_K: Final[int] = 0x45
_RET_K: Final[int] = 0x06
_RET_A: Final[int] = 0x16
_MAX_CHUNK_NRS: Final[int] = 250

STAGE7_PEP517_EXTRA_SYSCALLS: Final[frozenset[str]] = frozenset(
    {
        "chdir",
        "chmod",
        "clock_nanosleep",
        "clone",
        "clone3",
        "close_range",
        "dup3",
        "execve",
        "execveat",
        "fchdir",
        "fchmod",
        "fchmodat",
        "fork",
        "fstatfs",
        "nanosleep",
        "prctl",
        "statfs",
        "utimensat",
        "vfork",
        "wait4",
        "waitid",
    }
)

_STAGE7_ALLOWED_SUBPROC_SYSCALLS: Final[frozenset[str]] = frozenset(
    {"clone", "clone3", "execve", "execveat", "fork", "vfork"}
)
_STAGE7_FORBIDDEN_SYSCALLS: Final[frozenset[str]] = (
    (set(gov1_sandbox.MANDATORY_DENIED_SYSCALLS) - _STAGE7_ALLOWED_SUBPROC_SYSCALLS)
    | set(gov1_sandbox.KERNEL_BYPASS_DENIED_SYSCALLS)
    | {"chroot", "seccomp", "shutdown", "setsockopt", "getsockopt", "sendmmsg"}
)

X86_64_SYSCALL_NUMBERS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
        "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
        "brk": 12, "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
        "ioctl": 16, "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
        "access": 21, "pipe": 22, "select": 23, "sched_yield": 24, "mremap": 25,
        "msync": 26, "mincore": 27, "madvise": 28, "shmget": 29, "shmat": 30,
        "shmctl": 31, "dup": 32, "dup2": 33, "pause": 34, "nanosleep": 35,
        "getitimer": 36, "alarm": 37, "setitimer": 38, "getpid": 39, "sendfile": 40,
        "socket": 41, "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
        "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "bind": 49, "listen": 50,
        "getsockname": 51, "getpeername": 52, "socketpair": 53, "setsockopt": 54,
        "getsockopt": 55, "clone": 56, "fork": 57, "vfork": 58, "execve": 59,
        "exit": 60, "wait4": 61, "kill": 62, "uname": 63, "fcntl": 72, "flock": 73,
        "fsync": 74, "fdatasync": 75, "truncate": 76, "ftruncate": 77, "getdents": 78,
        "getcwd": 79, "chdir": 80, "fchdir": 81, "rename": 82, "mkdir": 83, "rmdir": 84,
        "creat": 85, "link": 86, "unlink": 87, "symlink": 88, "readlink": 89,
        "chmod": 90, "fchmod": 91, "chown": 92, "fchown": 93, "lchown": 94, "umask": 95,
        "gettimeofday": 96, "getrlimit": 97, "getrusage": 98, "sysinfo": 99,
        "times": 100, "ptrace": 101, "getuid": 102, "getgid": 104, "setuid": 105,
        "setgid": 106, "geteuid": 107, "getegid": 108, "setpgid": 109, "getppid": 110,
        "getpgrp": 111, "setsid": 112, "setreuid": 113, "setregid": 114,
        "getgroups": 115, "setgroups": 116, "setresuid": 117, "getresuid": 118,
        "setresgid": 119, "getresgid": 120, "getpgid": 121, "getsid": 124,
        "capget": 125, "capset": 126, "rt_sigpending": 127, "rt_sigtimedwait": 128,
        "rt_sigqueueinfo": 129, "rt_sigsuspend": 130, "sigaltstack": 131, "mknod": 133,
        "statfs": 137, "fstatfs": 138, "pivot_root": 155, "prctl": 157,
        "arch_prctl": 158, "setrlimit": 160, "chroot": 161, "mount": 165,
        "umount2": 166, "gettid": 186, "tkill": 200, "time": 201, "futex": 202,
        "sched_setaffinity": 203, "sched_getaffinity": 204, "epoll_create": 213,
        "getdents64": 217, "set_tid_address": 218, "fadvise64": 221,
        "clock_gettime": 228, "clock_getres": 229, "clock_nanosleep": 230,
        "exit_group": 231, "epoll_wait": 232, "epoll_ctl": 233, "tgkill": 234,
        "waitid": 247, "keyctl": 250, "openat": 257, "mkdirat": 258, "mknodat": 259,
        "fchownat": 260, "newfstatat": 262, "unlinkat": 263, "renameat": 264,
        "linkat": 265, "symlinkat": 266, "readlinkat": 267, "fchmodat": 268,
        "faccessat": 269, "pselect6": 270, "ppoll": 271, "unshare": 272,
        "set_robust_list": 273, "get_robust_list": 274, "splice": 275, "tee": 276,
        "utimensat": 280, "epoll_pwait": 281, "fallocate": 285, "accept4": 288,
        "eventfd2": 290, "epoll_create1": 291, "dup3": 292, "pipe2": 293,
        "prlimit64": 302, "name_to_handle_at": 303, "open_by_handle_at": 304,
        "syncfs": 306, "sendmmsg": 307, "setns": 308, "getcpu": 309, "renameat2": 316,
        "seccomp": 317, "getrandom": 318, "memfd_create": 319, "bpf": 321,
        "execveat": 322, "copy_file_range": 326, "preadv2": 327, "pwritev2": 328,
        "statx": 332, "rseq": 334, "pidfd_send_signal": 424, "io_uring_setup": 425,
        "io_uring_enter": 426, "io_uring_register": 427, "pidfd_open": 434,
        "clone3": 435, "close_range": 436, "openat2": 437, "pidfd_getfd": 438,
        "faccessat2": 439, "epoll_pwait2": 441, "cachestat": 451, "fchmodat2": 452,
    }
)


def _map_seccomp_action(action: str, errno_ret: object = 1) -> int:
    if action == "SCMP_ACT_ALLOW":
        return SECCOMP_RET_ALLOW
    if action == "SCMP_ACT_ERRNO":
        if type(errno_ret) is not int or not (0 <= errno_ret <= 0xFFFF):
            raise ValueError(f"seccomp errnoRet out of range: {errno_ret!r}")
        return 0x00050000 | (errno_ret & 0xFFFF)
    if action == "SCMP_ACT_KILL_PROCESS":
        return SECCOMP_RET_KILL_PROCESS
    if action in ("SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD"):
        return SECCOMP_RET_KILL_THREAD
    raise ValueError(f"unsupported seccomp action: {action!r}")


def _compile_single_arg_comparator(
    arg_spec: Mapping[str, Any],
) -> tuple[list[tuple[int, int, int, int]], int]:
    idx = int(arg_spec["index"])
    val = int(arg_spec["value"])
    op = str(arg_spec["op"])
    lo_off, hi_off = 16 + 8 * idx, 20 + 8 * idx
    v_lo, v_hi = val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF
    if op == "SCMP_CMP_EQ":
        body = [(_LD_ABS, 0, 0, hi_off), (_JMP_JEQ_K, 0, 2, v_hi), (_LD_ABS, 0, 0, lo_off), (_JMP_JEQ_K, 1, 0, v_lo)]
    elif op == "SCMP_CMP_NE":
        body = [(_LD_ABS, 0, 0, hi_off), (_JMP_JEQ_K, 0, 3, v_hi), (_LD_ABS, 0, 0, lo_off), (_JMP_JEQ_K, 0, 1, v_lo)]
    elif op == "SCMP_CMP_GT":
        body = [(_LD_ABS, 0, 0, hi_off), (_JMP_JGT_K, 4, 0, v_hi), (_JMP_JEQ_K, 0, 2, v_hi), (_LD_ABS, 0, 0, lo_off), (_JMP_JGT_K, 1, 0, v_lo)]
    elif op == "SCMP_CMP_GE":
        body = [(_LD_ABS, 0, 0, hi_off), (_JMP_JGT_K, 4, 0, v_hi), (_JMP_JEQ_K, 0, 2, v_hi), (_LD_ABS, 0, 0, lo_off), (_JMP_JGE_K, 1, 0, v_lo)]
    elif op == "SCMP_CMP_LT":
        body = [(_LD_ABS, 0, 0, hi_off), (_JMP_JGT_K, 3, 0, v_hi), (_JMP_JEQ_K, 0, 3, v_hi), (_LD_ABS, 0, 0, lo_off), (_JMP_JGE_K, 0, 1, v_lo)]
    elif op == "SCMP_CMP_LE":
        body = [(_LD_ABS, 0, 0, hi_off), (_JMP_JGT_K, 3, 0, v_hi), (_JMP_JEQ_K, 0, 3, v_hi), (_LD_ABS, 0, 0, lo_off), (_JMP_JGT_K, 0, 1, v_lo)]
    elif op == "SCMP_CMP_MASKED_EQ":
        target = int(arg_spec.get("valueTwo", 0))
        t_lo, t_hi = target & 0xFFFFFFFF, (target >> 32) & 0xFFFFFFFF
        body = [
            (_LD_ABS, 0, 0, hi_off), (_ALU_AND_K, 0, 0, v_hi), (_JMP_JEQ_K, 0, 3, t_hi),
            (_LD_ABS, 0, 0, lo_off), (_ALU_AND_K, 0, 0, v_lo), (_JMP_JEQ_K, 1, 0, t_lo),
        ]
    else:
        raise ValueError(f"unsupported seccomp comparator: {op!r}")
    body.append((_JMP_JA, 0, 0, 0))
    return body, len(body) - 1


def _compile_args_sequence(
    args_list: Sequence[Mapping[str, Any]],
) -> list[tuple[int, int, int, int]]:
    combined: list[tuple[int, int, int, int]] = []
    fail_indices: list[int] = []
    for arg_spec in args_list:
        sub_insns, local_fail = _compile_single_arg_comparator(arg_spec)
        fail_indices.append(len(combined) + local_fail)
        combined.extend(sub_insns)
    total_len = len(combined)
    for f_idx in fail_indices:
        combined[f_idx] = (_JMP_JA, 0, 0, total_len - f_idx)
    return combined


def _compile_rule_chunks(
    nr_list: Sequence[int],
    args_list: Sequence[Mapping[str, Any]],
    ret_action: int,
) -> list[tuple[int, int, int, int]]:
    unique_nrs = list(dict.fromkeys(nr_list))
    out: list[tuple[int, int, int, int]] = []
    for pos in range(0, len(unique_nrs), _MAX_CHUNK_NRS):
        chunk = unique_nrs[pos : pos + _MAX_CHUNK_NRS]
        c_len = len(chunk)
        if not args_list:
            for idx, nr_val in enumerate(chunk[:-1]):
                out.append((_JMP_JEQ_K, c_len - 1 - idx, 0, nr_val))
            out.append((_JMP_JEQ_K, 0, 1, chunk[-1]))
            out.append((_RET_K, 0, 0, ret_action))
        else:
            args_insns = _compile_args_sequence(args_list)
            for idx, nr_val in enumerate(chunk):
                out.append((_JMP_JEQ_K, c_len - idx, 0, nr_val))
            out.append((_JMP_JA, 0, 0, len(args_insns) + 2))
            out.extend(args_insns)
            out.append((_RET_K, 0, 0, ret_action))
            out.append((_LD_ABS, 0, 0, 0))
    return out


def _pack_bpf_program(
    rule_specs: Sequence[tuple[Sequence[int], Sequence[Mapping[str, Any]], int]],
) -> bytes:
    insns: list[tuple[int, int, int, int]] = [
        (_LD_ABS, 0, 0, 4),
        (_JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        (_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (_LD_ABS, 0, 0, 0),
        (_JMP_JGE_K, 0, 2, 0x40000000),
        (_JMP_JGE_K, 1, 0, 0x80000000),
        (_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ]
    for nr_list, args_list, ret_action in rule_specs:
        insns.extend(_compile_rule_chunks(nr_list, args_list, ret_action))
    insns.append((_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM))
    if not (1 <= len(insns) <= BPF_MAXINSNS):
        raise ValueError(f"seccomp BPF program size {len(insns)} exceeds BPF_MAXINSNS={BPF_MAXINSNS}")
    for idx, (code, jt, jf, k) in enumerate(insns):
        if not (0 <= jt <= 255 and 0 <= jf <= 255 and 0 <= k <= 0xFFFFFFFF):
            raise ValueError(f"seccomp BPF insn[{idx}] jump/immediate overflow: {(code, jt, jf, k)!r}")
    return b"".join(struct.pack("<HBBI", code, jt, jf, k) for code, jt, jf, k in insns)


def compile_seccomp_profile_to_bpf(seccomp_profile: dict[str, Any]) -> tuple[str, bytes]:
    """Verify an OCI x86_64 seccomp profile and compile it to classic BPF bytes."""
    seccomp_digest = verify_seccomp_profile(seccomp_profile)
    rule_specs: list[tuple[list[int], list[Mapping[str, Any]], int]] = []
    for idx, rule in enumerate(seccomp_profile["syscalls"]):
        nr_list: list[int] = []
        for name in rule["names"]:
            if name not in X86_64_SYSCALL_NUMBERS:
                raise ValueError(f"seccomp_profile.syscalls[{idx}]: unknown x86_64 syscall {name!r}")
            nr_list.append(X86_64_SYSCALL_NUMBERS[name])
        ret_action = _map_seccomp_action(rule["action"], rule.get("errnoRet", 1))
        args_list = list(rule.get("args", ()))
        rule_specs.append((nr_list, args_list, ret_action))
    return seccomp_digest, _pack_bpf_program(rule_specs)


def compile_stage7_pep517_seccomp_bpf() -> bytes:
    """Compile the Stage-7 PEP 517 container seccomp allowlist to classic BPF bytes."""
    stage7_names = sorted(
        set(gov1_sandbox._DEFAULT_7A_ALLOWED_SYSCALLS) | STAGE7_PEP517_EXTRA_SYSCALLS
    )
    forbidden_hit = sorted(set(stage7_names) & _STAGE7_FORBIDDEN_SYSCALLS)
    if forbidden_hit:
        raise ValueError(f"Stage-7 seccomp allowlist contains forbidden syscalls: {forbidden_hit!r}")
    nr_list: list[int] = []
    for name in stage7_names:
        if name not in X86_64_SYSCALL_NUMBERS:
            raise ValueError(f"Stage-7 seccomp allowlist contains unknown x86_64 syscall {name!r}")
        nr_list.append(X86_64_SYSCALL_NUMBERS[name])
    return _pack_bpf_program([(nr_list, [], SECCOMP_RET_ALLOW)])


def _unpack_and_validate_bpf_insns(
    bpf_bytes: bytes,
) -> list[tuple[int, int, int, int]]:
    if type(bpf_bytes) is not bytes or len(bpf_bytes) == 0 or len(bpf_bytes) % 8 != 0:
        raise ValueError("bpf_bytes: expected non-empty bytes aligned to 8-byte sock_filter structs")
    n_insns = len(bpf_bytes) // 8
    if n_insns > BPF_MAXINSNS:
        raise ValueError(f"bpf_bytes: {n_insns} instructions exceeds BPF_MAXINSNS={BPF_MAXINSNS}")
    insns = list(struct.iter_unpack("<HBBI", bpf_bytes))
    for pc, (code, jt, jf, k) in enumerate(insns):
        if code == _LD_ABS:
            if k % 4 != 0 or k > 60:
                raise ValueError(f"bpf insn[{pc}]: invalid seccomp_data word offset {k}")
        elif code in (_LD_IMM, _LD_LEN, _ALU_ADD_K, _ALU_SUB_K, _ALU_MUL_K, _ALU_OR_K, _ALU_AND_K, _ALU_LSH_K, _ALU_RSH_K, _ALU_NEG, _ALU_XOR_K, _RET_K, _RET_A):
            pass
        elif code == _ALU_DIV_K:
            if k == 0:
                raise ValueError(f"bpf insn[{pc}]: division by zero")
        elif code == _JMP_JA:
            if pc + 1 + k >= n_insns:
                raise ValueError(f"bpf insn[{pc}]: BPF_JA target {pc + 1 + k} out of bounds {n_insns}")
        elif code in (_JMP_JEQ_K, _JMP_JGT_K, _JMP_JGE_K, _JMP_JSET_K):
            if pc + 1 + jt >= n_insns or pc + 1 + jf >= n_insns:
                raise ValueError(f"bpf insn[{pc}]: conditional jump target out of bounds {n_insns}")
        else:
            raise ValueError(f"bpf insn[{pc}]: unsupported classic BPF opcode 0x{code:02x}")
    return insns


def _step_bpf_alu(code: int, acc: int, k: int) -> int:
    if code == _ALU_ADD_K:
        return (acc + k) & 0xFFFFFFFF
    if code == _ALU_SUB_K:
        return (acc - k) & 0xFFFFFFFF
    if code == _ALU_MUL_K:
        return (acc * k) & 0xFFFFFFFF
    if code == _ALU_DIV_K:
        return (acc // k) & 0xFFFFFFFF
    if code == _ALU_OR_K:
        return (acc | k) & 0xFFFFFFFF
    if code == _ALU_AND_K:
        return (acc & k) & 0xFFFFFFFF
    if code == _ALU_LSH_K:
        return ((acc << k) & 0xFFFFFFFF) if k < 32 else 0
    if code == _ALU_RSH_K:
        return (acc >> k) if k < 32 else 0
    if code == _ALU_NEG:
        return (-acc) & 0xFFFFFFFF
    return (acc ^ k) & 0xFFFFFFFF


def evaluate_seccomp_bpf(
    bpf_bytes: bytes,
    *,
    arch: int,
    nr: int,
    args: tuple[int, int, int, int, int, int] = (0, 0, 0, 0, 0, 0),
) -> int:
    """Execute classic BPF `bpf_bytes` over a 64-byte `seccomp_data` buffer."""
    if type(arch) is not int or type(nr) is not int:
        raise ValueError("arch and nr: expected strict int")
    if type(args) is not tuple or len(args) != 6 or any(type(a) is not int for a in args):
        raise ValueError("args: expected 6-tuple of strict ints")
    insns = _unpack_and_validate_bpf_insns(bpf_bytes)
    seccomp_data = struct.pack(
        "<IIQ6Q", nr & 0xFFFFFFFF, arch & 0xFFFFFFFF, 0, *(a & 0xFFFFFFFFFFFFFFFF for a in args)
    )
    acc, pc, n_insns = 0, 0, len(insns)
    while pc < n_insns:
        code, jt, jf, k = insns[pc]
        if code == _LD_ABS:
            acc = struct.unpack_from("<I", seccomp_data, k)[0]
        elif code == _LD_IMM:
            acc = k
        elif code == _LD_LEN:
            acc = 64
        elif code in (_RET_K, _RET_A):
            return (k if code == _RET_K else acc) & 0xFFFFFFFF
        elif code == _JMP_JA:
            pc += 1 + k
            continue
        elif code in (_JMP_JEQ_K, _JMP_JGT_K, _JMP_JGE_K, _JMP_JSET_K):
            cond = (acc == k) if code == _JMP_JEQ_K else (acc > k) if code == _JMP_JGT_K else (acc >= k) if code == _JMP_JGE_K else ((acc & k) != 0)
            pc += 1 + (jt if cond else jf)
            continue
        else:
            acc = _step_bpf_alu(code, acc, k)
        pc += 1
    raise ValueError("bpf program terminated without BPF_RET")
