//! Pure-Rust x86_64 seccomp-bpf bytecode generator for Linux bwrap --seccomp <fd>.

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const EPERM: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

const NR_SOCKET: u32 = 41;
const BLOCKED_SYSCALLS_X86_64: &[u32] = &[
    101, // ptrace
    103, // syslog
    155, // pivot_root
    165, // mount
    166, // umount2
    167, // swapon
    168, // swapoff
    169, // reboot
    175, // init_module
    246, // kexec_load
    272, // unshare
    308, // setns
    313, // finit_module
    320, // kexec_file_load
    321, // bpf
];

fn push_insn(out: &mut Vec<u8>, code: u16, jt: u8, jf: u8, k: u32) {
    out.extend_from_slice(&code.to_le_bytes());
    out.push(jt);
    out.push(jf);
    out.extend_from_slice(&k.to_le_bytes());
}

/// Generate raw `struct sock_filter` bytecode for Linux x86_64.
///
/// - Enforces `AUDIT_ARCH_X86_64` (otherwise `KILL_PROCESS`).
/// - Denies `socket(AF_INET / AF_INET6, ...)` with `EPERM` (defense-in-depth with `--unshare-net`).
/// - Denies high-risk privilege/namespace/kernel syscalls with `EPERM`.
/// - Allows ordinary user-space syscalls.
#[must_use]
pub fn build_x86_64_seccomp_bpf() -> Vec<u8> {
    let mut out = Vec::with_capacity((11 + BLOCKED_SYSCALLS_X86_64.len() * 2) * 8);

    // 1. Load seccomp_data.arch (offset 4)
    push_insn(&mut out, BPF_LD | BPF_W | BPF_ABS, 0, 0, 4);
    push_insn(&mut out, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64);
    push_insn(&mut out, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);

    // 2. Load seccomp_data.nr (offset 0)
    push_insn(&mut out, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0);

    // 3. Block socket(AF_INET / AF_INET6, ...)
    push_insn(&mut out, BPF_JMP | BPF_JEQ | BPF_K, 0, 5, NR_SOCKET);
    push_insn(&mut out, BPF_LD | BPF_W | BPF_ABS, 0, 0, 16);
    push_insn(&mut out, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AF_INET);
    push_insn(&mut out, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, AF_INET6);
    push_insn(&mut out, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    push_insn(&mut out, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);

    // 4. Block high-risk syscalls
    for &nr in BLOCKED_SYSCALLS_X86_64 {
        push_insn(&mut out, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, nr);
        push_insn(&mut out, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM);
    }

    // 5. Default allow
    push_insn(&mut out, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    out
}
