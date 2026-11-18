#pragma once

// Landlock domain and libseccomp filter installed after the command line and
// the settings file have been resolved. Filesystem and TCP/UDP rights follow
// from those settings. Everything else in the handled set is denied.
// execve is refused with EPERM so the in-process restart path can exit
// instead of being killed. Any other unexpected syscall kills the process.

#include "kiss_tnc.hh"

#include <arpa/inet.h>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <linux/landlock.h>
#include <netinet/in.h>
#include <seccomp.h>
#include <string>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>
#ifdef __x86_64__
#include <asm/prctl.h>
#endif

struct SandboxPolicy {
    std::string config_dir;
    std::string audio_backend = "auto";
    std::string audio_input;
    std::string audio_output;
    int bind_port = -1;
    int control_port = -1;
    bool ui = false;
    bool attach_only = false;
    std::string attach_host;
    int attach_port = 0;
    PTTType ptt = PTTType::NONE;
    std::string rigctl_host;
    int rigctl_port = 0;
    std::string com_port;
    std::string gpio_chip;
    std::string hamlib_device;
    bool hamlib = false;
    bool cm108 = false;
};

inline std::string sandbox_parent_dir(const std::string& path) {
    if (path.empty()) return {};
    auto slash = path.find_last_of('/');
    if (slash == std::string::npos) return {};
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

inline std::string sandbox_default_config_dir() {
    const char* home = std::getenv("HOME");
    if (home == nullptr || home[0] == '\0') return {};
    return std::string(home) + "/.config/modem73";
}

inline SandboxPolicy policy_from_config(const TNCConfig& config,
                                        const std::string& settings_file,
                                        bool ui) {
    SandboxPolicy policy;
    policy.ui = ui;
    policy.config_dir = sandbox_parent_dir(settings_file);
    if (policy.config_dir.empty()) policy.config_dir = sandbox_default_config_dir();
    policy.audio_backend = config.audio_backend;
    policy.audio_input = config.audio_input_device;
    policy.audio_output = config.audio_output_device;
    policy.bind_port = config.port;
    policy.control_port = config.control_port;
    policy.ptt = config.ptt_type;
    policy.rigctl_host = config.rigctl_host;
    policy.rigctl_port = config.rigctl_port;
    policy.com_port = config.com_port;
    policy.gpio_chip = config.gpio_chip;
    policy.hamlib_device = config.hamlib_device;
    policy.hamlib = config.ptt_type == PTTType::HAMLIB || config.hamlib_info;
#ifdef WITH_CM108
    policy.cm108 = config.ptt_type == PTTType::CM108;
#else
    policy.cm108 = false;
#endif
    return policy;
}

namespace {

enum class PathAdd { added, missing, failed };

int landlock_abi() {
    long rc = syscall(SYS_landlock_create_ruleset, nullptr, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (rc < 0) return -1;
    return static_cast<int>(rc);
}

uint64_t handled_fs_for(int abi) {
    uint64_t mask = (1ULL << 13) - 1;
    if (abi >= 2) mask |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    if (abi >= 9) mask |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    return mask;
}

uint64_t handled_net_for(int abi) {
    uint64_t mask = 0;
    if (abi >= 4) {
        mask |= LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }
    if (abi >= 10) {
        mask |= LANDLOCK_ACCESS_NET_BIND_UDP | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP;
    }
    return mask;
}

uint64_t fs_read(int abi) {
    uint64_t mask = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    if (abi >= 9) mask |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    return mask;
}

uint64_t fs_lib(int abi) {
    return fs_read(abi) | LANDLOCK_ACCESS_FS_EXECUTE;
}

uint64_t fs_write_dir(int abi) {
    uint64_t mask = fs_read(abi) | LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE;
    if (abi >= 2) mask |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return mask;
}

uint64_t fs_device(int abi) {
    uint64_t mask = fs_read(abi) | LANDLOCK_ACCESS_FS_WRITE_FILE;
    if (abi >= 3) mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return mask;
}

// Read and write an existing file. No create, unlink, rename, or execute.
uint64_t fs_rw(int abi) {
    uint64_t mask = fs_read(abi) | LANDLOCK_ACCESS_FS_WRITE_FILE;
    if (abi >= 3) mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return mask;
}

PathAdd add_fs_rule(int ruleset, const std::string& path, uint64_t access) {
    if (path.empty() || access == 0) return PathAdd::missing;
    int fd = open(path.c_str(), O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) return PathAdd::missing;
        std::cerr << "sandbox: cannot open " << path << ": " << std::strerror(errno)
                  << std::endl;
        return PathAdd::failed;
    }
    struct stat info;
    if (fstat(fd, &info) != 0) {
        int err = errno;
        close(fd);
        std::cerr << "sandbox: cannot stat " << path << ": " << std::strerror(err)
                  << std::endl;
        return PathAdd::failed;
    }
    if (!S_ISDIR(info.st_mode)) {
        // Directory rights on a file or device node are rejected with EINVAL.
        constexpr uint64_t directory_only =
            LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
            LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
        access &= ~directory_only;
    }
    if (access == 0) {
        close(fd);
        return PathAdd::missing;
    }
    landlock_path_beneath_attr beneath;
    std::memset(&beneath, 0, sizeof(beneath));
    beneath.allowed_access = access;
    beneath.parent_fd = fd;
    long rc = syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH,
                      &beneath, 0);
    int err = errno;
    close(fd);
    if (rc < 0) {
        std::cerr << "sandbox: landlock rule for " << path << " failed: "
                  << std::strerror(err) << std::endl;
        return PathAdd::failed;
    }
    return PathAdd::added;
}

bool add_fs_required(int ruleset, const std::string& path, uint64_t access) {
    PathAdd added = add_fs_rule(ruleset, path, access);
    if (added == PathAdd::added) return true;
    std::cerr << "sandbox: required path " << path << " was not granted" << std::endl;
    return false;
}

void add_fs_optional(int ruleset, const std::string& path, uint64_t access, int* count) {
    PathAdd added = add_fs_rule(ruleset, path, access);
    if (added == PathAdd::added && count != nullptr) *count += 1;
}

bool add_net_port(int ruleset, uint64_t access, int port) {
    if (port < 0 || port > 65535 || access == 0) return false;
    landlock_net_port_attr net;
    std::memset(&net, 0, sizeof(net));
    net.allowed_access = access;
    net.port = static_cast<uint64_t>(port);
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_NET_PORT, &net, 0) < 0) {
        std::cerr << "sandbox: landlock port " << port << " failed: "
                  << std::strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool numeric_host(const std::string& host) {
    if (host.empty()) return true;
    in_addr v4;
    in6_addr v6;
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool endpoint_port(const std::string& spec, std::string* host, int* port) {
    auto colon = spec.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size()) return false;
    if (spec.find('/') != std::string::npos) return false;
    int value = 0;
    for (size_t i = colon + 1; i < spec.size(); ++i) {
        char digit = spec.at(i);
        if (digit < '0' || digit > '9') return false;
        value = value * 10 + (digit - '0');
        if (value > 65535) return false;
    }
    if (value <= 0) return false;
    *host = spec.substr(0, colon);
    *port = value;
    return true;
}

std::string tcp_host_of(const std::string& device) {
    const std::string prefix = "tcp:";
    if (device.compare(0, prefix.size(), prefix) != 0) return {};
    std::string host;
    int port = 0;
    if (!endpoint_port(device.substr(prefix.size()), &host, &port)) return {};
    return host;
}

int tcp_port_of(const std::string& device) {
    const std::string prefix = "tcp:";
    if (device.compare(0, prefix.size(), prefix) != 0) return 0;
    std::string host;
    int port = 0;
    if (!endpoint_port(device.substr(prefix.size()), &host, &port)) return 0;
    return port;
}

std::string xdg_or(const char* env, const std::string& fallback) {
    const char* value = std::getenv(env);
    if (value != nullptr && value[0] != '\0') return value;
    return fallback;
}

std::string runtime_dir() {
    return xdg_or("XDG_RUNTIME_DIR", "/run/user/" + std::to_string(getuid()));
}

std::string config_home() {
    std::string home = sandbox_default_config_dir();
    auto slash = home.rfind("/modem73");
    if (slash != std::string::npos) home.erase(slash);
    const char* env = std::getenv("XDG_CONFIG_HOME");
    if (env != nullptr && env[0] != '\0') return env;
    return home;
}

bool wants_alsa(const std::string& backend) {
    return backend == "auto" || backend == "alsa";
}

bool wants_pulse(const std::string& backend) {
    return backend == "auto" || backend == "pulse" || backend == "pulseaudio";
}

bool wants_jack(const std::string& backend) {
    return backend == "auto" || backend == "jack";
}

void add_hidraw_nodes(int ruleset, uint64_t access, int* count) {
    DIR* dir = opendir("/dev");
    if (dir == nullptr) return;
    while (dirent* ent = readdir(dir)) {
        const char* name = ent->d_name;
        if (std::strncmp(name, "hidraw", 6) != 0) continue;
        add_fs_optional(ruleset, std::string("/dev/") + name, access, count);
    }
    closedir(dir);
}

std::string gpio_path(const std::string& chip) {
    if (chip.empty()) return {};
    if (chip.find('/') != std::string::npos) return chip;
    return "/dev/" + chip;
}

bool allow_named(scmp_filter_ctx ctx, const char* name, bool required) {
    int nr = seccomp_syscall_resolve_name(name);
    if (nr == __NR_SCMP_ERROR) {
        if (required) {
            std::cerr << "sandbox: syscall " << name << " is not known" << std::endl;
            return false;
        }
        return true;
    }
    int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0);
    if (rc < 0) {
        std::cerr << "sandbox: seccomp rule for " << name << " failed: "
                  << std::strerror(-rc) << std::endl;
        return false;
    }
    return true;
}

bool allow_prctl(scmp_filter_ctx ctx, unsigned long option) {
    int nr = seccomp_syscall_resolve_name("prctl");
    if (nr == __NR_SCMP_ERROR) return false;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 1,
                         SCMP_CMP(0, SCMP_CMP_EQ, option)) < 0) {
        std::cerr << "sandbox: seccomp prctl rule failed" << std::endl;
        return false;
    }
    return true;
}

bool allow_socket_family(scmp_filter_ctx ctx, int family) {
    int nr = seccomp_syscall_resolve_name("socket");
    if (nr == __NR_SCMP_ERROR) return false;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 1,
                         SCMP_CMP(0, SCMP_CMP_EQ, static_cast<uint64_t>(family))) < 0) {
        std::cerr << "sandbox: seccomp socket rule failed" << std::endl;
        return false;
    }
    return true;
}

// libseccomp rejects a KILL_PROCESS rule that the default action already
// covers. Allow only protections that are not writable and executable at once,
// and let every other prot value hit the default kill.
bool allow_memory_prot(scmp_filter_ctx ctx, const char* name, bool required) {
    int nr = seccomp_syscall_resolve_name(name);
    if (nr == __NR_SCMP_ERROR) {
        if (required) {
            std::cerr << "sandbox: syscall " << name << " is not known" << std::endl;
            return false;
        }
        return true;
    }
    const uint64_t prots[] = {
        PROT_NONE,
        PROT_READ,
        PROT_WRITE,
        static_cast<uint64_t>(PROT_READ) | PROT_WRITE,
        PROT_EXEC,
        static_cast<uint64_t>(PROT_READ) | PROT_EXEC,
    };
    for (uint64_t prot : prots) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 1,
                                  SCMP_CMP(2, SCMP_CMP_EQ, prot));
        if (rc < 0) {
            std::cerr << "sandbox: seccomp " << name << " prot rule failed: "
                      << std::strerror(-rc) << std::endl;
            return false;
        }
    }
    return true;
}

bool refuse_exec(scmp_filter_ctx ctx, const char* name) {
    int nr = seccomp_syscall_resolve_name(name);
    if (nr == __NR_SCMP_ERROR) return true;
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0) < 0) {
        std::cerr << "sandbox: seccomp " << name << " rule failed" << std::endl;
        return false;
    }
    return true;
}

#ifdef __x86_64__
bool allow_arch_prctl(scmp_filter_ctx ctx) {
    int nr = seccomp_syscall_resolve_name("arch_prctl");
    if (nr == __NR_SCMP_ERROR) return true;
    const unsigned long ops[] = {
        ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS, ARCH_SHSTK_STATUS,
    };
    for (unsigned long op : ops) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 1,
                             SCMP_CMP(0, SCMP_CMP_EQ, op)) < 0)
            return false;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 2,
                         SCMP_CMP(0, SCMP_CMP_EQ, ARCH_SHSTK_ENABLE),
                         SCMP_CMP(1, SCMP_CMP_EQ, ARCH_SHSTK_SHSTK)) < 0)
        return false;
    return true;
}
#endif

bool install_seccomp() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::cerr << "sandbox: no_new_privs failed: " << std::strerror(errno) << std::endl;
        return false;
    }
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (ctx == nullptr) {
        std::cerr << "sandbox: seccomp_init failed" << std::endl;
        return false;
    }
    bool ok = true;
    if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0) ok = false;

    const char* required[] = {
        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "munmap", "brk", "rt_sigaction",
        "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
        "readv", "writev", "access", "pipe", "pipe2", "select", "sched_yield",
        "mremap", "msync", "mincore", "madvise", "dup", "dup2", "dup3",
        "nanosleep", "getpid", "gettid", "sendfile", "connect", "accept",
        "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
        "bind", "listen", "getsockname", "getpeername", "socketpair",
        "setsockopt", "getsockopt", "clone", "exit", "exit_group", "fcntl",
        "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getcwd",
        "mkdir", "mkdirat", "umask",
        "rename", "renameat", "renameat2", "unlink", "unlinkat", "readlink",
        "readlinkat", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
        "times", "getuid", "getgid", "geteuid", "getegid", "getgroups",
        "getresuid", "getresgid", "capget", "statfs", "fstatfs",
        "sched_getparam", "sched_setparam", "sched_setscheduler",
        "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
        "sched_rr_get_interval", "sched_getaffinity", "sched_setaffinity",
        "clock_gettime", "clock_nanosleep", "clock_getres", "tgkill", "tkill",
        "set_tid_address", "futex", "set_robust_list", "epoll_create",
        "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait", "getdents64",
        "eventfd2", "timerfd_create", "timerfd_settime", "timerfd_gettime",
        "pselect6", "ppoll", "getrandom", "memfd_create", "fallocate",
        "mlock", "munlock", "mlockall", "munlockall", "sigaltstack",
        "rt_sigpending", "rt_sigtimedwait", "rt_sigsuspend", "restart_syscall",
        "uname", "prlimit64", "kill", "shmget", "shmat", "shmctl", "shmdt",
        "timer_create", "timer_settime", "timer_gettime", "timer_delete",
        "timer_getoverrun", "alarm", "setitimer", "getitimer",
    };
    for (const char* name : required) {
        if (!allow_named(ctx, name, true)) ok = false;
    }
    const char* optional[] = {
        "clone3", "rseq", "statx", "faccessat", "faccessat2", "openat2",
        "close_range", "epoll_pwait2", "futex_waitv", "futex_wait", "futex_wake",
        "futex_requeue", "membarrier", "getdents", "preadv", "pwritev",
        "preadv2", "pwritev2", "recvmmsg", "sendmmsg", "sendfile64",
        "newfstatat", "map_shadow_stack", "cachestat", "fadvise64",
        "inotify_init1", "inotify_add_watch", "inotify_rm_watch",
        "sched_getattr", "sched_setattr", "pidfd_send_signal",
        "mseal", "getcpu", "pkey_alloc", "pkey_free",
    };
    for (const char* name : optional) {
        if (!allow_named(ctx, name, false)) ok = false;
    }
    if (!allow_socket_family(ctx, AF_UNIX) || !allow_socket_family(ctx, AF_INET) ||
        !allow_socket_family(ctx, AF_INET6) || !allow_socket_family(ctx, AF_NETLINK))
        ok = false;
    if (!allow_memory_prot(ctx, "mmap", true) ||
        !allow_memory_prot(ctx, "mprotect", true) ||
        !allow_memory_prot(ctx, "pkey_mprotect", false))
        ok = false;
    if (!refuse_exec(ctx, "execve") || !refuse_exec(ctx, "execveat")) ok = false;
    const unsigned long prctls[] = {
        PR_SET_NAME, PR_GET_NAME, PR_SET_VMA, PR_GET_NO_NEW_PRIVS, PR_SET_NO_NEW_PRIVS,
        PR_CAPBSET_READ, PR_GET_SECUREBITS, PR_SET_TIMERSLACK, PR_GET_TIMERSLACK,
        PR_GET_DUMPABLE,
    };
    for (unsigned long option : prctls) {
        if (!allow_prctl(ctx, option)) ok = false;
    }
#ifdef __x86_64__
    if (!allow_arch_prctl(ctx)) ok = false;
#endif
    if (ok && seccomp_load(ctx) < 0) {
        std::cerr << "sandbox: seccomp_load failed: " << std::strerror(errno) << std::endl;
        ok = false;
    }
    seccomp_release(ctx);
    return ok;
}

bool confinement_holds() {
    int cpu = open("/proc/cpuinfo", O_RDONLY | O_CLOEXEC);
    if (cpu >= 0) {
        close(cpu);
        std::cerr << "sandbox: /proc/cpuinfo stayed readable" << std::endl;
        return false;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "sandbox: confinement socket failed: " << std::strerror(errno)
                  << std::endl;
        return false;
    }
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        close(sock);
        std::cerr << "sandbox: ephemeral TCP bind was not confined" << std::endl;
        return false;
    }
    addr.sin_port = htons(1);
    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int err = errno;
    close(sock);
    if (rc == 0 || err != EACCES) {
        std::cerr << "sandbox: TCP connect was not confined: "
                  << (rc == 0 ? "connected" : std::strerror(err)) << std::endl;
        return false;
    }
    return true;
}

void remember_port(std::vector<int>* ports, int port) {
    if (port <= 0 || port > 65535) return;
    for (int have : *ports) {
        if (have == port) return;
    }
    ports->push_back(port);
}

void remember_host(std::vector<std::string>* hosts, const std::string& host) {
    if (host.empty() || numeric_host(host)) return;
    for (const std::string& have : *hosts) {
        if (have == host) return;
    }
    hosts->push_back(host);
}

}  // namespace

inline bool install_sandbox(const SandboxPolicy& policy) {
    int abi = landlock_abi();
    if (abi < 4) {
        std::cerr << "sandbox: Landlock ABI " << abi
                  << " is too old to confine TCP (need 4 or newer)" << std::endl;
        return false;
    }
    landlock_ruleset_attr attr;
    std::memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = handled_fs_for(abi);
    attr.handled_access_net = handled_net_for(abi);
    if (abi >= 6) {
        attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
    }
    const size_t sizes[] = {
        offsetof(landlock_ruleset_attr, quiet_access_fs),
        offsetof(landlock_ruleset_attr, scoped),
        offsetof(landlock_ruleset_attr, handled_access_net),
    };
    int ruleset = -1;
    for (size_t size : sizes) {
        ruleset = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attr, size, 0));
        if (ruleset >= 0) break;
        if (errno != EINVAL) {
            std::cerr << "sandbox: landlock_create_ruleset failed: " << std::strerror(errno)
                      << std::endl;
            return false;
        }
    }
    if (ruleset < 0) {
        std::cerr << "sandbox: landlock_create_ruleset failed: " << std::strerror(errno)
                  << std::endl;
        return false;
    }

    const uint64_t read = fs_read(abi) & attr.handled_access_fs;
    const uint64_t libs = fs_lib(abi) & attr.handled_access_fs;
    const uint64_t write = fs_write_dir(abi) & attr.handled_access_fs;
    const uint64_t rw = fs_rw(abi) & attr.handled_access_fs;
    const uint64_t device = fs_device(abi) & attr.handled_access_fs;
    int fs_rules = 0;
    bool ok = true;
    if (!add_fs_required(ruleset, "/usr", libs)) ok = false;
    else fs_rules += 1;
    if (!add_fs_required(ruleset, "/etc", libs)) ok = false;
    else fs_rules += 1;
    for (const char* path : {"/lib", "/lib64"}) {
        PathAdd added = add_fs_rule(ruleset, path, libs);
        if (added == PathAdd::added) fs_rules += 1;
        else if (added == PathAdd::failed) ok = false;
    }

    std::string config_dir = policy.config_dir.empty() ? sandbox_default_config_dir()
                                                       : policy.config_dir;
    std::string perf_dir = sandbox_default_config_dir();
    if (config_dir.empty()) {
        std::cerr << "sandbox: no configuration directory to confine" << std::endl;
        ok = false;
    } else if (!add_fs_required(ruleset, config_dir, write)) {
        ok = false;
    } else {
        fs_rules += 1;
    }
    if (!perf_dir.empty() && perf_dir != config_dir) {
        PathAdd added = add_fs_rule(ruleset, perf_dir, write);
        if (added == PathAdd::added) fs_rules += 1;
        else if (added == PathAdd::failed) ok = false;
    }

    for (const char* path : {"/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"}) {
        add_fs_optional(ruleset, path, device, &fs_rules);
    }
    std::string proc_self = "/proc/self";
    std::string proc_pid = "/proc/" + std::to_string(getpid());
    add_fs_optional(ruleset, proc_self, read, &fs_rules);
    add_fs_optional(ruleset, "/proc/thread-self", read, &fs_rules);
    if (!add_fs_required(ruleset, proc_pid, read)) ok = false;
    else fs_rules += 1;

    if (policy.ui) {
        add_fs_optional(ruleset, "/dev/tty", device, &fs_rules);
        for (int fd : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
            char name[256];
            if (ttyname_r(fd, name, sizeof(name)) == 0)
                add_fs_optional(ruleset, name, device, &fs_rules);
        }
        std::string terminfo = std::getenv("TERMINFO") != nullptr ? std::getenv("TERMINFO") : "";
        add_fs_optional(ruleset, terminfo, read, &fs_rules);
        const char* home = std::getenv("HOME");
        if (home != nullptr && home[0] != '\0')
            add_fs_optional(ruleset, std::string(home) + "/.terminfo", read, &fs_rules);
    }

    if (wants_alsa(policy.audio_backend)) {
        add_fs_optional(ruleset, "/dev/snd", device, &fs_rules);
        add_fs_optional(ruleset, "/proc/asound", read, &fs_rules);
        add_fs_optional(ruleset, "/sys/class/sound", read, &fs_rules);
        const char* home = std::getenv("HOME");
        if (home != nullptr && home[0] != '\0')
            add_fs_optional(ruleset, std::string(home) + "/.asoundrc", read, &fs_rules);
    }
    if (wants_pulse(policy.audio_backend) || wants_jack(policy.audio_backend)) {
        std::string runtime = runtime_dir();
        if (wants_pulse(policy.audio_backend)) {
            add_fs_optional(ruleset, runtime + "/pulse", rw, &fs_rules);
            add_fs_optional(ruleset, "/run/pulse", read, &fs_rules);
            add_fs_optional(ruleset, config_home() + "/pulse", read, &fs_rules);
        }
        if (wants_jack(policy.audio_backend))
            add_fs_optional(ruleset, runtime + "/jack", rw, &fs_rules);
        add_fs_optional(ruleset, "/dev/shm", write, &fs_rules);
    }

    if (!policy.attach_only && policy.ptt == PTTType::COM)
        add_fs_optional(ruleset, policy.com_port, device, &fs_rules);
    if (!policy.attach_only && policy.ptt == PTTType::GPIO)
        add_fs_optional(ruleset, gpio_path(policy.gpio_chip), device, &fs_rules);
    if (!policy.attach_only && policy.cm108) {
        add_hidraw_nodes(ruleset, device, &fs_rules);
        add_fs_optional(ruleset, "/sys/class/hidraw", read, &fs_rules);
        add_fs_optional(ruleset, "/sys/devices", read, &fs_rules);
        add_fs_optional(ruleset, "/sys/bus/hid", read, &fs_rules);
    }
    if (!policy.attach_only && policy.hamlib && !policy.hamlib_device.empty()) {
        std::string host;
        int port = 0;
        if (!endpoint_port(policy.hamlib_device, &host, &port))
            add_fs_optional(ruleset, policy.hamlib_device, device, &fs_rules);
    }

    std::vector<int> bind_ports;
    std::vector<int> connect_ports;
    std::vector<std::string> names;
    if (!policy.attach_only) {
        remember_port(&bind_ports, policy.bind_port);
        remember_port(&bind_ports, policy.control_port);
        if (policy.ptt == PTTType::RIGCTL) {
            remember_port(&connect_ports, policy.rigctl_port);
            remember_host(&names, policy.rigctl_host);
        }
        if (policy.hamlib) {
            std::string host;
            int port = 0;
            if (endpoint_port(policy.hamlib_device, &host, &port)) {
                remember_port(&connect_ports, port);
                remember_host(&names, host);
            }
        }
        for (const std::string& dev : {policy.audio_input, policy.audio_output}) {
            remember_port(&connect_ports, tcp_port_of(dev));
            remember_host(&names, tcp_host_of(dev));
        }
    } else {
        remember_port(&connect_ports, policy.attach_port);
        remember_host(&names, policy.attach_host);
    }

    bool need_dns = !names.empty();
    if (need_dns && abi < 10) {
        std::cerr << "sandbox: DNS for a hostname needs Landlock ABI 10 "
                     "(UDP); this kernel cannot confine it, refusing"
                  << std::endl;
        ok = false;
    } else if (need_dns) {
        add_fs_optional(ruleset, "/run/systemd/resolve", read, &fs_rules);
        add_fs_optional(ruleset, "/var/run/systemd/resolve", read, &fs_rules);
        remember_port(&connect_ports, 53);
    }

    for (int port : bind_ports) {
        if (!add_net_port(ruleset, LANDLOCK_ACCESS_NET_BIND_TCP, port)) ok = false;
    }
    for (int port : connect_ports) {
        if (!add_net_port(ruleset, LANDLOCK_ACCESS_NET_CONNECT_TCP, port)) ok = false;
    }
    if (need_dns && abi >= 10) {
        if (!add_net_port(ruleset, LANDLOCK_ACCESS_NET_BIND_UDP, 0)) ok = false;
        if (!add_net_port(ruleset, LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP, 53)) ok = false;
        constexpr std::string::size_type local_suffix = 6;
        for (const std::string& host : names) {
            if (host.size() >= local_suffix &&
                host.compare(host.size() - local_suffix, local_suffix, ".local") == 0) {
                if (!add_net_port(ruleset, LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP, 5353))
                    ok = false;
                break;
            }
        }
    }

    if (!ok) {
        close(ruleset);
        return false;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::cerr << "sandbox: no_new_privs failed: " << std::strerror(errno) << std::endl;
        close(ruleset);
        return false;
    }
    unsigned int flags = 0;
#ifdef LANDLOCK_RESTRICT_SELF_TSYNC
    flags |= LANDLOCK_RESTRICT_SELF_TSYNC;
#endif
    if (syscall(SYS_landlock_restrict_self, ruleset, flags) != 0) {
        int err = errno;
        if (flags != 0 && (err == EINVAL || err == EOPNOTSUPP || err == ENOSYS)) {
            if (syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) {
                std::cerr << "sandbox: landlock_restrict_self failed: "
                          << std::strerror(errno) << std::endl;
                close(ruleset);
                return false;
            }
        } else {
            std::cerr << "sandbox: landlock_restrict_self failed: " << std::strerror(err)
                      << std::endl;
            close(ruleset);
            return false;
        }
    }
    close(ruleset);

    if (!confinement_holds()) return false;
    if (!install_seccomp()) return false;

    std::cerr << "sandbox: landlock ABI " << abi << ", " << fs_rules
              << " filesystem rules, TCP bind";
    if (bind_ports.empty()) std::cerr << " none";
    for (int port : bind_ports) std::cerr << " " << port;
    std::cerr << ", TCP connect";
    if (connect_ports.empty()) std::cerr << " none";
    for (int port : connect_ports) std::cerr << " " << port;
    std::cerr << ", UDP DNS " << (need_dns ? "53" : "off")
              << ", execve refused" << std::endl;
    return true;
}
