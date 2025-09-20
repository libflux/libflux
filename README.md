# libflux

libflux is a Rust-based CLI tool for creating temporary, isolated test containers. Its primary purpose is to provide a fast, secure, and reproducible environment for testing code, scripts, or system features in a contained Linux namespace. libflux containers are ephemeral and designed for short-lived, experimental workloads—not for running persistent applications or services.

---

## Overview

libflux leverages Linux namespaces and cgroups v2 to create lightweight, rootless containers. All configuration is provided via CLI arguments, and containers are deleted on exit. The focus is on test isolation, resource control, and rapid container lifecycle.

---

## Key Features

- **Ephemeral Test Containers**: Containers exist only for the duration of the test or command.
- **Namespace Isolation**: PID, user, network, mount, IPC, UTS
- **Resource Control**: CPU and memory limits (cgroups v2)
- **Filesystem Management**: Bind mounts, tmpfs, overlayfs, custom rootfs
- **User Mapping**: UID/GID remapping for rootless containers
- **Logging**: Container stdout/stderr capture, system logging
- **Benchmarking**: Built-in performance benchmarks for container creation/startup

---

## System Requirements

- Linux kernel 4.0+ with namespace and cgroups v2 support
- Rust 1.70+ (for building)
- Required kernel features: user, PID, network, mount namespaces; overlayfs
- Runtime dependencies: `ip` (iproute2), `iptables` (for networking)

---

## Installation

### Build from Source

```bash
git clone https://github.com/libflux/libflux.git
cd libflux
cargo build --release
sudo cp target/release/libflux /usr/local/bin/
```

Or install using cargo:

```bash
cargo install --path .
```

---

## Architecture

- **src/main.rs**: CLI entrypoint, command parsing
- **src/container.rs**: Container struct, lifecycle management
- **src/namespace.rs**: Namespace setup and management
- **src/cgroups.rs**: Resource limits via cgroups v2
- **src/fs.rs**: Filesystem operations, mounts
- **src/net.rs**: Networking, bridge setup, veth pairs
- **src/user.rs**: UID/GID mapping, user namespace support
- **src/config.rs**: Container configuration
- **src/logging.rs**: Logging utilities
- **src/utils.rs**: Helper functions
- **src/error.rs**: Error types

---

## Development

Build a local binary:

```bash
cargo build
```

Manual testing:

```bash
mkdir -p /tmp/test-rootfs
# Populate with minimal rootfs
sudo ./target/debug/libflux run test --image /tmp/test-rootfs -- /bin/echo "Hello, libflux!"
```

---

## Security Notes

- Run as non-root where possible (user namespaces)
- Always set resource limits
- Use read-only mounts for sensitive data
- Minimal rootfs recommended

Known limitations:

- Seccomp filtering not yet implemented
- AppArmor/SELinux integration pending
- Not production-ready; use with caution

---

## Benchmarks

Container creation and startup times (on modern hardware):

- **Container Creation**: ~307µs
- **Container Start**: ~50ms
- **Total Container Creation & Start**: ~50ms

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Acknowledgments

- Rust community
- Linux kernel developers
- Projects like runc, systemd-nspawn
- libflux contributors

---

## Disclaimer

libflux is in early development. Not recommended for production use without thorough review.

---

Made with ❤️ and 🦀 by the libflux team
