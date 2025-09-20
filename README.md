# libflux: Rust-based Container Runtime

A secure, performant, and developer-friendly container runtime built with Rust, using Linux namespaces, cgroups, and capabilities. libflux provides a CLI-driven, modular, and extensible alternative to systemd-nspawn and other container runtimes.

## 🚀 Features

### Core Features

- **Container Isolation**: Full process isolation using Linux namespaces (PID, mount, network, IPC, UTS, user)
- **Resource Control**: CPU and memory limits using cgroups v2
- **Filesystem Management**: Bind mounts, overlayfs, and rootfs management
- **Network Isolation**: Bridge networking with veth pairs
- **User Mapping**: UID/GID remapping for rootless containers
- **Logging**: Comprehensive container stdout/stderr capture and system logging

### CLI Features

- **Container Lifecycle**: Run containers temporarily; containers are deleted on exit.
- **Real-time Configuration**: All configuration via CLI arguments, no config files needed
- **Container Listing**: List running containers with state information
- **Performance Benchmarking**: Built-in benchmark system for performance analysis
- **Image Support**: Basic rootfs archive extraction (planned)

## 📋 Prerequisites

### System Requirements

- Linux kernel 4.0+ with namespace support
- cgroups v2 enabled
- Rust 1.70+ (for building)

### Required Kernel Features

- User namespaces (`CONFIG_USER_NS=y`)
- PID namespaces (`CONFIG_PID_NS=y`)
- Network namespaces (`CONFIG_NET_NS=y`)
- Mount namespaces (`CONFIG_UTS_NS=y`, `CONFIG_IPC_NS=y`)
- Cgroups v2 (`CONFIG_CGROUPS=y`)
- Overlay filesystem (`CONFIG_OVERLAY_FS=y`)

### Runtime Dependencies

- `ip` command (iproute2 package)
- `iptables` (for port forwarding)

## 🛠 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/libflux/libflux.git
cd libflux

# Build the project
cargo build --release

# Install binary
sudo cp target/release/libflux /usr/local/bin/

# Or install using cargo
cargo install --path .
```

## 🚀 Quick Start

### Check System Compatibility

```bash
# Check if your system supports container features
libflux info
```

### Run Your First Container

```bash
# Run a simple command in an isolated environment
sudo libflux run container-name \
  --image /path/to/rootfs \
  -- /bin/echo "Hello from libflux!"

# Run interactively
sudo libflux run container-name \
  --image /path/to/rootfs \
  -- /bin/bash
```

### List Running Containers

```bash
# List running containers
libflux ps

# Output in JSON format
libflux ps --format json
```

## 📖 Usage Examples

### Basic Container Operations

```bash
# Create and run a container
sudo libflux run web-server \
  --image /opt/alpine-rootfs \
  --memory 512M \
  --bind /var/www:/var/www \
  -- /usr/sbin/httpd
```

### Resource Limits

```bash
# Run with resource constraints
sudo libflux run limited-container \
  --image /opt/ubuntu-rootfs \
  --memory 1G \
  --cpu-weight 500 \
  -- /bin/bash
```

### Networking

```bash
# Run with custom networking
sudo libflux run web-app \
  --image /opt/webapp-rootfs \
  --port 8080:80 \
  -- /app/server
```

### Bind Mounts

```bash
# Mount host directories
sudo libflux run data-processor \
  --image /opt/processor-rootfs \
  --bind /host/data:/container/data \
  --bind /host/output:/container/output \
  -- /app/process
```

### Runtime Environment Variables

```bash
# Set environment variables
sudo libflux run app \
  --image /opt/app-rootfs \
  --env DATABASE_URL=postgresql://localhost/mydb \
  --env DEBUG=true \
  -- /app/start
```

### Performance Benchmarking

```bash
# Run performance benchmark
sudo libflux benchmark \
  --count 50 \
  --image /opt/test-rootfs \
  --command true \
  --memory \
  --verbose
```

## 🏗 Architecture

```text
┌─────────────────────────────┐
│         CLI (libflux)       │
├─────────────────────────────┤
│     Container Manager       │ ← Main entrypoint, manages lifecycle
├─────────────────────────────┤
│  Namespace & Cgroup APIs    │ ← Syscall wrappers, resource limits
├─────────────────────────────┤
│   Filesystem/Overlay API    │ ← Mount, bind, overlay support
├─────────────────────────────┤
│    Networking Manager       │ ← veth, bridge management
├─────────────────────────────┤
│ Logging / Monitoring API    │ ← Container output capture
└─────────────────────────────┘
```

### Key Components

- **Container Manager**: Orchestrates container lifecycle and coordinates other components
- **Namespace Manager**: Handles Linux namespace creation and management
- **Filesystem Manager**: Manages mounts, overlays, and rootfs operations
- **Cgroup Manager**: Controls resource limits using cgroups v2
- **Network Manager**: Sets up container networking and isolation
- **User Mapping Manager**: Handles UID/GID mapping for rootless containers

## 🔧 Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/libflux/libflux.git
cd libflux

# Build in debug mode
cargo build

# Run tests
cargo test

# Build documentation
cargo doc --open
```

### Project Structure

```text
libflux/
├── src/
│   ├── main.rs         # CLI entrypoint
│   ├── container.rs    # Container struct & lifecycle
│   ├── namespace.rs    # Namespace management
│   ├── cgroups.rs      # Cgroup management
│   ├── fs.rs           # Filesystem operations
│   ├── net.rs          # Networking
│   ├── user.rs         # UID/GID mapping
│   ├── config.rs       # Runtime configuration
│   ├── logging.rs      # Logging utilities
│   ├── utils.rs        # Helper functions
│   └── error.rs        # Error types
├── tests/             # Integration tests
└── Cargo.toml         # Dependencies
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🧪 Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

```bash
# Run integration tests (requires root privileges)
sudo cargo test --test integration
```

### Manual Testing

```bash
# Create a simple rootfs for testing
mkdir -p /tmp/test-rootfs
# ... populate with basic filesystem structure

# Test basic container functionality
sudo ./target/debug/libflux run test \
  --image /tmp/test-rootfs \
  -- /bin/echo "Hello, libflux!"

# Test container listing (while a container is running)
./target/debug/libflux ps

# Test benchmarking
sudo ./target/debug/libflux benchmark \
  --count 5 \
  --image /tmp/test-rootfs
```

## 🔒 Security Considerations

### Current Security Features

- **Namespace Isolation**: Process, filesystem, and network isolation
- **Resource Limits**: Prevention of resource exhaustion attacks
- **User Mapping**: UID/GID remapping for privilege separation
- **Capability Dropping**: Minimal required capabilities (planned)

### Security Best Practices

1. **Run as Non-Root**: Use user namespaces for rootless containers
2. **Resource Limits**: Always set memory and CPU limits
3. **Read-Only Mounts**: Use read-only bind mounts where possible
4. **Network Isolation**: Use bridge mode for network isolation
5. **Minimal Rootfs**: Use minimal root filesystems

### Known Limitations

- **Seccomp**: Syscall filtering not yet implemented
- **AppArmor/SELinux**: Mandatory access controls not integrated
- **Container Escape**: Some advanced escape prevention measures pending

## 🗺 Roadmap

### Version 0.2.0 (Next Release)

- [ ] Advanced networking (custom bridges, port forwarding)
- [ ] Image extraction from OCI archives
- [ ] Seccomp support
- [ ] Enhanced benchmarking metrics

### Version 1.0.0

- [ ] Production hardening
- [ ] Performance optimizations
- [ ] Complete OCI compatibility
- [ ] Advanced security features

## 📊 Performance

### Benchmarks

Container creation and startup times (on modern hardware):

- **Container Creation**: ~307µs
- **Container Start**: ~50ms
- **Total Container Creation & Start**: ~50ms

*Note: Performance may vary based on system configuration and container complexity.*

## 🤝 Community

- **GitHub Issues**: [Report bugs and request features](https://github.com/libflux/libflux/issues)
- **Discussions**: [Community discussions](https://github.com/libflux/libflux/discussions)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- The Rust community for excellent documentation and crates
- The Linux kernel developers for namespace and cgroup APIs
- Container runtime projects that inspired this work (runc, systemd-nspawn)
- All contributors and early adopters

## ⚠️ Disclaimer

libflux is currently in early development. While it implements core container functionality, it should not be used in production environments without thorough testing and security review.

---

Made with ❤️ and 🦀 by the libflux team
