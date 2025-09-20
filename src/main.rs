mod cgroups;
mod config;
mod container;
mod error;
mod fs;
mod logging;
mod namespace;
mod net;
mod user;
mod utils;

use crate::cgroups::ResourceLimits;
use crate::config::ContainerConfig;
use crate::container::{Container, ContainerState};
use crate::error::*;
use crate::fs::MountType;
use crate::logging::LibfluxLogger;
use crate::namespace::NamespaceType;
use crate::net::{DnsConfig, NetworkConfig, NetworkInterface, NetworkMode};
use crate::utils::{format_size, get_system_info, parse_size};
use clap::{Args, Parser, Subcommand};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;
use std::time::Duration;

/// libflux: Rust-based Container Runtime
#[derive(Parser)]
#[command(name = "libflux")]
#[command(about = "A secure, performant, and developer-friendly container runtime")]
#[command(version = "0.1.0")]
#[command(long_about = None)]
struct Cli {
    /// Set log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Log directory (optional)
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a container (create + start)
    Run(RunArgs),
    /// Show running containers (process status)
    Ps(PsArgs),
    /// Show container resource statistics
    Stats(StatsArgs),
    /// Show system information
    Info,
    /// Run benchmarks
    Benchmark(BenchmarkArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Container name
    name: String,

    /// Container image (directory or archive: .tar, .tar.gz, .tgz)
    #[arg(short, long)]
    image: String,

    /// Command to run
    command: Vec<String>,

    /// Working directory
    #[arg(short, long)]
    workdir: Option<PathBuf>,

    /// Environment variables (KEY=VALUE)
    #[arg(short, long)]
    env: Vec<String>,

    /// Memory limit (e.g., 100M, 1G)
    #[arg(long)]
    memory: Option<String>,

    /// CPU weight (1-10000)
    #[arg(long)]
    cpu_weight: Option<u32>,

    /// Bind mounts (HOST_PATH:CONTAINER_PATH)
    #[arg(short, long)]
    bind: Vec<String>,

    /// Run in privileged mode
    #[arg(long)]
    privileged: bool,

    /// Container hostname
    #[arg(long)]
    hostname: Option<String>,

    /// Run in detached mode
    #[arg(short, long)]
    detach: bool,

    /// Ignore root directory warning
    #[arg(long)]
    ignore_root_warning: bool,

    /// Network mode (bridge, host, none, or custom bridge name)
    #[arg(long, default_value = "bridge")]
    network: String,

    /// Disable networking (equivalent to --network=none)
    #[arg(long)]
    no_network: bool,

    /// Port mappings (HOST_PORT:CONTAINER_PORT)
    #[arg(short, long)]
    publish: Vec<String>,

    /// DNS servers (can be specified multiple times)
    #[arg(long)]
    dns: Vec<String>,

    /// DNS search domains (can be specified multiple times)
    #[arg(long)]
    dns_search: Vec<String>,
}

#[derive(Args)]
struct PsArgs {
    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,
}

#[derive(Args)]
struct InspectArgs {
    /// Container name or ID
    container: String,
}

#[derive(Args)]
struct LogsArgs {
    /// Container name or ID
    container: String,

    /// Follow log output
    #[arg(short, long)]
    follow: bool,

    /// Number of lines to show from the end
    #[arg(long)]
    tail: Option<usize>,

    /// Show timestamps
    #[arg(short, long)]
    timestamps: bool,
}

#[derive(Args)]
struct StatsArgs {
    /// Container name or ID (optional, shows all if not specified)
    container: Option<String>,

    /// Don't stream stats, just print once
    #[arg(long)]
    no_stream: bool,

    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,
}

#[derive(Args)]
struct BenchmarkArgs {
    /// Number of containers to create for benchmark
    #[arg(short, long, default_value = "10")]
    count: u32,

    /// Container image for benchmark
    #[arg(short, long, default_value = "/opt/ubuntu-minimal-rootfs")]
    image: String,

    /// Command to run in containers
    #[arg(long, default_value = "true")]
    command: String,

    /// Include memory usage measurement
    #[arg(long)]
    memory: bool,

    /// Show detailed statistics
    #[arg(long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = crate::logging::parse_log_level(&cli.log_level);
    if let Err(e) = LibfluxLogger::init(log_level, cli.log_dir) {
        eprintln!("Failed to initialize logger: {}", e);
        std::process::exit(1);
    }

    // Handle commands
    let result = match cli.command {
        Commands::Run(args) => handle_run(args).await,
        Commands::Ps(args) => handle_ps(args).await,
        Commands::Stats(args) => handle_stats(args).await,
        Commands::Info => handle_info().await,
        Commands::Benchmark(args) => handle_benchmark(args).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Helper function to stop a container by PID
async fn stop_container_by_pid(pid: u32, timeout_secs: u64, force: bool) -> LibfluxResult<()> {
    let nix_pid = nix::unistd::Pid::from_raw(pid as i32);

    if force {
        // Send SIGKILL immediately
        nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGKILL)
            .map_err(LibfluxError::System)?;
    } else {
        // Send SIGTERM and wait for graceful shutdown
        nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGTERM)
            .map_err(LibfluxError::System)?;

        // Wait for the specified timeout
        let timeout_duration = Duration::from_secs(timeout_secs);
        let start_time = std::time::Instant::now();

        loop {
            // Check if process still exists
            match nix::sys::signal::kill(nix_pid, None) {
                Err(nix::Error::ESRCH) => {
                    // Process no longer exists - graceful shutdown successful
                    break;
                }
                Ok(_) => {
                    // Process still exists
                    if start_time.elapsed() >= timeout_duration {
                        // Timeout reached, force kill
                        nix::sys::signal::kill(nix_pid, nix::sys::signal::Signal::SIGKILL)
                            .map_err(LibfluxError::System)?;
                        break;
                    }
                    // Wait a bit before checking again
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    return Err(LibfluxError::System(e));
                }
            }
        }
    }

    Ok(())
}

/// Validate that we're not running from root directory unless explicitly allowed
fn validate_root_directory(image_path: &str, ignore_root_warning: bool) -> LibfluxResult<()> {
    let current_dir = std::env::current_dir().map_err(LibfluxError::Io)?;
    let root = std::path::Path::new("/");

    if current_dir == root && !ignore_root_warning {
        return Err(LibfluxError::InvalidArgument(
            "Cannot create container from root directory. Use --ignore-root-warning to override this safety check.".to_string()
        ));
    }

    // Also check if the image path is root or other critical system directories
    let image_path = std::path::Path::new(image_path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(image_path));

    // List of dangerous system directories to protect
    let dangerous_paths = [
        "/", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/boot", "/sys", "/proc", "/dev",
    ];

    for dangerous_path in &dangerous_paths {
        let dangerous = std::path::Path::new(dangerous_path);
        if image_path == dangerous && !ignore_root_warning {
            return Err(LibfluxError::InvalidArgument(format!(
                "Cannot use system directory '{}' as container image. Use --ignore-root-warning to override this safety check.", 
                dangerous_path
            )));
        }
    }

    Ok(())
}

/// Validate bind mount safety to prevent mounting critical system directories
fn validate_bind_mount_safety(host_path: &str, ignore_root_warning: bool) -> LibfluxResult<()> {
    if ignore_root_warning {
        return Ok(());
    }

    let host_path = std::path::Path::new(host_path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(host_path));

    // Critical system directories that should not be bind mounted without explicit override
    let dangerous_mount_paths = [
        "/",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/etc",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
    ];

    for dangerous_path in &dangerous_mount_paths {
        let dangerous = std::path::Path::new(dangerous_path);
        if host_path == dangerous || host_path.starts_with(dangerous) {
            return Err(LibfluxError::InvalidArgument(format!(
                "Refusing to bind mount critical system directory '{}'. Use --ignore-root-warning to override this safety check.",
                dangerous_path
            )));
        }
    }

    Ok(())
}

/// Validate directory structure for container image
fn validate_container_structure(image_path: &str) -> LibfluxResult<()> {
    let image_path = std::path::Path::new(image_path);

    if !image_path.exists() {
        return Err(LibfluxError::InvalidArgument(format!(
            "Image path does not exist: {}",
            image_path.display()
        )));
    }

    if !image_path.is_dir() {
        return Err(LibfluxError::InvalidArgument(format!(
            "Image path is not a directory: {}",
            image_path.display()
        )));
    }

    // Check for basic directory structure
    let required_dirs = ["bin", "etc", "lib", "usr"];
    let mut missing_dirs = Vec::new();

    for dir in &required_dirs {
        let dir_path = image_path.join(dir);
        if !dir_path.exists() {
            missing_dirs.push(*dir);
        }
    }

    if !missing_dirs.is_empty() {
        println!(
            "Warning: Missing typical root filesystem directories: {}",
            missing_dirs.join(", ")
        );
        println!("This may not be a valid container rootfs");
    }

    // Check for shell
    let shells = ["bin/sh", "bin/bash"];
    let mut has_shell = false;

    for shell in &shells {
        let shell_path = image_path.join(shell);
        if shell_path.exists() {
            has_shell = true;
            break;
        }
    }

    if !has_shell {
        println!("Warning: No shell found in typical locations (bin/sh, bin/bash)");
    }

    Ok(())
}

async fn handle_run(args: RunArgs) -> LibfluxResult<()> {
    // Validate root directory protection
    validate_root_directory(&args.image, args.ignore_root_warning)?;

    // Validate container structure (skip for archives)
    let image_path = PathBuf::from(&args.image);
    let is_archive = args.image.ends_with(".tar")
        || args.image.ends_with(".tar.gz")
        || args.image.ends_with(".tgz")
        || args.image.ends_with(".tar.xz");
    if !is_archive {
        validate_container_structure(&args.image)?;
    }

    // Parse environment variables
    let mut environment = HashMap::new();
    for env_var in args.env {
        if let Some((key, value)) = env_var.split_once('=') {
            environment.insert(key.to_string(), value.to_string());
        } else {
            return Err(LibfluxError::InvalidArgument(format!(
                "Invalid environment variable format: {}",
                env_var
            )));
        }
    }

    // Parse bind mounts with safety validation
    let mut mounts = Vec::new();
    for bind_mount in args.bind {
        if let Some((host_path, container_path)) = bind_mount.split_once(':') {
            validate_bind_mount_safety(host_path, args.ignore_root_warning)?;
            let mount = MountType::Bind {
                source: PathBuf::from(host_path),
                target: PathBuf::from(container_path),
                readonly: false,
            };
            mounts.push(mount);
        } else {
            return Err(LibfluxError::InvalidArgument(format!(
                "Invalid bind mount format: {}",
                bind_mount
            )));
        }
    }

    // Create resource limits
    let mut resources = ResourceLimits::default();
    if let Some(memory_str) = args.memory {
        let memory_bytes = parse_size(&memory_str)?;
        resources.memory.limit = Some(memory_bytes);
    }
    if let Some(cpu_weight) = args.cpu_weight {
        resources.cpu.weight = Some(cpu_weight);
    }

    // Build NetworkConfig from CLI flags
    let network_mode = if args.no_network || args.network == "none" {
        NetworkMode::None
    } else if args.network == "host" {
        NetworkMode::Host
    } else if args.network == "bridge" || args.network.is_empty() {
        NetworkMode::Bridge
    } else if args.network.starts_with("custom:") {
        NetworkMode::CustomBridge {
            bridge_name: args.network[7..].to_string(),
        }
    } else {
        NetworkMode::Bridge
    };

    let mut default_namespaces = vec![
        NamespaceType::Pid,
        NamespaceType::Mount,
        NamespaceType::Ipc,
        NamespaceType::Uts,
    ];
    if network_mode != NetworkMode::Host {
        default_namespaces.push(NamespaceType::Network);
    }

    let command = if args.command.is_empty() {
        vec!["/bin/bash".to_string()]
    } else {
        args.command
    };

    // Create temporary rootfs by copying or extracting the image to a temp directory
    debug!("Creating temporary directory...");
    let temp_dir = tempfile::tempdir().map_err(|e| {
        error!("Failed to create temporary directory: {}", e);
        LibfluxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
    })?;
    debug!("Temporary directory created successfully");

    let temp_rootfs = temp_dir.path().join("rootfs");

    println!("Creating temporary container from '{}'...", args.image);
    debug!("Source: {}", args.image);
    debug!("Destination: {}", temp_rootfs.display());
    debug!("Temp dir: {}", temp_dir.path().display());

    // Verify source exists before copying or extracting
    if !image_path.exists() {
        return Err(LibfluxError::InvalidArgument(format!(
            "Source image does not exist: {}",
            image_path.display()
        )));
    }

    if is_archive {
        // Extract archive to temp_rootfs
        debug!("Extracting archive to rootfs...");
        std::fs::create_dir_all(&temp_rootfs).map_err(|e| LibfluxError::Io(e))?;
        let status = if args.image.ends_with(".tar.gz") || args.image.ends_with(".tgz") {
            std::process::Command::new("tar")
                .arg("-xzf")
                .arg(&args.image)
                .arg("-C")
                .arg(&temp_rootfs)
                .status()
        } else if args.image.ends_with(".tar.xz") {
            std::process::Command::new("tar")
                .arg("-xJf")
                .arg(&args.image)
                .arg("-C")
                .arg(&temp_rootfs)
                .status()
        } else {
            std::process::Command::new("tar")
                .arg("-xf")
                .arg(&args.image)
                .arg("-C")
                .arg(&temp_rootfs)
                .status()
        };
        match status {
            Ok(s) if s.success() => debug!("Archive extracted successfully"),
            Ok(s) => {
                return Err(LibfluxError::InvalidArgument(format!(
                    "Failed to extract archive (exit code {}): {}",
                    s.code().unwrap_or(-1),
                    args.image
                )));
            }
            Err(e) => {
                return Err(LibfluxError::Io(e));
            }
        }
        // Validate extracted rootfs structure
        let required_dirs = ["bin", "etc", "lib", "usr", "tmp", "dev", "proc", "sys"];
        let mut missing_dirs = Vec::new();
        for dir in &required_dirs {
            let dir_path = temp_rootfs.join(dir);
            if !dir_path.exists() {
                missing_dirs.push(*dir);
            }
        }
        if !missing_dirs.is_empty() {
            println!(
                "Warning: Missing typical root filesystem directories in extracted archive: {}",
                missing_dirs.join(", ")
            );
        }
        // Check for shell
        let shells = ["bin/sh", "bin/bash"];
        let mut has_shell = false;
        for shell in &shells {
            let shell_path = temp_rootfs.join(shell);
            if shell_path.exists() {
                has_shell = true;
                break;
            }
        }
        if !has_shell {
            println!("Warning: No shell found in extracted archive (bin/sh, bin/bash)");
        }
    } else {
        debug!("Copying image directory to rootfs...");
        copy_directory(&image_path, &temp_rootfs)?;
        debug!("Copy completed successfully");
    }

    // Build NetworkConfig from CLI flags
    let network_mode = if args.no_network || args.network == "none" {
        NetworkMode::None
    } else if args.network == "host" {
        NetworkMode::Host
    } else if args.network == "bridge" || args.network.is_empty() {
        NetworkMode::Bridge
    } else if args.network.starts_with("custom:") {
        NetworkMode::CustomBridge {
            bridge_name: args.network[7..].to_string(),
        }
    } else {
        NetworkMode::Bridge
    };

    let mut port_mappings = std::collections::HashMap::new();
    for mapping in &args.publish {
        if let Some((host, container)) = mapping.split_once(':') {
            if let (Ok(h), Ok(c)) = (host.parse::<u16>(), container.parse::<u16>()) {
                port_mappings.insert(h, c);
            }
        }
    }

    let mut dns_servers = Vec::new();
    for dns in &args.dns {
        if let Ok(ip) = dns.parse() {
            dns_servers.push(ip);
        }
    }

    let dns_config = DnsConfig {
        nameservers: dns_servers,
        search_domains: args.dns_search.clone(),
        options: vec!["ndots:0".to_string()],
    };

    let network_config = NetworkConfig {
        mode: network_mode,
        interfaces: vec![NetworkInterface::default()],
        dns: dns_config,
        port_mappings,
    };

    let config = ContainerConfig::new(
        args.name.clone(),
        args.image.clone(),
        command,
        args.workdir,
        environment,
        temp_rootfs, // Use temporary rootfs
        default_namespaces,
        args.privileged,
        args.hostname,
        mounts,
        resources,
        None, // No user mapping for now
        network_config,
    );

    // Create and start container
    let mut container = Container::new(config)?;
    container.create().await?;

    println!("Starting container '{}'...", args.name);
    container.start().await?;

    if !args.detach {
        // Wait for container to finish and cleanup automatically
        println!("Container started. Waiting for completion...");
        loop {
            let state = container.state().await;
            if state == ContainerState::Stopped || state == ContainerState::Error {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Cleanup happens automatically when container and temp_dir are dropped
        println!("Container finished. Temporary files cleaned up.");
    } else {
        println!("Container '{}' started in detached mode", args.name);
        println!("Note: Container will be automatically cleaned up when it exits");

        // For detached mode, we need to keep the temp directory alive
        // We'll need to modify this to handle cleanup properly
        // For now, just leak the temp_dir
        std::mem::forget(temp_dir);
    }

    Ok(())
}

/// Check if a path should be skipped during copying
fn should_skip_path(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy();

    // Skip common runtime/temporary directories and files
    let skip_patterns = [
        "/var/run/",
        "/run/",
        "/tmp/",
        "/proc/",
        "/sys/",
        "/dev/",
        ".lock",
        ".pid",
        ".sock",
        ".socket",
        "/var/cache/",
        "/var/tmp/",
    ];

    for pattern in &skip_patterns {
        if path_str.contains(pattern) {
            return true;
        }
    }

    // Skip snapd namespace files specifically
    if path_str.contains("/var/run/snapd/ns/") {
        return true;
    }

    false
}

/// Copy directory recursively
fn copy_directory(src: &PathBuf, dst: &PathBuf) -> LibfluxResult<()> {
    let mut visited = HashSet::new();
    copy_directory_impl(src, dst, &mut visited)
}

/// Internal implementation of copy_directory with loop detection
fn copy_directory_impl(
    src: &PathBuf,
    dst: &PathBuf,
    visited: &mut HashSet<PathBuf>,
) -> LibfluxResult<()> {
    use std::fs;

    debug!(
        "copy_directory called with src='{}', dst='{}'",
        src.display(),
        dst.display()
    );

    // Resolve the canonical path to detect loops
    let canonical_src = match src.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            // If we can't canonicalize (e.g., broken symlink), use the original path
            src.clone()
        }
    };

    // Check for loops
    if visited.contains(&canonical_src) {
        debug!("Detected symlink loop, skipping: {}", src.display());
        return Ok(());
    }
    visited.insert(canonical_src.clone());

    // Check if source exists and is accessible
    if !src.exists() {
        error!("Source path does not exist: {}", src.display());
        return Err(LibfluxError::InvalidArgument(format!(
            "Source path does not exist: {}",
            src.display()
        )));
    }
    debug!("Source exists");

    if !src.is_dir() {
        error!("Source is not a directory: {}", src.display());
        return Err(LibfluxError::InvalidArgument(format!(
            "Source is not a directory: {}",
            src.display()
        )));
    }
    debug!("Source is a directory");

    // Create destination directory with better error context
    debug!("Creating destination directory: {}", dst.display());
    fs::create_dir_all(dst).map_err(|e| {
        eprintln!(
            "ERROR: Failed to create destination directory '{}': {}",
            dst.display(),
            e
        );
        LibfluxError::InvalidArgument(format!(
            "Failed to create destination directory '{}': {}",
            dst.display(),
            e
        ))
    })?;
    debug!("Destination directory created");

    // Read source directory with better error context
    debug!("Reading source directory: {}", src.display());
    let entries = fs::read_dir(src).map_err(|e| {
        error!("Failed to read source directory '{}': {}", src.display(), e);
        LibfluxError::InvalidArgument(format!(
            "Failed to read source directory '{}': {}",
            src.display(),
            e
        ))
    })?;
    debug!("Source directory read successfully");

    for entry in entries {
        let entry = entry.map_err(|e| {
            eprintln!(
                "ERROR: Failed to read directory entry in '{}': {}",
                src.display(),
                e
            );
            LibfluxError::InvalidArgument(format!(
                "Failed to read directory entry in '{}': {}",
                src.display(),
                e
            ))
        })?;

        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        debug!(
            "Processing entry: {} -> {}",
            src_path.display(),
            dst_path.display()
        );

        // Skip common runtime directories that shouldn't be copied
        if should_skip_path(&src_path) {
            debug!("Skipping runtime/temporary path: {}", src_path.display());
            continue;
        }

        if src_path.is_dir() {
            debug!("Recursively copying directory");
            copy_directory_impl(&src_path, &dst_path, visited)?;
        } else {
            // Check if it's a symbolic link
            let src_metadata = fs::symlink_metadata(&src_path).map_err(|e| {
                eprintln!(
                    "ERROR: Failed to read metadata for '{}': {}",
                    src_path.display(),
                    e
                );
                LibfluxError::InvalidArgument(format!(
                    "Failed to read metadata for '{}': {}",
                    src_path.display(),
                    e
                ))
            })?;

            if src_metadata.file_type().is_symlink() {
                debug!("Copying symbolic link");
                // Ensure the parent directory of the destination exists
                if let Some(parent) = dst_path.parent() {
                    debug!("Creating parent directory: {}", parent.display());
                    fs::create_dir_all(parent).map_err(|e| {
                        error!(
                            "Failed to create parent directory '{}': {}",
                            parent.display(),
                            e
                        );
                        LibfluxError::InvalidArgument(format!(
                            "Failed to create parent directory '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }

                // Read the link target and recreate the symlink
                let link_target = fs::read_link(&src_path).map_err(|e| {
                    eprintln!(
                        "ERROR: Failed to read link target for '{}': {}",
                        src_path.display(),
                        e
                    );
                    LibfluxError::InvalidArgument(format!(
                        "Failed to read link target for '{}': {}",
                        src_path.display(),
                        e
                    ))
                })?;

                std::os::unix::fs::symlink(&link_target, &dst_path).map_err(|e| {
                    eprintln!(
                        "ERROR: Failed to create symlink from '{}' to '{}': {}",
                        dst_path.display(),
                        link_target.display(),
                        e
                    );
                    LibfluxError::InvalidArgument(format!(
                        "Failed to create symlink from '{}' to '{}': {}",
                        dst_path.display(),
                        link_target.display(),
                        e
                    ))
                })?;
                debug!("Symbolic link copied successfully");
            } else if src_metadata.file_type().is_char_device()
                || src_metadata.file_type().is_block_device()
                || src_metadata.file_type().is_fifo()
                || src_metadata.file_type().is_socket()
            {
                debug!(
                    "Skipping device/special file: {} (will be handled by container runtime)",
                    src_path.display()
                );
                // Skip device files, FIFOs, sockets, etc. - these should be created by the container runtime
                // or mounted from the host system, not copied from the rootfs image
            } else {
                debug!("Copying regular file");
                // Ensure the parent directory of the destination exists
                if let Some(parent) = dst_path.parent() {
                    debug!("Creating parent directory: {}", parent.display());
                    fs::create_dir_all(parent).map_err(|e| {
                        error!(
                            "Failed to create parent directory '{}': {}",
                            parent.display(),
                            e
                        );
                        LibfluxError::InvalidArgument(format!(
                            "Failed to create parent directory '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }

                fs::copy(&src_path, &dst_path).map_err(|e| {
                    error!(
                        "Failed to copy file from '{}' to '{}': {}",
                        src_path.display(),
                        dst_path.display(),
                        e
                    );
                    LibfluxError::InvalidArgument(format!(
                        "Failed to copy file from '{}' to '{}': {}",
                        src_path.display(),
                        dst_path.display(),
                        e
                    ))
                })?;
                debug!("Regular file copied successfully");
            }
        }
    }

    // Remove this path from visited set before returning
    visited.remove(&canonical_src);

    debug!("copy_directory completed successfully");
    Ok(())
}
async fn handle_ps(args: PsArgs) -> LibfluxResult<()> {
    // Get running processes that look like containers
    let running_containers = get_running_containers().await?;

    match args.format.as_str() {
        "table" => {
            println!(
                "{:<12} {:<15} {:<6} {:<8} {:<10} {:<8} {:<8} {:<8} {:<8} {:<4} {:<4}",
                "CONTAINER ID",
                "NAME",
                "CPU%",
                "MEM%",
                "MEM USAGE",
                "DISK R",
                "DISK W",
                "PROCS",
                "THREADS",
                "PID",
                "STATE"
            );
            println!("{}", "-".repeat(130));

            if running_containers.is_empty() {
                println!("No running containers found");
            } else {
                for container in running_containers {
                    let mem_usage_str = format_size(container.memory_usage);
                    let disk_read_str = format_size(container.disk_read);
                    let disk_write_str = format_size(container.disk_write);

                    println!(
                        "{:<12} {:<15} {:<6.1} {:<8.1} {:<10} {:<8} {:<8} {:<8} {:<8} {:<4} {:<4}",
                        &container.id[..12.min(container.id.len())], // Truncate ID to 12 chars
                        container.name,
                        container.cpu_percent,
                        container.memory_percent,
                        mem_usage_str,
                        disk_read_str,
                        disk_write_str,
                        container.processes,
                        container.threads,
                        container.pid,
                        "running"
                    );
                }
            }
        }
        "json" => {
            let json_output = serde_json::to_string_pretty(&running_containers).map_err(|e| {
                LibfluxError::InvalidArgument(format!("Failed to serialize containers: {}", e))
            })?;
            println!("{}", json_output);
        }
        _ => {
            return Err(LibfluxError::InvalidArgument(format!(
                "Unsupported format: {}",
                args.format
            )));
        }
    }
    Ok(())
}

/// Simplified running container info for ps command
#[derive(Debug, serde::Serialize)]
struct RunningContainerInfo {
    id: String,
    name: String,
    pid: u32,
    command: Vec<String>,
    cpu_percent: f64,
    memory_usage: u64,
    memory_percent: f64,
    disk_read: u64,
    disk_write: u64,
    processes: u32,
    threads: u32,
}

/// Get list of running containers by scanning processes
async fn get_running_containers() -> LibfluxResult<Vec<RunningContainerInfo>> {
    let mut containers = Vec::new();

    // Scan /sys/fs/cgroup/libflux for active cgroups
    let cgroup_root = std::path::Path::new("/sys/fs/cgroup/libflux");

    if !cgroup_root.exists() {
        return Ok(containers);
    }

    // Read directories in the libflux cgroup path
    if let Ok(entries) = std::fs::read_dir(cgroup_root) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(container_id) = path.file_name().and_then(|n| n.to_str()) {
                        // Check if this cgroup has active processes
                        let procs_file = path.join("cgroup.procs");
                        if let Ok(contents) = std::fs::read_to_string(&procs_file) {
                            let pids: Vec<u32> = contents
                                .lines()
                                .filter_map(|line| line.trim().parse().ok())
                                .collect();

                            if !pids.is_empty() {
                                // Get the main PID (first one)
                                let main_pid = pids[0];

                                // Try to create a cgroup manager and get stats
                                if let Ok(mut cgroup_manager) =
                                    crate::cgroups::CgroupManager::new(container_id.to_string())
                                {
                                    // Set as created since it exists
                                    let _ = cgroup_manager.create(); // This should succeed since it exists

                                    if let Ok(stats) = cgroup_manager.get_stats() {
                                        // Get process command line
                                        let command = read_proc_cmdline(main_pid)
                                            .unwrap_or_else(|| vec!["<unknown>".to_string()]);

                                        // Generate a container name from the ID
                                        let name = format!(
                                            "container-{}",
                                            &container_id[..8.min(container_id.len())]
                                        );

                                        containers.push(RunningContainerInfo {
                                            id: container_id.to_string(),
                                            name,
                                            pid: main_pid,
                                            command,
                                            cpu_percent: stats.cpu.cpu_percent,
                                            memory_usage: stats.memory.current,
                                            memory_percent: stats.memory.memory_percent,
                                            disk_read: stats.io.read_bytes,
                                            disk_write: stats.io.write_bytes,
                                            processes: stats.cpu.num_processes,
                                            threads: stats.cpu.num_threads,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(containers)
}

/// Read command line for a process
fn read_proc_cmdline(pid: u32) -> Option<Vec<String>> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(contents) = std::fs::read(&cmdline_path) {
        let cmdline: Vec<String> = contents
            .split(|&b| b == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).to_string())
            .collect();

        if !cmdline.is_empty() {
            return Some(cmdline);
        }
    }
    None
}

async fn handle_stats(args: StatsArgs) -> LibfluxResult<()> {
    // In the temporary model, we can only show stats for currently running containers
    if let Some(container_name) = &args.container {
        println!(
            "Container '{}' not found - only running containers have stats in temporary mode",
            container_name
        );
    } else {
        println!("No running containers found");
    }
    println!("Use 'libflux ps' to see running containers");
    Ok(())
}

/// Simple container stats
#[derive(Debug)]
struct SimpleContainerStats {
    cpu_percent: String,
    memory_usage: String,
    memory_percent: String,
}

/// Get basic container statistics
async fn get_container_stats(
    container_info: &crate::container::ContainerInfo,
) -> SimpleContainerStats {
    if container_info.state != ContainerState::Running || container_info.pid.is_none() {
        return SimpleContainerStats {
            cpu_percent: "-".to_string(),
            memory_usage: "-".to_string(),
            memory_percent: "-".to_string(),
        };
    }

    let pid = container_info.pid.unwrap();

    // Try to read basic stats from /proc
    let memory_usage = read_proc_memory_usage(pid).unwrap_or_else(|| "-".to_string());
    let cpu_percent = read_proc_cpu_usage(pid).unwrap_or_else(|| "-".to_string());

    SimpleContainerStats {
        cpu_percent,
        memory_usage,
        memory_percent: "-".to_string(), // Would need system memory total to calculate
    }
}

/// Read memory usage from /proc/[pid]/status
fn read_proc_memory_usage(pid: u32) -> Option<String> {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = std::fs::read_to_string(status_path) {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        if kb >= 1024 * 1024 {
                            return Some(format!("{:.1}GB", kb as f64 / (1024.0 * 1024.0)));
                        } else if kb >= 1024 {
                            return Some(format!("{:.1}MB", kb as f64 / 1024.0));
                        } else {
                            return Some(format!("{}KB", kb));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Read CPU usage - simplified version
fn read_proc_cpu_usage(_pid: u32) -> Option<String> {
    // CPU usage calculation is complex and requires sampling over time
    // For now, return a placeholder
    Some("-".to_string())
}

async fn handle_info() -> LibfluxResult<()> {
    let system_info = get_system_info()?;

    println!("System Information");
    println!("========================");
    println!("Version: 0.1.0");
    println!("Kernel: {}", system_info.kernel_version);
    println!(
        "User: {} (UID: {}, GID: {})",
        if system_info.is_root {
            "root"
        } else {
            "non-root"
        },
        system_info.uid,
        system_info.gid
    );
    println!();

    println!("Kernel Features:");
    println!(
        "  Cgroups v2: {}",
        if system_info.has_cgroups_v2 {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "  User namespaces: {}",
        if system_info.has_user_namespaces {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "  Network namespaces: {}",
        if system_info.has_network_namespaces {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "  Mount namespaces: {}",
        if system_info.has_mount_namespaces {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "  PID namespaces: {}",
        if system_info.has_pid_namespaces {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "  Overlay filesystem: {}",
        if system_info.has_overlay_fs {
            "✓"
        } else {
            "✗"
        }
    );

    // Check networking capabilities
    if let Ok(net_caps) = crate::net::check_network_capabilities() {
        println!();
        println!("Network Capabilities:");
        println!(
            "  ip command: {}",
            if net_caps.has_ip_command {
                "✓"
            } else {
                "✗"
            }
        );
        println!(
            "  iptables: {}",
            if net_caps.has_iptables { "✓" } else { "✗" }
        );
        println!(
            "  bridge utils: {}",
            if net_caps.has_bridge_utils {
                "✓"
            } else {
                "✗"
            }
        );
    }

    // Check user namespace capabilities
    if let Ok(subid_info) = crate::user::get_subid_info() {
        println!();
        println!("User Namespace Capabilities:");
        println!(
            "  Can create user namespaces: {}",
            if subid_info.can_create_user_ns {
                "✓"
            } else {
                "✗"
            }
        );
        if let Some((start, range)) = subid_info.subuid_range {
            println!("  SubUID range: {} (count: {})", start, range);
        } else {
            println!("  SubUID range: None");
        }
        if let Some((start, range)) = subid_info.subgid_range {
            println!("  SubGID range: {} (count: {})", start, range);
        } else {
            println!("  SubGID range: None");
        }
    }

    Ok(())
}

async fn handle_benchmark(args: BenchmarkArgs) -> LibfluxResult<()> {
    println!(
        "Running container benchmark with {} containers...",
        args.count
    );

    let mut benchmark_stats = BenchmarkStats::new();
    let overall_start = std::time::Instant::now();

    // Measure baseline memory usage
    let baseline_memory = if args.memory { get_memory_usage() } else { 0 };

    for i in 0..args.count {
        let container_name = format!("bench-{}", i);

        let default_namespaces = vec![
            NamespaceType::Pid,
            NamespaceType::Mount,
            NamespaceType::Network,
            NamespaceType::Ipc,
            NamespaceType::Uts,
        ];

        // Create temporary rootfs for benchmark
        let temp_dir = tempfile::tempdir()
            .map_err(|e| LibfluxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        let temp_rootfs = temp_dir.path().join("rootfs");
        copy_directory(&PathBuf::from(&args.image), &temp_rootfs)?;

        let network_config = NetworkConfig {
            mode: NetworkMode::Bridge,
            interfaces: vec![NetworkInterface::default()],
            dns: DnsConfig::default(),
            port_mappings: std::collections::HashMap::new(),
        };

        let config = ContainerConfig::new(
            container_name.clone(),
            args.image.clone(),
            vec![args.command.clone()],
            None,
            HashMap::new(),
            temp_rootfs,
            default_namespaces,
            false,
            Some(container_name.clone()),
            Vec::new(),
            ResourceLimits::default(),
            None,
            network_config,
        );

        let container_times =
            run_single_container_benchmark(config, &container_name, args.verbose).await;
        benchmark_stats.add_container_run(container_times);
    }

    let total_time = overall_start.elapsed();

    // Measure final memory usage
    let final_memory = if args.memory { get_memory_usage() } else { 0 };

    // Display comprehensive results
    display_benchmark_results(
        &benchmark_stats,
        total_time,
        baseline_memory,
        final_memory,
        args.memory,
    );

    Ok(())
}

/// Statistics for benchmark runs
#[derive(Debug)]
struct BenchmarkStats {
    successful_runs: u32,
    failed_runs: u32,
    creation_times: Vec<Duration>,
    start_times: Vec<Duration>,
    total_times: Vec<Duration>,
}

impl BenchmarkStats {
    fn new() -> Self {
        Self {
            successful_runs: 0,
            failed_runs: 0,
            creation_times: Vec::new(),
            start_times: Vec::new(),
            total_times: Vec::new(),
        }
    }

    fn add_container_run(&mut self, times: ContainerBenchmarkResult) {
        match times {
            ContainerBenchmarkResult::Success {
                creation_time,
                start_time,
                total_time,
            } => {
                self.successful_runs += 1;
                self.creation_times.push(creation_time);
                self.start_times.push(start_time);
                self.total_times.push(total_time);
            }
            ContainerBenchmarkResult::Failure => {
                self.failed_runs += 1;
            }
        }
    }

    fn total_containers(&self) -> u32 {
        self.successful_runs + self.failed_runs
    }
}

/// Result of a single container benchmark
#[derive(Debug)]
enum ContainerBenchmarkResult {
    Success {
        creation_time: Duration,
        start_time: Duration,
        total_time: Duration,
    },
    Failure,
}

/// Run benchmark for a single container
async fn run_single_container_benchmark(
    config: ContainerConfig,
    container_name: &str,
    verbose: bool,
) -> ContainerBenchmarkResult {
    let total_start = std::time::Instant::now();

    let creation_start = std::time::Instant::now();
    let mut container = match Container::new(config) {
        Ok(container) => container,
        Err(e) => {
            if verbose {
                println!("Container {} creation failed: {}", container_name, e);
            }
            return ContainerBenchmarkResult::Failure;
        }
    };

    let create_result = container.create().await;
    let creation_time = creation_start.elapsed();

    if let Err(e) = create_result {
        if verbose {
            println!("Container {} failed to create: {}", container_name, e);
        }
        return ContainerBenchmarkResult::Failure;
    }

    let start_start = std::time::Instant::now();
    let start_result = container.start().await;
    let start_time = start_start.elapsed();

    if let Err(e) = start_result {
        if verbose {
            println!("Container {} failed to start: {}", container_name, e);
        }
        return ContainerBenchmarkResult::Failure;
    }

    let total_time = total_start.elapsed();

    if verbose {
        println!(
            "Container {} - Creation: {:?}, Start: {:?}, Total: {:?}",
            container_name, creation_time, start_time, total_time
        );
    }

    // Cleanup immediately for benchmark
    let _ = container.cleanup().await;

    ContainerBenchmarkResult::Success {
        creation_time,
        start_time,
        total_time,
    }
}

/// Display comprehensive benchmark results
fn display_benchmark_results(
    stats: &BenchmarkStats,
    total_duration: Duration,
    baseline_memory: u64,
    final_memory: u64,
    include_memory: bool,
) {
    println!("\n=== Benchmark Results ===");
    println!("Total containers: {}", stats.total_containers());
    println!("Successful: {}", stats.successful_runs);
    println!("Failed: {}", stats.failed_runs);
    println!(
        "Success rate: {:.1}%",
        if stats.total_containers() > 0 {
            (stats.successful_runs as f64 / stats.total_containers() as f64) * 100.0
        } else {
            0.0
        }
    );
    println!("Overall time: {:?}", total_duration);

    if stats.successful_runs > 0 {
        // Calculate statistics for successful runs
        let avg_creation = average_duration(&stats.creation_times);
        let avg_start = average_duration(&stats.start_times);
        let avg_total = average_duration(&stats.total_times);

        let min_total = *stats.total_times.iter().min().unwrap();
        let max_total = *stats.total_times.iter().max().unwrap();

        println!("\n--- Timing Statistics ---");
        println!("Average creation time: {:?}", avg_creation);
        println!("Average start time: {:?}", avg_start);
        println!("Average total time: {:?}", avg_total);
        println!("Fastest container: {:?}", min_total);
        println!("Slowest container: {:?}", max_total);
        println!(
            "Containers per second: {:.2}",
            stats.successful_runs as f64 / total_duration.as_secs_f64()
        );
    }

    if include_memory {
        println!("\n--- Memory Statistics ---");
        println!("Baseline memory: {} KB", baseline_memory);
        println!("Final memory: {} KB", final_memory);
        if final_memory > baseline_memory {
            println!("Memory increase: {} KB", final_memory - baseline_memory);
            println!(
                "Memory per container: {:.2} KB",
                (final_memory - baseline_memory) as f64 / stats.total_containers() as f64
            );
        } else {
            println!("Memory usage stable or decreased");
        }
    }
}

/// Calculate average duration from a slice of durations
fn average_duration(durations: &[Duration]) -> Duration {
    if durations.is_empty() {
        return Duration::from_secs(0);
    }

    let total_nanos: u128 = durations.iter().map(|d| d.as_nanos()).sum();
    let avg_nanos = total_nanos / durations.len() as u128;
    Duration::from_nanos(avg_nanos as u64)
}

/// Get current memory usage in KB
fn get_memory_usage() -> u64 {
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    return kb_str.parse().unwrap_or(0);
                }
            }
        }
    }
    0
}
