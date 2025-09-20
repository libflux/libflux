use crate::error::*;
use nix::unistd::{getgid, getuid, Gid, Uid};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use uuid::Uuid;

/// Generate a unique container ID
pub fn generate_container_id() -> String {
    format!("libflux-{}", Uuid::new_v4().to_string()[..8].to_lowercase())
}

/// Check if the current process is running as root
pub fn is_root() -> bool {
    getuid().is_root()
}

/// Get the current user ID
pub fn current_uid() -> Uid {
    getuid()
}

/// Get the current group ID
pub fn current_gid() -> Gid {
    getgid()
}

/// Ensure a directory exists, creating it if necessary
pub fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> LibfluxResult<()> {
    let path = path.as_ref();
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_e| {
            LibfluxError::Filesystem(FilesystemError::DirectoryCreationFailed {
                path: path.to_string_lossy().to_string(),
            })
        })?;
    } else if !path.is_dir() {
        return Err(LibfluxError::Filesystem(FilesystemError::NotDirectory {
            path: path.to_string_lossy().to_string(),
        }));
    }
    Ok(())
}

/// Check if a file exists and is accessible
pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists() && path.as_ref().is_file()
}

/// Check if a directory exists and is accessible
pub fn dir_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists() && path.as_ref().is_dir()
}

/// Get the default libflux data directory
pub fn get_data_dir() -> LibfluxResult<PathBuf> {
    if let Some(data_dir) = std::env::var_os("LIBFLUX_DATA_DIR") {
        return Ok(PathBuf::from(data_dir));
    }

    if is_root() {
        Ok(PathBuf::from("/var/lib/libflux"))
    } else {
        let home_dir = directories::BaseDirs::new()
            .ok_or_else(|| LibfluxError::NotFound("Home directory not found".to_string()))?
            .data_local_dir()
            .to_path_buf();
        Ok(home_dir.join("libflux"))
    }
}

/// Get the default libflux config directory
pub fn get_config_dir() -> LibfluxResult<PathBuf> {
    if let Some(config_dir) = std::env::var_os("LIBFLUX_CONFIG_DIR") {
        return Ok(PathBuf::from(config_dir));
    }

    if is_root() {
        Ok(PathBuf::from("/etc/libflux"))
    } else {
        let home_dir = directories::BaseDirs::new()
            .ok_or_else(|| LibfluxError::NotFound("Home directory not found".to_string()))?
            .config_dir()
            .to_path_buf();
        Ok(home_dir.join("libflux"))
    }
}

/// Get the default libflux runtime directory
pub fn get_runtime_dir() -> LibfluxResult<PathBuf> {
    if let Some(runtime_dir) = std::env::var_os("LIBFLUX_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime_dir));
    }

    // Always use /tmp directory with user-specific subdirectory
    Ok(PathBuf::from("/tmp").join(format!("libflux-{}", getuid())))
}

/// Execute a command and return its output
pub fn execute_command(cmd: &str, args: &[&str]) -> LibfluxResult<String> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| LibfluxError::Io(e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(LibfluxError::InvalidArgument(format!(
            "Command '{}' failed: {}",
            cmd, stderr
        )))
    }
}

/// Parse a size string (e.g., "1G", "512M", "2048K") into bytes
pub fn parse_size(size_str: &str) -> LibfluxResult<u64> {
    let size_str = size_str.trim().to_uppercase();

    if size_str.is_empty() {
        return Err(LibfluxError::InvalidArgument(
            "Empty size string".to_string(),
        ));
    }

    let (num_str, multiplier) = if size_str.ends_with('K') {
        (&size_str[..size_str.len() - 1], 1024u64)
    } else if size_str.ends_with('M') {
        (&size_str[..size_str.len() - 1], 1024u64.pow(2))
    } else if size_str.ends_with('G') {
        (&size_str[..size_str.len() - 1], 1024u64.pow(3))
    } else if size_str.ends_with('T') {
        (&size_str[..size_str.len() - 1], 1024u64.pow(4))
    } else {
        (size_str.as_str(), 1u64)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| LibfluxError::InvalidArgument(format!("Invalid size format: {}", size_str)))?;

    Ok(num * multiplier)
}

/// Format bytes into a human-readable string
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{}{}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1}{}", size, UNITS[unit_index])
    }
}

/// Check if a string is a valid container name
pub fn is_valid_container_name(name: &str) -> bool {
    // Container names should:
    // - Be 1-253 characters long
    // - Contain only lowercase letters, numbers, and hyphens
    // - Start and end with a letter or number
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    let chars: Vec<char> = name.chars().collect();

    // Check first and last characters
    if !chars[0].is_ascii_alphanumeric() || !chars[chars.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    // Check all characters
    chars
        .iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Sanitize a string to be used as a container name
pub fn sanitize_container_name(name: &str) -> String {
    let mut sanitized = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();

    // Remove leading/trailing non-alphanumeric characters
    sanitized = sanitized
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_string();

    // Collapse multiple consecutive hyphens
    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }

    // Ensure it's not empty and not too long
    if sanitized.is_empty() {
        sanitized = "container".to_string();
    }

    if sanitized.len() > 253 {
        sanitized.truncate(253);
        sanitized = sanitized.trim_end_matches('-').to_string();
    }

    sanitized
}

/// Check if the system supports a given kernel feature
pub fn check_kernel_feature(feature: &str) -> bool {
    match feature {
        "cgroups_v2" => Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "user_namespaces" => Path::new("/proc/self/uid_map").exists(),
        "network_namespaces" => Path::new("/proc/self/ns/net").exists(),
        "mount_namespaces" => Path::new("/proc/self/ns/mnt").exists(),
        "pid_namespaces" => Path::new("/proc/self/ns/pid").exists(),
        "overlay_fs" => {
            file_exists("/proc/filesystems")
                && fs::read_to_string("/proc/filesystems")
                    .unwrap_or_default()
                    .contains("overlay")
        }
        _ => false,
    }
}

/// Get system information relevant to container operations
pub fn get_system_info() -> LibfluxResult<SystemInfo> {
    let kernel_version = fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "Unknown".to_string())
        .lines()
        .next()
        .unwrap_or("Unknown")
        .to_string();

    Ok(SystemInfo {
        kernel_version,
        has_cgroups_v2: check_kernel_feature("cgroups_v2"),
        has_user_namespaces: check_kernel_feature("user_namespaces"),
        has_network_namespaces: check_kernel_feature("network_namespaces"),
        has_mount_namespaces: check_kernel_feature("mount_namespaces"),
        has_pid_namespaces: check_kernel_feature("pid_namespaces"),
        has_overlay_fs: check_kernel_feature("overlay_fs"),
        is_root: is_root(),
        uid: current_uid().as_raw(),
        gid: current_gid().as_raw(),
    })
}

/// System information structure
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub kernel_version: String,
    pub has_cgroups_v2: bool,
    pub has_user_namespaces: bool,
    pub has_network_namespaces: bool,
    pub has_mount_namespaces: bool,
    pub has_pid_namespaces: bool,
    pub has_overlay_fs: bool,
    pub is_root: bool,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_container_id() {
        let id1 = generate_container_id();
        let id2 = generate_container_id();

        assert!(id1.starts_with("libflux-"));
        assert!(id2.starts_with("libflux-"));
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 16); // "libflux-" + 8 characters
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);

        assert!(parse_size("invalid").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(1024), "1.0K");
        assert_eq!(format_size(1024 * 1024), "1.0M");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0G");
        assert_eq!(format_size(500), "500B");
    }

    #[test]
    fn test_is_valid_container_name() {
        assert!(is_valid_container_name("test"));
        assert!(is_valid_container_name("test-container"));
        assert!(is_valid_container_name("test123"));
        assert!(is_valid_container_name("123test"));

        assert!(!is_valid_container_name(""));
        assert!(!is_valid_container_name("Test")); // uppercase
        assert!(!is_valid_container_name("-test")); // starts with hyphen
        assert!(!is_valid_container_name("test-")); // ends with hyphen
        assert!(!is_valid_container_name("test_container")); // underscore
    }

    #[test]
    fn test_sanitize_container_name() {
        assert_eq!(sanitize_container_name("Test_Container"), "test-container");
        assert_eq!(
            sanitize_container_name("_test-container_"),
            "test-container"
        );
        assert_eq!(sanitize_container_name("test--container"), "test-container");
        assert_eq!(sanitize_container_name(""), "container");
    }
}
