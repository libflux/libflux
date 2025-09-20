use std::io;
use thiserror::Error;

/// Main error type for libflux operations
#[derive(Error, Debug)]
pub enum LibfluxError {
    #[error("Container error: {0}")]
    Container(#[from] ContainerError),

    #[error("Namespace error: {0}")]
    Namespace(#[from] NamespaceError),

    #[error("Cgroup error: {0}")]
    Cgroup(#[from] CgroupError),

    #[error("Filesystem error: {0}")]
    Filesystem(#[from] FilesystemError),

    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("User/Group mapping error: {0}")]
    UserMapping(#[from] UserMappingError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("System error: {0}")]
    System(#[from] nix::Error),

    #[error("Permission denied: {0}")]
    Permission(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Operation not supported: {0}")]
    NotSupported(String),
}

/// Container-specific errors
#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("Container not found: {container_id}")]
    NotFound { container_id: String },

    #[error("Container already exists: {container_id}")]
    AlreadyExists { container_id: String },

    #[error("Container is not running: {container_id}")]
    NotRunning { container_id: String },

    #[error("Container is already running: {container_id}")]
    AlreadyRunning { container_id: String },

    #[error("Invalid container state: expected {expected}, found {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("Container process exited with code: {exit_code}")]
    ProcessExited { exit_code: i32 },

    #[error("Container initialization failed: {reason}")]
    InitializationFailed { reason: String },

    #[error("Container cleanup failed: {reason}")]
    CleanupFailed { reason: String },
}

/// Namespace-related errors
#[derive(Error, Debug)]
pub enum NamespaceError {
    #[error("Failed to create namespace: {namespace_type}")]
    CreationFailed { namespace_type: String },

    #[error("Failed to enter namespace: {namespace_type}")]
    EnterFailed { namespace_type: String },

    #[error("Namespace not supported: {namespace_type}")]
    NotSupported { namespace_type: String },

    #[error("Failed to unshare namespace: {namespace_type}")]
    UnshareFailed { namespace_type: String },

    #[error("Invalid namespace file descriptor")]
    InvalidFd,
}

/// Cgroup-related errors
#[derive(Error, Debug)]
pub enum CgroupError {
    #[error("Failed to create cgroup: {cgroup_path}")]
    CreationFailed { cgroup_path: String },

    #[error("Failed to join cgroup: {cgroup_path}")]
    JoinFailed { cgroup_path: String },

    #[error("Failed to set cgroup limit: {controller} = {value}")]
    SetLimitFailed { controller: String, value: String },

    #[error("Cgroup not found: {cgroup_path}")]
    NotFound { cgroup_path: String },

    #[error("Cgroup controller not available: {controller}")]
    ControllerNotAvailable { controller: String },

    #[error("Invalid cgroup value: {value}")]
    InvalidValue { value: String },

    #[error("Cgroups v2 not supported on this system")]
    V2NotSupported,
}

/// Filesystem-related errors
#[derive(Error, Debug)]
pub enum FilesystemError {
    #[error("Mount failed: {mount_source} -> {target}")]
    MountFailed {
        mount_source: String,
        target: String,
    },

    #[error("Unmount failed: {target}")]
    UnmountFailed { target: String },

    #[error("Bind mount failed: {mount_source} -> {target}")]
    BindMountFailed {
        mount_source: String,
        target: String,
    },

    #[error("Overlay mount failed")]
    OverlayFailed,

    #[error("Directory creation failed: {path}")]
    DirectoryCreationFailed { path: String },

    #[error("Path does not exist: {path}")]
    PathNotFound { path: String },

    #[error("Path is not a directory: {path}")]
    NotDirectory { path: String },

    #[error("Path is not a file: {path}")]
    NotFile { path: String },

    #[error("Insufficient permissions for path: {path}")]
    InsufficientPermissions { path: String },
}

/// Network-related errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Failed to create network interface: {interface}")]
    InterfaceCreationFailed { interface: String },

    #[error("Failed to configure network interface: {interface}")]
    InterfaceConfigFailed { interface: String },

    #[error("Failed to create bridge: {bridge_name}")]
    BridgeCreationFailed { bridge_name: String },

    #[error("Failed to create veth pair: {veth1} <-> {veth2}")]
    VethCreationFailed { veth1: String, veth2: String },

    #[error("Network interface not found: {interface}")]
    InterfaceNotFound { interface: String },

    #[error("IP address assignment failed: {ip} -> {interface}")]
    IpAssignmentFailed { ip: String, interface: String },

    #[error("Route configuration failed")]
    RouteConfigFailed,
}

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },

    #[error("Invalid configuration format: {reason}")]
    InvalidFormat { reason: String },

    #[error("Missing required configuration field: {field}")]
    MissingField { field: String },

    #[error("Invalid configuration value for field '{field}': {value}")]
    InvalidValue { field: String, value: String },

    #[error("Configuration parsing failed: {reason}")]
    ParseError { reason: String },

    #[error("Configuration validation failed: {reason}")]
    ValidationFailed { reason: String },
}

/// User/Group mapping errors
#[derive(Error, Debug)]
pub enum UserMappingError {
    #[error("Failed to write UID map: {reason}")]
    UidMapFailed { reason: String },

    #[error("Failed to write GID map: {reason}")]
    GidMapFailed { reason: String },

    #[error("Invalid UID mapping: {mapping}")]
    InvalidUidMapping { mapping: String },

    #[error("Invalid GID mapping: {mapping}")]
    InvalidGidMapping { mapping: String },

    #[error("User not found: {user}")]
    UserNotFound { user: String },

    #[error("Group not found: {group}")]
    GroupNotFound { group: String },

    #[error("Insufficient privileges for user mapping")]
    InsufficientPrivileges,
}

/// Result type alias for libflux operations
pub type LibfluxResult<T> = Result<T, LibfluxError>;

/// Helper macro for creating container errors
#[macro_export]
macro_rules! container_error {
    ($variant:ident { $($key:ident: $value:expr),* }) => {
        LibfluxError::Container(ContainerError::$variant { $($key: $value.into()),* })
    };
}

/// Helper macro for creating namespace errors
#[macro_export]
macro_rules! namespace_error {
    ($variant:ident { $($key:ident: $value:expr),* }) => {
        LibfluxError::Namespace(NamespaceError::$variant { $($key: $value.into()),* })
    };
}

/// Helper macro for creating filesystem errors
#[macro_export]
macro_rules! fs_error {
    ($variant:ident { $($key:ident: $value:expr),* }) => {
        LibfluxError::Filesystem(FilesystemError::$variant { $($key: $value.into()),* })
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = ContainerError::NotFound {
            container_id: "test-container".to_string(),
        };
        let libflux_error = LibfluxError::Container(error);

        assert!(libflux_error
            .to_string()
            .contains("Container not found: test-container"));
    }

    #[test]
    fn test_error_conversion() {
        let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let libflux_error: LibfluxError = io_error.into();

        assert!(matches!(libflux_error, LibfluxError::Io(_)));
    }
}
