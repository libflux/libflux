use crate::cgroups::ResourceLimits;
use crate::fs::MountType;
use crate::namespace::NamespaceType;
use crate::net::NetworkConfig;
use crate::user::UserMapping;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main container configuration (CLI-only, no file loading)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Container metadata
    pub metadata: ContainerMetadata,
    /// Runtime configuration
    pub runtime: RuntimeConfig,
    /// Resource limits
    pub resources: ResourceLimits,
    /// Network configuration
    pub network: NetworkConfig,
    /// Filesystem mounts
    pub mounts: Vec<MountType>,
    /// User and group mappings
    pub user_mapping: Option<UserMapping>,
    /// Environment variables
    pub environment: HashMap<String, String>,
}

impl ContainerConfig {
    /// Create a new config with CLI arguments
    pub fn new(
        name: String,
        image: String,
        command: Vec<String>,
        working_dir: Option<PathBuf>,
        environment: HashMap<String, String>,
        rootfs: PathBuf,
        namespaces: Vec<NamespaceType>,
        privileged: bool,
        hostname: Option<String>,
        mounts: Vec<MountType>,
        resources: ResourceLimits,
        user_mapping: Option<UserMapping>,
        network: NetworkConfig,
    ) -> Self {
        ContainerConfig {
            metadata: ContainerMetadata {
                name,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                image,
            },
            runtime: RuntimeConfig {
                command,
                working_dir,
                user: None,
                rootfs,
                namespaces,
                readonly: false,
                privileged,
                hostname,
                terminal: TerminalConfig::default(),
            },
            resources,
            mounts,
            network,
            user_mapping,
            environment,
        }
    }
}

/// Container metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMetadata {
    /// Container name
    pub name: String,
    /// Container image or rootfs path
    pub image: String,
    /// Container labels
    pub labels: HashMap<String, String>,
    /// Container annotations
    pub annotations: HashMap<String, String>,
}

/// Runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Command to execute
    pub command: Vec<String>,
    /// Working directory
    pub working_dir: Option<PathBuf>,
    /// User to run as
    pub user: Option<String>,
    /// Container rootfs path
    pub rootfs: PathBuf,
    /// Namespaces to enable
    pub namespaces: Vec<NamespaceType>,
    /// Read-only rootfs
    pub readonly: bool,
    /// Privileged container
    pub privileged: bool,
    /// Container hostname
    pub hostname: Option<String>,
    /// Terminal configuration
    pub terminal: TerminalConfig,
}

/// Terminal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalConfig {
    /// Allocate TTY
    pub tty: bool,
    /// Keep stdin open
    pub stdin: bool,
    /// Capture stdout
    pub stdout: bool,
    /// Capture stderr
    pub stderr: bool,
}

impl Default for TerminalConfig {
    fn default() -> Self {
        TerminalConfig {
            tty: true,
            stdin: true,
            stdout: true,
            stderr: true,
        }
    }
}
