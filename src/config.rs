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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::NamespaceType;

    fn sample_config() -> ContainerConfig {
        let mut env = HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        ContainerConfig::new(
            "web".to_string(),
            "alpine:latest".to_string(),
            vec!["/bin/sh".to_string(), "-c".to_string(), "echo hi".to_string()],
            Some(PathBuf::from("/srv")),
            env,
            PathBuf::from("/tmp/rootfs"),
            vec![NamespaceType::Pid, NamespaceType::Mount],
            true,
            Some("web-host".to_string()),
            Vec::new(),
            ResourceLimits::default(),
            None,
            NetworkConfig::default(),
        )
    }

    #[test]
    fn new_maps_arguments_to_fields() {
        let config = sample_config();

        assert_eq!(config.metadata.name, "web");
        assert_eq!(config.metadata.image, "alpine:latest");
        assert!(config.metadata.labels.is_empty());
        assert!(config.metadata.annotations.is_empty());

        assert_eq!(config.runtime.command, vec!["/bin/sh", "-c", "echo hi"]);
        assert_eq!(config.runtime.working_dir, Some(PathBuf::from("/srv")));
        assert_eq!(config.runtime.rootfs, PathBuf::from("/tmp/rootfs"));
        assert_eq!(config.runtime.namespaces.len(), 2);
        assert!(config.runtime.privileged);
        assert_eq!(config.runtime.hostname.as_deref(), Some("web-host"));
        assert!(config.runtime.user.is_none());
        assert!(!config.runtime.readonly);

        assert_eq!(config.environment.get("FOO").map(String::as_str), Some("bar"));
        assert!(config.user_mapping.is_none());
        assert!(config.mounts.is_empty());
    }

    #[test]
    fn new_defaults_terminal_to_all_enabled() {
        let config = sample_config();
        let term = &config.runtime.terminal;
        assert!(term.tty && term.stdin && term.stdout && term.stderr);
    }

    #[test]
    fn terminal_config_default_enables_all_streams() {
        let term = TerminalConfig::default();
        assert!(term.tty);
        assert!(term.stdin);
        assert!(term.stdout);
        assert!(term.stderr);
    }

    #[test]
    fn config_survives_json_round_trip() {
        let config = sample_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ContainerConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.metadata.name, config.metadata.name);
        assert_eq!(restored.runtime.command, config.runtime.command);
        assert_eq!(restored.runtime.namespaces, config.runtime.namespaces);
        assert_eq!(restored.environment, config.environment);
    }
}
