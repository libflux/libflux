use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use crate::cgroups::{CgroupManager, ResourceStats};
use crate::config::ContainerConfig;
use crate::error::*;
use crate::fs::{create_basic_rootfs, FilesystemManager};
use crate::logging::{ContainerLogger, LogSource, OutputCapture};
use crate::namespace::{fork_with_namespaces, wait_for_child, NamespaceConfig, NamespaceManager};
use crate::net::NetworkManager;
use crate::user::UserMappingManager;
use crate::utils::{ensure_dir_exists, generate_container_id, get_runtime_dir};

/// Container state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerState {
    /// Container is being created
    Creating,
    /// Container is created but not started
    Created,
    /// Container is running
    Running,
    /// Container is paused
    Paused,
    /// Container has stopped
    Stopped,
    /// Container has exited with error
    Error,
}

impl std::fmt::Display for ContainerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerState::Creating => write!(f, "creating"),
            ContainerState::Created => write!(f, "created"),
            ContainerState::Running => write!(f, "running"),
            ContainerState::Paused => write!(f, "paused"),
            ContainerState::Stopped => write!(f, "stopped"),
            ContainerState::Error => write!(f, "error"),
        }
    }
}

/// Container metadata and runtime information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Container ID
    pub id: String,
    /// Container name
    pub name: String,
    /// Container state
    pub state: ContainerState,
    /// Container PID (if running)
    pub pid: Option<u32>,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Start timestamp
    pub started_at: Option<SystemTime>,
    /// Exit code (if stopped)
    pub exit_code: Option<i32>,
    /// Container image/rootfs
    pub image: String,
    /// Command being executed
    pub command: Vec<String>,
    /// Container configuration
    pub config: ContainerConfig,
}

/// Main container struct
pub struct Container {
    /// Container information
    info: Arc<RwLock<ContainerInfo>>,
    /// Container runtime directory
    runtime_dir: PathBuf,
    /// Container data directory
    data_dir: PathBuf,
    /// Container root filesystem path
    rootfs_path: PathBuf,
    /// Namespace manager
    namespace_manager: Option<NamespaceManager>,
    /// Filesystem manager
    fs_manager: Option<FilesystemManager>,
    /// Cgroup manager
    cgroup_manager: Option<CgroupManager>,
    /// Network manager
    network_manager: Option<NetworkManager>,
    /// User mapping manager
    user_mapping_manager: Option<UserMappingManager>,
    /// Container logger
    logger: Option<ContainerLogger>,
    /// Output capture
    output_capture: Option<OutputCapture>,
    /// Child process handle
    child_process: Arc<Mutex<Option<Child>>>,
    /// Container PID
    container_pid: Arc<Mutex<Option<Pid>>>,
}

impl Container {
    /// Create a new container
    pub fn new(config: ContainerConfig) -> LibfluxResult<Self> {
        let id = generate_container_id();
        let name = config.metadata.name.clone();

        let runtime_dir = get_runtime_dir()?.join(&id);
        let data_dir = runtime_dir.join("data");
        let rootfs_path = if config.runtime.rootfs == PathBuf::from("/") {
            data_dir.join("rootfs")
        } else {
            config.runtime.rootfs.clone()
        };

        // Ensure directories exist
        ensure_dir_exists(&runtime_dir)?;
        ensure_dir_exists(&data_dir)?;

        let info = Arc::new(RwLock::new(ContainerInfo {
            id: id.clone(),
            name,
            state: ContainerState::Creating,
            pid: None,
            created_at: SystemTime::now(),
            started_at: None,
            exit_code: None,
            image: config.metadata.image.clone(),
            command: config.runtime.command.clone(),
            config,
        }));

        Ok(Container {
            info,
            runtime_dir,
            data_dir,
            rootfs_path,
            namespace_manager: None,
            fs_manager: None,
            cgroup_manager: None,
            network_manager: None,
            user_mapping_manager: None,
            logger: None,
            output_capture: None,
            child_process: Arc::new(Mutex::new(None)),
            container_pid: Arc::new(Mutex::new(None)),
        })
    }

    /// Get container ID
    pub async fn id(&self) -> String {
        self.info.read().await.id.clone()
    }

    /// Get container name
    pub async fn name(&self) -> String {
        self.info.read().await.name.clone()
    }

    /// Get container state
    pub async fn state(&self) -> ContainerState {
        self.info.read().await.state.clone()
    }

    /// Get container information
    pub async fn info(&self) -> ContainerInfo {
        self.info.read().await.clone()
    }

    /// Initialize the container (create all managers)
    pub async fn create(&mut self) -> LibfluxResult<()> {
        let config = {
            let info = self.info.read().await;
            info.config.clone()
        };

        // Update state
        self.set_state(ContainerState::Creating).await;

        // Create rootfs if needed
        if config.runtime.rootfs == PathBuf::from("/") {
            create_basic_rootfs(&self.rootfs_path)?;
        }

        // Initialize cgroup manager
        let mut cgroup_manager = CgroupManager::new(self.id().await)?;
        cgroup_manager.create()?;
        cgroup_manager.apply_limits(&config.resources)?;
        self.cgroup_manager = Some(cgroup_manager);

        // Initialize filesystem manager
        let mut fs_manager = FilesystemManager::new(self.rootfs_path.clone());
        fs_manager.setup_rootfs(&config.runtime.rootfs)?;

        // Add configured mounts
        for mount in &config.mounts {
            fs_manager.add_mount(mount.clone());
        }

        self.fs_manager = Some(fs_manager);

        // Initialize network manager
        let network_manager = NetworkManager::new(self.id().await, config.network);
        self.network_manager = Some(network_manager);

        // Initialize logger
        let log_dir = self.runtime_dir.join("logs");
        ensure_dir_exists(&log_dir)?;
        let logger = ContainerLogger::new(self.id().await, &log_dir, true)?;
        logger.info("Container created", LogSource::Runtime)?;
        self.logger = Some(logger);

        // Initialize output capture
        let output_capture = OutputCapture::new(self.id().await, &log_dir, true)?;
        self.output_capture = Some(output_capture);

        // Update state
        self.set_state(ContainerState::Created).await;

        Ok(())
    }

    /// Start the container
    pub async fn start(&mut self) -> LibfluxResult<()> {
        let state = self.state().await;
        if state != ContainerState::Created && state != ContainerState::Stopped {
            return Err(ContainerError::InvalidState {
                expected: "created or stopped".to_string(),
                actual: state.to_string(),
            }
            .into());
        }

        let config = {
            let info = self.info.read().await;
            info.config.clone()
        };

        self.set_state(ContainerState::Running).await;
        self.set_started_at(Some(SystemTime::now())).await;

        if let Some(logger) = &self.logger {
            logger.info("Starting container", LogSource::Runtime)?;
        }

        // Setup networking if enabled
        if let Some(network_manager) = self.network_manager.as_mut() {
            if network_manager.config.mode != crate::net::NetworkMode::None {
                network_manager.setup()?;
            }
        }

        // Create namespace configuration
        let ns_config = NamespaceConfig {
            namespaces: config.runtime.namespaces.clone(),
            share_net: false,
            share_pid: false,
            share_ipc: false,
            join_namespaces: HashMap::new(),
        };

        // Fork and start container process
        let container_id = self.id().await;
        let runtime_dir = self.runtime_dir.clone();
        let rootfs_path = self.rootfs_path.clone();
        let command = config.runtime.command.clone();
        let working_dir = config.runtime.working_dir.clone();
        let environment = config.environment.clone();

        let child_pid = fork_with_namespaces(ns_config, move || {
            // This runs in the child process (container)
            Self::container_main(
                container_id,
                runtime_dir,
                rootfs_path,
                command,
                working_dir,
                environment,
            )
        })?;

        // Store the container PID
        {
            let mut pid_lock = self.container_pid.lock().unwrap();
            *pid_lock = Some(child_pid);
        }

        // Set PID in container info
        self.set_pid(Some(child_pid.as_raw() as u32)).await;

        // Give the child process a moment to initialize before joining cgroup
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Join cgroup (non-fatal if it fails)
        if let Some(cgroup_manager) = &self.cgroup_manager {
            if let Err(e) = cgroup_manager.join_pid(child_pid) {
                eprintln!("[WARN] Failed to join cgroup: {}", e);
                // Continue execution - cgroup joining failure shouldn't stop the container
            }
        }

        // Setup user mapping if configured
        if let Some(user_mapping) = &config.user_mapping {
            let mut mapping_manager = UserMappingManager::new(child_pid, user_mapping.clone());
            mapping_manager.apply()?;
            self.user_mapping_manager = Some(mapping_manager);
        }

        // Start monitoring thread
        self.start_monitoring_thread().await;

        if let Some(logger) = &self.logger {
            logger.info(
                &format!("Container started with PID {}", child_pid),
                LogSource::Runtime,
            )?;
        }

        Ok(())
    }

    /// Container main function (runs inside the container)
    fn container_main(
        container_id: String,
        _runtime_dir: PathBuf,
        rootfs_path: PathBuf,
        command: Vec<String>,
        working_dir: Option<PathBuf>,
        environment: HashMap<String, String>,
    ) -> LibfluxResult<()> {
        // Setup filesystem mounts
        let mut fs_manager = FilesystemManager::new(rootfs_path.clone());
        fs_manager.setup_standard_mounts()?;

        // Change root to container rootfs
        if rootfs_path != PathBuf::from("/") {
            std::env::set_current_dir(&rootfs_path).map_err(|e| {
                LibfluxError::InvalidArgument(format!("Failed to change to rootfs: {}", e))
            })?;

            nix::unistd::chroot(&rootfs_path).map_err(|e| LibfluxError::System(e))?;

            std::env::set_current_dir("/").map_err(|e| {
                LibfluxError::InvalidArgument(format!("Failed to change to /: {}", e))
            })?;
        }

        // Set working directory
        if let Some(work_dir) = working_dir {
            std::env::set_current_dir(&work_dir).map_err(|e| {
                LibfluxError::InvalidArgument(format!("Failed to change working directory: {}", e))
            })?;
        }

        // Set environment variables
        for (key, value) in environment {
            std::env::set_var(key, value);
        }

        // Setup hostname
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            let _ = nix::unistd::sethostname(&hostname);
        } else {
            let _ = nix::unistd::sethostname(&container_id);
        }

        // Execute the main command
        if command.is_empty() {
            return Err(LibfluxError::InvalidArgument(
                "No command specified".to_string(),
            ));
        }

        let mut cmd = Command::new(&command[0]);
        if command.len() > 1 {
            cmd.args(&command[1..]);
        }

        let mut child = cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                LibfluxError::InvalidArgument(format!("Failed to execute command: {}", e))
            })?;

        let exit_status = child.wait().map_err(|e| {
            LibfluxError::InvalidArgument(format!("Failed to wait for command: {}", e))
        })?;

        // Exit with the same code as the main process
        std::process::exit(exit_status.code().unwrap_or(1));
    }

    /// Start monitoring thread for the container
    async fn start_monitoring_thread(&self) {
        let container_pid = self.container_pid.clone();
        let info = self.info.clone();
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let pid = {
                let guard = container_pid.lock().unwrap();
                *guard
            };

            if let Some(pid) = pid {
                match wait_for_child(pid) {
                    Ok(exit_code) => {
                        // Update container state
                        {
                            let mut info_lock = info.write().await;
                            info_lock.state = ContainerState::Stopped;
                            info_lock.exit_code = Some(exit_code);
                            info_lock.pid = None;
                        }

                        if let Some(logger) = logger {
                            let _ = logger.info(
                                &format!("Container exited with code {}", exit_code),
                                LogSource::Runtime,
                            );
                        }
                    }
                    Err(e) => {
                        // Update container state to error
                        {
                            let mut info_lock = info.write().await;
                            info_lock.state = ContainerState::Error;
                            info_lock.pid = None;
                        }

                        if let Some(logger) = logger {
                            let _ = logger.error(
                                &format!("Container monitoring error: {}", e),
                                LogSource::Runtime,
                            );
                        }
                    }
                }
            }
        });
    }

    /// Stop the container
    pub async fn stop(&mut self, timeout: Option<Duration>) -> LibfluxResult<()> {
        let state = self.state().await;
        if state != ContainerState::Running && state != ContainerState::Paused {
            return Err(ContainerError::NotRunning {
                container_id: self.id().await,
            }
            .into());
        }

        if let Some(logger) = &self.logger {
            logger.info("Stopping container", LogSource::Runtime)?;
        }

        let pid = {
            let pid_lock = self.container_pid.lock().unwrap();
            *pid_lock
        };

        if let Some(pid) = pid {
            // Send SIGTERM first
            signal::kill(pid, Signal::SIGTERM).map_err(|e| LibfluxError::System(e))?;

            // Wait for timeout
            let timeout = timeout.unwrap_or(Duration::from_secs(10));
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < timeout {
                if self.state().await == ContainerState::Stopped {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            // If still running, send SIGKILL
            if self.state().await == ContainerState::Running {
                signal::kill(pid, Signal::SIGKILL).map_err(|e| LibfluxError::System(e))?;

                if let Some(logger) = &self.logger {
                    logger.warn("Forcefully killed container", LogSource::Runtime)?;
                }
            }
        }

        Ok(())
    }

    /// Pause the container
    pub async fn pause(&mut self) -> LibfluxResult<()> {
        let state = self.state().await;
        if state != ContainerState::Running {
            return Err(ContainerError::InvalidState {
                expected: "running".to_string(),
                actual: state.to_string(),
            }
            .into());
        }

        let pid = {
            let pid_lock = self.container_pid.lock().unwrap();
            *pid_lock
        };

        if let Some(pid) = pid {
            signal::kill(pid, Signal::SIGSTOP).map_err(|e| LibfluxError::System(e))?;

            self.set_state(ContainerState::Paused).await;

            if let Some(logger) = &self.logger {
                logger.info("Container paused", LogSource::Runtime)?;
            }
        }

        Ok(())
    }

    /// Resume the container
    pub async fn resume(&mut self) -> LibfluxResult<()> {
        let state = self.state().await;
        if state != ContainerState::Paused {
            return Err(ContainerError::InvalidState {
                expected: "paused".to_string(),
                actual: state.to_string(),
            }
            .into());
        }

        let pid = {
            let pid_lock = self.container_pid.lock().unwrap();
            *pid_lock
        };

        if let Some(pid) = pid {
            signal::kill(pid, Signal::SIGCONT).map_err(|e| LibfluxError::System(e))?;

            self.set_state(ContainerState::Running).await;

            if let Some(logger) = &self.logger {
                logger.info("Container resumed", LogSource::Runtime)?;
            }
        }

        Ok(())
    }

    /// Get container resource statistics
    pub async fn stats(&mut self) -> LibfluxResult<ResourceStats> {
        if let Some(cgroup_manager) = &mut self.cgroup_manager {
            cgroup_manager.get_stats()
        } else {
            Err(ContainerError::NotRunning {
                container_id: self.id().await,
            }
            .into())
        }
    }

    /// Execute a command inside the running container
    pub async fn exec(&self, _command: Vec<String>) -> LibfluxResult<i32> {
        let state = self.state().await;
        if state != ContainerState::Running {
            return Err(ContainerError::NotRunning {
                container_id: self.id().await,
            }
            .into());
        }

        // This is a simplified implementation
        // In practice, you'd need to enter the container's namespaces and execute the command
        Err(LibfluxError::NotSupported(
            "exec not yet implemented".to_string(),
        ))
    }

    /// Cleanup container resources
    pub async fn cleanup(&mut self) -> LibfluxResult<()> {
        if let Some(logger) = &self.logger {
            logger.info("Cleaning up container", LogSource::Runtime)?;
        }

        // Stop container if running
        let state = self.state().await;
        if state == ContainerState::Running || state == ContainerState::Paused {
            self.stop(Some(Duration::from_secs(5))).await?;
        }

        // Cleanup filesystem
        if let Some(mut fs_manager) = self.fs_manager.take() {
            fs_manager.cleanup()?;
        }

        // Cleanup network
        if let Some(mut network_manager) = self.network_manager.take() {
            network_manager.cleanup()?;
        }

        // Cleanup cgroup
        if let Some(cgroup_manager) = self.cgroup_manager.take() {
            cgroup_manager.destroy()?;
        }

        if let Some(logger) = &self.logger {
            logger.info("Container cleanup completed", LogSource::Runtime)?;
        }

        Ok(())
    }

    /// Helper methods for updating container state

    async fn set_state(&self, state: ContainerState) {
        let mut info = self.info.write().await;
        info.state = state;
    }

    async fn set_pid(&self, pid: Option<u32>) {
        let mut info = self.info.write().await;
        info.pid = pid;
    }

    async fn set_started_at(&self, started_at: Option<SystemTime>) {
        let mut info = self.info.write().await;
        info.started_at = started_at;
    }

    /// Get the container runtime directory
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Get the container rootfs path
    pub fn rootfs_path(&self) -> &Path {
        &self.rootfs_path
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // Attempt cleanup on drop, but don't panic if it fails
        let _ = futures::executor::block_on(self.cleanup());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroups::ResourceLimits;
    use crate::namespace::NamespaceType;
    use crate::net::NetworkConfig;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_container_creation() {
        let config = ContainerConfig::new(
            "test-container".to_string(),
            "test:latest".to_string(),
            vec!["echo".to_string(), "hello".to_string()],
            None,
            HashMap::new(),
            PathBuf::from("test:latest"),
            vec![NamespaceType::Pid],
            false,
            None,
            Vec::new(),
            ResourceLimits::default(),
            None,
            NetworkConfig::default(),
        );

        let container = Container::new(config).unwrap();
        assert_eq!(container.name().await, "test-container");
        assert_eq!(container.state().await, ContainerState::Creating);
    }

    #[tokio::test]
    async fn test_container_state_transitions() {
        let config = ContainerConfig::new(
            "test-state".to_string(),
            "test:latest".to_string(),
            vec!["true".to_string()],
            None,
            HashMap::new(),
            PathBuf::from("test:latest"),
            vec![NamespaceType::Pid],
            false,
            None,
            Vec::new(),
            ResourceLimits::default(),
            None,
            NetworkConfig::default(),
        );

        let container = Container::new(config).unwrap();
        assert_eq!(container.state().await, ContainerState::Creating);

        // Note: This test would need more setup to actually work
        // including proper rootfs, permissions, etc.
    }

    #[test]
    fn test_container_state_display() {
        assert_eq!(ContainerState::Creating.to_string(), "creating");
        assert_eq!(ContainerState::Running.to_string(), "running");
        assert_eq!(ContainerState::Stopped.to_string(), "stopped");
    }
}
