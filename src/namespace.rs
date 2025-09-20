use crate::error::*;
use nix::fcntl::{open, OFlag};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

// Manual setns implementation using libc
fn setns(fd: RawFd, nstype: i32) -> Result<(), nix::Error> {
    let result = unsafe { libc::setns(fd, nstype) };
    if result == 0 {
        Ok(())
    } else {
        Err(nix::Error::last())
    }
}

/// Represents different types of Linux namespaces
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NamespaceType {
    /// Process ID namespace
    Pid,
    /// Mount namespace
    Mount,
    /// Network namespace
    Network,
    /// IPC namespace
    Ipc,
    /// UTS namespace (hostname/domainname)
    Uts,
    /// User namespace
    User,
    /// Cgroup namespace
    Cgroup,
}

impl NamespaceType {
    /// Get the corresponding clone flag for this namespace type
    pub fn to_clone_flag(&self) -> CloneFlags {
        match self {
            NamespaceType::Pid => CloneFlags::CLONE_NEWPID,
            NamespaceType::Mount => CloneFlags::CLONE_NEWNS,
            NamespaceType::Network => CloneFlags::CLONE_NEWNET,
            NamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
            NamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
            NamespaceType::User => CloneFlags::CLONE_NEWUSER,
            NamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        }
    }

    /// Get the proc filesystem path for this namespace type
    pub fn proc_path(&self) -> &'static str {
        match self {
            NamespaceType::Pid => "ns/pid",
            NamespaceType::Mount => "ns/mnt",
            NamespaceType::Network => "ns/net",
            NamespaceType::Ipc => "ns/ipc",
            NamespaceType::Uts => "ns/uts",
            NamespaceType::User => "ns/user",
            NamespaceType::Cgroup => "ns/cgroup",
        }
    }

    /// Get all available namespace types
    pub fn all() -> Vec<NamespaceType> {
        vec![
            NamespaceType::Pid,
            NamespaceType::Mount,
            NamespaceType::Network,
            NamespaceType::Ipc,
            NamespaceType::Uts,
            NamespaceType::User,
            NamespaceType::Cgroup,
        ]
    }
}

impl std::fmt::Display for NamespaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NamespaceType::Pid => write!(f, "pid"),
            NamespaceType::Mount => write!(f, "mnt"),
            NamespaceType::Network => write!(f, "net"),
            NamespaceType::Ipc => write!(f, "ipc"),
            NamespaceType::Uts => write!(f, "uts"),
            NamespaceType::User => write!(f, "user"),
            NamespaceType::Cgroup => write!(f, "cgroup"),
        }
    }
}

/// Namespace file descriptor for joining existing namespaces
#[derive(Debug)]
pub struct NamespaceFd {
    pub namespace_type: NamespaceType,
    pub fd: RawFd,
    pub path: PathBuf,
}

impl NamespaceFd {
    /// Create a new namespace file descriptor
    pub fn new(namespace_type: NamespaceType, pid: Pid) -> LibfluxResult<Self> {
        let path = PathBuf::from(format!("/proc/{}/{}", pid, namespace_type.proc_path()));

        let fd = open(&path, OFlag::O_RDONLY, Mode::empty()).map_err(|_e| {
            NamespaceError::EnterFailed {
                namespace_type: namespace_type.to_string(),
            }
        })?;

        Ok(NamespaceFd {
            namespace_type,
            fd,
            path,
        })
    }

    /// Join this namespace
    pub fn enter(&self) -> LibfluxResult<()> {
        setns(self.fd, self.namespace_type.to_clone_flag().bits() as i32).map_err(|_| {
            NamespaceError::EnterFailed {
                namespace_type: self.namespace_type.to_string(),
            }
        })?;
        Ok(())
    }
}

impl Drop for NamespaceFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Configuration for namespace creation
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    /// Namespaces to create
    pub namespaces: Vec<NamespaceType>,
    /// Whether to share parent's network namespace
    pub share_net: bool,
    /// Whether to share parent's PID namespace
    pub share_pid: bool,
    /// Whether to share parent's IPC namespace
    pub share_ipc: bool,
    /// Custom namespace paths to join
    pub join_namespaces: HashMap<NamespaceType, PathBuf>,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        NamespaceConfig {
            namespaces: vec![
                NamespaceType::Pid,
                NamespaceType::Mount,
                NamespaceType::Network,
                NamespaceType::Ipc,
                NamespaceType::Uts,
            ],
            share_net: false,
            share_pid: false,
            share_ipc: false,
            join_namespaces: HashMap::new(),
        }
    }
}

/// Namespace manager for creating and managing Linux namespaces
pub struct NamespaceManager {
    config: NamespaceConfig,
    created_namespaces: Vec<NamespaceType>,
}

impl NamespaceManager {
    /// Create a new namespace manager
    pub fn new(config: NamespaceConfig) -> Self {
        NamespaceManager {
            config,
            created_namespaces: Vec::new(),
        }
    }

    /// Create namespaces according to configuration
    pub fn create_namespaces(&mut self) -> LibfluxResult<()> {
        // Filter out namespaces that should be shared
        let mut namespaces_to_create = self.config.namespaces.clone();

        if self.config.share_net {
            namespaces_to_create.retain(|ns| *ns != NamespaceType::Network);
        }
        if self.config.share_pid {
            namespaces_to_create.retain(|ns| *ns != NamespaceType::Pid);
        }
        if self.config.share_ipc {
            namespaces_to_create.retain(|ns| *ns != NamespaceType::Ipc);
        }

        // Remove namespaces that we're joining from existing paths
        for ns_type in self.config.join_namespaces.keys() {
            namespaces_to_create.retain(|ns| ns != ns_type);
        }

        // Build clone flags
        let mut clone_flags = CloneFlags::empty();
        for ns_type in &namespaces_to_create {
            clone_flags |= ns_type.to_clone_flag();
        }

        // Create new namespaces using unshare
        if !clone_flags.is_empty() {
            unshare(clone_flags).map_err(|_| NamespaceError::CreationFailed {
                namespace_type: "multiple".to_string(),
            })?;

            self.created_namespaces = namespaces_to_create;
        }

        // Join existing namespaces if specified
        for (ns_type, path) in &self.config.join_namespaces {
            self.join_namespace_by_path(ns_type.clone(), path)?;
        }

        Ok(())
    }

    /// Join an existing namespace by path
    pub fn join_namespace_by_path(&self, ns_type: NamespaceType, path: &Path) -> LibfluxResult<()> {
        let fd = open(path, OFlag::O_RDONLY, Mode::empty()).map_err(|_| {
            NamespaceError::EnterFailed {
                namespace_type: ns_type.to_string(),
            }
        })?;

        let result = setns(fd, ns_type.to_clone_flag().bits() as i32);

        unsafe {
            libc::close(fd);
        }

        result.map_err(|_| NamespaceError::EnterFailed {
            namespace_type: ns_type.to_string(),
        })?;

        Ok(())
    }

    /// Join an existing namespace by PID
    pub fn join_namespace_by_pid(&self, ns_type: NamespaceType, pid: Pid) -> LibfluxResult<()> {
        let path = PathBuf::from(format!("/proc/{}/{}", pid, ns_type.proc_path()));
        self.join_namespace_by_path(ns_type, &path)
    }

    /// Get the list of created namespaces
    pub fn created_namespaces(&self) -> &[NamespaceType] {
        &self.created_namespaces
    }

    /// Check if a namespace was created
    pub fn has_namespace(&self, ns_type: &NamespaceType) -> bool {
        self.created_namespaces.contains(ns_type)
    }

    /// Get namespace file descriptor for current process
    pub fn get_namespace_fd(&self, ns_type: NamespaceType) -> LibfluxResult<NamespaceFd> {
        NamespaceFd::new(ns_type, nix::unistd::getpid())
    }
}

/// Execute a function in a new set of namespaces
pub fn with_namespaces<F, R>(config: NamespaceConfig, f: F) -> LibfluxResult<R>
where
    F: FnOnce() -> LibfluxResult<R>,
{
    let mut manager = NamespaceManager::new(config);
    manager.create_namespaces()?;
    f()
}

/// Fork and execute a function in new namespaces (parent perspective)
pub fn fork_with_namespaces<F>(config: NamespaceConfig, child_fn: F) -> LibfluxResult<Pid>
where
    F: FnOnce() -> LibfluxResult<()>,
{
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent process - return child PID
            Ok(child)
        }
        Ok(ForkResult::Child) => {
            // Child process - setup namespaces and execute function
            let mut manager = NamespaceManager::new(config);
            if let Err(e) = manager.create_namespaces() {
                eprintln!("Failed to create namespaces: {}", e);
                std::process::exit(1);
            }

            if let Err(e) = child_fn() {
                eprintln!("Child function failed: {}", e);
                std::process::exit(1);
            }

            std::process::exit(0);
        }
        Err(e) => Err(LibfluxError::System(e)),
    }
}

/// Wait for a child process and return its exit status
pub fn wait_for_child(child_pid: Pid) -> LibfluxResult<i32> {
    match waitpid(child_pid, None) {
        Ok(WaitStatus::Exited(_, exit_code)) => Ok(exit_code),
        Ok(WaitStatus::Signaled(_, signal, _)) => Err(LibfluxError::InvalidArgument(format!(
            "Child process killed by signal: {:?}",
            signal
        ))),
        Ok(status) => Err(LibfluxError::InvalidArgument(format!(
            "Unexpected child status: {:?}",
            status
        ))),
        Err(e) => Err(LibfluxError::System(e)),
    }
}

/// Check if a namespace type is supported on the current system
pub fn is_namespace_supported(ns_type: &NamespaceType) -> bool {
    let path = format!("/proc/self/{}", ns_type.proc_path());
    Path::new(&path).exists()
}

/// Get information about current process namespaces
pub fn get_namespace_info() -> LibfluxResult<HashMap<NamespaceType, String>> {
    let mut info = HashMap::new();

    for ns_type in NamespaceType::all() {
        let path = format!("/proc/self/{}", ns_type.proc_path());
        if let Ok(link) = std::fs::read_link(&path) {
            if let Some(ns_id) = link
                .to_string_lossy()
                .strip_prefix(&format!("{}:[", ns_type))
            {
                if let Some(ns_id) = ns_id.strip_suffix(']') {
                    info.insert(ns_type, ns_id.to_string());
                }
            }
        }
    }

    Ok(info)
}

/// Get namespace ID for a specific namespace type
pub fn get_namespace_id(ns_type: &NamespaceType) -> LibfluxResult<String> {
    let path = format!("/proc/self/{}", ns_type.proc_path());
    let link = std::fs::read_link(&path).map_err(|_| NamespaceError::NotSupported {
        namespace_type: ns_type.to_string(),
    })?;

    let link_str = link.to_string_lossy();
    if let Some(ns_id) = link_str.strip_prefix(&format!("{}:[", ns_type)) {
        if let Some(ns_id) = ns_id.strip_suffix(']') {
            return Ok(ns_id.to_string());
        }
    }

    Err(NamespaceError::InvalidFd.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_type_display() {
        assert_eq!(NamespaceType::Pid.to_string(), "pid");
        assert_eq!(NamespaceType::Mount.to_string(), "mnt");
        assert_eq!(NamespaceType::Network.to_string(), "net");
    }

    #[test]
    fn test_namespace_type_proc_path() {
        assert_eq!(NamespaceType::Pid.proc_path(), "ns/pid");
        assert_eq!(NamespaceType::Mount.proc_path(), "ns/mnt");
        assert_eq!(NamespaceType::Network.proc_path(), "ns/net");
    }

    #[test]
    fn test_namespace_type_clone_flag() {
        assert_eq!(NamespaceType::Pid.to_clone_flag(), CloneFlags::CLONE_NEWPID);
        assert_eq!(
            NamespaceType::Mount.to_clone_flag(),
            CloneFlags::CLONE_NEWNS
        );
        assert_eq!(
            NamespaceType::Network.to_clone_flag(),
            CloneFlags::CLONE_NEWNET
        );
    }

    #[test]
    fn test_namespace_config_default() {
        let config = NamespaceConfig::default();
        assert!(config.namespaces.contains(&NamespaceType::Pid));
        assert!(config.namespaces.contains(&NamespaceType::Mount));
        assert!(!config.share_net);
        assert!(!config.share_pid);
    }

    #[test]
    fn test_namespace_support_check() {
        // These should be available on most modern Linux systems
        assert!(is_namespace_supported(&NamespaceType::Pid));
        assert!(is_namespace_supported(&NamespaceType::Mount));
        assert!(is_namespace_supported(&NamespaceType::Network));
    }

    #[test]
    fn test_get_namespace_info() {
        let info = get_namespace_info().unwrap();
        assert!(!info.is_empty());

        // Should have at least PID namespace info
        assert!(info.contains_key(&NamespaceType::Pid));
    }
}
