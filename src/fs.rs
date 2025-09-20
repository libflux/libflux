use crate::error::*;
use crate::utils::ensure_dir_exists;
use nix::mount::{mount, umount, MsFlags};
use nix::sys::stat::{mknod, Mode, SFlag};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Mount options for different filesystem types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountOptions {
    #[serde(skip, default = "default_flags")] // MsFlags doesn't implement Serialize/Deserialize
    pub flags: MsFlags,
    pub data: Option<String>,
}

fn default_flags() -> MsFlags {
    MsFlags::MS_NODEV | MsFlags::MS_NOSUID
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            flags: MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            data: None,
        }
    }
}

/// Different types of mounts supported by libflux
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MountType {
    /// Bind mount - bind a host directory/file to container
    Bind {
        source: PathBuf,
        target: PathBuf,
        readonly: bool,
    },
    /// Tmpfs mount - temporary filesystem in memory
    Tmpfs {
        target: PathBuf,
        size: Option<String>, // e.g., "100M", "1G"
        mode: Option<u32>,
    },
    /// Overlay mount - overlay filesystem with lower, upper, and work directories
    Overlay {
        target: PathBuf,
        lower: Vec<PathBuf>,
        upper: PathBuf,
        work: PathBuf,
    },
    /// Proc mount - /proc filesystem
    Proc { target: PathBuf },
    /// Sys mount - /sys filesystem
    Sys { target: PathBuf },
    /// Dev mount - /dev filesystem
    Dev { target: PathBuf },
    /// DevPts mount - /dev/pts filesystem
    DevPts { target: PathBuf },
    /// Custom mount with specific filesystem type
    Custom {
        source: Option<PathBuf>,
        target: PathBuf,
        fstype: String,
        options: MountOptions,
    },
}

impl MountType {
    /// Get the target path for this mount
    pub fn target(&self) -> &Path {
        match self {
            MountType::Bind { target, .. } => target,
            MountType::Tmpfs { target, .. } => target,
            MountType::Overlay { target, .. } => target,
            MountType::Proc { target } => target,
            MountType::Sys { target } => target,
            MountType::Dev { target } => target,
            MountType::DevPts { target } => target,
            MountType::Custom { target, .. } => target,
        }
    }

    /// Check if this is a readonly mount
    pub fn is_readonly(&self) -> bool {
        match self {
            MountType::Bind { readonly, .. } => *readonly,
            MountType::Proc { .. } | MountType::Sys { .. } => true,
            _ => false,
        }
    }
}

/// Filesystem manager for handling container mounts
pub struct FilesystemManager {
    container_root: PathBuf,
    mounts: Vec<MountType>,
    mounted_paths: Vec<PathBuf>,
}

impl FilesystemManager {
    /// Create a new filesystem manager
    pub fn new(container_root: PathBuf) -> Self {
        FilesystemManager {
            container_root,
            mounts: Vec::new(),
            mounted_paths: Vec::new(),
        }
    }

    /// Add a mount to be created
    pub fn add_mount(&mut self, mount: MountType) {
        self.mounts.push(mount);
    }

    /// Set up the container root filesystem
    pub fn setup_rootfs(&mut self, rootfs_path: &Path) -> LibfluxResult<()> {
        // Create container root if it doesn't exist
        ensure_dir_exists(&self.container_root)?;

        // If rootfs_path is provided, bind mount it as the container root
        if rootfs_path != self.container_root {
            self.bind_mount(rootfs_path, &self.container_root, false)?;
        }

        Ok(())
    }

    /// Setup all configured mounts
    pub fn setup_mounts(&mut self) -> LibfluxResult<()> {
        for mount in self.mounts.clone() {
            self.create_mount(&mount)?;
        }
        Ok(())
    }

    /// Create a specific mount
    pub fn create_mount(&mut self, mount: &MountType) -> LibfluxResult<()> {
        let target = self.resolve_container_path(mount.target());

        // Ensure target directory exists
        if let Some(parent) = target.parent() {
            ensure_dir_exists(parent)?;
        }

        match mount {
            MountType::Bind {
                source, readonly, ..
            } => {
                self.bind_mount(source, &target, *readonly)?;
            }
            MountType::Tmpfs { size, mode, .. } => {
                self.tmpfs_mount(&target, size.as_deref(), *mode)?;
            }
            MountType::Overlay {
                lower, upper, work, ..
            } => {
                self.overlay_mount(&target, lower, upper, work)?;
            }
            MountType::Proc { .. } => {
                self.proc_mount(&target)?;
            }
            MountType::Sys { .. } => {
                self.sys_mount(&target)?;
            }
            MountType::Dev { .. } => {
                self.dev_mount(&target)?;
            }
            MountType::DevPts { .. } => {
                self.devpts_mount(&target)?;
            }
            MountType::Custom {
                source,
                fstype,
                options,
                ..
            } => {
                self.custom_mount(source.as_deref(), &target, fstype, options)?;
            }
        }

        self.mounted_paths.push(target);
        Ok(())
    }

    /// Create a bind mount
    pub fn bind_mount(&self, source: &Path, target: &Path, readonly: bool) -> LibfluxResult<()> {
        // Validate source exists
        if !source.exists() {
            return Err(FilesystemError::PathNotFound {
                path: source.to_string_lossy().to_string(),
            }
            .into());
        }

        // Create target if it doesn't exist
        if source.is_dir() {
            ensure_dir_exists(target)?;
        } else {
            if let Some(parent) = target.parent() {
                ensure_dir_exists(parent)?;
            }
            if !target.exists() {
                fs::File::create(target).map_err(|_| FilesystemError::DirectoryCreationFailed {
                    path: target.to_string_lossy().to_string(),
                })?;
            }
        }

        // Initial bind mount
        let mut flags = MsFlags::MS_BIND;
        mount(Some(source), target, None::<&str>, flags, None::<&str>).map_err(|_| {
            FilesystemError::BindMountFailed {
                mount_source: source.to_string_lossy().to_string(),
                target: target.to_string_lossy().to_string(),
            }
        })?;

        // Make readonly if requested
        if readonly {
            flags |= MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT;
            mount(None::<&Path>, target, None::<&str>, flags, None::<&str>).map_err(|_| {
                FilesystemError::BindMountFailed {
                    mount_source: source.to_string_lossy().to_string(),
                    target: target.to_string_lossy().to_string(),
                }
            })?;
        }

        Ok(())
    }

    /// Create a tmpfs mount
    pub fn tmpfs_mount(
        &self,
        target: &Path,
        size: Option<&str>,
        mode: Option<u32>,
    ) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;

        let mut options = Vec::new();
        if let Some(size) = size {
            options.push(format!("size={}", size));
        }
        if let Some(mode) = mode {
            options.push(format!("mode={:o}", mode));
        }

        let data = if options.is_empty() {
            None
        } else {
            Some(options.join(","))
        };

        mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            data.as_deref(),
        )
        .map_err(|_| FilesystemError::MountFailed {
            mount_source: "tmpfs".to_string(),
            target: target.to_string_lossy().to_string(),
        })?;

        Ok(())
    }

    /// Create an overlay mount
    pub fn overlay_mount(
        &self,
        target: &Path,
        lower: &[PathBuf],
        upper: &Path,
        work: &Path,
    ) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;
        ensure_dir_exists(upper)?;
        ensure_dir_exists(work)?;

        let lower_str = lower
            .iter()
            .map(|p| p.to_string_lossy())
            .collect::<Vec<_>>()
            .join(":");

        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower_str,
            upper.to_string_lossy(),
            work.to_string_lossy()
        );

        mount(
            Some("overlay"),
            target,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|_| FilesystemError::OverlayFailed)?;

        Ok(())
    }

    /// Create a proc mount
    pub fn proc_mount(&self, target: &Path) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;

        mount(
            Some("proc"),
            target,
            Some("proc"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|_| FilesystemError::MountFailed {
            mount_source: "proc".to_string(),
            target: target.to_string_lossy().to_string(),
        })?;

        Ok(())
    }

    /// Create a sys mount
    pub fn sys_mount(&self, target: &Path) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;

        mount(
            Some("sysfs"),
            target,
            Some("sysfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|_| FilesystemError::MountFailed {
            mount_source: "sysfs".to_string(),
            target: target.to_string_lossy().to_string(),
        })?;

        Ok(())
    }

    /// Create a dev mount
    pub fn dev_mount(&self, target: &Path) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;

        // Mount tmpfs for /dev
        mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
            Some("mode=755"),
        )
        .map_err(|_| FilesystemError::MountFailed {
            mount_source: "tmpfs".to_string(),
            target: target.to_string_lossy().to_string(),
        })?;

        // Create essential device nodes
        self.create_device_nodes(target)?;

        Ok(())
    }

    /// Create a devpts mount
    pub fn devpts_mount(&self, target: &Path) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;

        mount(
            Some("devpts"),
            target,
            Some("devpts"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
            Some("newinstance,ptmxmode=0666,mode=0620"),
        )
        .map_err(|_| FilesystemError::MountFailed {
            mount_source: "devpts".to_string(),
            target: target.to_string_lossy().to_string(),
        })?;

        Ok(())
    }

    /// Create a custom mount
    pub fn custom_mount(
        &self,
        source: Option<&Path>,
        target: &Path,
        fstype: &str,
        options: &MountOptions,
    ) -> LibfluxResult<()> {
        ensure_dir_exists(target)?;

        mount(
            source,
            target,
            Some(fstype),
            options.flags,
            options.data.as_deref(),
        )
        .map_err(|_| FilesystemError::MountFailed {
            mount_source: source
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| fstype.to_string()),
            target: target.to_string_lossy().to_string(),
        })?;

        Ok(())
    }

    /// Create essential device nodes in /dev
    fn create_device_nodes(&self, dev_path: &Path) -> LibfluxResult<()> {
        let devices = [
            ("null", SFlag::S_IFCHR, 1, 3, 0o666),
            ("zero", SFlag::S_IFCHR, 1, 5, 0o666),
            ("full", SFlag::S_IFCHR, 1, 7, 0o666),
            ("random", SFlag::S_IFCHR, 1, 8, 0o666),
            ("urandom", SFlag::S_IFCHR, 1, 9, 0o666),
            ("tty", SFlag::S_IFCHR, 5, 0, 0o666),
        ];

        for (name, flag, major, minor, mode) in devices.iter() {
            let device_path = dev_path.join(name);
            let dev = nix::sys::stat::makedev(*major, *minor);

            if let Err(_) = mknod(&device_path, *flag, Mode::from_bits_truncate(*mode), dev) {
                // If mknod fails, try to bind mount from host
                let host_device = PathBuf::from("/dev").join(name);
                if host_device.exists() {
                    if let Err(_) = fs::File::create(&device_path) {
                        continue;
                    }
                    let _ = self.bind_mount(&host_device, &device_path, false);
                }
            }
        }

        // Create symbolic links
        let links = [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ];

        for (link_name, target) in links.iter() {
            let link_path = dev_path.join(link_name);
            let _ = std::os::unix::fs::symlink(target, link_path);
        }

        Ok(())
    }

    /// Resolve a container path relative to the container root
    fn resolve_container_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            self.container_root
                .join(path.strip_prefix("/").unwrap_or(path))
        } else {
            self.container_root.join(path)
        }
    }

    /// Cleanup all mounts
    pub fn cleanup(&mut self) -> LibfluxResult<()> {
        // Unmount in reverse order
        for mount_path in self.mounted_paths.iter().rev() {
            if let Err(e) = umount(mount_path) {
                // Log the error but continue with cleanup
                eprintln!("Failed to unmount {}: {}", mount_path.display(), e);
            }
        }

        self.mounted_paths.clear();
        Ok(())
    }

    /// Get list of mounted paths
    pub fn mounted_paths(&self) -> &[PathBuf] {
        &self.mounted_paths
    }

    /// Create standard container mounts
    pub fn setup_standard_mounts(&mut self) -> LibfluxResult<()> {
        // Add standard mounts
        let standard_mounts = vec![
            MountType::Proc {
                target: PathBuf::from("/proc"),
            },
            MountType::Sys {
                target: PathBuf::from("/sys"),
            },
            MountType::Dev {
                target: PathBuf::from("/dev"),
            },
            MountType::DevPts {
                target: PathBuf::from("/dev/pts"),
            },
            MountType::Tmpfs {
                target: PathBuf::from("/tmp"),
                size: Some("100M".to_string()),
                mode: Some(0o1777),
            },
        ];

        for mount in standard_mounts {
            self.add_mount(mount);
        }

        self.setup_mounts()
    }
}

impl Drop for FilesystemManager {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Helper function to create a basic rootfs structure
pub fn create_basic_rootfs(rootfs_path: &Path) -> LibfluxResult<()> {
    let dirs = [
        "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root",
        "run", "sbin", "srv", "sys", "tmp", "usr", "var", "usr/bin", "usr/lib", "usr/sbin",
        "var/log", "var/tmp",
    ];

    for dir in dirs.iter() {
        let dir_path = rootfs_path.join(dir);
        ensure_dir_exists(&dir_path)?;
    }

    // Set correct permissions for /tmp
    let tmp_path = rootfs_path.join("tmp");
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o1777)).map_err(|_| {
        FilesystemError::DirectoryCreationFailed {
            path: tmp_path.to_string_lossy().to_string(),
        }
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mount_type_target() {
        let bind_mount = MountType::Bind {
            source: PathBuf::from("/host/path"),
            target: PathBuf::from("/container/path"),
            readonly: false,
        };

        assert_eq!(bind_mount.target(), Path::new("/container/path"));
    }

    #[test]
    fn test_mount_type_readonly() {
        let readonly_bind = MountType::Bind {
            source: PathBuf::from("/host/path"),
            target: PathBuf::from("/container/path"),
            readonly: true,
        };

        let readwrite_bind = MountType::Bind {
            source: PathBuf::from("/host/path"),
            target: PathBuf::from("/container/path"),
            readonly: false,
        };

        assert!(readonly_bind.is_readonly());
        assert!(!readwrite_bind.is_readonly());
    }

    #[test]
    fn test_filesystem_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let manager = FilesystemManager::new(temp_dir.path().to_path_buf());

        assert_eq!(manager.container_root, temp_dir.path());
        assert_eq!(manager.mounts.len(), 0);
        assert_eq!(manager.mounted_paths.len(), 0);
    }

    #[test]
    fn test_create_basic_rootfs() {
        let temp_dir = TempDir::new().unwrap();
        create_basic_rootfs(temp_dir.path()).unwrap();

        assert!(temp_dir.path().join("bin").exists());
        assert!(temp_dir.path().join("etc").exists());
        assert!(temp_dir.path().join("usr/bin").exists());
        assert!(temp_dir.path().join("var/log").exists());
    }
}
