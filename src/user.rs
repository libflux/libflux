use crate::error::*;
use nix::unistd::{getgid, getuid};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// User and group mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMapping {
    /// UID mappings
    pub uid_mappings: Vec<IdMapping>,
    /// GID mappings
    pub gid_mappings: Vec<IdMapping>,
    /// Whether to deny setgroups (required for unprivileged user namespaces)
    pub deny_setgroups: bool,
}

impl Default for UserMapping {
    fn default() -> Self {
        UserMapping {
            uid_mappings: vec![],
            gid_mappings: vec![],
            deny_setgroups: true,
        }
    }
}

/// Individual ID mapping entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdMapping {
    /// ID inside the namespace
    pub container_id: u32,
    /// ID on the host
    pub host_id: u32,
    /// Range size
    pub range: u32,
}

impl IdMapping {
    /// Create a new ID mapping
    pub fn new(container_id: u32, host_id: u32, range: u32) -> Self {
        IdMapping {
            container_id,
            host_id,
            range,
        }
    }

    /// Create a simple 1:1 mapping
    pub fn simple(container_id: u32, host_id: u32) -> Self {
        IdMapping::new(container_id, host_id, 1)
    }

    /// Format as string for writing to mapping files
    pub fn to_mapping_string(&self) -> String {
        format!("{} {} {}", self.container_id, self.host_id, self.range)
    }
}

/// User mapping manager
pub struct UserMappingManager {
    pid: nix::unistd::Pid,
    mapping: UserMapping,
    applied: bool,
}

impl UserMappingManager {
    /// Create a new user mapping manager for a process
    pub fn new(pid: nix::unistd::Pid, mapping: UserMapping) -> Self {
        UserMappingManager {
            pid,
            mapping,
            applied: false,
        }
    }

    /// Create a default rootless mapping for the current user
    pub fn rootless(pid: nix::unistd::Pid) -> Self {
        let current_uid = getuid().as_raw();
        let current_gid = getgid().as_raw();

        let mapping = UserMapping {
            uid_mappings: vec![IdMapping::simple(0, current_uid)],
            gid_mappings: vec![IdMapping::simple(0, current_gid)],
            deny_setgroups: true,
        };

        UserMappingManager::new(pid, mapping)
    }

    /// Create a mapping that maps root to the current user with a range
    pub fn rootless_range(pid: nix::unistd::Pid, range: u32) -> LibfluxResult<Self> {
        let current_uid = getuid().as_raw();
        let current_gid = getgid().as_raw();

        // Try to get a subuid/subgid range for the current user
        let (subuid_start, subuid_range) = Self::get_subuid_range(current_uid)?;
        let (subgid_start, subgid_range) = Self::get_subgid_range(current_gid)?;

        let mut uid_mappings = vec![IdMapping::simple(0, current_uid)];
        let mut gid_mappings = vec![IdMapping::simple(0, current_gid)];

        // Add subuid mapping if available and requested range fits
        if range > 1 && subuid_range >= range - 1 {
            uid_mappings.push(IdMapping::new(1, subuid_start, range - 1));
        }

        // Add subgid mapping if available and requested range fits
        if range > 1 && subgid_range >= range - 1 {
            gid_mappings.push(IdMapping::new(1, subgid_start, range - 1));
        }

        let mapping = UserMapping {
            uid_mappings,
            gid_mappings,
            deny_setgroups: true,
        };

        Ok(UserMappingManager::new(pid, mapping))
    }

    /// Apply the user and group mappings
    pub fn apply(&mut self) -> LibfluxResult<()> {
        if self.applied {
            return Ok(());
        }

        // Deny setgroups first if required (must be done before GID mapping)
        if self.mapping.deny_setgroups {
            self.deny_setgroups()?;
        }

        // Apply UID mappings
        if !self.mapping.uid_mappings.is_empty() {
            self.write_uid_map()?;
        }

        // Apply GID mappings
        if !self.mapping.gid_mappings.is_empty() {
            self.write_gid_map()?;
        }

        self.applied = true;
        Ok(())
    }

    /// Write UID mappings to /proc/{pid}/uid_map
    fn write_uid_map(&self) -> LibfluxResult<()> {
        let uid_map_path = format!("/proc/{}/uid_map", self.pid);
        let mappings: Vec<String> = self
            .mapping
            .uid_mappings
            .iter()
            .map(|m| m.to_mapping_string())
            .collect();

        self.write_mapping_file(&uid_map_path, &mappings.join("\n"))
            .map_err(|e| UserMappingError::UidMapFailed {
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Write GID mappings to /proc/{pid}/gid_map
    fn write_gid_map(&self) -> LibfluxResult<()> {
        let gid_map_path = format!("/proc/{}/gid_map", self.pid);
        let mappings: Vec<String> = self
            .mapping
            .gid_mappings
            .iter()
            .map(|m| m.to_mapping_string())
            .collect();

        self.write_mapping_file(&gid_map_path, &mappings.join("\n"))
            .map_err(|e| UserMappingError::GidMapFailed {
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Deny setgroups for the process
    fn deny_setgroups(&self) -> LibfluxResult<()> {
        let setgroups_path = format!("/proc/{}/setgroups", self.pid);
        self.write_mapping_file(&setgroups_path, "deny")
            .map_err(|e| UserMappingError::GidMapFailed {
                reason: format!("Failed to deny setgroups: {}", e),
            })?;

        Ok(())
    }

    /// Write content to a mapping file
    fn write_mapping_file(&self, path: &str, content: &str) -> LibfluxResult<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(LibfluxError::Io)?;

        file.write_all(content.as_bytes())
            .map_err(LibfluxError::Io)?;

        Ok(())
    }

    /// Get subuid range for a user
    fn get_subuid_range(uid: u32) -> LibfluxResult<(u32, u32)> {
        Self::parse_subid_file("/etc/subuid", uid)
    }

    /// Get subgid range for a user  
    fn get_subgid_range(gid: u32) -> LibfluxResult<(u32, u32)> {
        Self::parse_subid_file("/etc/subgid", gid)
    }

    /// Parse /etc/subuid or /etc/subgid file
    fn parse_subid_file(path: &str, id: u32) -> LibfluxResult<(u32, u32)> {
        let file = File::open(path).map_err(|_| UserMappingError::InsufficientPrivileges)?;

        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(LibfluxError::Io)?;
            let parts: Vec<&str> = line.split(':').collect();

            if parts.len() == 3 {
                // Check if this is for our user (by name or ID)
                let user_part = parts[0];
                let start_id: u32 =
                    parts[1]
                        .parse()
                        .map_err(|_| UserMappingError::InvalidUidMapping {
                            mapping: line.clone(),
                        })?;
                let range: u32 =
                    parts[2]
                        .parse()
                        .map_err(|_| UserMappingError::InvalidUidMapping {
                            mapping: line.clone(),
                        })?;

                // Check if this entry matches our ID or username
                if user_part
                    .parse::<u32>()
                    .map(|uid| uid == id)
                    .unwrap_or(false)
                {
                    return Ok((start_id, range));
                }

                // Could also check by username here if needed
                // This is a simplified implementation
            }
        }

        Err(UserMappingError::InsufficientPrivileges.into())
    }

    /// Get the current user and group mappings from /proc
    pub fn get_current_mappings(pid: nix::unistd::Pid) -> LibfluxResult<UserMapping> {
        let uid_mappings = Self::read_mapping_file(&format!("/proc/{}/uid_map", pid))?;
        let gid_mappings = Self::read_mapping_file(&format!("/proc/{}/gid_map", pid))?;

        Ok(UserMapping {
            uid_mappings,
            gid_mappings,
            deny_setgroups: false, // We can't easily determine this from proc files
        })
    }

    /// Read mappings from a proc file
    fn read_mapping_file(path: &str) -> LibfluxResult<Vec<IdMapping>> {
        let file = File::open(path).map_err(LibfluxError::Io)?;
        let reader = BufReader::new(file);
        let mut mappings = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(LibfluxError::Io)?;
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() == 3 {
                let container_id: u32 =
                    parts[0]
                        .parse()
                        .map_err(|_| UserMappingError::InvalidUidMapping {
                            mapping: line.clone(),
                        })?;
                let host_id: u32 =
                    parts[1]
                        .parse()
                        .map_err(|_| UserMappingError::InvalidUidMapping {
                            mapping: line.clone(),
                        })?;
                let range: u32 =
                    parts[2]
                        .parse()
                        .map_err(|_| UserMappingError::InvalidUidMapping {
                            mapping: line.clone(),
                        })?;

                mappings.push(IdMapping::new(container_id, host_id, range));
            }
        }

        Ok(mappings)
    }

    /// Check if user namespaces are supported
    pub fn is_user_namespace_supported() -> bool {
        Path::new("/proc/self/uid_map").exists()
    }

    /// Get the mapping configuration
    pub fn mapping(&self) -> &UserMapping {
        &self.mapping
    }

    /// Check if mappings have been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

/// Helper functions for common mapping scenarios

/// Create a simple rootless mapping for current user
pub fn create_rootless_mapping(pid: nix::unistd::Pid) -> UserMappingManager {
    UserMappingManager::rootless(pid)
}

/// Create a rootless mapping with a specific range
pub fn create_rootless_range_mapping(
    pid: nix::unistd::Pid,
    range: u32,
) -> LibfluxResult<UserMappingManager> {
    UserMappingManager::rootless_range(pid, range)
}

/// Check if the current user can create user namespaces
pub fn can_create_user_namespace() -> bool {
    // Check if user namespaces are enabled
    if !UserMappingManager::is_user_namespace_supported() {
        return false;
    }

    // Check if unprivileged user namespaces are allowed
    let unprivileged_userns = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .unwrap_or_else(|_| "1".to_string());

    unprivileged_userns.trim() == "1"
}

/// Get information about available subuid/subgid ranges
pub fn get_subid_info() -> LibfluxResult<SubIdInfo> {
    let current_uid = getuid().as_raw();
    let current_gid = getgid().as_raw();

    let subuid = UserMappingManager::get_subuid_range(current_uid).ok();
    let subgid = UserMappingManager::get_subgid_range(current_gid).ok();

    Ok(SubIdInfo {
        uid: current_uid,
        gid: current_gid,
        subuid_range: subuid,
        subgid_range: subgid,
        can_create_user_ns: can_create_user_namespace(),
    })
}

/// Information about subuid/subgid availability
#[derive(Debug, Clone)]
pub struct SubIdInfo {
    pub uid: u32,
    pub gid: u32,
    pub subuid_range: Option<(u32, u32)>,
    pub subgid_range: Option<(u32, u32)>,
    pub can_create_user_ns: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_mapping_creation() {
        let mapping = IdMapping::new(0, 1000, 1);
        assert_eq!(mapping.container_id, 0);
        assert_eq!(mapping.host_id, 1000);
        assert_eq!(mapping.range, 1);
    }

    #[test]
    fn test_id_mapping_string() {
        let mapping = IdMapping::new(0, 1000, 65536);
        assert_eq!(mapping.to_mapping_string(), "0 1000 65536");
    }

    #[test]
    fn test_simple_mapping() {
        let mapping = IdMapping::simple(0, 1000);
        assert_eq!(mapping.container_id, 0);
        assert_eq!(mapping.host_id, 1000);
        assert_eq!(mapping.range, 1);
    }

    #[test]
    fn test_user_mapping_default() {
        let mapping = UserMapping::default();
        assert!(mapping.uid_mappings.is_empty());
        assert!(mapping.gid_mappings.is_empty());
        assert!(mapping.deny_setgroups);
    }

    #[test]
    fn test_user_namespace_support_check() {
        let supported = UserMappingManager::is_user_namespace_supported();
        println!("User namespaces supported: {}", supported);
        // This is system-dependent, so we just check that it doesn't panic
    }

    #[test]
    fn test_can_create_user_namespace() {
        let can_create = can_create_user_namespace();
        println!("Can create user namespace: {}", can_create);
        // This is system and configuration dependent
    }

    #[test]
    fn test_subid_info() {
        if let Ok(info) = get_subid_info() {
            println!("SubID info: {:?}", info);
            assert!(info.uid > 0);
            assert!(info.gid > 0);
        }
    }
}
