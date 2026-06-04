//! libflux: a secure, performant, and developer-friendly container runtime
//! built on Linux namespaces and cgroups v2.
//!
//! This crate can be used in two ways:
//!
//! 1. As the standalone `libflux` command-line binary.
//! 2. As a library embedded in another service, by depending on the
//!    `libflux` crate and driving [`Container`] directly.
//!
//! # Library example
//!
//! ```no_run
//! use std::collections::HashMap;
//! use libflux::{
//!     Container, ContainerConfig, NamespaceType, NetworkConfig, ResourceLimits,
//! };
//!
//! # async fn run() -> libflux::LibfluxResult<()> {
//! let config = ContainerConfig::new(
//!     "example".to_string(),
//!     "/path/to/rootfs".to_string(),
//!     vec!["/bin/sh".to_string()],
//!     None,
//!     HashMap::new(),
//!     "/path/to/rootfs".into(),
//!     vec![NamespaceType::Pid, NamespaceType::Mount, NamespaceType::Uts],
//!     false,
//!     None,
//!     Vec::new(),
//!     ResourceLimits::default(),
//!     None,
//!     NetworkConfig::default(),
//! );
//!
//! let mut container = Container::new(config)?;
//! container.create().await?;
//! container.start().await?;
//! # Ok(())
//! # }
//! ```

pub mod cgroups;
pub mod config;
pub mod container;
pub mod error;
pub mod fs;
pub mod logging;
pub mod namespace;
pub mod net;
pub mod user;
pub mod utils;

// Curated re-exports forming the primary public API surface.
pub use crate::cgroups::{CgroupManager, ResourceLimits, ResourceStats};
pub use crate::config::ContainerConfig;
pub use crate::container::{Container, ContainerInfo, ContainerState};
pub use crate::error::{LibfluxError, LibfluxResult};
pub use crate::fs::{FilesystemManager, MountType};
pub use crate::logging::{LibfluxLogger, parse_log_level};
pub use crate::namespace::{NamespaceConfig, NamespaceManager, NamespaceType};
pub use crate::net::{
    DnsConfig, NetworkConfig, NetworkInterface, NetworkManager, NetworkMode,
};
pub use crate::user::{UserMapping, UserMappingManager};
pub use crate::utils::{format_size, get_system_info, parse_size, SystemInfo};
