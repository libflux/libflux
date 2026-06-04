//! Integration tests that exercise libflux through its public crate API,
//! the same way an external service embedding the library would.
//!
//! These tests deliberately avoid any operation requiring elevated
//! privileges (no namespace, cgroup, or mount syscalls), so they run in a
//! normal `cargo test` on any machine. Privileged lifecycle tests live in
//! `tests/privileged.rs` and are `#[ignore]`d by default.

use std::collections::HashMap;
use std::path::PathBuf;

// Pull everything from the curated crate-root re-exports to confirm the
// public surface stays usable without reaching into private module paths.
use libflux::{
    format_size, parse_size, Container, ContainerConfig, ContainerState, LibfluxError,
    NamespaceType, NetworkConfig, ResourceLimits,
};

fn minimal_config(name: &str) -> ContainerConfig {
    ContainerConfig::new(
        name.to_string(),
        "test:latest".to_string(),
        vec!["/bin/true".to_string()],
        None,
        HashMap::new(),
        PathBuf::from("/tmp/does-not-need-to-exist"),
        vec![NamespaceType::Pid, NamespaceType::Mount, NamespaceType::Uts],
        false,
        None,
        Vec::new(),
        ResourceLimits::default(),
        None,
        NetworkConfig::default(),
    )
}

#[test]
fn parse_size_accepts_unit_suffixes() {
    assert_eq!(parse_size("512").unwrap(), 512);
    assert_eq!(parse_size("1K").unwrap(), 1024);
    assert_eq!(parse_size("4M").unwrap(), 4 * 1024 * 1024);
    assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
    // Case-insensitive and whitespace-tolerant.
    assert_eq!(parse_size("  1g ").unwrap(), 1024 * 1024 * 1024);
}

#[test]
fn parse_size_rejects_garbage() {
    assert!(matches!(
        parse_size("not-a-size"),
        Err(LibfluxError::InvalidArgument(_))
    ));
    assert!(parse_size("").is_err());
}

#[test]
fn parse_and_format_size_are_consistent() {
    // parse_size and format_size share the same single-letter units, so a
    // round value through one should come back recognizably through the other.
    assert_eq!(format_size(parse_size("1K").unwrap()), "1.0K");
    assert_eq!(format_size(parse_size("4M").unwrap()), "4.0M");
    assert_eq!(format_size(parse_size("2G").unwrap()), "2.0G");
    assert_eq!(format_size(500), "500B");
}

#[test]
fn container_name_helpers_are_reachable() {
    // These live behind `libflux::utils`, confirming the module is public.
    assert!(libflux::utils::is_valid_container_name("web-1"));
    assert!(!libflux::utils::is_valid_container_name("Web_1"));
    assert_eq!(
        libflux::utils::sanitize_container_name("My App!"),
        "my-app"
    );
}

#[test]
fn generated_container_ids_are_unique_and_prefixed() {
    let a = libflux::utils::generate_container_id();
    let b = libflux::utils::generate_container_id();
    assert!(a.starts_with("libflux-"));
    assert_ne!(a, b);
}

#[test]
fn config_round_trips_through_json() {
    let config = minimal_config("round-trip");
    let json = serde_json::to_string(&config).expect("serialize config");
    let restored: ContainerConfig = serde_json::from_str(&json).expect("deserialize config");

    assert_eq!(restored.metadata.name, "round-trip");
    assert_eq!(restored.runtime.command, vec!["/bin/true".to_string()]);
    assert_eq!(restored.runtime.namespaces, config.runtime.namespaces);
}

#[tokio::test]
async fn new_container_starts_in_creating_state() {
    let container = Container::new(minimal_config("lifecycle")).expect("construct container");

    assert_eq!(container.name().await, "lifecycle");
    assert_eq!(container.state().await, ContainerState::Creating);

    let info = container.info().await;
    assert_eq!(info.name, "lifecycle");
    assert_eq!(info.image, "test:latest");
    assert!(info.pid.is_none());
    assert!(info.started_at.is_none());

    // Runtime paths are derived eagerly and should be non-empty.
    assert!(!container.runtime_dir().as_os_str().is_empty());
    assert!(!container.rootfs_path().as_os_str().is_empty());
}

#[tokio::test]
async fn start_without_create_is_rejected() {
    // Starting from `Creating` (never `create()`d) must fail rather than
    // silently forking, since none of the managers are initialized.
    let mut container = Container::new(minimal_config("no-create")).expect("construct container");
    let result = container.start().await;
    assert!(result.is_err(), "start() should reject an uncreated container");
    // State must not have advanced to Running.
    assert_ne!(container.state().await, ContainerState::Running);
}
