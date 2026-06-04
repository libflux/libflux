//! Privileged runtime tests that perform real cgroup, namespace, and mount
//! syscalls. These cannot run unprivileged, so every test is `#[ignore]`d by
//! default and only executes via:
//!
//! ```text
//! sudo -E cargo test --test privileged -- --ignored
//! ```
//!
//! Even when invoked with `--ignored`, each test self-skips (passes as a
//! no-op) if the process is not root or the kernel lacks the required feature,
//! so the suite stays green on CI runners and developer laptops alike.
//!
//! Tests are marked `#[serial]` because they mutate shared global state under
//! `/sys/fs/cgroup` and the host network/mount namespaces.

use std::collections::HashMap;

use libflux::cgroups::{is_cgroups_v2_available, CgroupManager};
use libflux::utils::{generate_container_id, is_root};
use libflux::{
    Container, ContainerConfig, ContainerState, NamespaceType, NetworkConfig, NetworkMode,
    ResourceLimits,
};
use serial_test::serial;

/// Returns true (and logs) when the test should be skipped for lack of root.
fn skip_unless_root(test: &str) -> bool {
    if !is_root() {
        eprintln!("skipping {test}: requires root");
        return true;
    }
    false
}

#[test]
#[ignore = "requires root + cgroups v2"]
#[serial]
fn cgroup_create_apply_destroy() {
    if skip_unless_root("cgroup_create_apply_destroy") {
        return;
    }
    if !is_cgroups_v2_available() {
        eprintln!("skipping cgroup_create_apply_destroy: cgroups v2 not mounted");
        return;
    }

    let id = generate_container_id();
    let mut mgr = CgroupManager::new(id).expect("construct cgroup manager");

    mgr.create().expect("create cgroup");
    assert!(
        mgr.path().exists(),
        "cgroup dir should exist after create: {}",
        mgr.path().display()
    );

    // Applying default limits to a freshly created cgroup must succeed.
    mgr.apply_limits(&ResourceLimits::default())
        .expect("apply default limits");

    mgr.destroy().expect("destroy cgroup");
    assert!(
        !mgr.path().exists(),
        "cgroup dir should be gone after destroy"
    );
}

#[tokio::test]
#[ignore = "requires root (bind mounts + cgroups)"]
#[serial]
async fn container_create_then_cleanup() {
    if skip_unless_root("container_create_then_cleanup") {
        return;
    }
    if !is_cgroups_v2_available() {
        eprintln!("skipping container_create_then_cleanup: cgroups v2 not mounted");
        return;
    }

    // A real (if empty) source rootfs directory for the bind mount in
    // setup_rootfs. Lives in a tempdir that is removed on drop.
    let source = tempfile::tempdir().expect("create temp rootfs");
    let source_rootfs = source.path().to_path_buf();

    // No networking: keeps create()/cleanup() off the `ip` command path.
    let network = NetworkConfig {
        mode: NetworkMode::None,
        ..NetworkConfig::default()
    };

    let config = ContainerConfig::new(
        "priv-create".to_string(),
        "test:latest".to_string(),
        vec!["/bin/true".to_string()],
        None,
        HashMap::new(),
        source_rootfs,
        vec![NamespaceType::Pid, NamespaceType::Mount, NamespaceType::Uts],
        false,
        Some("priv-host".to_string()),
        Vec::new(),
        ResourceLimits::default(),
        None,
        network,
    );

    let mut container = Container::new(config).expect("construct container");
    assert_eq!(container.state().await, ContainerState::Creating);

    // create() bind-mounts the rootfs, creates a cgroup, and sets up logging.
    container.create().await.expect("create container");
    assert_eq!(container.state().await, ContainerState::Created);

    // The per-container log directory should now exist on disk.
    let log_dir = container.runtime_dir().join("logs");
    assert!(log_dir.exists(), "log dir missing: {}", log_dir.display());

    // cleanup() must unmount the rootfs and tear down the cgroup without error.
    container.cleanup().await.expect("cleanup container");
}
