use crate::error::*;
use crate::utils::execute_command;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

/// Network configuration for containers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network mode
    pub mode: NetworkMode,
    /// Container interfaces
    pub interfaces: Vec<NetworkInterface>,
    /// DNS configuration
    pub dns: DnsConfig,
    /// Port mappings (host_port -> container_port)
    pub port_mappings: HashMap<u16, u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            mode: NetworkMode::Bridge,
            interfaces: vec![],
            dns: DnsConfig::default(),
            port_mappings: HashMap::new(),
        }
    }
}

/// Network modes supported by libflux
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkMode {
    /// No networking (only loopback)
    None,
    /// Share host network namespace
    Host,
    /// Bridge networking (default)
    Bridge,
    /// Custom bridge
    CustomBridge { bridge_name: String },
    /// Container networking (share with another container)
    Container { container_id: String },
}

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name inside container
    pub name: String,
    /// IP address and subnet mask
    pub ip: Option<IpAddr>,
    /// Subnet prefix length
    pub prefix_len: Option<u8>,
    /// Gateway IP address
    pub gateway: Option<IpAddr>,
    /// MAC address
    pub mac_address: Option<String>,
    /// MTU size
    pub mtu: Option<u16>,
}

impl Default for NetworkInterface {
    fn default() -> Self {
        NetworkInterface {
            name: "eth0".to_string(),
            ip: None,
            prefix_len: None,
            gateway: None,
            mac_address: None,
            mtu: Some(1500),
        }
    }
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS nameservers
    pub nameservers: Vec<IpAddr>,
    /// Search domains
    pub search_domains: Vec<String>,
    /// Options
    pub options: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            nameservers: vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // Google DNS
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), // Google DNS
            ],
            search_domains: vec![],
            options: vec!["ndots:0".to_string()],
        }
    }
}

/// Network manager for container networking
pub struct NetworkManager {
    container_id: String,
    pub config: NetworkConfig,
    created_interfaces: Vec<String>,
    created_bridges: Vec<String>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(container_id: String, config: NetworkConfig) -> Self {
        NetworkManager {
            container_id,
            config,
            created_interfaces: Vec::new(),
            created_bridges: Vec::new(),
        }
    }

    /// Setup networking for the container
    pub fn setup(&mut self) -> LibfluxResult<()> {
        let mode = self.config.mode.clone();
        match mode {
            NetworkMode::None => self.setup_no_network(),
            NetworkMode::Host => self.setup_host_network(),
            NetworkMode::Bridge => self.setup_bridge_network(),
            NetworkMode::CustomBridge { bridge_name } => {
                self.setup_custom_bridge_network(&bridge_name)
            }
            NetworkMode::Container { container_id } => self.setup_container_network(&container_id),
        }
    }

    /// Setup no networking (only loopback)
    fn setup_no_network(&mut self) -> LibfluxResult<()> {
        // Bring up loopback interface
        self.execute_ip_command(&["link", "set", "lo", "up"])?;
        Ok(())
    }

    /// Setup host networking (no isolation)
    fn setup_host_network(&mut self) -> LibfluxResult<()> {
        // Nothing to do - container shares host network namespace
        Ok(())
    }

    /// Setup bridge networking
    fn setup_bridge_network(&mut self) -> LibfluxResult<()> {
        let bridge_name = "libflux0";
        self.ensure_bridge_exists(bridge_name)?;
        self.setup_veth_pair(bridge_name)
    }

    /// Setup custom bridge networking
    fn setup_custom_bridge_network(&mut self, bridge_name: &str) -> LibfluxResult<()> {
        self.ensure_bridge_exists(bridge_name)?;
        self.setup_veth_pair(bridge_name)
    }

    /// Setup container networking (share with another container)
    fn setup_container_network(&mut self, _container_id: &str) -> LibfluxResult<()> {
        // This would require joining the network namespace of the target container
        // For now, return an error as this is complex to implement
        Err(NetworkError::InterfaceConfigFailed {
            interface: "container".to_string(),
        }
        .into())
    }

    /// Ensure a bridge interface exists
    fn ensure_bridge_exists(&mut self, bridge_name: &str) -> LibfluxResult<()> {
        // Check if bridge already exists
        if self.interface_exists(bridge_name)? {
            return Ok(());
        }

        // Create bridge
        self.execute_ip_command(&["link", "add", "name", bridge_name, "type", "bridge"])?;
        self.execute_ip_command(&["link", "set", bridge_name, "up"])?;

        // Configure bridge IP if not already configured
        if !self.has_ip_address(bridge_name)? {
            self.execute_ip_command(&["addr", "add", "172.16.0.1/24", "dev", bridge_name])?;
        }

        self.created_bridges.push(bridge_name.to_string());
        Ok(())
    }

    /// Setup veth pair for container
    fn setup_veth_pair(&mut self, bridge_name: &str) -> LibfluxResult<()> {
        let veth_host = format!("veth-{}", &self.container_id[..8]);
        let veth_container = format!("veth-c-{}", &self.container_id[..8]);

        // Create veth pair
        self.execute_ip_command(&[
            "link",
            "add",
            &veth_host,
            "type",
            "veth",
            "peer",
            "name",
            &veth_container,
        ])?;

        // Move container end to container namespace (this would be done from the host side)
        // For now, we'll configure the host side

        // Attach host end to bridge
        self.execute_ip_command(&["link", "set", &veth_host, "master", bridge_name])?;
        self.execute_ip_command(&["link", "set", &veth_host, "up"])?;

        // Configure container interface (this would happen inside the container)
        self.configure_container_interface(&veth_container)?;

        self.created_interfaces.push(veth_host);
        self.created_interfaces.push(veth_container);

        Ok(())
    }

    /// Configure the container's network interface
    fn configure_container_interface(&self, interface_name: &str) -> LibfluxResult<()> {
        // Set interface name to what's expected in container
        if let Some(container_if) = self.config.interfaces.first() {
            if container_if.name != interface_name {
                self.execute_ip_command(&[
                    "link",
                    "set",
                    interface_name,
                    "name",
                    &container_if.name,
                ])?;
            }

            let if_name = &container_if.name;

            // Configure IP address
            if let (Some(ip), Some(prefix_len)) = (&container_if.ip, container_if.prefix_len) {
                let addr_str = format!("{}/{}", ip, prefix_len);
                self.execute_ip_command(&["addr", "add", &addr_str, "dev", if_name])?;
            } else {
                // Use DHCP or assign a default IP
                self.execute_ip_command(&["addr", "add", "172.16.0.100/24", "dev", if_name])?;
            }

            // Set MTU if specified
            if let Some(mtu) = container_if.mtu {
                self.execute_ip_command(&["link", "set", if_name, "mtu", &mtu.to_string()])?;
            }

            // Set MAC address if specified
            if let Some(mac) = &container_if.mac_address {
                self.execute_ip_command(&["link", "set", if_name, "address", mac])?;
            }

            // Bring interface up
            self.execute_ip_command(&["link", "set", if_name, "up"])?;

            // Configure gateway
            if let Some(gateway) = &container_if.gateway {
                self.execute_ip_command(&[
                    "route",
                    "add",
                    "default",
                    "via",
                    &gateway.to_string(),
                    "dev",
                    if_name,
                ])?;
            } else {
                // Use bridge IP as gateway
                self.execute_ip_command(&[
                    "route",
                    "add",
                    "default",
                    "via",
                    "172.16.0.1",
                    "dev",
                    if_name,
                ])?;
            }
        }

        Ok(())
    }

    /// Setup DNS configuration
    pub fn setup_dns(&self) -> LibfluxResult<()> {
        let resolv_conf_content = self.generate_resolv_conf();
        std::fs::write("/etc/resolv.conf", resolv_conf_content).map_err(|_e| {
            NetworkError::InterfaceConfigFailed {
                interface: "dns".to_string(),
            }
        })?;

        Ok(())
    }

    /// Generate resolv.conf content
    fn generate_resolv_conf(&self) -> String {
        let mut content = String::new();

        // Add nameservers
        for nameserver in &self.config.dns.nameservers {
            content.push_str(&format!("nameserver {}\n", nameserver));
        }

        // Add search domains
        if !self.config.dns.search_domains.is_empty() {
            content.push_str(&format!(
                "search {}\n",
                self.config.dns.search_domains.join(" ")
            ));
        }

        // Add options
        if !self.config.dns.options.is_empty() {
            content.push_str(&format!("options {}\n", self.config.dns.options.join(" ")));
        }

        content
    }

    /// Execute ip command
    fn execute_ip_command(&self, args: &[&str]) -> LibfluxResult<()> {
        execute_command("ip", args).map_err(|_e| NetworkError::InterfaceConfigFailed {
            interface: args.join(" "),
        })?;
        Ok(())
    }

    /// Check if a network interface exists
    fn interface_exists(&self, interface_name: &str) -> LibfluxResult<bool> {
        match execute_command("ip", &["link", "show", interface_name]) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if an interface has an IP address
    fn has_ip_address(&self, interface_name: &str) -> LibfluxResult<bool> {
        match execute_command("ip", &["addr", "show", interface_name]) {
            Ok(output) => Ok(output.contains("inet ")),
            Err(_) => Ok(false),
        }
    }

    /// Configure port forwarding/NAT rules
    pub fn setup_port_forwarding(&self) -> LibfluxResult<()> {
        for (host_port, container_port) in &self.config.port_mappings {
            self.setup_port_mapping(*host_port, *container_port)?;
        }
        Ok(())
    }

    /// Setup individual port mapping using iptables
    fn setup_port_mapping(&self, host_port: u16, container_port: u16) -> LibfluxResult<()> {
        // This is a simplified implementation
        // In practice, you'd need to determine the container IP and setup proper NAT rules

        let container_ip = "172.16.0.100"; // This should be dynamically determined

        // DNAT rule for incoming traffic
        execute_command(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                &host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &format!("{}:{}", container_ip, container_port),
            ],
        )
        .map_err(|_| NetworkError::RouteConfigFailed)?;

        // SNAT rule for outgoing traffic
        execute_command(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-p",
                "tcp",
                "-s",
                container_ip,
                "--sport",
                &container_port.to_string(),
                "-j",
                "MASQUERADE",
            ],
        )
        .map_err(|_| NetworkError::RouteConfigFailed)?;

        Ok(())
    }

    /// Cleanup network resources
    pub fn cleanup(&mut self) -> LibfluxResult<()> {
        // Remove created interfaces
        for interface in &self.created_interfaces {
            let _ = execute_command("ip", &["link", "del", interface]);
        }

        // Clean up port forwarding rules
        for (host_port, container_port) in &self.config.port_mappings {
            let _ = self.cleanup_port_mapping(*host_port, *container_port);
        }

        // Note: We don't remove bridges as they might be shared

        self.created_interfaces.clear();
        Ok(())
    }

    /// Cleanup port mapping rules
    fn cleanup_port_mapping(&self, host_port: u16, container_port: u16) -> LibfluxResult<()> {
        let container_ip = "172.16.0.100"; // This should be dynamically determined

        // Remove DNAT rule
        let _ = execute_command(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                &host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &format!("{}:{}", container_ip, container_port),
            ],
        );

        // Remove SNAT rule
        let _ = execute_command(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-p",
                "tcp",
                "-s",
                container_ip,
                "--sport",
                &container_port.to_string(),
                "-j",
                "MASQUERADE",
            ],
        );

        Ok(())
    }

    /// Get network statistics
    pub fn get_stats(&self) -> LibfluxResult<NetworkStats> {
        // This is a simplified implementation
        Ok(NetworkStats {
            interfaces: HashMap::new(),
        })
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub interfaces: HashMap<String, InterfaceStats>,
}

/// Per-interface statistics
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// Check if the system has necessary networking capabilities
pub fn check_network_capabilities() -> LibfluxResult<NetworkCapabilities> {
    Ok(NetworkCapabilities {
        has_ip_command: Command::new("ip").arg("--version").output().is_ok(),
        has_iptables: Command::new("iptables").arg("--version").output().is_ok(),
        has_bridge_utils: Command::new("brctl").arg("--version").output().is_ok(),
        can_create_bridge: true, // This would need more sophisticated checking
        can_create_veth: true,   // This would need more sophisticated checking
    })
}

/// System networking capabilities
#[derive(Debug, Clone)]
pub struct NetworkCapabilities {
    pub has_ip_command: bool,
    pub has_iptables: bool,
    pub has_bridge_utils: bool,
    pub can_create_bridge: bool,
    pub can_create_veth: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert!(matches!(config.mode, NetworkMode::Bridge));
        assert!(config.interfaces.is_empty());
        assert!(!config.dns.nameservers.is_empty());
    }

    #[test]
    fn test_network_interface_default() {
        let interface = NetworkInterface::default();
        assert_eq!(interface.name, "eth0");
        assert_eq!(interface.mtu, Some(1500));
        assert!(interface.ip.is_none());
    }

    #[test]
    fn test_dns_config_default() {
        let dns = DnsConfig::default();
        assert_eq!(dns.nameservers.len(), 2);
        assert!(dns.search_domains.is_empty());
        assert!(!dns.options.is_empty());
    }

    #[test]
    fn test_network_manager_creation() {
        let config = NetworkConfig::default();
        let manager = NetworkManager::new("test-container".to_string(), config);

        assert_eq!(manager.container_id, "test-container");
        assert!(manager.created_interfaces.is_empty());
        assert!(manager.created_bridges.is_empty());
    }

    #[test]
    fn test_generate_resolv_conf() {
        let mut config = NetworkConfig::default();
        config.dns.search_domains.push("example.com".to_string());

        let manager = NetworkManager::new("test".to_string(), config);
        let resolv_conf = manager.generate_resolv_conf();

        assert!(resolv_conf.contains("nameserver 8.8.8.8"));
        assert!(resolv_conf.contains("search example.com"));
        assert!(resolv_conf.contains("options ndots:0"));
    }

    #[test]
    fn test_check_network_capabilities() {
        let caps = check_network_capabilities().unwrap();
        println!("Network capabilities: {:?}", caps);
        // System-dependent, so we just ensure it doesn't panic
    }
}
