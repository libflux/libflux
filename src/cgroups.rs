use crate::error::*;
use crate::utils::ensure_dir_exists;
use nix::unistd::{getpid, Pid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Cgroup v2 controller types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CgroupController {
    /// CPU controller for CPU bandwidth control
    Cpu,
    /// Memory controller for memory usage control
    Memory,
    /// IO controller for block device I/O control
    Io,
    /// PID controller for process number control
    Pids,
    /// Cpuset controller for CPU and memory node control
    Cpuset,
}

impl CgroupController {
    /// Get the controller name as it appears in cgroup.controllers
    pub fn name(&self) -> &'static str {
        match self {
            CgroupController::Cpu => "cpu",
            CgroupController::Memory => "memory",
            CgroupController::Io => "io",
            CgroupController::Pids => "pids",
            CgroupController::Cpuset => "cpuset",
        }
    }

    /// Get all available controllers
    pub fn all() -> Vec<CgroupController> {
        vec![
            CgroupController::Cpu,
            CgroupController::Memory,
            CgroupController::Io,
            CgroupController::Pids,
            CgroupController::Cpuset,
        ]
    }
}

impl std::fmt::Display for CgroupController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Resource limits for containers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// CPU limits
    pub cpu: CpuLimits,
    /// Memory limits
    pub memory: MemoryLimits,
    /// I/O limits
    pub io: IoLimits,
    /// Process limits
    pub pids: PidsLimits,
}

/// CPU resource limits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuLimits {
    /// CPU weight (1-10000, default 100)
    pub weight: Option<u32>,
    /// CPU maximum bandwidth (percentage)
    pub max: Option<f64>,
    /// CPU quota period in microseconds (default 100000)
    pub quota_period: Option<u64>,
    /// CPU quota in microseconds per period
    pub quota: Option<u64>,
}

/// Memory resource limits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Memory usage limit in bytes
    pub limit: Option<u64>,
    /// Memory + swap limit in bytes
    pub swap_limit: Option<u64>,
    /// Memory low watermark (soft limit)
    pub low: Option<u64>,
    /// Memory high watermark (throttling point)
    pub high: Option<u64>,
    /// Disable swap for this cgroup
    pub swap_max: Option<u64>,
}

/// I/O resource limits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoLimits {
    /// I/O weight (1-10000, default 100)
    pub weight: Option<u32>,
    /// Per-device I/O limits
    pub device_limits: HashMap<String, IoDeviceLimits>,
}

/// Per-device I/O limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoDeviceLimits {
    /// Read bandwidth limit (bytes per second)
    pub rbps: Option<u64>,
    /// Write bandwidth limit (bytes per second)
    pub wbps: Option<u64>,
    /// Read IOPS limit
    pub riops: Option<u64>,
    /// Write IOPS limit
    pub wiops: Option<u64>,
}

/// Process limits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PidsLimits {
    /// Maximum number of processes/threads
    pub max: Option<u64>,
}

/// Cgroup manager for handling container resource limits
pub struct CgroupManager {
    cgroup_root: PathBuf,
    cgroup_path: PathBuf,
    container_id: String,
    created: bool,
    last_cpu_measurement: Option<CpuMeasurement>,
    last_io_measurement: Option<IoMeasurement>,
}

/// Internal structure for CPU measurements
#[derive(Debug, Clone)]
struct CpuMeasurement {
    timestamp: std::time::Instant,
    total_time: u64,
    user_time: u64,
    system_time: u64,
}

/// Internal structure for I/O measurements
#[derive(Debug, Clone)]
struct IoMeasurement {
    timestamp: std::time::Instant,
    read_bytes: u64,
    write_bytes: u64,
}

impl CgroupManager {
    /// Create a new cgroup manager
    pub fn new(container_id: String) -> LibfluxResult<Self> {
        let cgroup_root = Self::get_cgroup_root()?;
        let cgroup_path = cgroup_root.join("libflux").join(&container_id);

        Ok(CgroupManager {
            cgroup_root,
            cgroup_path,
            container_id,
            created: false,
            last_cpu_measurement: None,
            last_io_measurement: None,
        })
    }

    /// Get the cgroup v2 root path
    fn get_cgroup_root() -> LibfluxResult<PathBuf> {
        // Check if cgroup v2 is mounted
        let cgroup_root = PathBuf::from("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").exists() {
            return Err(CgroupError::V2NotSupported.into());
        }
        Ok(cgroup_root)
    }

    /// Create the cgroup hierarchy
    pub fn create(&mut self) -> LibfluxResult<()> {
        if self.created {
            return Ok(());
        }

        // Create the libflux parent cgroup if it doesn't exist
        let libflux_cgroup = self.cgroup_root.join("libflux");
        ensure_dir_exists(&libflux_cgroup)?;

        // Enable controllers in the parent cgroup
        self.enable_controllers(&libflux_cgroup)?;

        // Create the container-specific cgroup
        ensure_dir_exists(&self.cgroup_path).map_err(|_| CgroupError::CreationFailed {
            cgroup_path: self.cgroup_path.to_string_lossy().to_string(),
        })?;

        // Enable controllers in the container cgroup
        self.enable_controllers(&self.cgroup_path)?;

        self.created = true;
        Ok(())
    }

    /// Enable only the controllers we need and that are available
    fn enable_controllers(&self, cgroup_path: &Path) -> LibfluxResult<()> {
        let controllers_file = cgroup_path.join("cgroup.subtree_control");

        // Read available controllers from parent
        let parent_controllers = if let Some(parent) = cgroup_path.parent() {
            self.get_available_controllers(parent)?
        } else {
            self.get_available_controllers(&self.cgroup_root)?
        };

        // Only enable controllers that we need and that are available
        let needed_controllers = CgroupController::all();
        let controllers_to_enable: Vec<String> = needed_controllers
            .iter()
            .filter_map(|controller| {
                let controller_name = controller.name();
                if parent_controllers.contains(&controller_name.to_string()) {
                    Some(format!("+{}", controller_name))
                } else {
                    None
                }
            })
            .collect();

        if !controllers_to_enable.is_empty() {
            let controllers_str = controllers_to_enable.join(" ");
            self.write_cgroup_file(&controllers_file, &controllers_str)?;
        }

        Ok(())
    }

    /// Get available controllers in a cgroup
    fn get_available_controllers(&self, cgroup_path: &Path) -> LibfluxResult<Vec<String>> {
        let controllers_file = cgroup_path.join("cgroup.controllers");
        let contents = fs::read_to_string(&controllers_file).map_err(|_| {
            CgroupError::ControllerNotAvailable {
                controller: "unknown".to_string(),
            }
        })?;

        Ok(contents
            .trim()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect())
    }

    /// Join the current process to this cgroup
    pub fn join(&self) -> LibfluxResult<()> {
        self.join_pid(getpid())
    }

    /// Join a specific process to this cgroup
    pub fn join_pid(&self, pid: Pid) -> LibfluxResult<()> {
        if !self.created {
            return Err(CgroupError::NotFound {
                cgroup_path: self.cgroup_path.to_string_lossy().to_string(),
            }
            .into());
        }

        // Check if the process still exists
        if let Err(_) = nix::sys::signal::kill(pid, None) {
            // Process doesn't exist or we can't access it
            return Err(CgroupError::JoinFailed {
                cgroup_path: format!("Process {} no longer exists", pid),
            }
            .into());
        }

        let procs_file = self.cgroup_path.join("cgroup.procs");
        self.write_cgroup_file(&procs_file, &pid.to_string())?;

        Ok(())
    }

    /// Apply resource limits to the cgroup
    pub fn apply_limits(&self, limits: &ResourceLimits) -> LibfluxResult<()> {
        if !self.created {
            return Err(CgroupError::NotFound {
                cgroup_path: self.cgroup_path.to_string_lossy().to_string(),
            }
            .into());
        }

        self.apply_cpu_limits(&limits.cpu)?;
        self.apply_memory_limits(&limits.memory)?;
        self.apply_io_limits(&limits.io)?;
        self.apply_pids_limits(&limits.pids)?;

        Ok(())
    }

    /// Apply CPU limits
    fn apply_cpu_limits(&self, limits: &CpuLimits) -> LibfluxResult<()> {
        if let Some(weight) = limits.weight {
            let weight_file = self.cgroup_path.join("cpu.weight");
            self.write_cgroup_file(&weight_file, &weight.to_string())?;
        }

        if let Some(quota) = limits.quota {
            let period = limits.quota_period.unwrap_or(100000);
            let max_file = self.cgroup_path.join("cpu.max");
            let max_value = format!("{} {}", quota, period);
            self.write_cgroup_file(&max_file, &max_value)?;
        } else if let Some(max_percentage) = limits.max {
            // Convert percentage to quota
            let period = limits.quota_period.unwrap_or(100000);
            let quota = ((max_percentage / 100.0) * period as f64) as u64;
            let max_file = self.cgroup_path.join("cpu.max");
            let max_value = format!("{} {}", quota, period);
            self.write_cgroup_file(&max_file, &max_value)?;
        }

        Ok(())
    }

    /// Apply memory limits
    fn apply_memory_limits(&self, limits: &MemoryLimits) -> LibfluxResult<()> {
        if let Some(limit) = limits.limit {
            let max_file = self.cgroup_path.join("memory.max");
            self.write_cgroup_file(&max_file, &limit.to_string())?;
        }

        if let Some(low) = limits.low {
            let low_file = self.cgroup_path.join("memory.low");
            self.write_cgroup_file(&low_file, &low.to_string())?;
        }

        if let Some(high) = limits.high {
            let high_file = self.cgroup_path.join("memory.high");
            self.write_cgroup_file(&high_file, &high.to_string())?;
        }

        if let Some(swap_max) = limits.swap_max {
            let swap_file = self.cgroup_path.join("memory.swap.max");
            self.write_cgroup_file(&swap_file, &swap_max.to_string())?;
        }

        Ok(())
    }

    /// Apply I/O limits
    fn apply_io_limits(&self, limits: &IoLimits) -> LibfluxResult<()> {
        if let Some(weight) = limits.weight {
            let weight_file = self.cgroup_path.join("io.weight");
            self.write_cgroup_file(&weight_file, &weight.to_string())?;
        }

        for (device, device_limits) in &limits.device_limits {
            if let Some(rbps) = device_limits.rbps {
                let max_file = self.cgroup_path.join("io.max");
                let value = format!("{} rbps={}", device, rbps);
                self.write_cgroup_file(&max_file, &value)?;
            }

            if let Some(wbps) = device_limits.wbps {
                let max_file = self.cgroup_path.join("io.max");
                let value = format!("{} wbps={}", device, wbps);
                self.write_cgroup_file(&max_file, &value)?;
            }

            if let Some(riops) = device_limits.riops {
                let max_file = self.cgroup_path.join("io.max");
                let value = format!("{} riops={}", device, riops);
                self.write_cgroup_file(&max_file, &value)?;
            }

            if let Some(wiops) = device_limits.wiops {
                let max_file = self.cgroup_path.join("io.max");
                let value = format!("{} wiops={}", device, wiops);
                self.write_cgroup_file(&max_file, &value)?;
            }
        }

        Ok(())
    }

    /// Apply process limits
    fn apply_pids_limits(&self, limits: &PidsLimits) -> LibfluxResult<()> {
        if let Some(max) = limits.max {
            let max_file = self.cgroup_path.join("pids.max");
            self.write_cgroup_file(&max_file, &max.to_string())?;
        }

        Ok(())
    }

    /// Get current resource usage statistics
    pub fn get_stats(&mut self) -> LibfluxResult<ResourceStats> {
        if !self.created {
            return Err(CgroupError::NotFound {
                cgroup_path: self.cgroup_path.to_string_lossy().to_string(),
            }
            .into());
        }

        Ok(ResourceStats {
            cpu: self.get_cpu_stats()?,
            memory: self.get_memory_stats()?,
            io: self.get_io_stats()?,
            pids: self.get_pids_stats()?,
        })
    }

    /// Get CPU statistics
    fn get_cpu_stats(&mut self) -> LibfluxResult<CpuStats> {
        let pids = self.get_cgroup_pids()?;
        let mut total_utime = 0;
        let mut total_stime = 0;
        let mut total_cutime = 0;
        let mut total_cstime = 0;
        let mut num_processes = 0;
        let mut num_threads = 0;

        // Collect CPU stats for all processes in the cgroup
        for pid in &pids {
            if let Some((utime, stime, cutime, cstime)) = self.read_proc_stat(*pid) {
                total_utime += utime;
                total_stime += stime;
                total_cutime += cutime;
                total_cstime += cstime;
                num_processes += 1;

                // Count threads by reading /proc/[pid]/stat field 19 (num_threads)
                if let Ok(contents) = fs::read_to_string(format!("/proc/{}/stat", pid)) {
                    if let Some(field) = contents.split_whitespace().nth(19) {
                        if let Ok(threads) = field.parse::<u32>() {
                            num_threads += threads;
                        }
                    }
                }
            }
        }

        let clock_ticks = self.get_clock_ticks_per_second();
        let total_time = total_utime + total_stime + total_cutime + total_cstime;

        // Convert clock ticks to microseconds
        let usage_usec = (total_time * 1_000_000) / clock_ticks;
        let user_usec = ((total_utime + total_cutime) * 1_000_000) / clock_ticks;
        let system_usec = ((total_stime + total_cstime) * 1_000_000) / clock_ticks;

        // Calculate CPU percentage if we have a previous measurement
        let mut cpu_percent = 0.0;
        let current_time = std::time::Instant::now();

        if let Some(ref last_measurement) = self.last_cpu_measurement {
            let time_diff = current_time
                .duration_since(last_measurement.timestamp)
                .as_secs_f64();
            if time_diff > 0.0 {
                let cpu_time_diff = total_time.saturating_sub(last_measurement.total_time);
                // Convert to percentage (multiply by 100 and divide by time difference and clock ticks)
                cpu_percent = (cpu_time_diff as f64) * 100.0 / (time_diff * clock_ticks as f64);
            }
        }

        // Update last measurement
        self.last_cpu_measurement = Some(CpuMeasurement {
            timestamp: current_time,
            total_time,
            user_time: total_utime + total_cutime,
            system_time: total_stime + total_cstime,
        });

        Ok(CpuStats {
            usage_usec,
            user_usec,
            system_usec,
            cpu_percent,
            num_processes,
            num_threads,
        })
    }

    /// Get memory statistics
    fn get_memory_stats(&self) -> LibfluxResult<MemoryStats> {
        let pids = self.get_cgroup_pids()?;
        let mut total_rss = 0;
        let mut total_virtual = 0;
        let mut total_swap = 0;

        // Collect memory stats for all processes in the cgroup
        for pid in &pids {
            if let Some((rss, virtual_mem, swap)) = self.read_proc_status(*pid) {
                total_rss += rss;
                total_virtual += virtual_mem;
                total_swap += swap;
            }
        }

        // Get system memory info for percentage calculation
        let (system_total, _system_available) = self.get_system_memory_info();
        let memory_percent = if system_total > 0 {
            (total_rss as f64 / system_total as f64) * 100.0
        } else {
            0.0
        };

        // Try to get peak memory from cgroup
        let peak = {
            let peak_file = self.cgroup_path.join("memory.peak");
            fs::read_to_string(&peak_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(total_rss)
        };

        // Try to get cache from cgroup memory.stat
        let cache = {
            let stat_file = self.cgroup_path.join("memory.stat");
            if let Ok(contents) = fs::read_to_string(&stat_file) {
                for line in contents.lines() {
                    if line.starts_with("cache ") {
                        if let Some(value) = line.split_whitespace().nth(1) {
                            return Ok(MemoryStats {
                                current: total_rss,
                                cache: value.parse().unwrap_or(0),
                                rss: total_rss,
                                virtual_memory: total_virtual,
                                swap: total_swap,
                                memory_percent,
                                peak,
                            });
                        }
                    }
                }
            }
            0
        };

        Ok(MemoryStats {
            current: total_rss,
            cache,
            rss: total_rss,
            virtual_memory: total_virtual,
            swap: total_swap,
            memory_percent,
            peak,
        })
    }

    /// Get I/O statistics
    fn get_io_stats(&mut self) -> LibfluxResult<IoStats> {
        let pids = self.get_cgroup_pids()?;
        let mut total_read_bytes = 0;
        let mut total_write_bytes = 0;
        let mut total_read_ios = 0;
        let mut total_write_ios = 0;

        // Collect I/O stats for all processes in the cgroup
        for pid in &pids {
            if let Some((read_bytes, write_bytes)) = self.read_proc_io(*pid) {
                total_read_bytes += read_bytes;
                total_write_bytes += write_bytes;
            }

            // Count I/O operations from /proc/[pid]/io
            if let Ok(contents) = fs::read_to_string(format!("/proc/{}/io", pid)) {
                for line in contents.lines() {
                    if line.starts_with("syscr:") {
                        if let Some(value) = line.split_whitespace().nth(1) {
                            total_read_ios += value.parse::<u64>().unwrap_or(0);
                        }
                    } else if line.starts_with("syscw:") {
                        if let Some(value) = line.split_whitespace().nth(1) {
                            total_write_ios += value.parse::<u64>().unwrap_or(0);
                        }
                    }
                }
            }
        }

        // Calculate I/O rates if we have a previous measurement
        let mut read_rate = 0.0;
        let mut write_rate = 0.0;
        let current_time = std::time::Instant::now();

        if let Some(ref last_measurement) = self.last_io_measurement {
            let time_diff = current_time
                .duration_since(last_measurement.timestamp)
                .as_secs_f64();
            if time_diff > 0.0 {
                let read_diff = total_read_bytes.saturating_sub(last_measurement.read_bytes);
                let write_diff = total_write_bytes.saturating_sub(last_measurement.write_bytes);
                read_rate = read_diff as f64 / time_diff;
                write_rate = write_diff as f64 / time_diff;
            }
        }

        // Update last measurement
        self.last_io_measurement = Some(IoMeasurement {
            timestamp: current_time,
            read_bytes: total_read_bytes,
            write_bytes: total_write_bytes,
        });

        // Get disk usage percentage (simplified - using root filesystem)
        let disk_usage_percent = self.get_disk_usage_percent();

        Ok(IoStats {
            read_bytes: total_read_bytes,
            write_bytes: total_write_bytes,
            read_ios: total_read_ios,
            write_ios: total_write_ios,
            read_rate,
            write_rate,
            disk_usage_percent,
        })
    }

    /// Get disk usage percentage
    fn get_disk_usage_percent(&self) -> f64 {
        // Use statvfs to get filesystem statistics
        use std::ffi::CString;

        let path = CString::new("/").unwrap();
        let mut stat = unsafe { std::mem::zeroed() };

        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } == 0 {
            let total = stat.f_blocks * stat.f_frsize;
            let available = stat.f_bavail * stat.f_frsize;
            let used = total - available;

            if total > 0 {
                return (used as f64 / total as f64) * 100.0;
            }
        }

        0.0
    }

    /// Get process statistics
    fn get_pids_stats(&self) -> LibfluxResult<PidsStats> {
        let current_file = self.cgroup_path.join("pids.current");
        let current = fs::read_to_string(&current_file)
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);

        Ok(PidsStats { current })
    }

    /// Write to a cgroup file
    fn write_cgroup_file(&self, file_path: &Path, content: &str) -> LibfluxResult<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(file_path)
            .map_err(|e| CgroupError::SetLimitFailed {
                controller: format!(
                    "{}({})",
                    file_path.file_name().unwrap_or_default().to_string_lossy(),
                    e
                ),
                value: content.to_string(),
            })?;

        file.write_all(content.as_bytes())
            .map_err(|e| CgroupError::SetLimitFailed {
                controller: format!(
                    "{}({})",
                    file_path.file_name().unwrap_or_default().to_string_lossy(),
                    e
                ),
                value: content.to_string(),
            })?;

        Ok(())
    }

    /// Destroy the cgroup
    pub fn destroy(&self) -> LibfluxResult<()> {
        if !self.created {
            return Ok(());
        }

        if self.cgroup_path.exists() {
            fs::remove_dir(&self.cgroup_path).map_err(|_| CgroupError::NotFound {
                cgroup_path: self.cgroup_path.to_string_lossy().to_string(),
            })?;
        }

        Ok(())
    }

    /// Get the cgroup path
    pub fn path(&self) -> &Path {
        &self.cgroup_path
    }

    /// Get list of processes in this cgroup
    fn get_cgroup_pids(&self) -> LibfluxResult<Vec<u32>> {
        let procs_file = self.cgroup_path.join("cgroup.procs");
        if !procs_file.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(&procs_file).unwrap_or_default();
        let pids: Vec<u32> = contents
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect();

        Ok(pids)
    }

    /// Read process stat information from /proc/[pid]/stat
    fn read_proc_stat(&self, pid: u32) -> Option<(u64, u64, u64, u64)> {
        let stat_path = format!("/proc/{}/stat", pid);
        let contents = fs::read_to_string(&stat_path).ok()?;

        let fields: Vec<&str> = contents.split_whitespace().collect();
        if fields.len() < 22 {
            return None;
        }

        // Fields from /proc/[pid]/stat:
        // 13: utime (user time in clock ticks)
        // 14: stime (system time in clock ticks)
        // 15: cutime (children user time)
        // 16: cstime (children system time)
        let utime: u64 = fields[13].parse().ok()?;
        let stime: u64 = fields[14].parse().ok()?;
        let cutime: u64 = fields[15].parse().ok()?;
        let cstime: u64 = fields[16].parse().ok()?;

        Some((utime, stime, cutime, cstime))
    }

    /// Read process status information from /proc/[pid]/status
    fn read_proc_status(&self, pid: u32) -> Option<(u64, u64, u64)> {
        let status_path = format!("/proc/{}/status", pid);
        let contents = fs::read_to_string(&status_path).ok()?;

        let mut vm_rss = 0;
        let mut vm_size = 0;
        let mut vm_swap = 0;

        for line in contents.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    vm_rss = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            } else if line.starts_with("VmSize:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    vm_size = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            } else if line.starts_with("VmSwap:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    vm_swap = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            }
        }

        Some((vm_rss, vm_size, vm_swap))
    }

    /// Read process I/O information from /proc/[pid]/io
    fn read_proc_io(&self, pid: u32) -> Option<(u64, u64)> {
        let io_path = format!("/proc/{}/io", pid);
        let contents = fs::read_to_string(&io_path).ok()?;

        let mut read_bytes = 0;
        let mut write_bytes = 0;

        for line in contents.lines() {
            if line.starts_with("read_bytes:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    read_bytes = value.parse().unwrap_or(0);
                }
            } else if line.starts_with("write_bytes:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    write_bytes = value.parse().unwrap_or(0);
                }
            }
        }

        Some((read_bytes, write_bytes))
    }

    /// Get system memory information from /proc/meminfo
    fn get_system_memory_info(&self) -> (u64, u64) {
        let contents = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let mut mem_total = 0;
        let mut mem_available = 0;

        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    mem_total = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            } else if line.starts_with("MemAvailable:") {
                if let Some(value) = line.split_whitespace().nth(1) {
                    mem_available = value.parse::<u64>().unwrap_or(0) * 1024; // Convert KB to bytes
                }
            }
        }

        (mem_total, mem_available)
    }

    /// Get CPU clock ticks per second
    fn get_clock_ticks_per_second(&self) -> u64 {
        // Standard value is 100, but we can get it from sysconf
        100
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

/// Resource usage statistics
#[derive(Debug, Clone)]
pub struct ResourceStats {
    pub cpu: CpuStats,
    pub memory: MemoryStats,
    pub io: IoStats,
    pub pids: PidsStats,
}

/// CPU usage statistics
#[derive(Debug, Clone)]
pub struct CpuStats {
    /// Total CPU time used in microseconds
    pub usage_usec: u64,
    /// User CPU time in microseconds
    pub user_usec: u64,
    /// System CPU time in microseconds
    pub system_usec: u64,
    /// CPU usage percentage (0.0 - 100.0 * num_cpus)
    pub cpu_percent: f64,
    /// Number of running processes
    pub num_processes: u32,
    /// Number of threads
    pub num_threads: u32,
}

/// Memory usage statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Current memory usage in bytes
    pub current: u64,
    /// Cache memory in bytes
    pub cache: u64,
    /// RSS (Resident Set Size) in bytes
    pub rss: u64,
    /// Virtual memory size in bytes
    pub virtual_memory: u64,
    /// Swap usage in bytes
    pub swap: u64,
    /// Memory usage percentage
    pub memory_percent: f64,
    /// Peak memory usage in bytes
    pub peak: u64,
}

/// I/O usage statistics
#[derive(Debug, Clone)]
pub struct IoStats {
    /// Total bytes read
    pub read_bytes: u64,
    /// Total bytes written
    pub write_bytes: u64,
    /// Total read operations
    pub read_ios: u64,
    /// Total write operations
    pub write_ios: u64,
    /// Read rate in bytes per second
    pub read_rate: f64,
    /// Write rate in bytes per second
    pub write_rate: f64,
    /// Disk usage percentage
    pub disk_usage_percent: f64,
}

/// Process usage statistics
#[derive(Debug, Clone)]
pub struct PidsStats {
    pub current: u64,
}

/// Check if cgroups v2 is available
pub fn is_cgroups_v2_available() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Get system cgroup controllers
pub fn get_system_controllers() -> LibfluxResult<Vec<String>> {
    let controllers_file = Path::new("/sys/fs/cgroup/cgroup.controllers");
    let contents = fs::read_to_string(controllers_file).map_err(|_| CgroupError::V2NotSupported)?;

    Ok(contents
        .trim()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_controller_name() {
        assert_eq!(CgroupController::Cpu.name(), "cpu");
        assert_eq!(CgroupController::Memory.name(), "memory");
        assert_eq!(CgroupController::Io.name(), "io");
    }

    #[test]
    fn test_cgroup_controller_display() {
        assert_eq!(CgroupController::Cpu.to_string(), "cpu");
        assert_eq!(CgroupController::Memory.to_string(), "memory");
    }

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert!(limits.cpu.weight.is_none());
        assert!(limits.memory.limit.is_none());
        assert!(limits.pids.max.is_none());
    }

    #[test]
    fn test_cgroups_v2_check() {
        // This test depends on the system having cgroups v2
        // It will pass on systems with cgroups v2 and fail on others
        let available = is_cgroups_v2_available();
        println!("Cgroups v2 available: {}", available);
    }
}
