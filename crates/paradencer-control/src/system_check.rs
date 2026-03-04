//! System prerequisite checks for validator operation.
//!
//! Validates that the host system meets the minimum requirements to run a
//! validator node: file descriptor limits, memory, CPU cores, disk space,
//! and Linux-specific settings (hugepages, sysctl tunables).

use std::fmt;
use std::path::Path;

/// Result of a single system check.
#[derive(Debug, Clone)]
pub struct SystemCheckResult {
    /// Human-readable check name.
    pub name: &'static str,
    /// Outcome of the check.
    pub status: CheckStatus,
    /// Detail message explaining the result.
    pub detail: String,
}

/// Check outcome severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warning,
    Error,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "FAIL"),
        }
    }
}

/// Run all system checks. When `mainnet` is true, thresholds are stricter.
pub fn run_system_checks(mainnet: bool) -> Vec<SystemCheckResult> {
    #[allow(unused_mut)]
    let mut results = vec![
        check_file_descriptor_limit(mainnet),
        check_memory(mainnet),
        check_cpu_cores(mainnet),
        check_disk_space(mainnet),
    ];
    #[cfg(target_os = "linux")]
    {
        results.push(check_hugepages());
        results.push(check_vm_max_map_count());
        results.push(check_net_buffer_sizes());
    }
    results
}

/// Format check results for terminal output.
pub fn format_system_checks(results: &[SystemCheckResult]) -> String {
    let mut lines = Vec::new();
    lines.push("System Prerequisites Check".to_string());
    lines.push("=".repeat(50));

    let mut ok_count = 0;
    let mut warn_count = 0;
    let mut err_count = 0;

    for result in results {
        let marker = match result.status {
            CheckStatus::Ok => {
                ok_count += 1;
                "+"
            }
            CheckStatus::Warning => {
                warn_count += 1;
                "~"
            }
            CheckStatus::Error => {
                err_count += 1;
                "!"
            }
        };
        lines.push(format!(
            "  [{}] {:<30} {}",
            marker, result.name, result.detail
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "Summary: {} passed, {} warnings, {} failed",
        ok_count, warn_count, err_count
    ));

    if err_count > 0 {
        lines.push("Action required: fix FAIL items before starting the validator.".to_string());
    } else if warn_count > 0 {
        lines.push(
            "Validator can start, but consider fixing WARN items for production.".to_string(),
        );
    } else {
        lines.push("All checks passed. System is ready.".to_string());
    }

    lines.join("\n")
}

/// Check that all checks passed (no errors).
pub fn all_checks_passed(results: &[SystemCheckResult]) -> bool {
    results.iter().all(|r| r.status != CheckStatus::Error)
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

fn check_file_descriptor_limit(mainnet: bool) -> SystemCheckResult {
    let min_fds: u64 = if mainnet { 1_000_000 } else { 65_536 };

    match get_soft_fd_limit() {
        Some(current) if current >= min_fds => SystemCheckResult {
            name: "File descriptor limit",
            status: CheckStatus::Ok,
            detail: format!("{current} (minimum: {min_fds})"),
        },
        Some(current) if current >= min_fds / 2 => SystemCheckResult {
            name: "File descriptor limit",
            status: CheckStatus::Warning,
            detail: format!("{current} (minimum: {min_fds}). Increase with: ulimit -n {min_fds}"),
        },
        Some(current) => SystemCheckResult {
            name: "File descriptor limit",
            status: CheckStatus::Error,
            detail: format!("{current} (minimum: {min_fds}). Increase with: ulimit -n {min_fds}"),
        },
        None => SystemCheckResult {
            name: "File descriptor limit",
            status: CheckStatus::Warning,
            detail: "Could not determine fd limit".to_string(),
        },
    }
}

fn check_memory(mainnet: bool) -> SystemCheckResult {
    let min_gb: u64 = if mainnet { 256 } else { 16 };

    match get_total_memory_gb() {
        Some(total_gb) if total_gb >= min_gb => SystemCheckResult {
            name: "System memory",
            status: CheckStatus::Ok,
            detail: format!("{total_gb} GB (minimum: {min_gb} GB)"),
        },
        Some(total_gb) if total_gb >= min_gb / 2 => SystemCheckResult {
            name: "System memory",
            status: CheckStatus::Warning,
            detail: format!("{total_gb} GB (minimum: {min_gb} GB)"),
        },
        Some(total_gb) => SystemCheckResult {
            name: "System memory",
            status: CheckStatus::Error,
            detail: format!("{total_gb} GB (minimum: {min_gb} GB)"),
        },
        None => SystemCheckResult {
            name: "System memory",
            status: CheckStatus::Warning,
            detail: "Could not determine system memory".to_string(),
        },
    }
}

fn check_cpu_cores(mainnet: bool) -> SystemCheckResult {
    let min_cores: usize = if mainnet { 12 } else { 4 };
    let available = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    if available >= min_cores {
        SystemCheckResult {
            name: "CPU cores",
            status: CheckStatus::Ok,
            detail: format!("{available} (minimum: {min_cores})"),
        }
    } else {
        SystemCheckResult {
            name: "CPU cores",
            status: if mainnet {
                CheckStatus::Error
            } else {
                CheckStatus::Warning
            },
            detail: format!("{available} (minimum: {min_cores})"),
        }
    }
}

fn check_disk_space(mainnet: bool) -> SystemCheckResult {
    let min_gb: u64 = if mainnet { 500 } else { 50 };
    let data_dir = Path::new(".");

    match get_available_disk_gb(data_dir) {
        Some(avail_gb) if avail_gb >= min_gb => SystemCheckResult {
            name: "Available disk space",
            status: CheckStatus::Ok,
            detail: format!("{avail_gb} GB (minimum: {min_gb} GB)"),
        },
        Some(avail_gb) if avail_gb >= min_gb / 2 => SystemCheckResult {
            name: "Available disk space",
            status: CheckStatus::Warning,
            detail: format!("{avail_gb} GB (minimum: {min_gb} GB)"),
        },
        Some(avail_gb) => SystemCheckResult {
            name: "Available disk space",
            status: CheckStatus::Error,
            detail: format!("{avail_gb} GB (minimum: {min_gb} GB)"),
        },
        None => SystemCheckResult {
            name: "Available disk space",
            status: CheckStatus::Warning,
            detail: "Could not determine available disk space".to_string(),
        },
    }
}

#[cfg(target_os = "linux")]
fn check_hugepages() -> SystemCheckResult {
    match read_sysfs_value("/proc/sys/vm/nr_hugepages") {
        Some(nr) if nr > 0 => SystemCheckResult {
            name: "Hugepages (2MB)",
            status: CheckStatus::Ok,
            detail: format!("{nr} pages allocated"),
        },
        Some(0) => SystemCheckResult {
            name: "Hugepages (2MB)",
            status: CheckStatus::Warning,
            detail: "0 pages. Set with: echo 2048 > /proc/sys/vm/nr_hugepages".to_string(),
        },
        _ => SystemCheckResult {
            name: "Hugepages (2MB)",
            status: CheckStatus::Warning,
            detail: "Could not read hugepages setting".to_string(),
        },
    }
}

#[cfg(target_os = "linux")]
fn check_vm_max_map_count() -> SystemCheckResult {
    let min_value: u64 = 1_000_000;
    match read_sysfs_value("/proc/sys/vm/max_map_count") {
        Some(current) if current >= min_value => SystemCheckResult {
            name: "vm.max_map_count",
            status: CheckStatus::Ok,
            detail: format!("{current} (minimum: {min_value})"),
        },
        Some(current) => SystemCheckResult {
            name: "vm.max_map_count",
            status: CheckStatus::Error,
            detail: format!(
                "{current} (minimum: {min_value}). Set with: sysctl -w vm.max_map_count={min_value}"
            ),
        },
        None => SystemCheckResult {
            name: "vm.max_map_count",
            status: CheckStatus::Warning,
            detail: "Could not read sysctl value".to_string(),
        },
    }
}

#[cfg(target_os = "linux")]
fn check_net_buffer_sizes() -> SystemCheckResult {
    let min_rmem: u64 = 134_217_728; // 128 MB
    match read_sysfs_value("/proc/sys/net/core/rmem_max") {
        Some(current) if current >= min_rmem => SystemCheckResult {
            name: "net.core.rmem_max",
            status: CheckStatus::Ok,
            detail: format!(
                "{} MB (minimum: {} MB)",
                current / 1_048_576,
                min_rmem / 1_048_576
            ),
        },
        Some(current) => SystemCheckResult {
            name: "net.core.rmem_max",
            status: CheckStatus::Warning,
            detail: format!(
                "{} MB (minimum: {} MB). Set with: sysctl -w net.core.rmem_max={min_rmem}",
                current / 1_048_576,
                min_rmem / 1_048_576
            ),
        },
        None => SystemCheckResult {
            name: "net.core.rmem_max",
            status: CheckStatus::Warning,
            detail: "Could not read sysctl value".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn get_soft_fd_limit() -> Option<u64> {
    // SAFETY: getrlimit is a standard POSIX call.
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if ret == 0 {
        Some(rlim.rlim_cur)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn get_soft_fd_limit() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn get_total_memory_gb() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
            return Some(kb / 1_048_576);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn get_total_memory_gb() -> Option<u64> {
    // SAFETY: sysctl is a standard macOS call.
    let mut size: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    let name = c"hw.memsize";
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut size as *mut u64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret == 0 {
        Some(size / (1024 * 1024 * 1024))
    } else {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_total_memory_gb() -> Option<u64> {
    None
}

fn get_available_disk_gb(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_path = CString::new(path.to_str()?).ok()?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret == 0 {
            let available_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
            Some(available_bytes / (1024 * 1024 * 1024))
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "linux")]
fn read_sysfs_value(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_checks_returns_at_least_four_results() {
        let results = run_system_checks(false);
        assert!(results.len() >= 4);
    }

    #[test]
    fn system_checks_mainnet_returns_at_least_four_results() {
        let results = run_system_checks(true);
        assert!(results.len() >= 4);
    }

    #[test]
    fn format_output_includes_summary() {
        let results = run_system_checks(false);
        let output = format_system_checks(&results);
        assert!(output.contains("Summary:"));
        assert!(output.contains("System Prerequisites Check"));
    }

    #[test]
    fn all_checks_passed_returns_true_for_all_ok() {
        let results = vec![
            SystemCheckResult {
                name: "test",
                status: CheckStatus::Ok,
                detail: "ok".to_string(),
            },
            SystemCheckResult {
                name: "test2",
                status: CheckStatus::Warning,
                detail: "warn".to_string(),
            },
        ];
        assert!(all_checks_passed(&results));
    }

    #[test]
    fn all_checks_passed_returns_false_with_error() {
        let results = vec![SystemCheckResult {
            name: "test",
            status: CheckStatus::Error,
            detail: "fail".to_string(),
        }];
        assert!(!all_checks_passed(&results));
    }

    #[test]
    fn check_status_display() {
        assert_eq!(format!("{}", CheckStatus::Ok), "OK");
        assert_eq!(format!("{}", CheckStatus::Warning), "WARN");
        assert_eq!(format!("{}", CheckStatus::Error), "FAIL");
    }

    #[test]
    fn fd_limit_check_returns_a_result() {
        let result = check_file_descriptor_limit(false);
        assert_eq!(result.name, "File descriptor limit");
        // Should not be an error on any reasonable development machine.
        assert_ne!(result.status, CheckStatus::Error);
    }

    #[test]
    fn cpu_cores_check_detects_at_least_one() {
        let result = check_cpu_cores(false);
        assert_eq!(result.name, "CPU cores");
        assert!(result.detail.contains('('));
    }

    #[test]
    fn disk_space_check_returns_a_result() {
        let result = check_disk_space(false);
        assert_eq!(result.name, "Available disk space");
    }

    #[test]
    fn memory_check_returns_a_result() {
        let result = check_memory(false);
        assert_eq!(result.name, "System memory");
    }
}
