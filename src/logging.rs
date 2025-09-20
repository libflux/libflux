use crate::error::*;
use crate::utils::ensure_dir_exists;
use log::{Level, LevelFilter, Metadata, Record};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Container log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
    pub container_id: Option<String>,
    pub source: LogSource,
}

/// Source of the log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogSource {
    Container,
    Runtime,
    Network,
    Filesystem,
    Cgroup,
}

/// Container logger that writes to both stdout and file
#[derive(Clone)]
pub struct ContainerLogger {
    container_id: String,
    log_file: Arc<Mutex<BufWriter<File>>>,
    console_output: bool,
}

impl ContainerLogger {
    /// Create a new container logger
    pub fn new(container_id: String, log_dir: &Path, console_output: bool) -> LibfluxResult<Self> {
        ensure_dir_exists(log_dir)?;

        let log_path = log_dir.join(format!("{}.log", container_id));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(LibfluxError::Io)?;

        let writer = BufWriter::new(file);

        Ok(ContainerLogger {
            container_id,
            log_file: Arc::new(Mutex::new(writer)),
            console_output,
        })
    }

    /// Log a message
    pub fn log(&self, level: Level, message: &str, source: LogSource) -> LibfluxResult<()> {
        let entry = LogEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            level: level.to_string(),
            message: message.to_string(),
            container_id: Some(self.container_id.clone()),
            source,
        };

        // Write to file
        if let Ok(mut writer) = self.log_file.lock() {
            let json_line = serde_json::to_string(&entry).map_err(|e| {
                LibfluxError::InvalidArgument(format!("JSON serialization failed: {}", e))
            })?;

            writeln!(writer, "{}", json_line).map_err(LibfluxError::Io)?;
            writer.flush().map_err(LibfluxError::Io)?;
        }

        // Write to console if enabled
        if self.console_output {
            let timestamp = chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                .unwrap_or_default()
                .format("%Y-%m-%d %H:%M:%S");

            println!(
                "[{}] [{}] [{}]: {}",
                timestamp,
                entry.level.to_uppercase(),
                self.container_id,
                entry.message
            );
        }

        Ok(())
    }

    /// Log info message
    pub fn info(&self, message: &str, source: LogSource) -> LibfluxResult<()> {
        self.log(Level::Info, message, source)
    }

    /// Log warning message
    pub fn warn(&self, message: &str, source: LogSource) -> LibfluxResult<()> {
        self.log(Level::Warn, message, source)
    }

    /// Log error message
    pub fn error(&self, message: &str, source: LogSource) -> LibfluxResult<()> {
        self.log(Level::Error, message, source)
    }

    /// Log debug message
    pub fn debug(&self, message: &str, source: LogSource) -> LibfluxResult<()> {
        self.log(Level::Debug, message, source)
    }

    /// Flush the log writer
    pub fn flush(&self) -> LibfluxResult<()> {
        if let Ok(mut writer) = self.log_file.lock() {
            writer.flush().map_err(LibfluxError::Io)?;
        }
        Ok(())
    }
}

/// Global libflux logger
pub struct LibfluxLogger {
    level: LevelFilter,
    log_dir: Option<PathBuf>,
}

impl LibfluxLogger {
    /// Create a new libflux logger
    pub fn new(level: LevelFilter, log_dir: Option<PathBuf>) -> Self {
        LibfluxLogger { level, log_dir }
    }

    /// Initialize the global logger
    pub fn init(level: LevelFilter, log_dir: Option<PathBuf>) -> LibfluxResult<()> {
        let logger = LibfluxLogger::new(level, log_dir);

        log::set_boxed_logger(Box::new(logger))
            .map_err(|e| LibfluxError::InvalidArgument(format!("Failed to set logger: {}", e)))?;

        log::set_max_level(level);
        Ok(())
    }
}

impl log::Log for LibfluxLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f");

            println!(
                "[{}] [{}] [{}]: {}",
                timestamp,
                record.level(),
                record.module_path().unwrap_or("unknown"),
                record.args()
            );

            // Also write to file if log directory is configured
            if let Some(ref log_dir) = self.log_dir {
                if let Ok(_) = ensure_dir_exists(log_dir) {
                    let log_path = log_dir.join("libflux.log");
                    if let Ok(mut file) =
                        OpenOptions::new().create(true).append(true).open(&log_path)
                    {
                        let _ = writeln!(
                            file,
                            "[{}] [{}] [{}]: {}",
                            timestamp,
                            record.level(),
                            record.module_path().unwrap_or("unknown"),
                            record.args()
                        );
                    }
                }
            }
        }
    }

    fn flush(&self) {
        io::stdout().flush().unwrap_or(());
    }
}

/// Container output capture
pub struct OutputCapture {
    stdout_logger: ContainerLogger,
    stderr_logger: ContainerLogger,
}

impl OutputCapture {
    /// Create a new output capture for a container
    pub fn new(container_id: String, log_dir: &Path, console_output: bool) -> LibfluxResult<Self> {
        let stdout_logger =
            ContainerLogger::new(format!("{}-stdout", container_id), log_dir, console_output)?;

        let stderr_logger =
            ContainerLogger::new(format!("{}-stderr", container_id), log_dir, console_output)?;

        Ok(OutputCapture {
            stdout_logger,
            stderr_logger,
        })
    }

    /// Log stdout output
    pub fn log_stdout(&self, message: &str) -> LibfluxResult<()> {
        self.stdout_logger.info(message, LogSource::Container)
    }

    /// Log stderr output
    pub fn log_stderr(&self, message: &str) -> LibfluxResult<()> {
        self.stderr_logger.error(message, LogSource::Container)
    }

    /// Flush both loggers
    pub fn flush(&self) -> LibfluxResult<()> {
        self.stdout_logger.flush()?;
        self.stderr_logger.flush()?;
        Ok(())
    }
}

/// Read log entries from a log file
pub fn read_logs(log_path: &Path, lines: Option<usize>) -> LibfluxResult<Vec<LogEntry>> {
    use std::io::{BufRead, BufReader};

    let file = File::open(log_path).map_err(LibfluxError::Io)?;
    let reader = BufReader::new(file);

    let all_lines: Result<Vec<String>, _> = reader.lines().collect();
    let all_lines = all_lines.map_err(LibfluxError::Io)?;

    let lines_to_take = lines.unwrap_or(all_lines.len());
    let lines_to_process = if all_lines.len() > lines_to_take {
        &all_lines[all_lines.len() - lines_to_take..]
    } else {
        &all_lines
    };

    let mut entries = Vec::new();
    for line in lines_to_process {
        if let Ok(entry) = serde_json::from_str::<LogEntry>(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Tail log entries from a log file (follow mode)
pub async fn tail_logs<F>(
    log_path: &Path,
    lines: Option<usize>,
    mut callback: F,
) -> LibfluxResult<()>
where
    F: FnMut(LogEntry) -> bool, // Return false to stop tailing
{
    use tokio::fs::File;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::time::{sleep, Duration};

    // First, read existing entries
    if let Ok(existing_entries) = read_logs(log_path, lines) {
        for entry in existing_entries {
            if !callback(entry) {
                return Ok(());
            }
        }
    }

    // Then, tail new entries
    loop {
        if let Ok(file) = File::open(log_path).await {
            let reader = BufReader::new(file);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(entry) = serde_json::from_str::<LogEntry>(&line) {
                    if !callback(entry) {
                        return Ok(());
                    }
                }
            }
        }

        // Wait a bit before checking for new entries
        sleep(Duration::from_millis(100)).await;
    }
}

/// Convert log level string to LevelFilter
pub fn parse_log_level(level: &str) -> LevelFilter {
    match level.to_lowercase().as_str() {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" | "warning" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("error"), LevelFilter::Error);
        assert_eq!(parse_log_level("INFO"), LevelFilter::Info);
        assert_eq!(parse_log_level("debug"), LevelFilter::Debug);
        assert_eq!(parse_log_level("invalid"), LevelFilter::Info);
    }

    #[test]
    fn test_container_logger() {
        let temp_dir = TempDir::new().unwrap();
        let logger =
            ContainerLogger::new("test-container".to_string(), temp_dir.path(), false).unwrap();

        logger.info("Test message", LogSource::Container).unwrap();
        logger.flush().unwrap();

        let log_path = temp_dir.path().join("test-container.log");
        assert!(log_path.exists());

        let logs = read_logs(&log_path, None).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "Test message");
        assert_eq!(logs[0].level, "INFO");
    }
}
