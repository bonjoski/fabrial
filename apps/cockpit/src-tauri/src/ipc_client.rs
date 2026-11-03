use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PillarHealth {
    pub pillar: String,
    pub role: String,
    pub status: String,
    pub details: String,
    #[serde(rename = "binary_path")]
    pub binary_path: Option<String>,
    #[serde(rename = "socket_path")]
    pub socket_path: Option<String>,
    #[serde(rename = "latency_ns")]
    pub latency_ns: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub name: String,
    pub state: String,
    pub pid: Option<i32>,
    pub target: Option<String>,
    pub message: String,
}

pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\fabrial")
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("fabrial").join("fabrial.sock")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".fabrial").join("fabrial.sock")
        } else {
            PathBuf::from("/tmp/fabrial.sock")
        }
    }
}

pub struct FabrialClient {
    pub socket_path: PathBuf,
    pub http_base: String,
}

impl FabrialClient {
    pub fn new() -> Self {
        Self {
            socket_path: default_socket_path(),
            http_base: "http://127.0.0.1:9191".to_string(),
        }
    }

    pub fn is_alive(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            self.socket_path.exists()
        }
        #[cfg(target_os = "windows")]
        {
            true
        }
    }
}
