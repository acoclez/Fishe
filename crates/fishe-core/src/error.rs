//! Application error type.
//!
//! Every Tauri command returns `AppResult<T>`. Errors are serialised to the
//! frontend as `{ code, message }` so the UI can branch on `code` and display
//! `message` as-is.

use serde::{Serialize, Serializer, ser::SerializeStruct};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("capture is not available: {0}")]
    NpcapUnavailable(String),

    #[error("\"{0}\" is not a valid IP address or resolvable host name")]
    InvalidTarget(String),

    #[error("network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("no usable network interface found to reach {0}")]
    NoRoute(String),

    #[error("process not found: {0}")]
    ProcessNotFound(String),

    #[error("packet capture failed: {0}")]
    Capture(#[from] pcap::Error),

    /// The named thing (a recording, a file) doesn't exist.
    #[error("{0}")]
    NotFound(String),

    /// The caller's input is out of range or not allowed.
    #[error("{0}")]
    InvalidArgument(String),

    /// Right request, wrong moment: nothing is running, or something still is.
    #[error("{0}")]
    InvalidState(String),

    /// A limit is reached or the resource is already in use; retry later.
    #[error("{0}")]
    Busy(String),

    /// A feature this build or machine doesn't offer (no owner database,
    /// process mode on a system other than Windows and Linux).
    #[error("{0}")]
    Unavailable(String),

    /// File or network I/O, with what was being done.
    #[error("{0}")]
    Io(String),

    #[error("{0}")]
    Internal(String),
}

impl AppError {
    /// Stable machine-readable identifier sent to the UI.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::NpcapUnavailable(_) => "npcap_unavailable",
            AppError::InvalidTarget(_) => "invalid_target",
            AppError::InterfaceNotFound(_) => "interface_not_found",
            AppError::NoRoute(_) => "no_route",
            AppError::ProcessNotFound(_) => "process_not_found",
            AppError::Capture(_) => "capture",
            AppError::NotFound(_) => "not_found",
            AppError::InvalidArgument(_) => "invalid_argument",
            AppError::InvalidState(_) => "invalid_state",
            AppError::Busy(_) => "busy",
            AppError::Unavailable(_) => "unavailable",
            AppError::Io(_) => "io",
            AppError::Internal(_) => "internal",
        }
    }

    /// `Io` with the operation that failed: `io("cannot write x", e)`.
    pub fn io(what: impl std::fmt::Display, e: impl std::fmt::Display) -> Self {
        AppError::Io(format!("{what}: {e}"))
    }
}

impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

// The shape `Serialize` above produces, so the generated TypeScript matches.
const _: () = {
    #[derive(specta::Type)]
    #[specta(remote = crate::error::AppError)]
    #[allow(dead_code)]
    struct AppError {
        /// Stable machine-readable identifier (see `AppError::code`).
        code: String,
        message: String,
    }
};
