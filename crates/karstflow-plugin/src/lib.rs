//! Plugin system for streaming validator notifications to external consumers.
//!
//! This crate provides the interface, types, and runtime management for
//! dynamically loaded plugins that receive account updates, transaction
//! notifications, slot status changes, and block metadata from the validator.
//!
//! # Architecture
//!
//! ```text
//!                    ┌──────────────┐
//!                    │ PluginService│
//!                    └──────┬───────┘
//!                           │ owns
//!                    ┌──────▼───────┐
//!                    │PluginManager │  ←── load/unload/reload via RPC
//!                    └──────┬───────┘
//!                           │ dispatches to
//!              ┌────────────┼────────────┐
//!              ▼            ▼            ▼
//!        ┌──────────┐ ┌──────────┐ ┌──────────┐
//!        │ Plugin A │ │ Plugin B │ │ Plugin C │  (.so / .dylib)
//!        └──────────┘ └──────────┘ └──────────┘
//! ```
//!
//! # Plugin Implementation
//!
//! External plugins implement the [`PluginInterface`] trait and export a
//! C constructor function:
//!
//! ```ignore
//! #[no_mangle]
//! pub unsafe extern "C" fn _create_plugin() -> *mut dyn PluginInterface {
//!     Box::into_raw(Box::new(MyPlugin::new()))
//! }
//! ```
//!
//! Plugins are configured via JSON files with at minimum a `"libpath"` field:
//!
//! ```json
//! {
//!     "libpath": "/path/to/libmyplugin.so",
//!     "name": "my-plugin",
//!     "custom_setting": "value"
//! }
//! ```

mod config;
mod error;
mod interface;
mod manager;
mod service;
mod types;

pub use config::PluginConfig;
pub use error::{PluginError, PluginResult};
pub use interface::PluginInterface;
pub use manager::{create_plugin_manager, PluginManager, SharedPluginManager};
pub use service::{PluginEvent, PluginService};
pub use types::{AccountUpdate, BlockMetadata, SlotStatus, TransactionNotification};
