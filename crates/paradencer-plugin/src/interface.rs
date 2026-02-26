use std::any::Any;

use crate::error::PluginResult;
use crate::types::{AccountUpdate, BlockMetadata, SlotStatus, TransactionNotification};

/// Trait for external plugins that receive streaming validator notifications.
///
/// Plugins are dynamically loaded shared libraries (`.so` on Linux, `.dylib` on macOS)
/// that implement this trait. The validator loads plugins at startup via JSON
/// configuration files specifying the library path and plugin-specific settings.
///
/// # Plugin Lifecycle
///
/// 1. Shared library loaded via dynamic linking
/// 2. `_create_plugin()` C constructor called to obtain a boxed trait object
/// 3. `on_load()` called with the config file path
/// 4. Notification callbacks invoked during validator operation
/// 5. `on_unload()` called before plugin shutdown and drop
///
/// # Thread Safety
///
/// Plugins must be `Send + Sync` since notifications may arrive from multiple
/// validator threads concurrently. All notification methods take `&self`.
///
/// # Implementing a Plugin
///
/// ```ignore
/// use paradencer_plugin::{PluginInterface, PluginResult, AccountUpdate};
///
/// #[derive(Debug)]
/// struct MyPlugin;
///
/// impl PluginInterface for MyPlugin {
///     fn name(&self) -> &'static str { "my-plugin" }
///
///     fn notify_account_update(
///         &self,
///         account: &AccountUpdate<'_>,
///         slot: u64,
///         _is_startup: bool,
///     ) -> PluginResult<()> {
///         println!("account updated at slot {slot}: {} lamports", account.lamports);
///         Ok(())
///     }
/// }
///
/// #[no_mangle]
/// pub unsafe extern "C" fn _create_plugin() -> *mut dyn PluginInterface {
///     Box::into_raw(Box::new(MyPlugin))
/// }
/// ```
pub trait PluginInterface: Any + Send + Sync + std::fmt::Debug {
    /// Returns the plugin's human-readable name.
    fn name(&self) -> &'static str;

    /// Called once after the plugin is loaded.
    ///
    /// `config_file` is the path to the JSON config file that triggered loading.
    /// The plugin can read additional settings from this file.
    /// `is_reload` is true if this load is replacing a previously loaded instance.
    fn on_load(&mut self, _config_file: &str, _is_reload: bool) -> PluginResult<()> {
        Ok(())
    }

    /// Called before the plugin is unloaded and dropped.
    ///
    /// Plugins should join all background threads, flush buffers, and release
    /// external resources in this method.
    fn on_unload(&mut self) {}

    /// Called when an account's state changes.
    ///
    /// During validator startup (snapshot loading), `is_startup` is true and
    /// accounts are delivered in bulk. After startup completes,
    /// `notify_end_of_startup()` is called once.
    ///
    /// Only called if `account_data_notifications_enabled()` returns true.
    fn notify_account_update(
        &self,
        _account: &AccountUpdate<'_>,
        _slot: u64,
        _is_startup: bool,
    ) -> PluginResult<()> {
        Ok(())
    }

    /// Called once after all startup (snapshot) account notifications are complete.
    fn notify_end_of_startup(&self) -> PluginResult<()> {
        Ok(())
    }

    /// Called after a transaction is executed within a slot.
    ///
    /// Only called if `transaction_notifications_enabled()` returns true.
    fn notify_transaction(
        &self,
        _transaction: &TransactionNotification<'_>,
        _slot: u64,
    ) -> PluginResult<()> {
        Ok(())
    }

    /// Called when a slot's consensus status changes.
    ///
    /// `parent` is the parent slot number, if known.
    fn notify_slot_status(
        &self,
        _slot: u64,
        _parent: Option<u64>,
        _status: &SlotStatus,
    ) -> PluginResult<()> {
        Ok(())
    }

    /// Called after a block completes replay with full metadata.
    fn notify_block_metadata(&self, _block: &BlockMetadata) -> PluginResult<()> {
        Ok(())
    }

    /// Whether this plugin wants account data notifications.
    ///
    /// If false, `notify_account_update()` and `notify_end_of_startup()` are
    /// never called. Default: true.
    fn account_data_notifications_enabled(&self) -> bool {
        true
    }

    /// Whether this plugin wants transaction notifications.
    ///
    /// If false, `notify_transaction()` is never called. Default: false.
    fn transaction_notifications_enabled(&self) -> bool {
        false
    }
}
