use std::path::Path;
use std::sync::{Arc, RwLock};

use tracing::{error, info, warn};

use crate::config::PluginConfig;
use crate::error::{PluginError, PluginResult};
use crate::interface::PluginInterface;
use crate::types::{AccountUpdate, BlockMetadata, SlotStatus, TransactionNotification};

/// A loaded plugin instance paired with its dynamic library handle.
///
/// The plugin is dropped before the library to ensure cleanup completes
/// while symbols are still valid.
struct LoadedPlugin {
    plugin: Box<dyn PluginInterface>,
    /// Kept alive to prevent the library from being unloaded.
    _library: libloading::Library,
    config_path: String,
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("name", &self.plugin.name())
            .field("config", &self.config_path)
            .finish()
    }
}

/// Manages the lifecycle of dynamically loaded plugins.
///
/// Supports loading multiple plugins, querying capabilities, and delivering
/// notifications to all active plugins. Thread-safe via internal `RwLock`.
#[derive(Debug)]
pub struct PluginManager {
    plugins: Vec<LoadedPlugin>,
}

impl PluginManager {
    /// Create an empty plugin manager with no loaded plugins.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Load a plugin from a JSON configuration file.
    ///
    /// The config must contain a `"libpath"` field pointing to the shared library.
    /// The library must export a `_create_plugin` C symbol that returns a boxed
    /// `PluginInterface` trait object.
    pub fn load_plugin(&mut self, config_path: &Path) -> PluginResult<()> {
        let config = PluginConfig::from_file(config_path)?;

        // Load the shared library.
        let library = unsafe { libloading::Library::new(&config.lib_path) }.map_err(|e| {
            PluginError::LoadFailed(format!("failed to load {}: {e}", config.lib_path.display()))
        })?;

        // Look up the constructor symbol.
        // Trait objects are not FFI-safe per Rust rules, but this is the standard
        // convention for Rust plugin systems (plugin and host share the same ABI).
        #[allow(improper_ctypes_definitions)]
        type Constructor = unsafe extern "C" fn() -> *mut dyn PluginInterface;
        let constructor: libloading::Symbol<Constructor> =
            unsafe { library.get(b"_create_plugin") }.map_err(|e| {
                PluginError::LoadFailed(format!(
                    "symbol _create_plugin not found in {}: {e}",
                    config.lib_path.display()
                ))
            })?;

        // Call the constructor to get a plugin instance.
        let raw = unsafe { constructor() };
        if raw.is_null() {
            return Err(PluginError::LoadFailed(
                "_create_plugin returned null".into(),
            ));
        }
        let mut plugin = unsafe { Box::from_raw(raw) };

        // Determine the display name.
        let display_name = config.name.unwrap_or_else(|| plugin.name().to_string());

        // Check for duplicate names.
        if self.plugins.iter().any(|p| p.plugin.name() == display_name) {
            return Err(PluginError::AlreadyLoaded(display_name));
        }

        // Initialize the plugin.
        let config_file_str = config.config_file.to_string_lossy().to_string();
        plugin.on_load(&config_file_str, false)?;

        info!(plugin = %display_name, "plugin loaded");

        self.plugins.push(LoadedPlugin {
            plugin,
            _library: library,
            config_path: config_file_str,
        });

        Ok(())
    }

    /// Unload a plugin by name.
    ///
    /// Calls `on_unload()` before dropping the plugin and its library.
    pub fn unload_plugin(&mut self, name: &str) -> PluginResult<()> {
        let idx = self
            .plugins
            .iter()
            .position(|p| p.plugin.name() == name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        let mut loaded = self.plugins.remove(idx);
        loaded.plugin.on_unload();
        info!(plugin = %name, "plugin unloaded");
        // Plugin dropped first, then library — correct order.
        drop(loaded);
        Ok(())
    }

    /// Reload a plugin by name with a new (or same) config file.
    ///
    /// Unloads the existing plugin first, then loads the new one with `is_reload=true`.
    pub fn reload_plugin(&mut self, name: &str, config_path: &Path) -> PluginResult<()> {
        // Unload existing.
        if let Some(idx) = self.plugins.iter().position(|p| p.plugin.name() == name) {
            let mut loaded = self.plugins.remove(idx);
            loaded.plugin.on_unload();
            drop(loaded);
        }

        let config = PluginConfig::from_file(config_path)?;

        let library = unsafe { libloading::Library::new(&config.lib_path) }.map_err(|e| {
            PluginError::LoadFailed(format!("failed to load {}: {e}", config.lib_path.display()))
        })?;

        // Trait objects are not FFI-safe per Rust rules, but this is the standard
        // convention for Rust plugin systems (plugin and host share the same ABI).
        #[allow(improper_ctypes_definitions)]
        type Constructor = unsafe extern "C" fn() -> *mut dyn PluginInterface;
        let constructor: libloading::Symbol<Constructor> =
            unsafe { library.get(b"_create_plugin") }.map_err(|e| {
                PluginError::LoadFailed(format!(
                    "symbol _create_plugin not found in {}: {e}",
                    config.lib_path.display()
                ))
            })?;

        let raw = unsafe { constructor() };
        if raw.is_null() {
            return Err(PluginError::LoadFailed(
                "_create_plugin returned null".into(),
            ));
        }
        let mut plugin = unsafe { Box::from_raw(raw) };

        let config_file_str = config.config_file.to_string_lossy().to_string();
        plugin.on_load(&config_file_str, true)?;

        info!(plugin = %name, "plugin reloaded");

        self.plugins.push(LoadedPlugin {
            plugin,
            _library: library,
            config_path: config_file_str,
        });

        Ok(())
    }

    /// List the names of all loaded plugins.
    pub fn list_plugins(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.plugin.name()).collect()
    }

    /// Returns true if any loaded plugin wants account data notifications.
    pub fn account_data_notifications_enabled(&self) -> bool {
        self.plugins
            .iter()
            .any(|p| p.plugin.account_data_notifications_enabled())
    }

    /// Returns true if any loaded plugin wants transaction notifications.
    pub fn transaction_notifications_enabled(&self) -> bool {
        self.plugins
            .iter()
            .any(|p| p.plugin.transaction_notifications_enabled())
    }

    /// Number of loaded plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Deliver an account update to all interested plugins.
    pub fn notify_account_update(&self, account: &AccountUpdate<'_>, slot: u64, is_startup: bool) {
        for loaded in &self.plugins {
            if loaded.plugin.account_data_notifications_enabled() {
                if let Err(e) = loaded
                    .plugin
                    .notify_account_update(account, slot, is_startup)
                {
                    error!(
                        plugin = %loaded.plugin.name(),
                        %slot,
                        "account update notification failed: {e}"
                    );
                }
            }
        }
    }

    /// Deliver end-of-startup signal to all interested plugins.
    pub fn notify_end_of_startup(&self) {
        for loaded in &self.plugins {
            if loaded.plugin.account_data_notifications_enabled() {
                if let Err(e) = loaded.plugin.notify_end_of_startup() {
                    error!(
                        plugin = %loaded.plugin.name(),
                        "end-of-startup notification failed: {e}"
                    );
                }
            }
        }
    }

    /// Deliver a transaction notification to all interested plugins.
    pub fn notify_transaction(&self, transaction: &TransactionNotification<'_>, slot: u64) {
        for loaded in &self.plugins {
            if loaded.plugin.transaction_notifications_enabled() {
                if let Err(e) = loaded.plugin.notify_transaction(transaction, slot) {
                    error!(
                        plugin = %loaded.plugin.name(),
                        %slot,
                        "transaction notification failed: {e}"
                    );
                }
            }
        }
    }

    /// Deliver a slot status change to all loaded plugins.
    pub fn notify_slot_status(&self, slot: u64, parent: Option<u64>, status: &SlotStatus) {
        for loaded in &self.plugins {
            if let Err(e) = loaded.plugin.notify_slot_status(slot, parent, status) {
                error!(
                    plugin = %loaded.plugin.name(),
                    %slot,
                    "slot status notification failed: {e}"
                );
            }
        }
    }

    /// Deliver block metadata to all loaded plugins.
    pub fn notify_block_metadata(&self, block: &BlockMetadata) {
        for loaded in &self.plugins {
            if let Err(e) = loaded.plugin.notify_block_metadata(block) {
                error!(
                    plugin = %loaded.plugin.name(),
                    slot = %block.slot,
                    "block metadata notification failed: {e}"
                );
            }
        }
    }

    /// Unload all plugins. Called during shutdown.
    pub fn unload_all(&mut self) {
        for loaded in self.plugins.iter_mut() {
            loaded.plugin.on_unload();
            info!(plugin = %loaded.plugin.name(), "plugin unloaded (shutdown)");
        }
        self.plugins.clear();
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        if !self.plugins.is_empty() {
            warn!(
                count = self.plugins.len(),
                "plugin manager dropped with active plugins — calling on_unload"
            );
            self.unload_all();
        }
    }
}

/// Thread-safe wrapper around `PluginManager` for use across validator components.
pub type SharedPluginManager = Arc<RwLock<PluginManager>>;

/// Create a `SharedPluginManager`, optionally loading plugins from config files.
pub fn create_plugin_manager(config_files: &[&Path]) -> PluginResult<SharedPluginManager> {
    let mut manager = PluginManager::new();
    for config_file in config_files {
        manager.load_plugin(config_file)?;
    }
    Ok(Arc::new(RwLock::new(manager)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_manager_has_no_plugins() {
        let mgr = PluginManager::new();
        assert_eq!(mgr.plugin_count(), 0);
        assert!(mgr.list_plugins().is_empty());
        assert!(!mgr.account_data_notifications_enabled());
        assert!(!mgr.transaction_notifications_enabled());
    }

    #[test]
    fn notifications_with_no_plugins_succeed() {
        let mgr = PluginManager::new();

        let pubkey = [0u8; 32];
        let owner = [1u8; 32];
        let account = AccountUpdate {
            pubkey: &pubkey,
            lamports: 100,
            owner: &owner,
            executable: false,
            rent_epoch: 0,
            data: &[],
            write_version: 1,
            txn_signature: None,
        };
        mgr.notify_account_update(&account, 42, false);

        let sig = [0u8; 64];
        let keys: Vec<[u8; 32]> = vec![];
        let tx = TransactionNotification {
            signature: &sig,
            is_vote: false,
            index: 0,
            account_keys: &keys,
            message_data: &[],
            success: true,
            error: None,
            compute_units_consumed: 0,
            fee: 0,
        };
        mgr.notify_transaction(&tx, 42);

        mgr.notify_slot_status(42, Some(41), &SlotStatus::Processed);

        let block = BlockMetadata {
            slot: 42,
            parent_slot: 41,
            blockhash: [0; 32],
            parent_blockhash: [0; 32],
            block_time: None,
            block_height: None,
            executed_transaction_count: 0,
            entry_count: 0,
            total_compute_units: 0,
            transaction_fee: 0,
            priority_fee: 0,
        };
        mgr.notify_block_metadata(&block);

        mgr.notify_end_of_startup();
    }

    #[test]
    fn load_nonexistent_config_returns_error() {
        let mut mgr = PluginManager::new();
        let result = mgr.load_plugin(Path::new("/nonexistent/plugin.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_plugin_with_missing_library_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("plugin.json");
        std::fs::write(&config_path, r#"{"libpath": "/nonexistent/libfoo.so"}"#).unwrap();

        let mut mgr = PluginManager::new();
        let result = mgr.load_plugin(&config_path);
        assert!(matches!(result, Err(PluginError::LoadFailed(_))));
    }

    #[test]
    fn unload_nonexistent_plugin_returns_error() {
        let mut mgr = PluginManager::new();
        let result = mgr.unload_plugin("nobody");
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }

    #[test]
    fn default_creates_empty_manager() {
        let mgr = PluginManager::default();
        assert_eq!(mgr.plugin_count(), 0);
    }

    #[test]
    fn create_shared_manager_with_no_configs() {
        let shared = create_plugin_manager(&[]).unwrap();
        let mgr = shared.read().unwrap();
        assert_eq!(mgr.plugin_count(), 0);
    }
}
