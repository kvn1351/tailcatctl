//! Password-free, atomically persisted multi-device connection registry.
//!
//! The registry is the durable source of endpoint settings. Passwords in a
//! [`Config`] are never persisted to disk and are stripped before writing.

use crate::Config;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VERSION: u32 = 1;
const DEFAULT_ENDPOINT: &str = "tailcat";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn default_version() -> u32 {
    VERSION
}
fn default_revision() -> u64 {
    0
}
fn default_active_endpoint() -> String {
    DEFAULT_ENDPOINT.to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub active_device_id: String,
    #[serde(default = "default_active_endpoint")]
    pub active_endpoint: String,
    #[serde(default = "default_revision")]
    pub revision: u64,
    #[serde(default)]
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    #[serde(alias = "alias")]
    pub name: String,
    #[serde(default)]
    pub lan: Option<Config>,
    #[serde(default)]
    pub tailcat: Option<Config>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, Value>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            version: VERSION,
            active_device_id: String::new(),
            active_endpoint: DEFAULT_ENDPOINT.to_owned(),
            revision: 0,
            devices: Vec::new(),
        }
    }
}

impl Device {
    pub fn new(id: String, name: String) -> Self {
        Self {
            id,
            name,
            lan: None,
            tailcat: None,
            metadata: HashMap::new(),
        }
    }

    /// Alias for backward compatibility with code using `.alias`.
    pub fn alias(&self) -> &str {
        &self.name
    }
}

pub fn registry_path() -> Result<PathBuf, String> {
    if let Some(custom) = env::var_os("TAILCATCTL_CONFIG_DIR")
        .or_else(|| env::var_os("TAILCAT_CONFIG_DIR"))
        .filter(|p| !p.is_empty())
    {
        return Ok(PathBuf::from(custom).join("devices.json"));
    }

    let root = env::var_os("XDG_CONFIG_HOME")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(|p| !p.is_empty())
                .map(|p| PathBuf::from(p).join(".config"))
        })
        .ok_or_else(|| {
            "cannot determine configuration directory (XDG_CONFIG_HOME/HOME unset)".to_owned()
        })?;

    let tailcat_path = root.join("tailcat").join("devices.json");
    if tailcat_path.exists() {
        return Ok(tailcat_path);
    }

    // One-time fallback check for legacy kindle-link config if tailcat config doesn't exist
    let legacy_path = root.join("kindle-link").join("devices.json");
    if legacy_path.exists() {
        return Ok(legacy_path);
    }

    Ok(tailcat_path)
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "registry path has no parent".to_owned())?;
    fs::create_dir_all(dir).map_err(|e| format!("cannot create registry directory: {}", e))?;
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| format!("cannot open registry directory securely: {}", e))?;
    let metadata = dir_file
        .metadata()
        .map_err(|e| format!("cannot inspect registry directory: {}", e))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("registry directory must be a real directory".to_owned());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("registry directory is not owned by the current user".to_owned());
    }
    dir_file
        .set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot secure registry directory: {}", e))?;
    let _ = dir_file.sync_all();
    Ok(())
}

pub struct RegistryLock {
    file: File,
}

impl Drop for RegistryLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn lock_registry(path: &Path, exclusive: bool) -> Result<RegistryLock, String> {
    ensure_private_dir(path)?;
    let lock_path = path.with_file_name("devices.json.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|e| format!("cannot open registry lock: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect registry lock: {}", e))?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("registry lock is not a private regular file".to_owned());
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot secure registry lock: {}", e))?;
    let mode = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    let result = unsafe { libc::flock(file.as_raw_fd(), mode) };
    if result != 0 {
        return Err(format!(
            "cannot lock registry: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(RegistryLock { file })
}

pub fn load_registry(path: &Path) -> Result<Registry, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Registry::default()),
        Err(error) => return Err(format!("cannot open registry: {}", error)),
    };
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect registry: {}", e))?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err("registry is not a private regular file".to_owned());
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot secure registry file: {}", e))?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| format!("cannot read registry: {}", e))?;
    let registry: Registry =
        serde_json::from_str(&text).map_err(|e| format!("invalid registry: {}", e))?;
    validate_registry(&registry)?;
    Ok(registry)
}

fn clear_password(config: &mut Config) {
    config.password.clear();
}

fn persisted_registry(registry: &Registry) -> Registry {
    let mut result = registry.clone();
    for device in &mut result.devices {
        if let Some(config) = &mut device.lan {
            clear_password(config);
        }
        if let Some(config) = &mut device.tailcat {
            clear_password(config);
        }
    }
    result
}

fn commit(path: &Path, registry: &mut Registry) -> Result<(), String> {
    registry.revision = registry.revision.saturating_add(1);
    validate_registry(registry)?;
    let persisted = persisted_registry(registry);
    let bytes = serde_json::to_vec_pretty(&persisted)
        .map_err(|e| format!("cannot serialize registry: {}", e))?;
    ensure_private_dir(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "registry path has no parent".to_owned())?;
    let temp_name = format!(
        ".devices.json.tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let temp_path = parent.join(temp_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|e| format!("cannot create temporary registry: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("cannot write temporary registry: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("cannot flush temporary registry: {}", e))?;
    drop(file);
    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        format!("cannot replace registry file: {}", e)
    })?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|e| format!("cannot open registry directory for sync: {}", e))?;
    let _ = dir.sync_all();
    Ok(())
}

fn validate_registry(registry: &Registry) -> Result<(), String> {
    if registry.version != VERSION {
        return Err(format!(
            "unsupported registry version {} (expected {})",
            registry.version, VERSION
        ));
    }
    if registry.active_endpoint != "lan" && registry.active_endpoint != "tailcat" {
        return Err("active_endpoint must be 'lan' or 'tailcat'".to_owned());
    }
    let mut ids = std::collections::HashSet::new();
    for device in &registry.devices {
        validate_id(&device.id)?;
        validate_name(&device.name)?;
        if !ids.insert(&device.id) {
            return Err(format!("duplicate device id: {}", device.id));
        }
        if device.lan.is_none() && device.tailcat.is_none() {
            return Err(format!(
                "device {} must have at least one endpoint configured",
                device.id
            ));
        }
        if let Some(config) = &device.lan {
            config.validate()?;
        }
        if let Some(config) = &device.tailcat {
            config.validate()?;
        }
    }
    if !registry.active_device_id.is_empty() {
        validate_id(&registry.active_device_id)?;
        let active = registry
            .devices
            .iter()
            .find(|d| d.id == registry.active_device_id)
            .ok_or_else(|| {
                format!(
                    "active device {} does not exist in registry",
                    registry.active_device_id
                )
            })?;
        if registry.active_endpoint == "lan" && active.lan.is_none() {
            return Err("active device has no lan endpoint".to_owned());
        }
        if registry.active_endpoint == "tailcat" && active.tailcat.is_none() {
            return Err("active device has no tailcat endpoint".to_owned());
        }
    }
    Ok(())
}

pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "invalid device id {:?}: must be 1-64 characters matching [a-zA-Z0-9._-]",
            id
        ));
    }
    Ok(())
}

pub fn validate_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 || trimmed.chars().any(|c| c.is_control()) {
        return Err(format!(
            "invalid device name {:?}: must be 1-64 non-control characters",
            name
        ));
    }
    Ok(())
}

pub fn normalized_alias(value: &str) -> String {
    let trimmed = value.trim();
    for suffix in ["(Tailcat)", "(Tailscale)"] {
        if let Some(prefix) = trimmed.strip_suffix(suffix) {
            let prefix = prefix.trim();
            if !prefix.is_empty() {
                return prefix.to_owned();
            }
        }
    }
    trimmed.to_owned()
}

pub fn is_tailcat_address(host: &str) -> bool {
    host.starts_with("tc") && !host.contains('.') && host.len() >= 20
}

fn hash_id(parts: &[&str]) -> String {
    let mut hasher: u64 = 0xcbf29ce484222325;
    for part in parts {
        for byte in part.as_bytes() {
            hasher ^= *byte as u64;
            hasher = hasher.wrapping_mul(0x100000001b3);
        }
        hasher ^= 0xff;
        hasher = hasher.wrapping_mul(0x100000001b3);
    }
    format!("dev_{:016x}", hasher)
}

pub fn list() -> Result<Registry, String> {
    let path = registry_path()?;
    let _lock = lock_registry(&path, false)?;
    load_registry(&path)
}

pub fn find_device(query: &str) -> Result<Device, String> {
    find_device_with_endpoint(query, None)
}

pub fn find_device_with_endpoint(query: &str, preferred_ep: Option<&str>) -> Result<Device, String> {
    let path = registry_path()?;
    let _lock = lock_registry(&path, false)?;
    let registry = load_registry(&path)?;

    // 1. Exact ID match
    if let Some(dev) = registry.devices.iter().find(|d| d.id == query) {
        return Ok(dev.clone());
    }

    // 2. Prefix match on ID (if query is at least 4 hex characters)
    if query.len() >= 4 {
        let id_matches: Vec<_> = registry
            .devices
            .iter()
            .filter(|d| d.id.starts_with(query))
            .collect();
        if id_matches.len() == 1 {
            return Ok((*id_matches[0]).clone());
        } else if id_matches.len() > 1 {
            return Err(format!("device ID prefix {:?} is ambiguous", query));
        }
    }

    // 3. Exact Name match (case-insensitive)
    let query_lower = query.to_ascii_lowercase();
    let exact_matches: Vec<_> = registry
        .devices
        .iter()
        .filter(|d| d.name.to_ascii_lowercase() == query_lower)
        .collect();

    if exact_matches.len() == 1 {
        return Ok(exact_matches[0].clone());
    } else if exact_matches.len() > 1 {
        // Disambiguate by endpoint if specified (e.g. "Kindle:tailcat" vs "Kindle:lan")
        if let Some(ep) = preferred_ep {
            let ep_matches: Vec<_> = exact_matches
                .iter()
                .filter(|d| match ep {
                    "lan" => d.lan.is_some(),
                    "tailcat" => d.tailcat.is_some(),
                    _ => false,
                })
                .collect();
            if ep_matches.len() == 1 {
                return Ok((*ep_matches[0]).clone());
            }
        }
        return Err(format!("device name {:?} is ambiguous (matches {} devices)", query, exact_matches.len()));
    }

    // 4. Prefix match on Name (case-insensitive)
    let prefix_matches: Vec<_> = registry
        .devices
        .iter()
        .filter(|d| d.name.to_ascii_lowercase().starts_with(&query_lower))
        .collect();

    if prefix_matches.len() == 1 {
        return Ok(prefix_matches[0].clone());
    } else if prefix_matches.len() > 1 {
        if let Some(ep) = preferred_ep {
            let ep_matches: Vec<_> = prefix_matches
                .iter()
                .filter(|d| match ep {
                    "lan" => d.lan.is_some(),
                    "tailcat" => d.tailcat.is_some(),
                    _ => false,
                })
                .collect();
            if ep_matches.len() == 1 {
                return Ok((*ep_matches[0]).clone());
            }
        }
        return Err(format!("device prefix {:?} is ambiguous", query));
    }

    Err(format!("no device found matching {:?}", query))
}

/// Resolves a target string (e.g. "kindle", "kindle:lan", "tc...", "192.168.1.50")
/// into a (Device, Config) pair.
pub fn resolve_target(
    target: &str,
    preferred_endpoint: Option<&str>,
) -> Result<(Option<Device>, Config), String> {
    let (base_query, endpoint_spec) = if let Some((base, ep)) = target.rsplit_once(':') {
        if ep == "lan" || ep == "tailcat" {
            (base, Some(ep))
        } else {
            (target, None)
        }
    } else {
        (target, None)
    };

    let desired_endpoint = endpoint_spec.or(preferred_endpoint);

    // Try finding registered device
    match find_device_with_endpoint(base_query, desired_endpoint) {
        Ok(dev) => {
            let ep = match desired_endpoint {
                Some("lan") => {
                    dev.lan.clone().ok_or_else(|| {
                        format!("device {:?} has no LAN endpoint configured", dev.name)
                    })?
                }
                Some("tailcat") => {
                    dev.tailcat.clone().ok_or_else(|| {
                        format!("device {:?} has no Tailcat endpoint configured", dev.name)
                    })?
                }
                Some(other) => return Err(format!("unknown endpoint type {:?}", other)),
                None => {
                    let path = registry_path()?;
                    let active_ep = load_registry(&path)
                        .map(|r| r.active_endpoint)
                        .unwrap_or_else(|_| "tailcat".to_string());
                    match active_ep.as_str() {
                        "lan" if dev.lan.is_some() => dev.lan.clone().unwrap(),
                        "tailcat" if dev.tailcat.is_some() => dev.tailcat.clone().unwrap(),
                        _ => {
                            if let Some(tc) = &dev.tailcat {
                                tc.clone()
                            } else if let Some(lan) = &dev.lan {
                                lan.clone()
                            } else {
                                return Err(format!("device {:?} has no configured endpoints", dev.name));
                            }
                        }
                    }
                }
            };
            return Ok((Some(dev), ep));
        }
        Err(err) if err.contains("ambiguous") => {
            return Err(err);
        }
        Err(_) => {}
    }

    // Check if target matches an endpoint host of any registered device
    let path = registry_path()?;
    let _lock = lock_registry(&path, false)?;
    let registry = load_registry(&path)?;

    for dev in &registry.devices {
        if let Some(tc) = &dev.tailcat {
            if tc.host == target || tc.host.eq_ignore_ascii_case(target) {
                return Ok((Some(dev.clone()), tc.clone()));
            }
        }
        if let Some(lan) = &dev.lan {
            if lan.host == target || lan.host.eq_ignore_ascii_case(target) {
                return Ok((Some(dev.clone()), lan.clone()));
            }
        }
    }

    // Direct ad-hoc host (e.g. tc... or IP address)
    let mut config = Config::default();
    config.host = target.to_owned();
    config.validate()?;
    Ok((None, config))
}

pub fn resolve(device_id: Option<&str>, prefer_lan: bool) -> Result<(Device, Config), String> {
    let path = registry_path()?;
    let _lock = lock_registry(&path, false)?;
    let registry = load_registry(&path)?;
    let id = match device_id {
        Some(id) if !id.is_empty() => id,
        _ if !registry.active_device_id.is_empty() => registry.active_device_id.as_str(),
        _ if !registry.devices.is_empty() => registry.devices[0].id.as_str(),
        _ => return Err("no devices are configured in registry".to_owned()),
    };

    let device = registry
        .devices
        .iter()
        .find(|d| d.id == id || d.name.eq_ignore_ascii_case(id))
        .ok_or_else(|| format!("device {:?} was not found in registry", id))?
        .clone();

    let config = if prefer_lan {
        device
            .lan
            .clone()
            .or_else(|| device.tailcat.clone())
            .ok_or_else(|| format!("device {} has no endpoints configured", device.id))?
    } else if registry.active_device_id == device.id && registry.active_endpoint == "lan" {
        device
            .lan
            .clone()
            .or_else(|| device.tailcat.clone())
            .ok_or_else(|| format!("device {} has no endpoints configured", device.id))?
    } else {
        device
            .tailcat
            .clone()
            .or_else(|| device.lan.clone())
            .ok_or_else(|| format!("device {} has no endpoints configured", device.id))?
    };

    Ok((device, config))
}

pub fn select(id_or_name: &str, endpoint_override: Option<&str>) -> Result<(Device, String), String> {
    let (base_query, endpoint_spec) = if let Some((base, ep)) = id_or_name.rsplit_once(':') {
        if ep == "lan" || ep == "tailcat" {
            (base, Some(ep))
        } else {
            (id_or_name, None)
        }
    } else {
        (id_or_name, None)
    };
    let desired_ep = endpoint_override.or(endpoint_spec);

    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let mut registry = load_registry(&path)?;

    let target_id = {
        let exact_id = registry.devices.iter().find(|d| d.id == base_query);
        if let Some(d) = exact_id {
            d.id.clone()
        } else {
            let matches: Vec<_> = registry
                .devices
                .iter()
                .filter(|d| d.name.eq_ignore_ascii_case(base_query))
                .collect();
            if matches.len() == 1 {
                matches[0].id.clone()
            } else if matches.len() > 1 {
                return Err(format!("device name {:?} is ambiguous", base_query));
            } else {
                return Err(format!("device {:?} not found", base_query));
            }
        }
    };

    let device = registry
        .devices
        .iter()
        .find(|d| d.id == target_id)
        .cloned()
        .unwrap();

    registry.active_device_id = target_id;
    if let Some(ep) = desired_ep {
        match ep {
            "lan" => {
                if device.lan.is_none() {
                    return Err(format!("device {:?} has no LAN endpoint configured", device.name));
                }
                registry.active_endpoint = "lan".to_owned();
            }
            "tailcat" => {
                if device.tailcat.is_none() {
                    return Err(format!("device {:?} has no Tailcat endpoint configured", device.name));
                }
                registry.active_endpoint = "tailcat".to_owned();
            }
            other => return Err(format!("unknown endpoint type {:?}", other)),
        }
    } else {
        if registry.active_endpoint == "lan" && device.lan.is_none() {
            registry.active_endpoint = "tailcat".to_owned();
        } else if registry.active_endpoint == "tailcat" && device.tailcat.is_none() {
            registry.active_endpoint = "lan".to_owned();
        }
    }

    commit(&path, &mut registry)?;
    Ok((device, registry.active_endpoint.clone()))
}

pub fn upsert_device(device: Device) -> Result<Device, String> {
    validate_id(&device.id)?;
    validate_name(&device.name)?;
    if let Some(cfg) = &device.lan {
        cfg.validate()?;
    }
    if let Some(cfg) = &device.tailcat {
        cfg.validate()?;
    }
    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let mut registry = load_registry(&path)?;

    let index = registry
        .devices
        .iter()
        .position(|d| d.id == device.id || d.name.eq_ignore_ascii_case(&device.name));
    if let Some(i) = index {
        registry.devices.remove(i);
    }
    let result = device.clone();
    registry.devices.push(device);

    if registry.active_device_id.is_empty() {
        registry.active_device_id = result.id.clone();
        registry.active_endpoint = if result.tailcat.is_some() {
            "tailcat".to_owned()
        } else {
            "lan".to_owned()
        };
    }

    commit(&path, &mut registry)?;
    Ok(result)
}

pub fn upsert_endpoint(
    config: Config,
    device_id: Option<&str>,
    name: Option<&str>,
    endpoint_type: Option<&str>,
    metadata: Option<HashMap<String, Value>>,
) -> Result<Device, String> {
    config.validate()?;
    let is_tc = match endpoint_type {
        Some("tailcat") => true,
        Some("lan") => false,
        _ => is_tailcat_address(&config.host),
    };

    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let mut registry = load_registry(&path)?;

    let chosen_name = name
        .map(normalized_alias)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "device".to_owned());

    let id = match device_id {
        Some(id) if !id.is_empty() => {
            validate_id(id)?;
            id.to_owned()
        }
        _ => {
            if let Some(existing) = registry
                .devices
                .iter()
                .find(|d| d.name.eq_ignore_ascii_case(&chosen_name))
            {
                existing.id.clone()
            } else {
                hash_id(&["device", &chosen_name, &config.host, &config.port.to_string()])
            }
        }
    };

    let index = registry.devices.iter().position(|d| d.id == id);
    let mut device = match index {
        Some(i) => registry.devices.remove(i),
        None => Device::new(id.clone(), chosen_name.clone()),
    };

    if name.is_some() {
        device.name = chosen_name;
    }
    if let Some(meta) = metadata {
        device.metadata.extend(meta);
    }

    if is_tc {
        device.tailcat = Some(config);
    } else {
        device.lan = Some(config);
    }

    let result = device.clone();
    registry.devices.push(device);

    if registry.active_device_id.is_empty() {
        registry.active_device_id = result.id.clone();
        registry.active_endpoint = if is_tc {
            "tailcat".to_owned()
        } else {
            "lan".to_owned()
        };
    }

    commit(&path, &mut registry)?;
    Ok(result)
}

pub fn remove_device(id_or_name: &str) -> Result<Device, String> {
    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let mut registry = load_registry(&path)?;

    let index = registry
        .devices
        .iter()
        .position(|d| {
            d.id == id_or_name
                || d.name.eq_ignore_ascii_case(id_or_name)
                || d.lan.as_ref().map_or(false, |l| {
                    l.host == id_or_name
                        || format!("{}:{}", l.host, l.port) == id_or_name
                        || (id_or_name.len() >= 8 && l.host.starts_with(id_or_name))
                })
                || d.tailcat.as_ref().map_or(false, |t| {
                    t.host == id_or_name
                        || format!("{}:{}", t.host, t.port) == id_or_name
                        || (id_or_name.len() >= 8 && t.host.starts_with(id_or_name))
                })
        })
        .ok_or_else(|| format!("device {:?} not found", id_or_name))?;

    let removed = registry.devices.remove(index);

    if registry.active_device_id == removed.id {
        if let Some(first) = registry.devices.first() {
            registry.active_device_id = first.id.clone();
            registry.active_endpoint = if first.tailcat.is_some() {
                "tailcat".to_owned()
            } else {
                "lan".to_owned()
            };
        } else {
            registry.active_device_id.clear();
        }
    }

    commit(&path, &mut registry)?;
    Ok(removed)
}

pub fn remove_tailcat(device_id: &str) -> Result<Device, String> {
    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let mut registry = load_registry(&path)?;

    let device = registry
        .devices
        .iter_mut()
        .find(|d| d.id == device_id || d.name.eq_ignore_ascii_case(device_id))
        .ok_or_else(|| format!("device {:?} was not found", device_id))?;

    device.tailcat = None;
    if device.lan.is_none() {
        return Err("cannot remove tailcat: device has no lan endpoint to retain".to_owned());
    }

    if registry.active_device_id == device.id && registry.active_endpoint == "tailcat" {
        registry.active_endpoint = "lan".to_owned();
    }

    let result = device.clone();
    commit(&path, &mut registry)?;
    Ok(result)
}

pub fn record_setup(
    lan_config: Config,
    tailcat_address: &str,
    device_id: Option<&str>,
    name: Option<&str>,
    metadata: Option<HashMap<String, Value>>,
) -> Result<Device, String> {
    lan_config.validate()?;
    if !is_tailcat_address(tailcat_address) {
        return Err(format!(
            "invalid tailcat address format: {:?}",
            tailcat_address
        ));
    }
    let mut tc_config = lan_config.clone();
    tc_config.host = tailcat_address.to_owned();
    tc_config.port = 22;

    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let mut registry = load_registry(&path)?;

    let base_name = name
        .map(normalized_alias)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "device".to_owned());

    let id = match device_id {
        Some(id) if !id.is_empty() => {
            validate_id(id)?;
            id.to_owned()
        }
        _ => {
            if let Some(existing) = registry
                .devices
                .iter()
                .find(|d| d.name.eq_ignore_ascii_case(&base_name))
            {
                existing.id.clone()
            } else {
                hash_id(&["device", &base_name, &lan_config.host, &lan_config.port.to_string()])
            }
        }
    };

    let index = registry.devices.iter().position(|d| d.id == id);
    let mut device = match index {
        Some(i) => registry.devices.remove(i),
        None => Device::new(id.clone(), base_name.clone()),
    };

    device.name = base_name;
    device.lan = Some(lan_config);
    device.tailcat = Some(tc_config);
    if let Some(meta) = metadata {
        device.metadata.extend(meta);
    }

    let result = device.clone();
    registry.devices.push(device);
    registry.active_device_id = result.id.clone();
    registry.active_endpoint = "tailcat".to_owned();

    commit(&path, &mut registry)?;
    Ok(result)
}

// Frontend export/sync for UI adapters (Calibre plugin, etc.)
fn frontend_from_registry(registry: &Registry) -> Value {
    let mut rows = Vec::new();

    for device in &registry.devices {
        if let Some(lan) = &device.lan {
            rows.push(frontend_row(device, "lan", lan));
        }
        if let Some(tc) = &device.tailcat {
            rows.push(frontend_row(device, "tailcat", tc));
        }
    }

    let active_id = if registry.active_device_id.is_empty() {
        Value::Null
    } else {
        Value::String(format!(
            "{}:{}",
            registry.active_device_id, registry.active_endpoint
        ))
    };

    json!({
        "revision": registry.revision,
        "active_id": active_id,
        "devices": rows,
    })
}

pub fn frontend() -> Result<Value, String> {
    let path = registry_path()?;
    let _lock = lock_registry(&path, false)?;
    let registry = load_registry(&path)?;
    Ok(frontend_from_registry(&registry))
}

fn frontend_row(device: &Device, endpoint: &str, config: &Config) -> Value {
    let alias = if endpoint == "tailcat" {
        format!("{} (Tailcat)", device.name)
    } else {
        device.name.clone()
    };

    let mut map = Map::new();
    map.insert("id".into(), Value::String(format!("{}:{}", device.id, endpoint)));
    map.insert("device_id".into(), Value::String(device.id.clone()));
    map.insert("alias".into(), Value::String(alias));
    map.insert("name".into(), Value::String(device.name.clone()));
    map.insert("endpoint".into(), Value::String(endpoint.into()));
    map.insert("host".into(), Value::String(config.host.clone()));
    map.insert("port".into(), json!(config.port));
    map.insert("username".into(), Value::String(config.username.clone()));
    map.insert("identity_file".into(), Value::String(config.identity_file.clone()));
    map.insert("known_hosts".into(), Value::String(config.known_hosts.clone()));
    map.insert("ssh_executable".into(), Value::String(config.ssh_executable.clone()));
    map.insert("tailcat_executable".into(), Value::String(config.tailcat_executable.clone()));
    map.insert("sftp_executable".into(), Value::String(config.sftp_executable.clone()));
    map.insert("timeout".into(), json!(config.timeout));

    for (k, v) in &device.metadata {
        map.insert(k.clone(), v.clone());
    }

    Value::Object(map)
}

pub fn sync_frontend(value: Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "frontend sync input must be an object".to_owned())?;
    let requested_revision = match object.get("revision") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => Some(
            n.as_u64()
                .ok_or_else(|| "revision must be a non-negative integer".to_owned())?,
        ),
        _ => return Err("revision must be a number or null".to_owned()),
    };

    let active_id = object
        .get("active_id")
        .and_then(Value::as_str)
        .unwrap_or("");

    let rows = object
        .get("devices")
        .and_then(Value::as_array)
        .ok_or_else(|| "frontend devices must be an array".to_owned())?;

    let path = registry_path()?;
    let _lock = lock_registry(&path, true)?;
    let current = load_registry(&path)?;

    if let Some(expected) = requested_revision {
        if expected != current.revision {
            return Err(format!(
                "stale profile revision (expected {}, current {})",
                expected, current.revision
            ));
        }
    }

    let mut groups: BTreeMap<String, Device> = BTreeMap::new();

    for row in rows {
        let row_obj = row
            .as_object()
            .ok_or_else(|| "device row must be an object".to_owned())?;

        let endpoint = if let Some(host) = row_obj.get("host").and_then(Value::as_str) {
            if crate::is_tailcat_host(host) {
                "tailcat".to_owned()
            } else {
                row_obj.get("endpoint").and_then(Value::as_str).unwrap_or("lan").to_owned()
            }
        } else {
            row_obj.get("endpoint").and_then(Value::as_str).unwrap_or("lan").to_owned()
        };
        if endpoint != "lan" && endpoint != "tailcat" {
            return Err(format!("invalid endpoint {:?}", endpoint));
        }

        let explicit_id = row_obj.get("device_id").and_then(Value::as_str);
        let alias = row_obj
            .get("alias")
            .or_else(|| row_obj.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("device");
        let base_name = normalized_alias(alias);

        let id = if let Some(id) = explicit_id {
            validate_id(id)?;
            id.to_owned()
        } else {
            hash_id(&["frontend", &base_name])
        };

        let device = groups
            .entry(id.clone())
            .or_insert_with(|| Device::new(id.clone(), base_name.clone()));

        if device.name == "device" || endpoint == "lan" {
            device.name = base_name;
        }

        // Extract metadata fields (any non-standard config fields)
        for (k, v) in row_obj {
            if !matches!(
                k.as_str(),
                "id" | "device_id"
                    | "alias"
                    | "name"
                    | "endpoint"
                    | "host"
                    | "port"
                    | "username"
                    | "identity_file"
                    | "known_hosts"
                    | "ssh_executable"
                    | "tailcat_executable"
                    | "sftp_executable"
                    | "timeout"
                    | "password"
            ) {
                device.metadata.insert(k.clone(), v.clone());
            }
        }

        let mut config = Config::default();
        if let Some(host) = row_obj.get("host").and_then(Value::as_str) {
            config.host = host.to_owned();
        }
        if let Some(port) = row_obj.get("port").and_then(Value::as_u64) {
            config.port = port as u16;
        }
        if let Some(user) = row_obj.get("username").and_then(Value::as_str) {
            config.username = user.to_owned();
        }
        if let Some(ident) = row_obj.get("identity_file").and_then(Value::as_str) {
            config.identity_file = ident.to_owned();
        }
        if let Some(kh) = row_obj.get("known_hosts").and_then(Value::as_str) {
            config.known_hosts = kh.to_owned();
        }
        if let Some(ssh) = row_obj.get("ssh_executable").and_then(Value::as_str) {
            config.ssh_executable = ssh.to_owned();
        }
        if let Some(tc) = row_obj.get("tailcat_executable").and_then(Value::as_str) {
            config.tailcat_executable = tc.to_owned();
        }
        if let Some(sftp) = row_obj.get("sftp_executable").and_then(Value::as_str) {
            config.sftp_executable = sftp.to_owned();
        }
        if let Some(t) = row_obj.get("timeout").and_then(Value::as_u64) {
            config.timeout = t;
        }

        config.validate()?;

        if endpoint == "lan" {
            if device.lan.is_some() {
                return Err(format!("duplicate lan endpoint for device {}", device.id));
            }
            device.lan = Some(config);
        } else {
            if device.tailcat.is_some() {
                return Err(format!("duplicate tailcat endpoint for device {}", device.id));
            }
            device.tailcat = Some(config);
        }
    }

    let mut registry = Registry {
        version: VERSION,
        active_device_id: String::new(),
        active_endpoint: DEFAULT_ENDPOINT.to_owned(),
        revision: current.revision,
        devices: groups.into_values().collect(),
    };

    if !active_id.is_empty() {
        if let Some((id, endpoint)) = active_id.rsplit_once(':') {
            validate_id(id)?;
            if endpoint != "lan" && endpoint != "tailcat" {
                return Err("active_id has an invalid endpoint".to_owned());
            }
            registry.active_device_id = id.to_owned();
            registry.active_endpoint = endpoint.to_owned();
        } else {
            validate_id(active_id)?;
            registry.active_device_id = active_id.to_owned();
        }
    }

    if registry.active_device_id.is_empty() && !registry.devices.is_empty() {
        registry.active_device_id = registry.devices[0].id.clone();
        registry.active_endpoint = if registry.devices[0].tailcat.is_some() {
            "tailcat".to_owned()
        } else {
            "lan".to_owned()
        };
    }

    if let Some(active) = registry.devices.iter().find(|d| d.id == registry.active_device_id) {
        if registry.active_endpoint == "lan" && active.lan.is_none() && active.tailcat.is_some() {
            registry.active_endpoint = "tailcat".to_owned();
        } else if registry.active_endpoint == "tailcat" && active.tailcat.is_none() && active.lan.is_some() {
            registry.active_endpoint = "lan".to_owned();
        }
    }

    commit(&path, &mut registry)?;
    Ok(frontend_from_registry(&registry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_strip_only_terminal_tailcat_suffix() {
        assert_eq!(normalized_alias("Reader (Tailcat)"), "Reader");
        assert_eq!(normalized_alias("Reader (Tailscale)"), "Reader");
        assert_eq!(
            normalized_alias("Reader (Tailcat) extra"),
            "Reader (Tailcat) extra"
        );
        assert_eq!(normalized_alias("Kindle"), "Kindle");
    }

    #[test]
    fn password_is_cleared_before_serialization() {
        let mut config = Config::default();
        config.host = "tc123456789012345678".to_owned();
        config.password = "secret".to_owned();
        let mut device = Device::new("id".to_owned(), "Kindle".to_owned());
        device.lan = Some(config);
        let encoded = serde_json::to_string(&persisted_registry(&Registry {
            devices: vec![device],
            ..Registry::default()
        }))
        .unwrap();
        assert!(!encoded.contains("secret"));
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct TestHome {
        _lock: std::sync::MutexGuard<'static, ()>,
        old_config_dir: Option<std::ffi::OsString>,
        _dir: TempDir,
    }

    impl TestHome {
        fn new() -> Self {
            let lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let old_config_dir = env::var_os("TAILCATCTL_CONFIG_DIR");
            env::set_var("TAILCATCTL_CONFIG_DIR", dir.path());
            Self {
                _lock: lock,
                old_config_dir,
                _dir: dir,
            }
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            if let Some(value) = self.old_config_dir.take() {
                env::set_var("TAILCATCTL_CONFIG_DIR", value);
            } else {
                env::remove_var("TAILCATCTL_CONFIG_DIR");
            }
        }
    }

    fn config(host: &str, password: &str) -> Config {
        let mut config = Config::default();
        config.host = host.to_owned();
        config.password = password.to_owned();
        config.known_hosts = "/tmp/tailcat-known-hosts".to_owned();
        config
    }

    #[test]
    fn password_never_reaches_registry_bytes() {
        let _home = TestHome::new();
        upsert_endpoint(
            config("192.0.2.10", "not-on-disk"),
            Some("one"),
            Some("Reader"),
            Some("lan"),
            None,
        )
        .unwrap();
        let bytes = fs::read(registry_path().unwrap()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("not-on-disk"));
    }

    #[test]
    fn stale_frontend_revision_is_rejected() {
        let _home = TestHome::new();
        upsert_endpoint(
            config("192.0.2.11", ""),
            Some("one"),
            Some("Reader"),
            Some("lan"),
            None,
        )
        .unwrap();
        let snapshot = frontend().unwrap();
        upsert_endpoint(
            config("192.0.2.12", ""),
            Some("two"),
            Some("Other"),
            Some("lan"),
            None,
        )
        .unwrap();
        assert!(sync_frontend(snapshot).is_err());
    }

    #[test]
    fn setup_pairs_endpoints_and_uninstall_keeps_lan() {
        let _home = TestHome::new();
        let device = record_setup(
            config("192.0.2.13", "session-only"),
            "tc123456789012345678",
            Some("one"),
            Some("Reader"),
            None,
        )
        .unwrap();
        assert!(device.lan.is_some() && device.tailcat.is_some());
        let removed = remove_tailcat("one").unwrap();
        assert!(removed.lan.is_some() && removed.tailcat.is_none());
    }

    #[test]
    fn ambiguous_alias_cannot_select_a_device() {
        let _home = TestHome::new();
        upsert_endpoint(
            config("192.0.2.14", ""),
            Some("one"),
            Some("Reader"),
            Some("lan"),
            None,
        )
        .unwrap();
        upsert_endpoint(
            config("192.0.2.15", ""),
            Some("two"),
            Some("Reader"),
            Some("lan"),
            None,
        )
        .unwrap();
        assert!(select("Reader", None).is_err());
    }

    #[test]
    fn resolve_target_finds_by_name_and_endpoint() {
        let _home = TestHome::new();
        record_setup(
            config("192.0.2.20", ""),
            "tc987654321098765432",
            Some("kindle-pw5"),
            Some("kindle"),
            None,
        )
        .unwrap();

        // Target: "kindle" (should resolve to tailcat by default)
        let (dev, ep) = resolve_target("kindle", None).unwrap();
        assert_eq!(dev.unwrap().id, "kindle-pw5");
        assert_eq!(ep.host, "tc987654321098765432");

        // Target: "kindle:lan" (should resolve to LAN)
        let (dev2, ep2) = resolve_target("kindle:lan", None).unwrap();
        assert_eq!(dev2.unwrap().id, "kindle-pw5");
        assert_eq!(ep2.host, "192.0.2.20");

        // Direct target: "tc987654321098765432"
        let (dev3, ep3) = resolve_target("tc987654321098765432", None).unwrap();
        assert_eq!(dev3.unwrap().id, "kindle-pw5");
        assert_eq!(ep3.host, "tc987654321098765432");
    }

    #[test]
    fn resolve_target_disambiguates_two_devices_with_same_name_by_endpoint() {
        let _home = TestHome::new();
        // Device 1: named "Kindle", only tailcat endpoint
        upsert_endpoint(
            config("tcp1111111111", ""),
            Some("dev-one-uuid"),
            Some("Kindle"),
            Some("tailcat"),
            None,
        )
        .unwrap();

        // Device 2: named "Kindle", only lan endpoint
        upsert_endpoint(
            config("192.168.1.50", ""),
            Some("dev-two-uuid"),
            Some("Kindle"),
            Some("lan"),
            None,
        )
        .unwrap();

        // Target: "Kindle:tailcat" -> should disambiguate to dev-one-uuid
        let (dev1, ep1) = resolve_target("Kindle:tailcat", None).unwrap();
        assert_eq!(dev1.unwrap().id, "dev-one-uuid");
        assert_eq!(ep1.host, "tcp1111111111");

        // Target: "Kindle:lan" -> should disambiguate to dev-two-uuid
        let (dev2, ep2) = resolve_target("Kindle:lan", None).unwrap();
        assert_eq!(dev2.unwrap().id, "dev-two-uuid");
        assert_eq!(ep2.host, "192.168.1.50");

        // Target: "Kindle" without endpoint specifier -> should return ambiguous error
        assert!(resolve_target("Kindle", None).is_err());
    }
}
