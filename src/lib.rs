#![cfg_attr(not(unix), allow(dead_code))]

#[cfg(not(unix))]
compile_error!("tailcatctl broker is supported on POSIX hosts only");

pub mod profiles;

#[cfg(unix)]
mod broker {
    use std::collections::HashMap;
    use std::env;
    use std::fmt;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tempfile::{Builder, TempDir};

    const PROTOCOL: u32 = 1;
    const MAX_MESSAGE: usize = 64 * 1024;
    const MAX_DIAGNOSTIC: usize = 16 * 1024;
    const IDLE_GRACE: Duration = Duration::from_secs(2);
    const STARTUP_GRACE: Duration = Duration::from_secs(5);
    static TERMINATING: AtomicBool = AtomicBool::new(false);

    const WATCHDOG_SCRIPT: &str = r#"
shell_pid=$$
exec 4<&3
("$@" 3<&- 4<&-) &
ssh_pid=$!
(
  trap '' TERM
  while IFS= read -r _ <&4; do :; done
  kill -TERM -"$shell_pid" 2>/dev/null
  sleep 1
  kill -KILL -"$shell_pid" 2>/dev/null
) &
watch_pid=$!
wait "$ssh_pid"
status=$?
kill -9 "$watch_pid" 2>/dev/null
wait "$watch_pid" 2>/dev/null
exit "$status"
"#;

    fn default_port() -> u16 {
        22
    }
    fn default_username() -> String {
        "root".to_string()
    }
    fn default_known_hosts() -> String {
        expand_path("~/.ssh/known_hosts")
    }
    fn default_ssh() -> String {
        "ssh".to_string()
    }
    fn default_timeout() -> u64 {
        15
    }
    fn default_sftp() -> String {
        "sftp".to_string()
    }

    pub fn expand_path(value: &str) -> String {
        if value == "~" || value.starts_with("~/") {
            if let Ok(home) = env::var("HOME") {
                return if value == "~" {
                    home
                } else {
                    format!("{}{}", home, &value[1..])
                };
            }
        }
        value.to_string()
    }

    fn deserialize_known_hosts<'de, D>(d: D) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(expand_path(&String::deserialize(d)?))
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Config {
        pub host: String,
        #[serde(default = "default_port")]
        pub port: u16,
        #[serde(default = "default_username")]
        pub username: String,
        #[serde(default)]
        pub identity_file: String,
        #[serde(
            default = "default_known_hosts",
            deserialize_with = "deserialize_known_hosts"
        )]
        pub known_hosts: String,
        #[serde(default, skip_serializing)]
        pub password: String,
        #[serde(default = "default_ssh")]
        pub ssh_executable: String,
        #[serde(default)]
        pub tailcat_executable: String,
        #[serde(default = "default_sftp")]
        pub sftp_executable: String,
        #[serde(default = "default_timeout")]
        pub timeout: u64,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                host: String::new(),
                port: 22,
                username: default_username(),
                identity_file: String::new(),
                known_hosts: default_known_hosts(),
                password: String::new(),
                ssh_executable: default_ssh(),
                tailcat_executable: String::new(),
                sftp_executable: default_sftp(),
                timeout: default_timeout(),
            }
        }
    }

    impl fmt::Debug for Config {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Config")
                .field("host", &self.host)
                .field("port", &self.port)
                .field("username", &self.username)
                .field("identity_file", &self.identity_file)
                .field("known_hosts", &self.known_hosts)
                .field("password", &"<redacted>")
                .field("ssh_executable", &self.ssh_executable)
                .field("tailcat_executable", &self.tailcat_executable)
                .field("sftp_executable", &self.sftp_executable)
                .field("timeout", &self.timeout)
                .finish()
        }
    }

    impl Config {
        pub fn validate(&self) -> Result<(), String> {
            if self.host.is_empty()
                || self.host.len() > 255
                || self.host.starts_with('-')
                || self.host.contains('@')
                || self.host.contains('%')
                || self.host.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err("host must be a non-empty hostname or address without whitespace".into());
            }
            if self.username.is_empty()
                || self.username.starts_with('-')
                || self.username.contains('@')
                || self.username.contains('%')
                || self
                    .username
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace())
            {
                return Err("username must be non-empty and contain no whitespace".into());
            }
            if self.port == 0 {
                return Err("port must be between 1 and 65535".into());
            }
            if self.timeout == 0 || self.timeout > 3600 {
                return Err("timeout must be between 1 and 3600 seconds".into());
            }
            if self.ssh_executable.is_empty() {
                return Err("ssh_executable must not be empty".into());
            }
            for value in [
                &self.host,
                &self.username,
                &self.identity_file,
                &self.known_hosts,
                &self.ssh_executable,
                &self.tailcat_executable,
                &self.sftp_executable,
            ] {
                if value.chars().any(|c| c == '\0' || c == '\n' || c == '\r') {
                    return Err("configuration contains an invalid control character".into());
                }
            }
            if self.password.contains('\0') {
                return Err("password contains an invalid NUL byte".into());
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Reply {
        pub ok: bool,
        pub protocol: u32,
        pub control_path: Option<String>,
        pub error: Option<String>,
        pub connections: Option<Value>,
    }

    impl Reply {
        fn success(path: Option<String>) -> Self {
            Self {
                ok: true,
                protocol: PROTOCOL,
                control_path: path,
                error: None,
                connections: None,
            }
        }
        fn failure(error: impl Into<String>) -> Self {
            Self {
                ok: false,
                protocol: PROTOCOL,
                control_path: None,
                error: Some(error.into()),
                connections: None,
            }
        }
        fn empty_status() -> Self {
            Self {
                ok: true,
                protocol: PROTOCOL,
                control_path: None,
                error: None,
                connections: Some(json!([])),
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct WireRequest {
        op: String,
        protocol: u32,
        config: Option<Value>,
    }

    #[derive(Clone)]
    struct EffectiveConfig(Config);

    struct Endpoint {
        config: EffectiveConfig,
        leases: usize,
        child: Child,
        control_path: PathBuf,
        _tempdir: TempDir,
        _diagnostics: Arc<Mutex<Vec<u8>>>,
        _watchdog_pipe: File,
    }

    struct BrokerState {
        endpoints: HashMap<String, Endpoint>,
        clients: usize,
    }

    fn uid() -> u32 {
        unsafe { libc::geteuid() as u32 }
    }

    fn secure_dir(path: &Path) -> Result<(), String> {
        let md = fs::symlink_metadata(path)
            .map_err(|e| format!("runtime directory {}: {}", path.display(), e))?;
        if !md.is_dir() || md.uid() != uid() || md.mode() & 0o077 != 0 {
            return Err(format!(
                "runtime directory {} is not private and user-owned",
                path.display()
            ));
        }
        Ok(())
    }

    pub fn runtime_dir() -> Result<PathBuf, String> {
        let path = if let Some(value) = env::var_os("TAILCATCTL_RUNTIME_DIR")
            .or_else(|| env::var_os("KINDLE_LINK_RUNTIME_DIR"))
        {
            PathBuf::from(value)
        } else {
            PathBuf::from(format!("/tmp/tailcatctl-{}", uid()))
        };
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| format!("create runtime directory: {}", e))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("secure runtime directory: {}", e))?;
        }
        secure_dir(&path)?;
        Ok(path)
    }

    pub fn socket_path() -> Result<PathBuf, String> {
        let path = runtime_dir()?.join("broker.sock");
        if path.as_os_str().as_bytes().len() >= 100 {
            return Err("broker socket path is too long for AF_UNIX".into());
        }
        Ok(path)
    }

    fn lock_file(dir: &Path) -> Result<File, String> {
        let path = dir.join("broker.lock");
        if let Ok(md) = fs::symlink_metadata(&path) {
            if md.file_type().is_symlink() || !md.is_file() || md.uid() != uid() {
                return Err("broker startup lock is not a user-owned regular file".into());
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("open broker startup lock: {}", e))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
        Ok(file)
    }

    fn take_lock(file: &File, blocking: bool) -> io::Result<bool> {
        let mut op = libc::LOCK_EX;
        if !blocking {
            op |= libc::LOCK_NB;
        }
        let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
        if rc == 0 {
            Ok(true)
        } else if !blocking
            && io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            Ok(false)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn validate_socket_entry(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(md) => {
                if md.file_type().is_symlink()
                    || !md.file_type().is_socket()
                    || md.uid() != uid()
                {
                    Err("broker socket is not a user-owned Unix socket".into())
                } else {
                    Ok(())
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("inspect broker socket: {}", error)),
        }
    }

    fn safe_socket_remove(path: &Path) -> Result<(), String> {
        let md = fs::symlink_metadata(path)
            .map_err(|e| format!("inspect stale broker socket: {}", e))?;
        if md.file_type().is_symlink() || !md.file_type().is_socket() || md.uid() != uid() {
            return Err("refusing to remove an untrusted broker socket".into());
        }
        fs::remove_file(path).map_err(|e| format!("remove stale broker socket: {}", e))
    }

    fn send_json(stream: &mut UnixStream, value: &impl Serialize) -> Result<(), String> {
        let mut bytes =
            serde_json::to_vec(value).map_err(|e| format!("encode IPC message: {}", e))?;
        if bytes.len() > MAX_MESSAGE - 1 {
            return Err("IPC message too large".into());
        }
        bytes.push(b'\n');
        stream
            .write_all(&bytes)
            .map_err(|e| format!("write IPC message: {}", e))
    }

    fn read_line_cap(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        let mut one = [0u8; 1];
        loop {
            let n = stream
                .read(&mut one)
                .map_err(|e| format!("read IPC message: {}", e))?;
            if n == 0 {
                if bytes.is_empty() {
                    return Err("truncated IPC message".into());
                }
                break;
            }
            if one[0] == b'\n' {
                break;
            }
            bytes.push(one[0]);
            if bytes.len() >= MAX_MESSAGE {
                return Err("IPC message exceeds size limit".into());
            }
        }
        Ok(bytes)
    }

    fn local_status_stream() -> UnixStream {
        let (a, b) = UnixStream::pair().expect("UnixStream::pair");
        drop(b);
        a
    }

    pub fn request(op: &str, config: Option<&Config>) -> Result<(UnixStream, Reply), String> {
        if op != "acquire" && op != "status" {
            return Err(format!("unsupported broker operation {:?}", op));
        }
        if op == "acquire" {
            let cfg = config.ok_or_else(|| "acquire requires a config".to_string())?;
            cfg.validate()?;
            ensure_daemon()?;
        }
        let path = socket_path()?;
        validate_socket_entry(&path)?;
        let mut stream = match UnixStream::connect(&path) {
            Ok(s) => s,
            Err(e)
                if op == "status"
                    && matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
            {
                return Ok((local_status_stream(), Reply::empty_status()))
            }
            Err(e) => return Err(format!("connect broker: {}", e)),
        };
        let ipc_timeout = config
            .map(|cfg| cfg.timeout.saturating_add(5).min(3600))
            .unwrap_or(10);
        stream
            .set_read_timeout(Some(Duration::from_secs(ipc_timeout)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(ipc_timeout)))
            .ok();
        let mut value = serde_json::Map::new();
        value.insert("op".into(), Value::String(op.into()));
        value.insert("protocol".into(), json!(PROTOCOL));
        if let Some(cfg) = config {
            let mut c = serde_json::to_value(cfg).map_err(|e| format!("encode config: {}", e))?;
            if let Value::Object(obj) = &mut c {
                if !cfg.password.is_empty() {
                    obj.insert("password".into(), Value::String(cfg.password.clone()));
                }
            }
            value.insert("config".into(), c);
        }
        send_json(&mut stream, &Value::Object(value))?;
        let bytes = read_line_cap(&mut stream)?;
        let reply: Reply = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid broker response: {}", e))?;
        if reply.protocol != PROTOCOL {
            return Err("broker protocol version mismatch".into());
        }
        if !reply.ok && op == "acquire" {
            return Err(reply.error.unwrap_or_else(|| "broker request failed".into()));
        }
        stream.set_read_timeout(None).ok();
        stream.set_write_timeout(None).ok();
        Ok((stream, reply))
    }

    pub fn ensure_daemon() -> Result<(), String> {
        let path = socket_path()?;
        validate_socket_entry(&path)?;
        if UnixStream::connect(&path).is_ok() {
            return Ok(());
        }
        let current_exe =
            env::current_exe().map_err(|e| format!("locate broker executable: {}", e))?;
        let mut cmd = Command::new(current_exe);
        cmd.arg("daemon");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        cmd.spawn().map_err(|e| format!("spawn broker: {}", e))?;
        let deadline = Instant::now() + STARTUP_GRACE;
        while Instant::now() < deadline {
            if UnixStream::connect(&path).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err("timed out waiting for broker to start".into())
    }

    fn resolve_program(value: &str) -> String {
        if value.contains('/') || value.contains('\\') {
            return expand_path(value);
        }
        if let Ok(paths) = env::var("PATH") {
            for entry in env::split_paths(&paths) {
                let candidate = entry.join(value);
                if candidate.is_file() {
                    return candidate.to_string_lossy().into_owned();
                }
            }
        }
        value.to_string()
    }

    pub fn find_tailcat() -> Option<String> {
        for candidate in ["tailcat", "tailcat.exe"] {
            let path = resolve_program(candidate);
            if path != candidate {
                return Some(path);
            }
        }
        let home = env::var_os("HOME").map(PathBuf::from);
        let mut paths = Vec::new();
        if let Some(h) = home {
            paths.extend([h.join("go/bin/tailcat"), h.join(".local/bin/tailcat")]);
        }
        paths.extend([
            PathBuf::from("/opt/homebrew/bin/tailcat"),
            PathBuf::from("/usr/local/bin/tailcat"),
        ]);
        paths
            .into_iter()
            .find(|p| {
                p.is_file()
                    && p.metadata()
                        .map(|m| m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
            })
            .map(|p| p.to_string_lossy().into_owned())
    }

    pub fn is_tailcat_host(host: &str) -> bool {
        host.starts_with("tc") && !host.contains('.') && host.len() >= 20
    }

    fn quote_shell(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn effective_config(cfg: &Config) -> Result<EffectiveConfig, String> {
        cfg.validate()?;
        let mut c = cfg.clone();
        c.known_hosts = expand_path(&c.known_hosts);
        c.identity_file = expand_path(&c.identity_file);
        c.ssh_executable = resolve_program(&c.ssh_executable);
        c.sftp_executable = resolve_program(&c.sftp_executable);
        if is_tailcat_host(&c.host) {
            c.tailcat_executable = if c.tailcat_executable.is_empty() {
                find_tailcat().ok_or_else(|| {
                    "Tailcat address requires a tailcat executable installed on host".to_string()
                })?
            } else {
                resolve_program(&c.tailcat_executable)
            };
        }
        Ok(EffectiveConfig(c))
    }

    fn endpoint_key(cfg: &Config) -> String {
        format!("{}\0{}", cfg.host, cfg.port)
    }

    fn compatible(a: &EffectiveConfig, b: &EffectiveConfig) -> bool {
        let x = &a.0;
        let y = &b.0;
        x.username == y.username
            && x.known_hosts == y.known_hosts
            && x.identity_file == y.identity_file
            && x.ssh_executable == y.ssh_executable
            && x.tailcat_executable == y.tailcat_executable
            && x.sftp_executable == y.sftp_executable
            && (y.password.is_empty() || x.password == y.password)
    }

    fn status_reply(state: &BrokerState) -> Reply {
        let connections: Vec<Value> = state
            .endpoints
            .values()
            .map(|e| {
                json!({
                    "host": e.config.0.host,
                    "port": e.config.0.port,
                    "username": e.config.0.username,
                    "leases": e.leases,
                    "master_pid": e.child.id(),
                    "control_path": e.control_path
                })
            })
            .collect();
        Reply {
            ok: true,
            protocol: PROTOCOL,
            control_path: None,
            error: None,
            connections: Some(Value::Array(connections)),
        }
    }

    fn collect_diagnostic(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        let data = buf.lock().map(|x| x.clone()).unwrap_or_default();
        String::from_utf8_lossy(&data).trim().to_string()
    }

    fn kill_group(child: &mut Child) {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        let pid = child.id() as libc::pid_t;
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    fn set_cloexec(fd: libc::c_int, enabled: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let next = if enabled {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn create_master(cfg: EffectiveConfig) -> Result<Endpoint, String> {
        let runtime = runtime_dir()?;
        let tempdir = Builder::new()
            .prefix("master-")
            .tempdir_in(&runtime)
            .map_err(|e| format!("create private master directory: {}", e))?;
        fs::set_permissions(tempdir.path(), fs::Permissions::from_mode(0o700)).ok();
        let control_path = tempdir.path().join("control.sock");
        if control_path.as_os_str().as_bytes().len() >= 100 {
            return Err("master control socket path is too long".into());
        }

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(WATCHDOG_SCRIPT)
            .arg("tailcatctl-watch")
            .arg(&cfg.0.ssh_executable)
            .arg("-M")
            .arg("-N")
            .arg("-S")
            .arg(&control_path)
            .arg("-o")
            .arg("ControlMaster=yes")
            .arg("-o")
            .arg("ControlPersist=no")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes");

        let default_ssh_kh = expand_path("~/.ssh/known_hosts");
        let default_tc_kh = expand_path("~/.config/tailcat/ssh_known_hosts");
        let kh_arg = if cfg.0.known_hosts == default_ssh_kh {
            if Path::new(&default_tc_kh).exists() {
                format!("{} {}", cfg.0.known_hosts, default_tc_kh)
            } else {
                cfg.0.known_hosts.clone()
            }
        } else if cfg.0.known_hosts == default_tc_kh {
            if Path::new(&default_ssh_kh).exists() {
                format!("{} {}", default_ssh_kh, cfg.0.known_hosts)
            } else {
                cfg.0.known_hosts.clone()
            }
        } else {
            cfg.0.known_hosts.clone()
        };

        command
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", kh_arg))
            .arg("-o")
            .arg("GlobalKnownHostsFile=/dev/null")
            .arg("-F")
            .arg("/dev/null")
            .arg("-o")
            .arg(format!("ConnectTimeout={}", cfg.0.timeout))
            .arg("-o")
            .arg("ServerAliveInterval=5")
            .arg("-o")
            .arg("ServerAliveCountMax=2")
            .arg("-p")
            .arg(cfg.0.port.to_string());

        if !cfg.0.identity_file.is_empty() {
            command.arg("-i").arg(&cfg.0.identity_file);
        }

        // Tailcat destination: preserve case in ProxyCommand
        if is_tailcat_host(&cfg.0.host) {
            let proxy = format!(
                "exec {} {} {}",
                quote_shell(&cfg.0.tailcat_executable),
                quote_shell(&cfg.0.host),
                cfg.0.port
            );
            command.arg("-o").arg(format!("ProxyCommand={}", proxy));
        }

        command.arg(format!("{}@{}", cfg.0.username, cfg.0.host));

        if !cfg.0.password.is_empty() {
            let script = tempdir.path().join("askpass");
            fs::write(
                &script,
                b"#!/bin/sh\ncase \"$1\" in\n  *[pP]assphrase*) exit 1 ;;\n  *) printf '%s\\n' \"$TAILCATCTL_PASSWORD\" ;;\nesac\n",
            )
            .map_err(|e| format!("create askpass helper: {}", e))?;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("secure askpass helper: {}", e))?;
            command
                .arg("-o")
                .arg("PasswordAuthentication=yes")
                .arg("-o")
                .arg("KbdInteractiveAuthentication=yes")
                .env("SSH_ASKPASS", &script)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("DISPLAY", "tailcatctl:0")
                .env("TAILCATCTL_PASSWORD", &cfg.0.password);
        } else {
            command
                .arg("-o")
                .arg("BatchMode=yes")
                .env("SSH_ASKPASS_REQUIRE", "never");
        }

        let mut pipe_fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(format!(
                "create broker watchdog pipe: {}",
                io::Error::last_os_error()
            ));
        }
        let read_fd = pipe_fds[0];
        let write_fd = pipe_fds[1];
        if let Err(error) =
            set_cloexec(read_fd, true).and_then(|_| set_cloexec(write_fd, true))
        {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(format!("secure broker watchdog pipe: {}", error));
        }

        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::dup2(read_fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if read_fd != 3 {
                    libc::close(read_fd);
                }
                Ok(())
            });
        }

        let spawn_result = command.spawn();
        unsafe {
            libc::close(read_fd);
        }
        let mut child = match spawn_result {
            Ok(c) => c,
            Err(error) => {
                unsafe {
                    libc::close(write_fd);
                }
                return Err(format!("start SSH master: {}", error));
            }
        };

        let watchdog_pipe = unsafe { File::from_raw_fd(write_fd) };
        let diagnostics = Arc::new(Mutex::new(Vec::new()));
        if let Some(mut stderr) = child.stderr.take() {
            let dest = diagnostics.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stderr.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut g) = dest.lock() {
                        let room = MAX_DIAGNOSTIC.saturating_sub(g.len());
                        if room > 0 {
                            g.extend_from_slice(&buf[..n.min(room)]);
                        }
                    }
                }
            });
        }

        let until = Instant::now() + Duration::from_secs(cfg.0.timeout);
        loop {
            if control_path.exists() {
                break;
            }
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                let diag = collect_diagnostic(&diagnostics);
                return Err(format!(
                    "SSH master exited with {}: {}",
                    status,
                    if diag.is_empty() {
                        "no diagnostic details captured"
                    } else {
                        &diag
                    }
                ));
            }
            if Instant::now() >= until {
                kill_group(&mut child);
                let diag = collect_diagnostic(&diagnostics);
                return Err(format!(
                    "timed out waiting for master socket: {}",
                    if diag.is_empty() {
                        "check host connectivity and SSH keys"
                    } else {
                        &diag
                    }
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }

        Ok(Endpoint {
            config: cfg,
            leases: 0,
            child,
            control_path,
            _tempdir: tempdir,
            _diagnostics: diagnostics,
            _watchdog_pipe: watchdog_pipe,
        })
    }

    fn handle_client(mut stream: UnixStream, shared: Arc<Mutex<BrokerState>>) {
        stream.set_nonblocking(false).ok();
        let mut holding_key: Option<String> = None;
        let result = (|| -> Result<(), String> {
            let raw = read_line_cap(&mut stream)?;
            let req: WireRequest = serde_json::from_slice(&raw)
                .map_err(|e| format!("invalid request JSON: {}", e))?;
            if req.protocol != PROTOCOL {
                return Err(format!(
                    "unsupported protocol {} (expected {})",
                    req.protocol, PROTOCOL
                ));
            }
            match req.op.as_str() {
                "status" => {
                    let reply = {
                        let guard = shared.lock().unwrap();
                        status_reply(&guard)
                    };
                    send_json(&mut stream, &reply)?;
                    Ok(())
                }
                "acquire" => {
                    let cfg_value = req
                        .config
                        .ok_or_else(|| "acquire requires a config".to_string())?;
                    let cfg: Config = serde_json::from_value(cfg_value)
                        .map_err(|e| format!("invalid config payload: {}", e))?;
                    let eff = effective_config(&cfg)?;
                    let key = endpoint_key(&cfg);
                    let control_path_str: String;

                    {
                        let mut guard = shared.lock().unwrap();
                        if let Some(endpoint) = guard.endpoints.get_mut(&key) {
                            if !compatible(&endpoint.config, &eff) {
                                return Err(
                                    "incompatible connection parameters for existing endpoint"
                                        .to_string(),
                                );
                            }
                            endpoint.leases += 1;
                            control_path_str = endpoint.control_path.to_string_lossy().into_owned();
                            holding_key = Some(key.clone());
                        } else {
                            let endpoint = create_master(eff)?;
                            control_path_str = endpoint.control_path.to_string_lossy().into_owned();
                            let mut ep = endpoint;
                            ep.leases = 1;
                            guard.endpoints.insert(key.clone(), ep);
                            holding_key = Some(key.clone());
                        }
                    }

                    send_json(&mut stream, &Reply::success(Some(control_path_str)))?;
                    stream.set_read_timeout(None).ok();
                    let mut sink = [0u8; 1024];
                    loop {
                        match stream.read(&mut sink) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    Ok(())
                }
                other => Err(format!("unknown operation {:?}", other)),
            }
        })();

        if let Err(e) = result {
            let _ = send_json(&mut stream, &Reply::failure(e));
        }

        if let Some(key) = holding_key {
            let mut guard = shared.lock().unwrap();
            let should_kill = if let Some(endpoint) = guard.endpoints.get_mut(&key) {
                endpoint.leases = endpoint.leases.saturating_sub(1);
                endpoint.leases == 0
            } else {
                false
            };
            if should_kill {
                if let Some(mut endpoint) = guard.endpoints.remove(&key) {
                    kill_group(&mut endpoint.child);
                    let _ = endpoint.child.wait();
                }
            }
        }

        if let Ok(mut guard) = shared.lock() {
            guard.clients = guard.clients.saturating_sub(1);
        }
    }

    extern "C" fn terminate_signal(_: libc::c_int) {
        TERMINATING.store(true, Ordering::SeqCst);
    }

    pub fn run_daemon() -> Result<(), String> {
        let lock = lock_file(&runtime_dir()?)?;
        if !take_lock(&lock, false).map_err(|e| format!("take broker startup lock: {}", e))? {
            return Ok(());
        }
        let socket = socket_path()?;
        validate_socket_entry(&socket)?;
        if socket.exists() {
            if UnixStream::connect(&socket).is_ok() {
                return Ok(());
            }
            safe_socket_remove(&socket)?;
        }
        let listener =
            UnixListener::bind(&socket).map_err(|e| format!("bind broker socket: {}", e))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).ok();
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("configure broker socket: {}", e))?;

        unsafe {
            libc::signal(
                libc::SIGTERM,
                terminate_signal as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGINT,
                terminate_signal as *const () as libc::sighandler_t,
            );
        }

        let state = Arc::new(Mutex::new(BrokerState {
            endpoints: HashMap::new(),
            clients: 0,
        }));
        let mut idle_since = Instant::now();

        loop {
            if TERMINATING.load(Ordering::SeqCst) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Ok(mut guard) = state.lock() {
                        guard.clients += 1;
                    }
                    idle_since = Instant::now();
                    let shared = state.clone();
                    thread::spawn(move || handle_client(stream, shared));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(e) => return Err(format!("accept broker connection: {}", e)),
            }

            let mut should_exit = false;
            if let Ok(mut guard) = state.lock() {
                let mut dead = Vec::new();
                for (key, endpoint) in &mut guard.endpoints {
                    if let Ok(Some(_)) = endpoint.child.try_wait() {
                        dead.push(key.clone());
                    } else if endpoint.leases == 0 && Instant::now().duration_since(idle_since) > IDLE_GRACE {
                        kill_group(&mut endpoint.child);
                        dead.push(key.clone());
                    }
                }
                for key in dead {
                    guard.endpoints.remove(&key);
                }
                if guard.clients == 0 && guard.endpoints.is_empty() {
                    if Instant::now().duration_since(idle_since) > IDLE_GRACE {
                        should_exit = true;
                    }
                } else {
                    idle_since = Instant::now();
                }
            }
            if should_exit {
                break;
            }
        }

        safe_socket_remove(&socket).ok();
        if let Ok(mut guard) = state.lock() {
            for (_, mut endpoint) in guard.endpoints.drain() {
                kill_group(&mut endpoint.child);
            }
        }
        Ok(())
    }

    /// Pings an endpoint to measure latency.
    /// For TCP/LAN: performs a TCP connect to port.
    /// For Tailcat: runs a quick TCP probe through Tailcat or OpenSSH probe.
    pub fn ping_endpoint(config: &Config) -> Result<Duration, String> {
        let timeout = Duration::from_secs(config.timeout.min(5));
        let start = Instant::now();

        if is_tailcat_host(&config.host) {
            let tc_bin = if config.tailcat_executable.is_empty() {
                find_tailcat().ok_or_else(|| "tailcat executable not found".to_string())?
            } else {
                resolve_program(&config.tailcat_executable)
            };

            let mut cmd = Command::new(&tc_bin);
            cmd.arg("ping")
                .arg(format!("--timeout={}s", timeout.as_secs().max(1)))
                .arg(&config.host);

            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("cannot start ping probe: {}", e))?;

            let deadline = Instant::now() + timeout;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if !status.success() {
                            return Err("tailcat ping returned error (target unreachable)".to_string());
                        }
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!("ping timed out after {:?}", timeout));
                    }
                }
            }
        } else {
            // LAN TCP ping
            let addr_str = format!("{}:{}", config.host, config.port);
            let addrs = addr_str
                .to_socket_addrs()
                .map_err(|e| format!("resolve address {}: {}", addr_str, e))?;
            let mut connected = false;
            for addr in addrs {
                if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                    connected = true;
                    break;
                }
            }
            if !connected {
                return Err(format!("connection to {} timed out", addr_str));
            }
        }

        Ok(start.elapsed())
    }
}

pub use broker::*;
