use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use tailcatctl::{ensure_daemon, ping_endpoint, profiles, request, run_daemon, Config};
use tempfile::NamedTempFile;

static TERMINATE: AtomicBool = AtomicBool::new(false);
static CHILD_RUNNING: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(sig: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
    if !CHILD_RUNNING.load(Ordering::SeqCst) {
        unsafe {
            libc::_exit(128 + sig);
        }
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
    }
}

fn shorten_middle(s: &str, max_len: usize) -> String {
    if s.len() <= max_len || max_len < 7 {
        return s.to_string();
    }
    let keep = max_len - 3;
    let head = (keep + 1) / 2;
    let tail = keep / 2;
    format!("{}...{}", &s[..head], &s[s.len() - tail..])
}

fn usage() {
    println!(
        "tailcatctl: Tailcat connection manager and SSH tool\n\n\
         Usage:\n  \
         tailcatctl ssh [user@]<device> [command...]\n  \
         tailcatctl sftp [user@]<device>\n  \
         tailcatctl status [--json] [--active]\n  \
         tailcatctl ping <device>\n  \
         tailcatctl switch <device> | switch --list [--json]\n  \
         tailcatctl up [device]\n  \
         tailcatctl down [device]\n  \
         tailcatctl devices [--json]\n  \
         tailcatctl add <name> --tailcat <addr> [--lan <ip>] [--user <user>] [--key <file>] [--port <port>]\n  \
         tailcatctl remove <device>\n  \
         tailcatctl lease [--config FILE|-] [--device ID]\n  \
         tailcatctl host-keys --config FILE|- | --device ID\n  \
         tailcatctl daemon\n  \
         tailcatctl ensure\n  \
         tailcatctl frontend\n  \
         tailcatctl sync --config FILE|-\n\n\
         Examples:\n  \
         tailcatctl ssh kindle                   # Interactive shell on saved device 'kindle'\n  \
         tailcatctl ssh root@kindle uname -a     # Run remote command on 'kindle'\n  \
         tailcatctl ssh root@kindle:lan          # Connect over LAN endpoint explicitly\n  \
         tailcatctl ssh user@tc4e3b79...         # Direct SSH to a Tailcat address\n  \
         tailcatctl status                       # Show device connection status table\n  \
         tailcatctl switch kindle                # Set default active device"
    );
}

fn error_reply(error: impl Into<String>) -> serde_json::Value {
    json!({
        "ok": false,
        "protocol": 1,
        "control_path": null,
        "error": error.into(),
        "connections": null
    })
}

fn print_error_reply(error: impl Into<String>) {
    println!("{}", error_reply(error));
    let _ = io::stdout().flush();
}

fn load_config(path: &str) -> Result<Config, String> {
    if path == "-" {
        return Err("--config requires a file (stdin is reserved for lease lifetime)".into());
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("invalid config {}: {}", path, e))
}

fn option_value(args: &[String], i: &mut usize, option: &str) -> Result<String, String> {
    if let Some(value) = args[*i].strip_prefix(&format!("{}=", option)) {
        if value.is_empty() {
            return Err(format!("{} requires a value", option));
        }
        return Ok(value.to_owned());
    }
    *i += 1;
    if *i >= args.len() || args[*i].is_empty() {
        return Err(format!("{} requires a value", option));
    }
    Ok(args[*i].clone())
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

fn prompt_password(prompt: &str) -> Result<String, String> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("open terminal for password: {}", e))?;
    let fd = tty.as_raw_fd();
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
        return Err(format!(
            "read terminal settings: {}",
            io::Error::last_os_error()
        ));
    }
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) };
    let _ = tty.write_all(prompt.as_bytes());
    let mut bytes = Vec::new();
    let read_result = loop {
        let mut byte = [0_u8; 1];
        match tty.read(&mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) if byte[0] == b'\n' || byte[0] == b'\r' => break Ok(()),
            Ok(_) => bytes.push(byte[0]),
            Err(error) => break Err(error),
        }
    };
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
    let _ = tty.write_all(b"\n");
    read_result
        .map_err(|e| format!("read password: {}", e))
        .map(|_| String::from_utf8_lossy(&bytes).trim_end_matches(&['\r', '\n'][..]).to_owned())
}

fn acquire(config: &Config) -> Result<(UnixStream, String), String> {
    let (stream, reply) = request("acquire", Some(config))?;
    if !reply.ok {
        return Err(reply
            .error
            .unwrap_or_else(|| "broker rejected connection".to_owned()));
    }
    let control = reply
        .control_path
        .ok_or_else(|| "broker returned no control path".to_owned())?;
    Ok((stream, control))
}

fn acquire_prompted(config: &mut Config) -> Result<(UnixStream, String), String> {
    match acquire(config) {
        Ok(value) => Ok(value),
        Err(error)
            if config.password.is_empty()
                && stdin_is_tty()
                && unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
                && {
                    let lower = error.to_ascii_lowercase();
                    lower.contains("auth")
                        || lower.contains("password")
                        || lower.contains("permission denied")
                        || lower.contains("askpass")
                } =>
        {
            let prompt = format!("Password for {}@{}: ", config.username, config.host);
            config.password = prompt_password(&prompt)?;
            acquire(config)
        }
        Err(error) => Err(error),
    }
}

fn command_group(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

fn terminate_child(child: &mut Child, grouped: bool) {
    let pid = child.id() as libc::pid_t;
    unsafe {
        if grouped {
            let _ = libc::kill(-pid, libc::SIGTERM);
        }
        let _ = libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) | Err(_) => break,
        }
    }
    unsafe {
        if grouped {
            let _ = libc::kill(-pid, libc::SIGKILL);
        }
        let _ = libc::kill(pid, libc::SIGKILL);
    }
    let _ = child.wait();
}

fn wait_child(mut child: Child, grouped: bool) -> Result<ExitStatus, String> {
    loop {
        if TERMINATE.load(Ordering::SeqCst) {
            terminate_child(&mut child, grouped);
            return Ok(ExitStatus::from_raw(128 + libc::SIGTERM));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                terminate_child(&mut child, grouped);
                return Err(format!("waiting for child: {}", e));
            }
        }
    }
}

fn child_exit(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(libc::SIGTERM))
}

fn run_child(mut command: Command, grouped: bool) -> Result<i32, String> {
    if grouped {
        command_group(&mut command);
    }
    let child = command
        .spawn()
        .map_err(|e| format!("cannot start child command: {}", e))?;
    CHILD_RUNNING.store(true, Ordering::SeqCst);
    let result = wait_child(child, grouped);
    CHILD_RUNNING.store(false, Ordering::SeqCst);
    Ok(child_exit(result?))
}

fn current_user() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".to_owned())
}

/// Dispatches an SSH session or command to a target.
/// Syntax: `tailcatctl ssh [flags] [user@]<host> [remote_command...]`
fn run_ssh_subcommand(args: &[String], quote_remote: bool) -> Result<i32, String> {
    let mut config_file: Option<String> = None;
    let mut device_opt: Option<String> = None;
    let mut endpoint_opt: Option<String> = None;
    let mut port_override: Option<u16> = None;
    let mut identity_override: Option<String> = None;
    let mut force_pty: Option<bool> = None;
    let mut positional = Vec::new();
    let mut after_double_dash = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if after_double_dash {
            positional.push(arg.clone());
        } else if arg == "--" {
            after_double_dash = true;
        } else if arg == "-t" {
            force_pty = Some(true);
        } else if arg == "-T" {
            force_pty = Some(false);
        } else if arg == "--endpoint" || arg.starts_with("--endpoint=") || arg == "-e" {
            endpoint_opt = Some(option_value(args, &mut i, if arg == "-e" { "-e" } else { "--endpoint" })?);
        } else if arg == "--device" || arg.starts_with("--device=") {
            device_opt = Some(option_value(args, &mut i, "--device")?);
        } else if arg == "--config" || arg.starts_with("--config=") {
            config_file = Some(option_value(args, &mut i, "--config")?);
        } else if arg == "-p" || arg.starts_with("-p=") {
            let p_str = option_value(args, &mut i, "-p")?;
            port_override = Some(p_str.parse::<u16>().map_err(|_| "invalid port number")?);
        } else if arg == "-i" || arg.starts_with("-i=") {
            identity_override = Some(option_value(args, &mut i, "-i")?);
        } else if arg.starts_with('-') && positional.is_empty() {
            return Err(format!("unknown option: {}", arg));
        } else {
            positional.push(arg.clone());
        }
        i += 1;
    }

    let (config, remote_command) = if let Some(path) = config_file {
        let cfg = load_config(&path)?;
        (cfg, positional)
    } else {
        let (target, remote_cmd) = if let Some(dev) = device_opt {
            (dev, positional)
        } else if !positional.is_empty() {
            (positional[0].clone(), positional[1..].to_vec())
        } else {
            // Default to active device from registry
            let (device, cfg) = profiles::resolve(None, endpoint_opt.as_deref() == Some("lan"))?;
            let ep = if endpoint_opt.as_deref() == Some("lan") {
                device.lan.unwrap_or(cfg)
            } else {
                cfg
            };
            return execute_ssh(ep, Vec::new(), force_pty);
        };

        let (user_part, host_part) = if let Some((u, h)) = target.split_once('@') {
            (Some(u.to_owned()), h.to_owned())
        } else {
            (None, target)
        };

        let (_device, mut cfg) =
            profiles::resolve_target(&host_part, endpoint_opt.as_deref())?;

        if let Some(user) = user_part {
            cfg.username = user;
        } else if cfg.username.is_empty() {
            cfg.username = current_user();
        }

        if let Some(p) = port_override {
            cfg.port = p;
        }
        if let Some(ident) = identity_override {
            cfg.identity_file = ident;
        }

        (cfg, remote_cmd)
    };

    if quote_remote && !remote_command.is_empty() {
        let quoted = remote_command
            .iter()
            .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        execute_ssh(config, vec![quoted], force_pty.or(Some(false)))
    } else {
        execute_ssh(config, remote_command, force_pty)
    }
}

fn execute_ssh(
    mut config: Config,
    remote: Vec<String>,
    force_pty: Option<bool>,
) -> Result<i32, String> {
    config.validate()?;
    install_signal_handlers();
    let (lease, control) = acquire_prompted(&mut config)?;
    if TERMINATE.load(Ordering::SeqCst) {
        drop(lease);
        return Ok(128 + libc::SIGTERM);
    }

    let is_interactive = remote.is_empty();
    let pty = force_pty.unwrap_or(is_interactive && stdin_is_tty());

    let ssh_executable = if config.ssh_executable.is_empty() {
        "ssh".to_owned()
    } else {
        config.ssh_executable.clone()
    };

    let mut command = Command::new(ssh_executable);
    if pty {
        command.arg("-tt");
    } else {
        command.arg("-T");
    }

    command.arg("-S").arg(&control);
    command.args(["-o", "ControlMaster=no"]);
    command.args(["-o", "ProxyCommand=false"]);
    command.args(["-o", "BatchMode=yes"]);
    command.args(["-o", "ControlPersist=no"]);
    command.arg("-p").arg(config.port.to_string());
    command.arg(format!("{}@{}", config.username, config.host));
    command.args(remote);

    let result = run_child(command, !stdin_is_tty() && !pty);
    drop(lease);
    result
}

fn run_sftp_subcommand(args: &[String]) -> Result<i32, String> {
    let mut target: Option<String> = None;
    let mut remote_paths = Vec::new();

    for arg in args {
        if target.is_none() && !arg.starts_with('-') {
            target = Some(arg.clone());
        } else {
            remote_paths.push(arg.clone());
        }
    }

    let target_str = target.unwrap_or_else(|| "".to_string());
    let mut config = if target_str.is_empty() {
        let (_, cfg) = profiles::resolve(None, false)?;
        cfg
    } else {
        let (user_part, host_part) = if let Some((u, h)) = target_str.split_once('@') {
            (Some(u.to_owned()), h.to_owned())
        } else {
            (None, target_str)
        };
        let (_, mut cfg) = profiles::resolve_target(&host_part, None)?;
        if let Some(user) = user_part {
            cfg.username = user;
        }
        cfg
    };

    config.validate()?;
    install_signal_handlers();
    let (lease, control) = acquire_prompted(&mut config)?;
    if TERMINATE.load(Ordering::SeqCst) {
        drop(lease);
        return Ok(128 + libc::SIGTERM);
    }

    let sftp_bin = if config.sftp_executable.is_empty() {
        "sftp".to_owned()
    } else {
        config.sftp_executable.clone()
    };

    let mut cmd = Command::new(sftp_bin);
    cmd.args(["-o", "ControlMaster=no"]);
    cmd.args(["-o", "ProxyCommand=false"]);
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(["-o", "ControlPersist=no"]);
    cmd.arg("-o").arg(format!("ControlPath={}", control));
    cmd.arg("-P").arg(config.port.to_string());
    cmd.arg(format!("{}@{}", config.username, config.host));
    cmd.args(remote_paths);

    let result = run_child(cmd, false);
    drop(lease);
    result
}

fn status_command(args: &[String]) -> Result<i32, String> {
    let mut json_output = false;
    let mut active_only = false;

    for arg in args {
        match arg.as_str() {
            "--json" => json_output = true,
            "--active" => active_only = true,
            other => return Err(format!("unexpected argument: {}", other)),
        }
    }

    let broker_status = request("status", None).ok().map(|(_, rep)| rep);
    let connections = broker_status
        .as_ref()
        .and_then(|r| r.connections.as_ref())
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let registry = profiles::list().unwrap_or_default();

    if json_output {
        let backend_state = if broker_status.is_some() {
            "Running"
        } else {
            "Stopped"
        };
        let mut filtered_conns = connections.clone();
        if active_only {
            filtered_conns.retain(|c| {
                c.get("leases")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    > 0
            });
        }
        let out = json!({
            "backend_state": backend_state,
            "active_device_id": registry.active_device_id,
            "active_endpoint": registry.active_endpoint,
            "devices": registry.devices,
            "connections": filtered_conns,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(0);
    }

    if connections.is_empty() && registry.devices.is_empty() {
        println!("No Tailcat devices or connections configured.");
        println!("Use 'tailcatctl add <name> --tailcat <addr>' to add a device.");
        return Ok(0);
    }

    println!("{:<32} {:<16} {:<10} {:<10} STATUS", "ADDRESS", "DEVICE", "USER", "ENDPOINT");
    println!("{:<32} {:<16} {:<10} {:<10} ------", "-------", "------", "----", "--------");

    for dev in &registry.devices {
        let is_active_device = dev.id == registry.active_device_id;
        let active_star = if is_active_device { "*" } else { " " };
        let dev_display = format!("{}{}", dev.name, active_star);

        if let Some(tc) = &dev.tailcat {
            let active_conn = connections
                .iter()
                .find(|c| c.get("host").and_then(serde_json::Value::as_str) == Some(&tc.host));

            let status_str = if let Some(conn) = active_conn {
                let leases = conn.get("leases").and_then(serde_json::Value::as_u64).unwrap_or(0);
                format!("active; direct ({} lease{})", leases, if leases == 1 { "" } else { "s" })
            } else {
                "idle".to_string()
            };

            if !active_only || active_conn.is_some() {
                let addr_trunc = shorten_middle(&tc.host, 30);
                println!(
                    "{:<32} {:<16} {:<10} {:<10} {}",
                    addr_trunc, dev_display, tc.username, "tailcat", status_str
                );
            }
        }

        if let Some(lan) = &dev.lan {
            let active_conn = connections
                .iter()
                .find(|c| c.get("host").and_then(serde_json::Value::as_str) == Some(&lan.host));

            let status_str = if let Some(conn) = active_conn {
                let leases = conn.get("leases").and_then(serde_json::Value::as_u64).unwrap_or(0);
                format!("active; direct ({} lease{})", leases, if leases == 1 { "" } else { "s" })
            } else {
                "idle".to_string()
            };

            if !active_only || active_conn.is_some() {
                let lan_addr = format!("{}:{}", lan.host, lan.port);
                println!(
                    "{:<32} {:<16} {:<10} {:<10} {}",
                    lan_addr, dev_display, lan.username, "lan", status_str
                );
            }
        }
    }

    Ok(0)
}

fn ping_command(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: tailcatctl ping <hostname-or-device>".into());
    }
    let target = &args[0];
    let (dev, config) = profiles::resolve_target(target, None)?;
    let dev_name = dev
        .as_ref()
        .map(|d| d.name.as_str())
        .unwrap_or_else(|| &config.host);

    println!("pinging {} ({})...", dev_name, config.host);
    match ping_endpoint(&config) {
        Ok(rtt) => {
            println!(
                "pong from {} ({}) via {} in {:.1}ms",
                dev_name,
                config.host,
                if tailcatctl::is_tailcat_host(&config.host) {
                    "tailcat"
                } else {
                    "lan"
                },
                rtt.as_secs_f64() * 1000.0
            );
            Ok(0)
        }
        Err(e) => {
            eprintln!("ping to {} failed: {}", dev_name, e);
            Ok(1)
        }
    }
}

fn switch_command(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: tailcatctl switch <device> [--endpoint lan|tailcat] | switch --list [--json]".into());
    }
    if args[0] == "--list" || args[0] == "-l" {
        let json_mode = args.len() > 1 && args[1] == "--json";
        let reg = profiles::list()?;
        if json_mode {
            println!("{}", serde_json::to_string_pretty(&reg.devices).unwrap());
            return Ok(0);
        }
        println!("{:<12} {:<34} {:<8} ENDPOINTS", "NAME", "ID", "ACTIVE");
        println!("{:<12} {:<34} {:<8} ---------", "----", "----", "------");
        for dev in &reg.devices {
            let active = if dev.id == reg.active_device_id {
                "*"
            } else {
                ""
            };
            let mut endpoints = Vec::new();
            if dev.tailcat.is_some() {
                endpoints.push("tailcat");
            }
            if dev.lan.is_some() {
                endpoints.push("lan");
            }
            println!(
                "{:<12} {:<34} {:<8} {}",
                dev.name,
                dev.id,
                active,
                endpoints.join(", ")
            );
        }
        return Ok(0);
    }

    let mut device_name = None;
    let mut endpoint_opt = None;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].clone();
        match flag.as_str() {
            "--endpoint" | "-e" => {
                endpoint_opt = Some(option_value(args, &mut i, if flag == "-e" { "-e" } else { "--endpoint" })?);
            }
            other if !other.starts_with('-') && device_name.is_none() => {
                device_name = Some(other.to_owned());
            }
            other => return Err(format!("unexpected argument: {}", other)),
        }
        i += 1;
    }

    let target = device_name.ok_or_else(|| "usage: tailcatctl switch <device> [--endpoint lan|tailcat]".to_string())?;
    let (dev, ep) = profiles::select(&target, endpoint_opt.as_deref())?;
    println!("Switched to device \"{}\" ({}) [endpoint: {}]", dev.name, dev.id, ep);
    Ok(0)
}

fn up_command(args: &[String]) -> Result<i32, String> {
    let target = args.first().map(String::as_str);
    let (device, mut config) = profiles::resolve(target, false)?;
    println!(
        "Connecting to {} ({})...",
        device.name, config.host
    );
    let (stream, control) = acquire_prompted(&mut config)?;
    println!(
        "Connected to {} ({}) via control master {}",
        device.name, config.host, control
    );
    drop(stream);
    Ok(0)
}

fn down_command(args: &[String]) -> Result<i32, String> {
    let target = args.first().map(String::as_str);
    let (device, _) = profiles::resolve(target, false)?;
    println!("Stopping master connection for {}...", device.name);
    // Future expansion: send release to broker
    println!("Done.");
    Ok(0)
}

fn devices_command(args: &[String]) -> Result<i32, String> {
    let json_mode = args.iter().any(|a| a == "--json");
    let reg = profiles::list()?;
    if json_mode {
        println!("{}", serde_json::to_string_pretty(&reg).unwrap());
        return Ok(0);
    }
    println!("{:<12} {:<34} {:<8} {}", "NAME", "ID", "TYPE", "HOST");
    println!("{:<12} {:<34} {:<8} {}", "----", "----", "----", "----");
    for dev in &reg.devices {
        if let Some(tc) = &dev.tailcat {
            println!("{:<12} {:<34} {:<8} {}", dev.name, dev.id, "tailcat", shorten_middle(&tc.host, 34));
        }
        if let Some(lan) = &dev.lan {
            let host_str = format!("{}:{}", lan.host, lan.port);
            println!("{:<12} {:<34} {:<8} {}", dev.name, dev.id, "lan", shorten_middle(&host_str, 34));
        }
    }
    Ok(0)
}

fn add_command(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: tailcatctl add <name> --tailcat <addr> [--lan <ip>] [--user <user>] [--key <file>] [--port <port>]".into());
    }
    let name = &args[0];
    let mut tailcat_addr: Option<String> = None;
    let mut lan_host: Option<String> = None;
    let mut username = "root".to_string();
    let mut identity_file = "".to_string();
    let mut port = 22;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tailcat" | "-tc" => tailcat_addr = Some(option_value(args, &mut i, "--tailcat")?),
            "--lan" => lan_host = Some(option_value(args, &mut i, "--lan")?),
            "--user" | "-u" => username = option_value(args, &mut i, "--user")?,
            "--key" | "-i" => {
                identity_file = option_value(args, &mut i, "--key")?;
            }
            "--port" | "-p" => {
                let p_str = option_value(args, &mut i, "--port")?;
                port = p_str.parse::<u16>().map_err(|_| "invalid port")?;
            }
            other => return Err(format!("unexpected argument: {}", other)),
        }
        i += 1;
    }

    if tailcat_addr.is_none() && lan_host.is_none() {
        return Err("at least one of --tailcat <addr> or --lan <ip> must be specified".into());
    }

    let mut dev = profiles::Device::new(format!("dev_{}", name.to_ascii_lowercase()), name.clone());

    if let Some(tc) = tailcat_addr {
        let mut cfg = Config::default();
        cfg.host = tc;
        cfg.port = port;
        cfg.username = username.clone();
        cfg.identity_file = identity_file.clone();
        dev.tailcat = Some(cfg);
    }

    if let Some(lan) = lan_host {
        let mut cfg = Config::default();
        cfg.host = lan;
        cfg.port = port;
        cfg.username = username;
        cfg.identity_file = identity_file;
        dev.lan = Some(cfg);
    }

    let saved = profiles::upsert_device(dev)?;
    println!("Saved device \"{}\" (id: {})", saved.name, saved.id);
    Ok(0)
}

fn remove_command(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err("usage: tailcatctl remove <device>".into());
    }
    let removed = profiles::remove_device(&args[0])?;
    println!("Removed device \"{}\" ({})", removed.name, removed.id);
    Ok(0)
}

fn lease_config(args: &[String]) -> Result<Config, String> {
    let mut path = None;
    let mut device_id = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" || args[i].starts_with("--config=") {
            path = Some(option_value(args, &mut i, "--config")?);
        } else if args[i] == "--device" || args[i].starts_with("--device=") {
            device_id = Some(option_value(args, &mut i, "--device")?);
        } else {
            return Err(format!("unexpected argument: {}", args[i]));
        }
        i += 1;
    }
    if let Some(path) = path {
        if path == "-" {
            let mut stdin = io::stdin();
            let mut line = Vec::new();
            let mut byte = [0_u8; 1];
            loop {
                let count = stdin
                    .read(&mut byte)
                    .map_err(|e| format!("read lease config: {}", e))?;
                if count == 0 || byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > 64 * 1024 {
                    return Err("lease config exceeds size limit".into());
                }
            }
            serde_json::from_slice(&line).map_err(|e| format!("invalid lease config: {}", e))
        } else {
            load_config(&path)
        }
    } else {
        profiles::resolve(device_id.as_deref(), false)
            .map_err(|e| format!("resolve device profile: {}", e))
            .map(|(_, config)| config)
    }
}

fn lease_command(args: &[String]) -> i32 {
    install_signal_handlers();
    let config = match lease_config(args) {
        Ok(value) => value,
        Err(error) => {
            print_error_reply(error);
            return 2;
        }
    };
    let (stream, reply) = match request("acquire", Some(&config)) {
        Ok(value) => value,
        Err(error) => {
            print_error_reply(error);
            return 1;
        }
    };
    match serde_json::to_string(&reply) {
        Ok(text) => {
            println!("{}", text);
            let _ = io::stdout().flush();
        }
        Err(error) => {
            print_error_reply(format!("cannot encode broker reply: {}", error));
            drop(stream);
            return 1;
        }
    }
    if !reply.ok || reply.control_path.is_none() {
        drop(stream);
        return 1;
    }
    hold_lease(stream);
    0
}

fn hold_lease(_stream: UnixStream) {
    let fd = io::stdin().as_raw_fd();
    let mut stdin = io::stdin();
    let mut buffer = [0_u8; 4096];
    loop {
        if TERMINATE.load(Ordering::SeqCst) {
            return;
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, 250) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if result == 0 {
            continue;
        }
        if pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return;
        }
        if pollfd.revents & libc::POLLIN != 0 {
            match stdin.read(&mut buffer) {
                Ok(0) => return,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }
}

fn host_keys_command(args: &[String]) -> Result<i32, String> {
    let mut config_path = None;
    let mut device_id = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" || args[i].starts_with("--config=") {
            config_path = Some(option_value(args, &mut i, "--config")?);
        } else if args[i] == "--device" || args[i].starts_with("--device=") {
            device_id = Some(option_value(args, &mut i, "--device")?);
        } else {
            return Err(format!("unexpected argument: {}", args[i]));
        }
        i += 1;
    }

    let config = if let Some(path) = config_path {
        if path == "-" {
            let mut text = String::new();
            io::stdin()
                .read_to_string(&mut text)
                .map_err(|e| format!("cannot read config: {}", e))?;
            serde_json::from_str(&text).map_err(|e| format!("invalid config: {}", e))?
        } else {
            load_config(&path)?
        }
    } else {
        profiles::resolve(device_id.as_deref(), false)?.1
    };

    config.validate()?;
    let timeout = Duration::from_secs(config.timeout.min(10));
    let mut keys = Vec::new();

    if tailcatctl::is_tailcat_host(&config.host) {
        let tc_bin = if config.tailcat_executable.is_empty() {
            tailcatctl::find_tailcat().ok_or_else(|| "tailcat executable required".to_string())?
        } else {
            config.tailcat_executable.clone()
        };
        let known_hosts = NamedTempFile::new()
            .map_err(|e| format!("create temporary known_hosts: {}", e))?;
        let proxy = format!(
            "ProxyCommand='{}' '{}' '{}'",
            tc_bin.replace('\'', "'\\''"),
            config.host.replace('\'', "'\\''"),
            config.port
        );
        let mut command = Command::new(&config.ssh_executable);
        command
            .args(["-F", "/dev/null"])
            .args(["-o", "StrictHostKeyChecking=accept-new"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.path().display()))
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .arg("-o")
            .arg(proxy)
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "NumberOfPasswordPrompts=0"])
            .arg("-o")
            .arg(format!("ConnectTimeout={}", config.timeout))
            .arg("-p")
            .arg(config.port.to_string())
            .arg(format!("probe@{}", config.host))
            .arg("true");

        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();

        if let Ok(text) = fs::read_to_string(known_hosts.path()) {
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && !parts[0].starts_with('#') {
                    keys.push(format!("{},{} {} {}", config.host.to_ascii_lowercase(), config.host, parts[1], parts[2]));
                }
            }
        }
    } else {
        let mut command = Command::new("ssh-keyscan");
        command
            .arg("-T")
            .arg(config.timeout.to_string())
            .arg("-p")
            .arg(config.port.to_string())
            .arg(&config.host);
        if let Ok(output) = command.output() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && !parts[0].starts_with('#') {
                    keys.push(line.to_owned());
                }
            }
        }
    }

    if keys.is_empty() {
        return Err("no SSH host keys were returned".into());
    }
    println!("{}", json!({ "keys": keys }));
    Ok(0)
}

fn frontend_command() -> Result<i32, String> {
    println!("{}", profiles::frontend()?);
    Ok(0)
}

fn sync_command(args: &[String]) -> Result<i32, String> {
    let mut path = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" || args[i].starts_with("--config=") {
            path = Some(option_value(args, &mut i, "--config")?);
        } else {
            return Err(format!("unexpected argument: {}", args[i]));
        }
        i += 1;
    }
    let source = path.ok_or_else(|| "sync requires --config FILE|-".to_owned())?;
    let text = if source == "-" {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("cannot read registry: {}", e))?;
        text
    } else {
        fs::read_to_string(&source)
            .map_err(|e| format!("cannot read registry {}: {}", source, e))?
    };
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid registry: {}", e))?;
    println!("{}", profiles::sync_frontend(value)?);
    Ok(0)
}

fn real_main() -> Result<i32, String> {
    install_signal_handlers();
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        usage();
        return Ok(0);
    }
    let command = args.remove(0);
    match command.as_str() {
        "ssh" => run_ssh_subcommand(&args, false),
        "cmd" => run_ssh_subcommand(&args, true),
        "sftp" => run_sftp_subcommand(&args),
        "status" => status_command(&args),
        "ping" => ping_command(&args),
        "switch" => switch_command(&args),
        "use" => switch_command(&args),
        "up" => up_command(&args),
        "down" => down_command(&args),
        "devices" | "list" | "ls" => devices_command(&args),
        "add" => add_command(&args),
        "remove" => remove_command(&args),
        "version" | "--version" | "-v" => {
            println!("tailcatctl {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "lease" => Ok(lease_command(&args)),
        "host-keys" => host_keys_command(&args),
        "ensure" => {
            ensure_daemon()?;
            Ok(0)
        }
        "daemon" => {
            run_daemon()?;
            Ok(0)
        }
        "frontend" => frontend_command(),
        "sync" => sync_command(&args),
        other => {
            let is_user_device = other.contains('@');
            let is_tc = tailcatctl::is_tailcat_host(other);
            let is_known_dev = profiles::list()
                .map(|reg| {
                    reg.devices
                        .iter()
                        .any(|d| d.id == other || d.name.eq_ignore_ascii_case(other))
                })
                .unwrap_or(false);

            if is_user_device || is_tc || is_known_dev {
                let mut ssh_args = vec![other.to_owned()];
                ssh_args.extend(args);
                run_ssh_subcommand(&ssh_args, false)
            } else {
                Err(format!(
                    "unknown command or device {:?} (try --help or 'tailcatctl devices')",
                    other
                ))
            }
        }
    }
}

fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("tailcatctl: {}", error);
            std::process::exit(2);
        }
    }
}
