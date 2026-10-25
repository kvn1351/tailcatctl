use std::env;
use std::process::Command;
use tempfile::TempDir;

struct TestContext {
    _config_dir: TempDir,
    _runtime_dir: TempDir,
    bin: String,
}

impl TestContext {
    fn new() -> Self {
        let config_dir = tempfile::tempdir().unwrap();
        let runtime_dir = tempfile::tempdir().unwrap();
        let bin = env::var("CARGO_BIN_EXE_tailcatctl")
            .unwrap_or_else(|_| "./target/debug/tailcatctl".to_string());
        Self {
            _config_dir: config_dir,
            _runtime_dir: runtime_dir,
            bin,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.bin)
            .args(args)
            .env("TAILCATCTL_CONFIG_DIR", self._config_dir.path())
            .env("TAILCATCTL_RUNTIME_DIR", self._runtime_dir.path())
            .output()
            .expect("execute tailcatctl")
    }
}

#[test]
fn test_cli_add_switch_status_remove() {
    let ctx = TestContext::new();

    // 1. Initial status with empty config
    let out = ctx.run(&["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No Tailcat devices"));

    // 2. Add device "kindle"
    let out = ctx.run(&[
        "add",
        "kindle",
        "--tailcat",
        "tc4e3b79f2c7a840e2417e908b",
        "--lan",
        "192.168.1.150",
        "--user",
        "root",
    ]);
    assert!(out.status.success(), "add failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Saved device \"kindle\""));

    // 3. Add second device "oasis"
    let out = ctx.run(&[
        "add",
        "oasis",
        "--lan",
        "192.168.1.151",
        "--user",
        "root",
    ]);
    assert!(out.status.success());

    // 4. Switch list
    let out = ctx.run(&["switch", "--list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("kindle"));
    assert!(stdout.contains("oasis"));
    assert!(stdout.contains("*")); // active marker

    // 5. Switch to oasis
    let out = ctx.run(&["switch", "oasis"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Switched to device \"oasis\""));

    // 6. Status table
    let out = ctx.run(&["status"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ADDRESS"));
    assert!(stdout.contains("DEVICE"));
    assert!(stdout.contains("kindle"));
    assert!(stdout.contains("oasis*"));

    // 7. Status JSON
    let out = ctx.run(&["status", "--json"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json_val: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json_val["active_device_id"], "dev_oasis");
    assert_eq!(json_val["devices"].as_array().unwrap().len(), 2);

    // 8. Devices command
    let out = ctx.run(&["devices"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tc4e3b79f2c7a840e2417e908b"));
    assert!(stdout.contains("192.168.1.150:22"));

    // 9. Remove device oasis
    let out = ctx.run(&["remove", "oasis"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Removed device \"oasis\""));

    // Check oasis is gone
    let out = ctx.run(&["switch", "--list"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("oasis"));
    assert!(stdout.contains("kindle"));
}

#[test]
fn test_cli_ping_local() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let ctx = TestContext::new();
    ctx.run(&[
        "add",
        "loopback",
        "--lan",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--user",
        "testuser",
    ]);

    let out = ctx.run(&["ping", "loopback"]);
    assert!(out.status.success(), "ping failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("pong from loopback"));
    assert!(stdout.contains("ms"));
}

#[test]
fn test_cli_ssh_argument_parsing() {

    let ctx = TestContext::new();

    // Add device
    ctx.run(&[
        "add",
        "myreader",
        "--tailcat",
        "tc4e3b79f2c7a840e2417e908b",
        "--lan",
        "192.168.1.120",
        "--user",
        "root",
    ]);

    // Test with mock non-interactive command against non-listening target:
    // It should attempt to acquire connection to the resolved target
    // We expect it to try contacting broker and fail gracefully with connection error,
    // verifying that target resolution and arguments succeeded without syntax error.
    let out = ctx.run(&["ssh", "root@myreader:lan", "uname", "-a"]);
    // Since 192.168.1.120:22 is not reachable in this mock test, it will fail to connect,
    // but the error should come from SSH/connection, NOT from CLI argument parsing.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stderr.contains("unknown option"), "Unexpected option error: {}", stderr);
    assert!(!stdout.contains("unknown command"), "Unexpected command error: {}", stdout);
}
