use std::process::Command;

fn vhdx_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vhdx"))
}

fn data_path(name: &str) -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn info_shows_virtual_disk_size_dynamic() {
    let output = vhdx_bin()
        .args(["info", &data_path("qemu_empty_dynamic.vhdx")])
        .output()
        .expect("vhdx binary must run");
    assert!(output.status.success(), "exit status: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("16,777,216") || stdout.contains("16 MiB"),
        "expected virtual disk size in output, got: {stdout}"
    );
}

#[test]
fn info_shows_virtual_disk_size_fixed() {
    let output = vhdx_bin()
        .args(["info", &data_path("qemu_fixed.vhdx")])
        .output()
        .expect("vhdx binary must run");
    assert!(output.status.success(), "exit status: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("8,388,608") || stdout.contains("8 MiB"),
        "expected virtual disk size in output, got: {stdout}"
    );
}

#[test]
fn info_shows_format_line() {
    let output = vhdx_bin()
        .args(["info", &data_path("qemu_empty_dynamic.vhdx")])
        .output()
        .expect("vhdx binary must run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("VHDX"),
        "expected VHDX format line in output, got: {stdout}"
    );
}

#[test]
fn info_shows_sector_size() {
    let output = vhdx_bin()
        .args(["info", &data_path("qemu_empty_dynamic.vhdx")])
        .output()
        .expect("vhdx binary must run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("512"),
        "expected logical sector size in output, got: {stdout}"
    );
}

#[test]
fn info_errors_on_missing_file() {
    let output = vhdx_bin()
        .args(["info", "nonexistent.vhdx"])
        .output()
        .expect("vhdx binary must run");
    assert!(
        !output.status.success(),
        "should exit non-zero for missing file"
    );
}
