fn main() {
    let _ = rb_sys_env::activate().unwrap();
    // T-331, D-271: since Rust 1.100, std's `WaitOnAddress`/`WakeByAddress*` come from a plain
    // `-lsynchronization` placed after `-lkernel32`. The MinGW in rb-sys-dock's Windows image has
    // those names in `libkernel32.a`, so the linker bound them to KERNEL32.dll, which does not
    // export them, and the gem failed to load (`127`). Naming the library here puts it before std's.
    let target = |key: &str| std::env::var(key).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") == "windows" && target("CARGO_CFG_TARGET_ENV") == "gnu" {
        println!("cargo:rustc-link-lib=dylib=synchronization");
    }
}
