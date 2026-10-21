//! Optionally embed wintun.dll in the binary, so Windows users need only one
//! file. Set `TSR_WINTUN_DLL` to the path of the amd64 wintun.dll at build time.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(embed_wintun)");
    println!("cargo::rerun-if-env-changed=TSR_WINTUN_DLL");
    if let Ok(path) = std::env::var("TSR_WINTUN_DLL") {
        println!("cargo::rerun-if-changed={path}");
        println!("cargo::rustc-cfg=embed_wintun");
        println!("cargo::rustc-env=TSR_WINTUN_DLL_PATH={path}");
    }
}
