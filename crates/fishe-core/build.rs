fn main() {
    // Npcap installs wpcap.dll in %SystemRoot%\System32\Npcap, which is NOT on
    // the default DLL search path. Everything that links this crate must
    // delay-load it, so the process can start without it and `npcap::init`
    // can point the loader at the Npcap folder first. The app's build script
    // does it for the app; this covers this crate's own test executables.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
