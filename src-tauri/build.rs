fn main() {
    // Npcap installs wpcap.dll in %SystemRoot%\System32\Npcap, which is NOT on
    // the default DLL search path (unless Npcap was installed in "WinPcap
    // compatible" mode). Delay-loading wpcap.dll lets the app start without it,
    // point the loader at the Npcap folder (see `npcap::init`), and only then
    // resolve the pcap functions on first use.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");

        // The unit-test harness links the Wry runtime too (through the IPC
        // builder in lib.rs), whose Windows dialogs import comctl32 v6
        // (TaskDialogIndirect). The app declares that dependency in the manifest
        // tauri-build embeds; the harness has none and fails to start with
        // STATUS_ENTRYPOINT_NOT_FOUND. This writes an external `<exe>.manifest`
        // next to every linked executable (the loader honours it; the app's
        // embedded manifest takes precedence). Must stay on one line.
        println!(
            "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
    }

    tauri_build::build()
}
