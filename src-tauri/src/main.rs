// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `fishe.exe --mcp-stdio`: MCP stdio bridge to the running app, no window.
    if std::env::args().any(|a| a == "--mcp-stdio") {
        std::process::exit(fishe_core::mcp::bridge::run());
    }
    fishe_lib::run()
}
