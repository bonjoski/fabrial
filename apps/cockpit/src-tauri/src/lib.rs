pub mod ipc_client;
pub mod tray;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if let Err(e) = tray::setup_tray(app.handle()) {
                eprintln!("Warning: Failed to initialize tray: {}", e);
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running fabrial cockpit");
}
