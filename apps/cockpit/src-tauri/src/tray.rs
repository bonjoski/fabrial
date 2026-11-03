use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager, Wry,
};

pub fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let show_item = MenuItem::with_id(app, "show", "Open Cockpit", true, None::<&str>)?;
    let doctor_item = MenuItem::with_id(app, "doctor", "Run Fabrial Doctor", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show_item, &doctor_item, &quit_item])?;

    let _tray = TrayIconBuilder::with_id("fabrial-tray")
        .tooltip("Fabrial Sovereign AI Agent Security Fabric")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "doctor" => {
                let _ = std::process::Command::new("fabrial")
                    .arg("doctor")
                    .spawn();
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}
