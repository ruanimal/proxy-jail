use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::config::JailConfig;
use crate::config::real_home;

/// System .desktop files directory
const SYSTEM_DESKTOP_DIR: &str = "/usr/share/applications";

/// User .desktop files directory
const USER_DESKTOP_DIR: &str = ".local/share/applications";

/// Uninstall a .desktop file by its original name or the generated name
pub fn desktop_uninstall_from_file(jail: &JailConfig, desktop_name: &str) -> Result<()> {
    let dir = user_desktop_dir()?;

    // Try matching by original source name: pj-{jail}-{command}.desktop
    // Derive command from desktop_name: strip path and .desktop suffix
    let stem = Path::new(desktop_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| desktop_name.to_string());

    // Try the generated name pattern first: pj-{jail}-{stem}.desktop
    let generated_name = format!("pj-{}-{}.desktop", jail.name, stem);
    let generated_path = dir.join(&generated_name);
    if generated_path.exists() {
        fs::remove_file(&generated_path)
            .with_context(|| format!("Failed to remove .desktop file: {:?}", generated_path))?;
        info!("Removed .desktop file: {:?}", generated_path);
        println!("Removed: {:?}", generated_path);
        return Ok(());
    }

    // If the user passed the full generated filename directly
    let direct_path = dir.join(desktop_name);
    if direct_path.exists() {
        fs::remove_file(&direct_path)
            .with_context(|| format!("Failed to remove .desktop file: {:?}", direct_path))?;
        info!("Removed .desktop file: {:?}", direct_path);
        println!("Removed: {:?}", direct_path);
        return Ok(());
    }

    anyhow::bail!("Desktop file not found for '{}' in jail '{}'", desktop_name, jail.name);
}

/// Find a .desktop file in system directories
fn find_desktop_file(name: &str) -> Result<PathBuf> {
    // If it's already a full path, use it
    let path = Path::new(name);
    if path.is_absolute() && path.exists() {
        return Ok(path.to_path_buf());
    }

    // Add .desktop extension if not present
    let filename = if name.ends_with(".desktop") {
        name.to_string()
    } else {
        format!("{}.desktop", name)
    };

    // Search in system directories
    let search_dirs = vec![
        PathBuf::from(SYSTEM_DESKTOP_DIR),
        user_desktop_dir()?,
    ];

    for dir in search_dirs {
        let path = dir.join(&filename);
        if path.exists() {
            return Ok(path);
        }
    }

    anyhow::bail!("Desktop file not found: {}", name)
}

/// Parse a .desktop file into a HashMap
fn parse_desktop_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read .desktop file: {:?}", path))?;

    let mut entries = HashMap::new();
    let mut in_desktop_entry = false;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Check for section headers
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }

        // Parse key=value pairs
        if in_desktop_entry {
            if let Some((key, value)) = line.split_once('=') {
                entries.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    Ok(entries)
}

/// Get the user's .desktop directory
fn user_desktop_dir() -> Result<PathBuf> {
    let dir = real_home().join(USER_DESKTOP_DIR);

    // Create directory if it doesn't exist
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create .desktop directory: {:?}", dir))?;
    }

    Ok(dir)
}

/// Install a .desktop file for an application in a jail, directly from a .desktop file path
pub fn desktop_install_from_file(jail: &JailConfig, desktop_path: &str) -> Result<()> {
    let source_path = find_desktop_file(desktop_path)?;
    info!("Installing .desktop file from {:?} in jail {}", source_path, jail.name);

    let desktop_entry = parse_desktop_file(&source_path)?;

    // Extract command from Exec field
    let original_exec = desktop_entry.get("Exec").cloned()
        .context("No Exec field found in .desktop file")?;

    // Use the source .desktop filename stem as the command identifier
    let exec_cmd = source_path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| {
            original_exec.split_whitespace()
                .next()
                .unwrap_or(&original_exec)
                .to_string()
        });

    let original_name = desktop_entry.get("Name").cloned().unwrap_or_else(|| exec_cmd.clone());
    let target_name = format!("pj-{}-{}.desktop", jail.name, exec_cmd);
    let target_path = user_desktop_dir()?.join(&target_name);

    let display_name = format!("{} (jail: {})", original_name, jail.name);
    let new_exec = format!("proxy-jail app run {} -- {}", jail.name, original_exec);

    let mut content = String::new();
    content.push_str("[Desktop Entry]\n");
    content.push_str(&format!("Name={}\n", display_name));
    content.push_str(&format!("GenericName={}\n", original_name));
    content.push_str(&format!("Exec={}\n", new_exec));

    if let Some(icon) = desktop_entry.get("Icon") {
        content.push_str(&format!("Icon={}\n", icon));
    }
    if let Some(comment) = desktop_entry.get("Comment") {
        content.push_str(&format!("Comment={} (via proxy-jail)\n", comment));
    }
    if let Some(terminal) = desktop_entry.get("Terminal") {
        content.push_str(&format!("Terminal={}\n", terminal));
    }
    if let Some(type_val) = desktop_entry.get("Type") {
        content.push_str(&format!("Type={}\n", type_val));
    } else {
        content.push_str("Type=Application\n");
    }
    if let Some(categories) = desktop_entry.get("Categories") {
        content.push_str(&format!("Categories={}\n", categories));
    }
    if let Some(mimetype) = desktop_entry.get("MimeType") {
        content.push_str(&format!("MimeType={}\n", mimetype));
    }
    if let Some(startup_wm_class) = desktop_entry.get("StartupWMClass") {
        content.push_str(&format!("StartupWMClass={}\n", startup_wm_class));
    }

    content.push_str(&format!("X-Proxy-Jail={}\n", jail.name));
    content.push_str(&format!("X-Proxy-Jail-Original={}\n", source_path.display()));

    fs::write(&target_path, &content)
        .with_context(|| format!("Failed to write .desktop file: {:?}", target_path))?;

    info!("Installed .desktop file: {:?}", target_path);
    println!("Installed: {:?}", target_path);
    Ok(())
}

/// List installed proxy-jail .desktop files
pub fn list_desktop_files(jail_name: Option<&str>) -> Result<Vec<PathBuf>> {
    let dir = user_desktop_dir()?;
    let mut files = Vec::new();

    if dir.exists() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map_or(false, |ext| ext == "desktop") {
                let filename = path.file_name().unwrap().to_string_lossy();

                match jail_name {
                    Some(jail) => {
                        if filename.starts_with(&format!("pj-{}-", jail)) {
                            files.push(path);
                        }
                    }
                    None => {
                        if filename.starts_with("pj-") {
                            files.push(path);
                        }
                    }
                }
            }
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_desktop_file() {
        let content = r#"[Desktop Entry]
Name=Firefox
Exec=firefox %u
Icon=firefox
Type=Application
Categories=Network;WebBrowser;
"#;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test.desktop");
        fs::write(&temp_file, content).unwrap();

        let entries = parse_desktop_file(&temp_file).unwrap();
        assert_eq!(entries.get("Name").unwrap(), "Firefox");
        assert_eq!(entries.get("Exec").unwrap(), "firefox %u");
        assert_eq!(entries.get("Icon").unwrap(), "firefox");
        assert_eq!(entries.get("Type").unwrap(), "Application");

        // Clean up
        fs::remove_file(&temp_file).unwrap();
    }
}
