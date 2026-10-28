use anyhow::{Context, Result};
use std::collections::HashMap;
use nix::unistd::{Gid, Uid, fchown};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

use crate::config::JailConfig;
use crate::config::real_home;

/// System .desktop files directory
const SYSTEM_DESKTOP_DIR: &str = "/usr/share/applications";

/// Uninstall a .desktop file by its original name or the generated name
pub fn desktop_uninstall_from_file(jail: &JailConfig, desktop_name: &str) -> Result<()> {
    let home = real_home();
    let owner = desktop_owner()?;
    let dir = ensure_desktop_dir(&home, owner)?;

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
        eprintln!("Removed desktop entry for jail '{}': {}", jail.name, generated_path.display());
        crate::desktop_cache::refresh(&dir, &home, owner);
        return Ok(());
    }

    // If the user passed the full generated filename directly
    let direct_path = dir.join(desktop_name);
    if direct_path.exists() {
        fs::remove_file(&direct_path)
            .with_context(|| format!("Failed to remove .desktop file: {:?}", direct_path))?;
        info!("Removed .desktop file: {:?}", direct_path);
        eprintln!("Removed desktop entry for jail '{}': {}", jail.name, direct_path.display());
        crate::desktop_cache::refresh(&dir, &home, owner);
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

/// Parse a .desktop file into a HashMap (for quick field lookups)
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
        if in_desktop_entry
            && let Some((key, value)) = line.split_once('=')
        {
            entries.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Ok(entries)
}

/// Transform the original .desktop file content line-by-line, only modifying
/// the fields that need to change (Name, Exec, Comment) and preserving everything
/// else — including [Desktop Action ...] sections, localized strings, Keywords,
/// StartupNotify, and any future fields the application may add.
fn transform_desktop_content(
    original_content: &str,
    jail_name: &str,
    source_path: &Path,
) -> String {
    let mut output = String::with_capacity(original_content.len() + 256);
    let mut in_desktop_entry = false;
    let mut desktop_entry_ended = false;

    for line in original_content.lines() {
        let trimmed = line.trim();

        // Section header
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Inject X-Proxy-Jail fields right before the first non-[Desktop Entry] section
            if !desktop_entry_ended && in_desktop_entry {
                // Strip at most one trailing blank line so metadata sits flush
                // with the [Desktop Entry] content.
                if output.ends_with("\n\n") {
                    output.pop();
                }
                output.push_str(&format!("X-Proxy-Jail={}\n", jail_name));
                output.push_str(&format!("X-Proxy-Jail-Original={}\n", source_path.display()));
                // Blank line to separate metadata from the next section
                output.push('\n');
                desktop_entry_ended = true;
            }
            in_desktop_entry = trimmed == "[Desktop Entry]";
            output.push_str(line);
            output.push('\n');
            continue;
        }

        if in_desktop_entry {
            if let Some((key, value)) = trimmed.split_once('=') {
                match key {
                    "Name" if !key.contains('[') => {
                        // Main Name field — append jail tag
                        output.push_str(&format!("Name={} (jail: {})\n", value, jail_name));
                        continue;
                    }
                    "Exec" if !key.contains('[') => {
                        // Main Exec field — wrap with proxy-jail
                        output.push_str(&format!(
                            "Exec=proxy-jail app exec --jail {} -- {}\n",
                            jail_name, value
                        ));
                        continue;
                    }
                    "Comment" if !key.contains('[') => {
                        // Main Comment field — annotate
                        output.push_str(&format!("Comment={} (via proxy-jail)\n", value));
                        continue;
                    }
                    _ => {}
                }
            }
        } else if let Some(value) = trimmed.strip_prefix("Exec=") {
            output.push_str(&format!(
                "Exec=proxy-jail app exec --jail {} -- {}\n",
                jail_name, value
            ));
            continue;
        }

        // All other lines pass through unchanged
        output.push_str(line);
        output.push('\n');
    }

    // If [Desktop Entry] was the only/last section, append metadata at the end
    if !desktop_entry_ended && in_desktop_entry {
        output.push_str(&format!("X-Proxy-Jail={}\n", jail_name));
        output.push_str(&format!("X-Proxy-Jail-Original={}\n", source_path.display()));
    }

    output
}

/// Resolve the invoking user and group when running under sudo.
fn desktop_owner() -> Result<(Uid, Gid)> {
    match std::env::var("SUDO_UID") {
        Ok(uid) => {
            let uid = uid.parse::<u32>().context("Invalid SUDO_UID")?;
            let gid = std::env::var("SUDO_GID")
                .context("SUDO_GID is required when SUDO_UID is set")?
                .parse::<u32>()
                .context("Invalid SUDO_GID")?;
            Ok((Uid::from_raw(uid), Gid::from_raw(gid)))
        }
        Err(std::env::VarError::NotPresent) => Ok((Uid::current(), Gid::current())),
        Err(err) => Err(err.into()),
    }
}

fn set_owner(file: &File, owner: (Uid, Gid)) -> Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != owner.0.as_raw() || metadata.gid() != owner.1.as_raw() {
        fchown(file.as_raw_fd(), Some(owner.0), Some(owner.1))?;
    }
    Ok(())
}

/// Create the user directories and repair root-owned directories from older versions.
fn ensure_desktop_dir(home: &Path, owner: (Uid, Gid)) -> Result<PathBuf> {
    let mut dir = home.to_path_buf();
    for component in [".local", "share", "applications"] {
        dir.push(component);
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err).with_context(|| format!("Failed to create directory: {:?}", dir)),
        }
        // Do not change an existing symlink's target or another user's directory.
        let metadata = fs::symlink_metadata(&dir)
            .with_context(|| format!("Failed to inspect directory: {:?}", dir))?;
        if metadata.is_dir() && metadata.uid() == 0 && owner.0.as_raw() != 0 {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&dir)
                .with_context(|| format!("Failed to open directory: {:?}", dir))?;
            let actual = file.metadata()?;
            if actual.uid() == 0 && owner.0.as_raw() != 0 {
                set_owner(&file, owner)
                    .with_context(|| format!("Failed to set directory owner: {:?}", dir))?;
            }
        }
    }
    Ok(dir)
}

/// Get the user's .desktop directory.
fn user_desktop_dir() -> Result<PathBuf> {
    ensure_desktop_dir(&real_home(), desktop_owner()?)
}

/// Replace a generated entry atomically, including previously root-owned entries.
fn write_desktop_file(path: &Path, content: &str, owner: (Uid, Gid)) -> Result<()> {
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().context("Desktop file has no parent directory")?;
    let (temp_path, mut file) = loop {
        let name = format!(".proxy-jail-{}-{}.tmp", std::process::id(), NEXT_TEMP.fetch_add(1, Ordering::Relaxed));
        let temp_path = parent.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&temp_path) {
            Ok(file) => break (temp_path, file),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err).with_context(|| format!("Failed to create temporary desktop file in {:?}", parent)),
        }
    };
    let result = (|| -> Result<()> {
        file.write_all(content.as_bytes()).context("Failed to write desktop file")?;
        set_owner(&file, owner).context("Failed to set desktop file owner")?;
        fs::rename(&temp_path, path).context("Failed to install desktop file")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

/// Install a .desktop file for an application in a jail, directly from a .desktop file path
/// Uses a line-by-line transform approach: only modifies Name, Exec, and Comment,
/// preserving all other fields, sections (including [Desktop Action ...]), and
/// localized strings from the original file.
pub fn desktop_install_from_file(jail: &JailConfig, desktop_path: &str) -> Result<()> {
    let source_path = find_desktop_file(desktop_path)?;
    info!("Installing .desktop file from {:?} in jail {}", source_path, jail.name);

    let original_content = fs::read_to_string(&source_path)
        .with_context(|| format!("Failed to read .desktop file: {:?}", source_path))?;

    // Parse just for the filename stem derivation
    let desktop_entry = parse_desktop_file(&source_path)?;
    let original_exec = desktop_entry.get("Exec").cloned()
        .context("No Exec field found in .desktop file")?;

    let exec_cmd = source_path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| {
            original_exec.split_whitespace()
                .next()
                .unwrap_or(&original_exec)
                .to_string()
        });

    let target_name = format!("pj-{}-{}.desktop", jail.name, exec_cmd);
    let home = real_home();
    let owner = desktop_owner()?;
    let dir = ensure_desktop_dir(&home, owner)?;
    let target_path = dir.join(&target_name);

    // Transform the original file content, preserving all fields and sections
    let content = transform_desktop_content(&original_content, &jail.name, &source_path);

    write_desktop_file(&target_path, &content, owner)
        .with_context(|| format!("Failed to write .desktop file: {:?}", target_path))?;

    info!("Installed .desktop file: {:?}", target_path);
    eprintln!("Installed desktop entry for jail '{}': {}", jail.name, target_path.display());
    crate::desktop_cache::refresh(&dir, &home, owner);
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

            if path.extension().is_some_and(|ext| ext == "desktop") {
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

    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desktop_ownership_and_replacement() {
        use std::os::unix::fs::symlink;

        let home = std::env::temp_dir().join(format!("proxy-jail-desktop-test-{}", std::process::id()));
        fs::create_dir(&home).unwrap();
        let owner = desktop_owner().unwrap();
        let old_dir = home.join(".local/share/applications");
        fs::create_dir_all(&old_dir).unwrap();
        let dir = ensure_desktop_dir(&home, owner).unwrap();
        for path in [home.join(".local"), home.join(".local/share"), dir.clone()] {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(metadata.uid(), owner.0.as_raw());
            assert_eq!(metadata.gid(), owner.1.as_raw());
        }

        let path = dir.join("pj-test.desktop");
        fs::write(&path, "old entry").unwrap();
        write_desktop_file(&path, "new entry", owner).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.uid(), owner.0.as_raw());
        assert_eq!(metadata.gid(), owner.1.as_raw());
        assert_eq!(fs::read_to_string(&path).unwrap(), "new entry");

        let other = home.join("other");
        fs::write(&other, "untouched").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&other, &path).unwrap();
        write_desktop_file(&path, "replacement", owner).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
        assert_eq!(fs::read_to_string(&other).unwrap(), "untouched");
        fs::remove_dir_all(home).unwrap();
    }

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

    #[test]
    fn test_transform_codex_desktop() {
        let content = "\
[Desktop Entry]
Name=Codex Desktop
Comment=Run Codex Desktop on Linux
Exec=env BAMF_DESKTOP_FILE_HINT=/usr/share/applications/codex-desktop.desktop CHROME_DESKTOP=codex-desktop.desktop /usr/bin/codex-desktop %u
Icon=codex-desktop
Terminal=false
Type=Application
Categories=Development;
MimeType=x-scheme-handler/codex;x-scheme-handler/codex-browser-sidebar;
StartupNotify=true
StartupWMClass=codex-desktop
X-GNOME-WMClass=codex-desktop
Actions=new-window;CheckForUpdates;InstallReadyUpdate;

[Desktop Action new-window]
Name=New Window
Exec=env BAMF_DESKTOP_FILE_HINT=/usr/share/applications/codex-desktop.desktop CHROME_DESKTOP=codex-desktop.desktop CODEX_MULTI_LAUNCH=1 /usr/bin/codex-desktop --new-instance

[Desktop Action CheckForUpdates]
Name=Check for Updates
Exec=/usr/bin/codex-update-manager check-now

[Desktop Action InstallReadyUpdate]
Name=Install Ready Update
Exec=/usr/bin/codex-update-manager install-ready
";
        let source = Path::new("/usr/share/applications/codex-desktop.desktop");
        let result = transform_desktop_content(content, "testjail", source);

        // [Desktop Entry] fields: Name/Exec/Comment modified, rest unchanged
        assert!(result.contains("Name=Codex Desktop (jail: testjail)"));
        assert!(result.contains("Comment=Run Codex Desktop on Linux (via proxy-jail)"));
        assert!(result.contains("Exec=proxy-jail app exec --jail testjail -- env BAMF_DESKTOP_FILE_HINT=/usr/share/applications/codex-desktop.desktop CHROME_DESKTOP=codex-desktop.desktop /usr/bin/codex-desktop %u"));
        assert!(result.contains("Icon=codex-desktop\n"));
        assert!(result.contains("Terminal=false\n"));
        assert!(result.contains("StartupNotify=true\n"));
        assert!(result.contains("StartupWMClass=codex-desktop\n"));
        assert!(result.contains("X-GNOME-WMClass=codex-desktop\n"));
        assert!(result.contains("Actions=new-window;CheckForUpdates;InstallReadyUpdate;\n"));

        // Metadata injected
        assert!(result.contains("X-Proxy-Jail=testjail\n"));
        assert!(result.contains("X-Proxy-Jail-Original=/usr/share/applications/codex-desktop.desktop\n"));

        // [Desktop Action] Exec lines also wrapped
        assert!(result.contains("Exec=proxy-jail app exec --jail testjail -- env BAMF_DESKTOP_FILE_HINT=/usr/share/applications/codex-desktop.desktop CHROME_DESKTOP=codex-desktop.desktop CODEX_MULTI_LAUNCH=1 /usr/bin/codex-desktop --new-instance"));
        assert!(result.contains("Exec=proxy-jail app exec --jail testjail -- /usr/bin/codex-update-manager check-now"));
        assert!(result.contains("Exec=proxy-jail app exec --jail testjail -- /usr/bin/codex-update-manager install-ready"));

        // [Desktop Action] Name lines NOT modified
        assert!(result.contains("Name=New Window\n"));
        assert!(result.contains("Name=Check for Updates\n"));
        assert!(result.contains("Name=Install Ready Update\n"));

        // All 3 action sections preserved
        assert!(result.contains("[Desktop Action new-window]\n"));
        assert!(result.contains("[Desktop Action CheckForUpdates]\n"));
        assert!(result.contains("[Desktop Action InstallReadyUpdate]\n"));
    }
}
