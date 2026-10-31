use anyhow::{Context, Result, ensure};
use nix::unistd::{Gid, Uid, fchown};
use std::collections::HashMap;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::config::JailConfig;
use crate::config::real_home;
use crate::security;

pub fn parse_desktop_name(name: &str) -> std::result::Result<String, String> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err("Expected a desktop filename, not a path".into());
    }
    Ok(name.to_string())
}

/// System .desktop files directory
const SYSTEM_DESKTOP_DIR: &str = "/usr/share/applications";

/// Uninstall a .desktop file by its original name or the generated name
pub fn desktop_uninstall_from_file(jail: &JailConfig, desktop_name: &str) -> Result<()> {
    let home = real_home();
    let owner = desktop_owner()?;
    let dir = ensure_desktop_dir(&home, owner)?;

    uninstall_in(&dir, &jail.name, desktop_name)?;
    crate::desktop_cache::refresh(&dir, &home, owner);
    Ok(())
}

fn uninstall_in(dir: &Path, jail_name: &str, desktop_name: &str) -> Result<()> {
    parse_desktop_name(desktop_name).map_err(anyhow::Error::msg)?;
    crate::config::parse_jail_name(jail_name).map_err(anyhow::Error::msg)?;
    let prefix = format!("pj-{jail_name}-");
    let filename = if desktop_name.starts_with(&prefix) && desktop_name.ends_with(".desktop") {
        desktop_name.to_string()
    } else {
        format!(
            "{prefix}{}.desktop",
            desktop_name
                .strip_suffix(".desktop")
                .unwrap_or(desktop_name)
        )
    };
    let path = dir.join(filename);
    let entries = parse_desktop_file(&path)?;
    ensure!(
        entries.get("X-Proxy-Jail").map(String::as_str) == Some(jail_name),
        "Refusing to delete an entry not managed by jail '{jail_name}'"
    );
    security::remove_file(&path).with_context(|| format!("Failed to remove {}", path.display()))?;
    eprintln!(
        "Removed desktop entry for jail '{jail_name}': {}",
        path.display()
    );
    Ok(())
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
    let search_dirs = vec![PathBuf::from(SYSTEM_DESKTOP_DIR), user_desktop_dir()?];

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
    let content = security::read_to_string(path)
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
        if in_desktop_entry && let Some((key, value)) = line.split_once('=') {
            entries.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    Ok(entries)
}

/// Transform the original .desktop file content line-by-line, only modifying
/// the fields that need to change (Name, Exec, Comment) and preserving everything
/// else — including [Desktop Action ...] sections, localized strings, Keywords,
/// StartupNotify, and any future fields the application may add.
///
/// `NoDisplay` and `Hidden` are dropped instead of being inherited. They hide
/// the entry the vendor chose to hide (for example Google Chrome ships
/// `com.google.Chrome.desktop` with `NoDisplay=true` so it does not duplicate
/// `google-chrome.desktop` in menus), but the generated entry has its own
/// desktop file ID (`pj-<jail>-<app>.desktop`), so inheriting the flag would
/// only make the jail entry invisible with nothing to deduplicate.
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
                output.push_str(&format!(
                    "X-Proxy-Jail-Original={}\n",
                    source_path.display()
                ));
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
                    // See the function docs: hide flags belong to the source
                    // entry, not to the generated one.
                    "NoDisplay" | "Hidden" => continue,
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
        output.push_str(&format!(
            "X-Proxy-Jail-Original={}\n",
            source_path.display()
        ));
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
        let file = security::directory(&dir, true, 0o755)
            .with_context(|| format!("Failed to open desktop directory: {dir:?}"))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.uid() == owner.0.as_raw() || metadata.uid() == 0,
            "Desktop directory belongs to another user: {}",
            dir.display()
        );
        if metadata.uid() == 0 && owner.0.as_raw() != 0 {
            set_owner(&file, owner)?;
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
    security::atomic_write_owned(path, content.as_bytes(), owner.0, owner.1)
}

/// Install a .desktop file for an application in a jail, directly from a .desktop file path
/// Uses a line-by-line transform approach: only modifies Name, Exec, and Comment,
/// preserving all other fields, sections (including [Desktop Action ...]), and
/// localized strings from the original file. `NoDisplay`/`Hidden` are removed so
/// the generated entry stays visible in application menus.
pub fn desktop_install_from_file(jail: &JailConfig, desktop_path: &str) -> Result<()> {
    crate::config::parse_jail_name(&jail.name).map_err(anyhow::Error::msg)?;
    let source_path = find_desktop_file(desktop_path)?;
    info!(
        "Installing .desktop file from {:?} in jail {}",
        source_path, jail.name
    );

    let original_content = security::read_to_string(&source_path)
        .with_context(|| format!("Failed to read .desktop file: {:?}", source_path))?;

    // Parse just for the filename stem derivation
    let desktop_entry = parse_desktop_file(&source_path)?;
    let original_exec = desktop_entry
        .get("Exec")
        .cloned()
        .context("No Exec field found in .desktop file")?;

    let exec_cmd = source_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| {
            original_exec
                .split_whitespace()
                .next()
                .unwrap_or(&original_exec)
                .to_string()
        });

    let target_name = format!("pj-{}-{}.desktop", jail.name, exec_cmd);
    parse_desktop_name(&target_name).map_err(anyhow::Error::msg)?;
    let home = real_home();
    let owner = desktop_owner()?;
    let dir = ensure_desktop_dir(&home, owner)?;
    let target_path = dir.join(&target_name);

    // Transform the original file content, preserving all fields and sections
    let content = transform_desktop_content(&original_content, &jail.name, &source_path);

    write_desktop_file(&target_path, &content, owner)
        .with_context(|| format!("Failed to write .desktop file: {:?}", target_path))?;

    info!("Installed .desktop file: {:?}", target_path);
    eprintln!(
        "Installed desktop entry for jail '{}': {}",
        jail.name,
        target_path.display()
    );
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
    fn desktop_deletion_is_confined_to_managed_entries() {
        for name in [
            "My Browser.desktop",
            "浏览器.desktop",
            "org.example..App.desktop",
        ] {
            assert!(parse_desktop_name(name).is_ok());
        }
        for name in [".", "..", "bad\nname.desktop", "bad\0name.desktop"] {
            assert!(parse_desktop_name(name).is_err());
        }
        let base = std::env::var_os("PI_SCRATCH_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!("desktop-delete-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("pj-work-browser.desktop");
        let content =
            "[Desktop Entry]\nX-Proxy-Jail=work\nExec=proxy-jail app exec --jail work -- browser\n";
        fs::write(&path, content).unwrap();
        for name in [
            "../victim",
            "/etc/passwd",
            "a/b.desktop",
            "..",
            "a\\b.desktop",
        ] {
            assert!(uninstall_in(&dir, "work", name).is_err());
        }
        assert!(uninstall_in(&dir, "other", "pj-work-browser.desktop").is_err());
        fs::write(&path, "[Desktop Entry]\nX-Proxy-Jail=other\n").unwrap();
        assert!(uninstall_in(&dir, "work", "browser.desktop").is_err());
        fs::remove_file(&path).unwrap();
        let victim = dir.join("victim");
        fs::write(&victim, content).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(uninstall_in(&dir, "work", "browser.desktop").is_err());
        assert!(victim.exists());
        fs::remove_file(&path).unwrap();
        fs::write(&path, content).unwrap();
        uninstall_in(&dir, "work", "browser.desktop").unwrap();
        assert!(!path.exists());
        fs::write(&path, content).unwrap();
        uninstall_in(&dir, "work", "pj-work-browser.desktop").unwrap();
        for stem in ["My Browser", "浏览器"] {
            let generated = format!("pj-work-{stem}.desktop");
            let path = dir.join(&generated);
            write_desktop_file(&path, content, desktop_owner().unwrap()).unwrap();
            uninstall_in(&dir, "work", &format!("{stem}.desktop")).unwrap();
            assert!(!path.exists());
            write_desktop_file(&path, content, desktop_owner().unwrap()).unwrap();
            uninstall_in(&dir, "work", &generated).unwrap();
            assert!(!path.exists());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn desktop_parent_symlinks_are_rejected() {
        let base = std::env::var_os("PI_SCRATCH_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let home = base.join(format!("desktop-parent-{}", std::process::id()));
        fs::create_dir(&home).unwrap();
        let actual = home.join("actual");
        fs::create_dir(&actual).unwrap();
        std::os::unix::fs::symlink(&actual, home.join(".local")).unwrap();
        assert!(ensure_desktop_dir(&home, desktop_owner().unwrap()).is_err());
        assert!(!actual.join("share").exists());
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn test_desktop_ownership_and_replacement() {
        use std::os::unix::fs::symlink;

        let home =
            std::env::temp_dir().join(format!("proxy-jail-desktop-test-{}", std::process::id()));
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
    fn test_transform_drops_hidden_flags() {
        // Mirrors /usr/share/applications/com.google.Chrome.desktop, whose only
        // difference from google-chrome.desktop is NoDisplay=true.
        let content = "\
[Desktop Entry]
Name=Google Chrome
Exec=/usr/bin/google-chrome-stable %U
Icon=google-chrome
NoDisplay=true
Hidden=true
Type=Application
Actions=new-window;

[Desktop Action new-window]
Name=New Window
Exec=/usr/bin/google-chrome-stable
";
        let source = Path::new("/usr/share/applications/com.google.Chrome.desktop");
        let result = transform_desktop_content(content, "pp", source);

        assert!(!result.contains("NoDisplay="));
        assert!(!result.contains("Hidden="));

        // Everything else still passes through unchanged.
        assert!(result.contains("Name=Google Chrome (jail: pp)\n"));
        assert!(
            result.contains(
                "Exec=proxy-jail app exec --jail pp -- /usr/bin/google-chrome-stable %U\n"
            )
        );
        assert!(result.contains("Icon=google-chrome\n"));
        assert!(result.contains("Actions=new-window;\n"));
        assert!(result.contains("X-Proxy-Jail=pp\n"));
        assert!(
            result.contains(
                "X-Proxy-Jail-Original=/usr/share/applications/com.google.Chrome.desktop\n"
            )
        );
        assert!(
            result
                .contains("Exec=proxy-jail app exec --jail pp -- /usr/bin/google-chrome-stable\n")
        );
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
        assert!(
            result
                .contains("X-Proxy-Jail-Original=/usr/share/applications/codex-desktop.desktop\n")
        );

        // [Desktop Action] Exec lines also wrapped
        assert!(result.contains("Exec=proxy-jail app exec --jail testjail -- env BAMF_DESKTOP_FILE_HINT=/usr/share/applications/codex-desktop.desktop CHROME_DESKTOP=codex-desktop.desktop CODEX_MULTI_LAUNCH=1 /usr/bin/codex-desktop --new-instance"));
        assert!(result.contains(
            "Exec=proxy-jail app exec --jail testjail -- /usr/bin/codex-update-manager check-now"
        ));
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
