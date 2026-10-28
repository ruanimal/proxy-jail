//! Small, shared boundaries for privileged commands and filesystem access.
use anyhow::{Context, Result, bail, ensure};
use nix::unistd::{Gid, Uid, User};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::{File, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const APP_ENV: &str = "PROXY_JAIL_APP_ENV";
pub const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

pub fn invoking_user() -> Result<User> {
    let uid = match std::env::var("SUDO_UID") {
        Ok(value) if Uid::effective().is_root() => value.parse().context("Invalid SUDO_UID")?,
        _ => Uid::current().as_raw(),
    };
    User::from_uid(Uid::from_raw(uid))?.context("Cannot resolve invoking user")
}

/// Never consult the caller's PATH for a program that will execute as root.
pub fn trusted_program(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains('/'),
        "Invalid system program name"
    );
    for directory in SYSTEM_PATH.split(':') {
        let path = Path::new(directory).join(name);
        if path.exists() {
            return trusted_executable(&path);
        }
    }
    bail!("System program '{name}' not found in {SYSTEM_PATH}")
}

pub fn trusted_executable(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Cannot resolve system executable {}", path.display()))?;
    for ancestor in canonical.ancestors() {
        let metadata = std::fs::metadata(ancestor)?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "Untrusted system executable path: {}",
            ancestor.display()
        );
    }
    let metadata = canonical.metadata()?;
    ensure!(
        metadata.is_file() && metadata.mode() & 0o111 != 0,
        "System program is not executable: {}",
        canonical.display()
    );
    Ok(canonical)
}

pub fn command(name: &str) -> Result<Command> {
    let mut command = Command::new(trusted_program(name)?);
    command
        // Debian's iptables/BusyBox-style multicall binaries dispatch on argv[0].
        .arg0(name)
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("LANG", "C")
        .env("HOME", "/root");
    Ok(command)
}

pub fn capture_environment() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(key, _)| key != APP_ENV && !key.starts_with("SUDO_"))
        .collect()
}

/// This is opaque data while privileged; only a downgraded child installs it.
pub fn application_environment() -> Result<BTreeMap<String, String>> {
    let mut environment: BTreeMap<String, String> = match std::env::var(APP_ENV) {
        Ok(value) => serde_json::from_str(&value).context("Invalid application environment")?,
        Err(std::env::VarError::NotPresent) => capture_environment(),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        environment.iter().all(|(key, value)| !key.is_empty()
            && !key.contains(['=', '\0'])
            && !value.contains('\0')),
        "Invalid application environment entry"
    );
    environment.retain(|key, _| key != APP_ENV && key != "MAIL" && !key.starts_with("SUDO_"));
    Ok(environment)
}

fn cstring(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

fn open_at(parent: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
    let name = cstring(name)?;
    // SAFETY: name is NUL-terminated; the returned descriptor is uniquely owned.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Walk directories by descriptor so replacing a path with a symlink cannot
/// redirect a privileged open. Parent traversal is never accepted.
pub fn directory(path: &Path, create: bool, mode: u32) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Expected absolute path",
        ));
    }
    let mut directory = File::open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid directory component",
                ));
            }
        };
        let flags = libc::O_RDONLY | libc::O_DIRECTORY;
        directory = match open_at(&directory, name, flags, 0) {
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                let c_name = cstring(name)?;
                if unsafe { libc::mkdirat(directory.as_raw_fd(), c_name.as_ptr(), mode) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                open_at(&directory, name, flags, 0)?
            }
            result => result?,
        };
    }
    Ok(directory)
}

pub fn private_directory(path: &Path) -> Result<File> {
    let directory = directory(path, true, 0o700)
        .with_context(|| format!("Cannot open private directory {}", path.display()))?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == Uid::effective().as_raw() && metadata.mode() & 0o077 == 0,
        "Unsafe private directory: {}",
        path.display()
    );
    Ok(directory)
}

fn parent(path: &Path, create: bool) -> io::Result<(File, &OsStr)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing filename"))?;
    Ok((directory(path.parent().unwrap(), create, 0o700)?, name))
}

fn regular(file: &File, single_link: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || (single_link && metadata.nlink() != 1) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Expected regular file without hard links",
        ));
    }
    Ok(())
}

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let (parent, name) = parent(path, false)?;
    let mut file = open_at(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    regular(&file, false)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

pub fn read_to_string(path: &Path) -> io::Result<String> {
    String::from_utf8(read(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Validate the opened inode before truncating, never a path checked earlier.
pub fn private_file(path: &Path, append: bool) -> io::Result<File> {
    let (parent, name) = parent(path, true)?;
    let file = open_at(
        &parent,
        name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK | if append { libc::O_APPEND } else { 0 },
        0o600,
    )?;
    regular(&file, true)?;
    let owner = file.metadata()?.uid();
    let caller = invoking_user().map_err(io::Error::other)?.uid.as_raw();
    if owner != Uid::effective().as_raw() && owner != caller {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unexpected file owner",
        ));
    }
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Existing credential-bearing configuration must be private even on reads.
pub fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    let (parent, name) = parent(path, false)?;
    let mut file = open_at(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    regular(&file, true)?;
    let owner = file.metadata()?.uid();
    let caller = invoking_user().map_err(io::Error::other)?.uid.as_raw();
    if owner != Uid::effective().as_raw() && owner != caller {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unexpected configuration owner",
        ));
    }
    file.set_permissions(Permissions::from_mode(0o600))?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    Ok(content)
}

pub fn write(path: &Path, content: impl AsRef<[u8]>) -> io::Result<()> {
    let mut file = private_file(path, false)?;
    file.set_len(0)?;
    file.write_all(content.as_ref())
}

/// Resolver files must remain readable after bind-mounting into user apps.
pub fn write_public(path: &Path, content: impl AsRef<[u8]>) -> io::Result<()> {
    let mut file = private_file(path, false)?;
    file.set_len(0)?;
    file.write_all(content.as_ref())?;
    file.set_permissions(Permissions::from_mode(0o644))
}

/// Temp file and rename both use the same pinned parent directory descriptor.
pub fn atomic_write_owned(path: &Path, content: &[u8], uid: Uid, gid: Gid) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let (parent, name) = parent(path, false)?;
    let temporary = format!(
        ".proxy-jail-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut file = open_at(
        &parent,
        OsStr::new(&temporary),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o644,
    )?;
    let source = cstring(OsStr::new(&temporary))?;
    let destination = cstring(name)?;
    let result = (|| -> Result<()> {
        file.write_all(content)?;
        set_owner(&file, uid, gid)?;
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), source.as_ptr(), 0);
        }
    }
    result
}

pub fn remove_file(path: &Path) -> io::Result<()> {
    let (parent, name) = parent(path, false)?;
    let name = cstring(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_owner(file: &File, uid: Uid, gid: Gid) -> Result<()> {
    if Uid::effective().is_root() {
        nix::unistd::fchown(file.as_raw_fd(), Some(uid), Some(gid))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> PathBuf {
        let base = std::env::var_os("PI_SCRATCH_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "security-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn commands_have_trusted_paths_and_clean_environments() {
        let command = command("ip").unwrap();
        assert!(Path::new(command.get_program()).is_absolute());
        let environment: Vec<_> = command.get_envs().collect();
        assert_eq!(environment.len(), 3);
        assert!(environment.contains(&(OsStr::new("PATH"), Some(OsStr::new(SYSTEM_PATH)))));
        assert!(trusted_program("../ip").is_err());
        assert!(trusted_program("/bin/sh").is_err());
        let output = super::command("env").unwrap().output().unwrap();
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).unwrap();
        assert_eq!(environment.lines().count(), 3);
        assert!(
            environment
                .lines()
                .any(|entry| entry == format!("PATH={SYSTEM_PATH}"))
        );
    }

    #[test]
    fn executable_in_a_user_writable_directory_is_rejected() {
        let base = fixture();
        let executable = base.join("ip");
        std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, Permissions::from_mode(0o755)).unwrap();
        assert!(trusted_executable(&executable).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn symlinks_in_files_and_parent_directories_are_rejected() {
        let base = fixture();
        let target = base.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = base.join("link");
        symlink(&target, &link).unwrap();
        assert!(write(&link, "bad").is_err());
        assert!(read(&link).is_err());
        let actual = base.join("actual");
        std::fs::create_dir(&actual).unwrap();
        let linked_dir = base.join("linked-dir");
        symlink(&actual, &linked_dir).unwrap();
        assert!(write(&linked_dir.join("new"), "bad").is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "keep");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn hardlinks_and_non_regular_files_are_not_truncated() {
        let base = fixture();
        let target = base.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = base.join("hardlink");
        std::fs::hard_link(&target, &link).unwrap();
        assert!(write(&link, "bad").is_err());
        assert!(write(&base, "bad").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn private_files_are_private_and_retain_their_inode() {
        let base = fixture();
        let path = base.join("new/file");
        write(&path, "first").unwrap();
        let before = path.metadata().unwrap();
        write(&path, "second").unwrap();
        assert_eq!(path.metadata().unwrap().ino(), before.ino());
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(read(&path).unwrap(), b"second");
        std::fs::remove_dir_all(base).unwrap();
    }
}

#[cfg(test)]
mod multicall_tests {
    #[test]
    fn trusted_iptables_keeps_its_multicall_name() {
        let output = super::command("iptables")
            .unwrap()
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("iptables "));
    }
}
