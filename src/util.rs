//! Small filesystem and formatting helpers shared across the tool.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Write `bytes` to `path`, creating parent directories as needed.
///
/// The write goes to a temporary file in the same directory and is renamed
/// into place, so a crash or a full disk cannot leave a half-written key or
/// signature that later looks merely "corrupt". Unless `force` is set an
/// existing file is left alone.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::usage(format!(
            "{}: already exists (use --force to overwrite)",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
    }

    let tmp = temp_sibling(path);
    let mut file = create_with_mode(&tmp, mode)?;
    file.write_all(bytes).map_err(|e| Error::io(&tmp, e))?;
    file.sync_all().map_err(|e| Error::io(&tmp, e))?;
    drop(file);

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::io(path, e)
    })
}

fn temp_sibling(path: &Path) -> std::path::PathBuf {
    let pid = std::process::id();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.pqsum-{pid}-{nonce}.tmp"))
}

#[cfg(unix)]
fn create_with_mode(path: &Path, mode: Option<u32>) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    if let Some(mode) = mode {
        opts.mode(mode);
    }
    opts.open(path).map_err(|e| Error::io(path, e))
}

#[cfg(not(unix))]
fn create_with_mode(path: &Path, _mode: Option<u32>) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| Error::io(path, e))
}

/// Permission bits for files that must not be world readable.
pub const MODE_PRIVATE: u32 = 0o600;
/// Permission bits for files meant to be published.
pub const MODE_PUBLIC: u32 = 0o644;

/// Warn when a private key is readable by anyone other than its owner. ssh
/// refuses outright in this situation; pqsum only warns, because a key that
/// lives in a container image or a CI checkout is often group readable by
/// design and the user has already accepted that.
#[cfg(unix)]
pub fn warn_if_key_is_exposed(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            eprintln!(
                "pqsum: warning: {} is accessible by other users (mode {:04o})",
                path.display(),
                meta.permissions().mode() & 0o7777
            );
        }
    }
}

#[cfg(not(unix))]
pub fn warn_if_key_is_exposed(_path: &Path) {}

/// The current time as an RFC 3339 UTC timestamp.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc(secs as i64)
}

/// Format a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Hand-rolled rather than pulling in a date library: pqsum needs exactly one
/// direction of exactly one format, and a signing tool benefits from a small
/// dependency tree.
pub fn rfc3339_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`: convert a day count since the Unix
/// epoch into a proleptic Gregorian calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_known_dates() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // A leap day, to exercise the calendar arithmetic.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(2_147_483_647), "2038-01-19T03:14:07Z");
    }

    #[test]
    fn atomic_write_refuses_to_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("f.txt");

        write_atomic(&path, b"first", None, false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");

        assert!(write_atomic(&path, b"second", None, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");

        write_atomic(&path, b"second", None, true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn atomic_write_leaves_no_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        write_atomic(&dir.path().join("f"), b"x", None, false).unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["f".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn private_mode_is_applied() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_atomic(&path, b"x", Some(MODE_PRIVATE), false).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, MODE_PRIVATE);
    }
}
