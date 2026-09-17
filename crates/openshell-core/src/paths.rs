// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Path utilities: XDG config directory resolution, permission helpers, and
//! lexical path normalization.
//!
//! All `OpenShell` crates should use [`xdg_config_dir`] from this module instead
//! of reimplementing the XDG lookup. The permission helpers ensure that
//! sensitive files (private keys, tokens) and the directories containing them
//! are created with restrictive modes. [`normalize_path`] performs purely
//! lexical normalization (no filesystem access, no symlink resolution).

use miette::{IntoDiagnostic, Result, WrapErr};
use std::path::{Path, PathBuf};

/// Resolve the XDG config base directory.
///
/// Returns `$XDG_CONFIG_HOME` if set, otherwise `$HOME/.config`.
pub fn xdg_config_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("APPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config"))
}

/// The top-level `OpenShell` config directory: `$XDG_CONFIG_HOME/openshell/`.
pub fn openshell_config_dir() -> Result<PathBuf> {
    Ok(xdg_config_dir()?.join("openshell"))
}

/// Resolve the XDG state base directory.
///
/// Returns `$XDG_STATE_HOME` if set, otherwise `$HOME/.local/state`.
pub fn xdg_state_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local").join("state"))
}

/// The top-level `OpenShell` state directory: `$XDG_STATE_HOME/openshell/`.
pub fn openshell_state_dir() -> Result<PathBuf> {
    Ok(xdg_state_dir()?.join("openshell"))
}

/// Resolve the XDG data base directory.
///
/// Returns `$XDG_DATA_HOME` if set, otherwise `$HOME/.local/share`.
pub fn xdg_data_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Ok(path) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .into_diagnostic()
        .wrap_err("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local").join("share"))
}

/// Create a directory (and parents) with owner-only permissions (`0o700` on
/// Unix; an owner-only DACL with inheritance disabled on Windows).
///
/// This should be used for any directory that contains sensitive material
/// (tokens, private keys, certificates).
pub fn create_dir_restricted(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    set_dir_owner_only(path)?;
    Ok(())
}

/// Restrict a directory to owner-only access: `0o700` on Unix, or an
/// owner-only DACL (with inherited ACEs stripped, and the ACE propagated to
/// children) on Windows.
pub fn set_dir_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(windows)]
    windows_acl::restrict_to_current_user(path, true)?;
    Ok(())
}

/// Restrict a file to owner-only read/write: `0o600` on Unix, or an
/// owner-only DACL (with inherited ACEs stripped) on Windows.
pub fn set_file_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    #[cfg(windows)]
    windows_acl::restrict_to_current_user(path, false)?;
    Ok(())
}

/// Ensure the parent directory of `path` exists with restricted permissions.
///
/// Equivalent to `create_dir_restricted(path.parent())` but handles the case
/// where `path` has no parent gracefully.
pub fn ensure_parent_dir_restricted(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_restricted(parent)?;
    }
    Ok(())
}

/// Check whether a file has permissions that are too open.
///
/// On Unix, returns `true` if the file has group or other read/write/execute
/// bits set. On Windows, returns `true` if the file's DACL grants access to
/// any trustee other than the current user. Returns `false` if the file's
/// permissions/ACL cannot be read.
#[cfg(unix)]
pub fn is_file_permissions_too_open(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
}

/// Check whether a file has permissions that are too open.
///
/// See the Unix doc comment above for the cross-platform contract.
#[cfg(windows)]
pub fn is_file_permissions_too_open(path: &Path) -> bool {
    windows_acl::has_foreign_trustee(path).unwrap_or(false)
}

/// Windows ACL/DACL implementation of the owner-only permission helpers
/// above. Confined to this submodule so the `unsafe` FFI surface stays out
/// of the rest of the crate, matching the precedent set by
/// `openshell-driver-mxc`'s ETW consumer.
#[cfg(windows)]
mod windows_acl {
    #![allow(unsafe_code)]

    use miette::{IntoDiagnostic, Result, WrapErr};
    use std::path::Path;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsValidAcl, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{HSTRING, PWSTR};

    /// An owned, `TOKEN_USER`-aligned buffer (backed by `Vec<u64>` purely for
    /// its alignment guarantee; the contents are opaque bytes filled in by
    /// `GetTokenInformation`).
    struct TokenUserBuf(Vec<u64>);

    /// Fetch the current process's user token info as an aligned buffer.
    ///
    /// Callers get the `PSID` out via [`sid_from_token_info`], which borrows
    /// from the returned buffer; keep it alive for as long as the `PSID` is
    /// used.
    fn current_user_token_info() -> Result<TokenUserBuf> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
                .into_diagnostic()
                .wrap_err("failed to open process token")?;
            let _guard = HandleGuard(token);

            let mut needed = 0u32;
            // First call is expected to fail with ERROR_INSUFFICIENT_BUFFER;
            // we only want the required buffer size out of it.
            let _ = GetTokenInformation(token, TokenUser, None, 0, &raw mut needed);
            if needed == 0 {
                return Err(miette::miette!("GetTokenInformation returned no size"));
            }
            let words = (needed as usize).div_ceil(size_of::<u64>());
            let mut buf = TokenUserBuf(vec![0u64; words]);
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.0.as_mut_ptr().cast()),
                needed,
                &raw mut needed,
            )
            .into_diagnostic()
            .wrap_err("failed to read current process token user")?;
            Ok(buf)
        }
    }

    /// Extract the `PSID` from a `TOKEN_USER` buffer produced by
    /// [`current_user_token_info`]. The `PSID` borrows from `buf`.
    fn sid_from_token_info(buf: &TokenUserBuf) -> PSID {
        // SAFETY: `buf` was sized and filled by `GetTokenInformation` for
        // `TokenUser` in `current_user_token_info`, and `Vec<u64>`'s 8-byte
        // alignment satisfies `TOKEN_USER`'s alignment requirement.
        let token_user = unsafe { &*buf.0.as_ptr().cast::<TOKEN_USER>() };
        token_user.User.Sid
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid handle owned by this guard.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalFreeGuard(*mut core::ffi::c_void);
    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by a Win32 API documented to
                // return LocalAlloc-owned memory (e.g. `SetEntriesInAclW`).
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
            }
        }
    }

    /// Overwrite `path`'s DACL with a single, non-inherited ACE granting full
    /// control to the current user, stripping any inherited ACEs. `is_dir`
    /// controls whether the ACE propagates to children (directories only).
    pub(super) fn restrict_to_current_user(path: &Path, is_dir: bool) -> Result<()> {
        let token_info = current_user_token_info()?;
        let sid = sid_from_token_info(&token_info);

        let trustee = TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(sid.0.cast()),
            ..Default::default()
        };

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS.0,
            grfAccessMode: SET_ACCESS,
            grfInheritance: if is_dir {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: trustee,
        };

        let mut new_acl: *mut ACL = core::ptr::null_mut();
        // SAFETY: `entry` is a valid, fully-initialized EXPLICIT_ACCESS_W
        // whose Trustee SID borrows from `token_info`, kept alive for this
        // call. `new_acl` receives a LocalAlloc-owned pointer on success.
        unsafe { SetEntriesInAclW(Some(&[entry]), None, &raw mut new_acl) }
            .ok()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to build ACL for {}", path.display()))?;
        let _acl_guard = LocalFreeGuard(new_acl.cast());

        let path_hstring = HSTRING::from(path.as_os_str());
        // SAFETY: `path_hstring` is a valid, NUL-terminated wide string for
        // the lifetime of this call; `new_acl` is a valid ACL just built
        // above. `PROTECTED_DACL_SECURITY_INFORMATION` is the flag that
        // strips inherited ACEs, which is the entire point of this call.
        unsafe {
            SetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_acl),
                None,
            )
        }
        .ok()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to set owner-only ACL on {}", path.display()))?;

        Ok(())
    }

    /// Returns `true` if `path`'s DACL grants access to any trustee other
    /// than the current user, or `None` if the ACL could not be read.
    pub(super) fn has_foreign_trustee(path: &Path) -> Option<bool> {
        let token_info = current_user_token_info().ok()?;
        let owner_sid = sid_from_token_info(&token_info);

        let path_hstring = HSTRING::from(path.as_os_str());
        let mut dacl: *mut ACL = core::ptr::null_mut();
        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `path_hstring` is valid for the call; the out-params are
        // simple pointers filled in by the API on success. The security
        // descriptor `dacl` points into is LocalAlloc-owned and freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PWSTR::from_raw(path_hstring.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&raw mut dacl),
                None,
                &raw mut security_descriptor,
            )
        };
        status.ok().ok()?;
        let _sd_guard = LocalFreeGuard(security_descriptor.0);

        if dacl.is_null() || unsafe { !IsValidAcl(dacl).as_bool() } {
            return Some(false);
        }

        let mut size_info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` was just validated above.
        unsafe {
            GetAclInformation(
                dacl,
                (&raw mut size_info).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                    .expect("ACL_SIZE_INFORMATION size fits in u32"),
                AclSizeInformation,
            )
        }
        .ok()?;

        for index in 0..size_info.AceCount {
            let mut ace_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
            // SAFETY: `dacl` is valid and `index` is within `AceCount`.
            if unsafe { GetAce(dacl, index, &raw mut ace_ptr) }.is_err() {
                continue;
            }
            // SAFETY: `GetAce` returned a pointer to a valid ACE header.
            let header = unsafe { &*ace_ptr.cast::<ACE_HEADER>() };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
                // Deny/other ACE types don't grant access; skip them for
                // this "is anyone but me granted access" check.
                continue;
            }
            // SAFETY: header.AceType confirms this is an ACCESS_ALLOWED_ACE.
            let ace = unsafe { &*ace_ptr.cast::<ACCESS_ALLOWED_ACE>() };
            let ace_sid = PSID((&raw const ace.SidStart).cast_mut().cast());
            // SAFETY: both SIDs come from Windows APIs (`GetTokenInformation`
            // and `GetAce`) and are valid for the duration of this call.
            let is_owner = unsafe { EqualSid(owner_sid, ace_sid) }.is_ok();
            if !is_owner {
                return Some(true);
            }
        }
        Some(false)
    }
}

/// Normalize a filesystem path by collapsing redundant separators
/// and removing trailing slashes, without requiring the path to exist on disk.
///
/// This is a lexical normalization only — it does NOT resolve symlinks or
/// check the filesystem. `..` components are preserved verbatim; callers that
/// need to reject parent traversal must validate separately. The normalized
/// representation always uses `/` so sandbox policy paths are host-independent.
pub fn normalize_path(path: &str) -> String {
    use std::path::Component;

    let p = Path::new(path);
    let mut normalized = PathBuf::new();
    for component in p.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            #[allow(clippy::path_buf_push_overwrite)]
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {} // skip "."
            Component::ParentDir => {
                // Keep ".." — validation will catch it separately
                normalized.push("..");
            }
            Component::Normal(c) => normalized.push(c),
        }
    }
    let normalized = normalized.to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        normalized.replace('\\', "/")
    }
    #[cfg(not(target_os = "windows"))]
    {
        normalized.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_config_dir_respects_env() {
        // This test checks the logic — actual env var mutation is unsafe so
        // we rely on the integration tests in openshell-bootstrap for full
        // round-trip testing.
        let result = xdg_config_dir();
        assert!(result.is_ok());
    }

    #[test]
    fn openshell_config_dir_appends_openshell() {
        let dir = openshell_config_dir().unwrap();
        assert!(
            dir.ends_with("openshell"),
            "expected path ending with 'openshell', got: {dir:?}"
        );
    }

    #[test]
    fn openshell_state_dir_appends_openshell() {
        let dir = openshell_state_dir().unwrap();
        assert!(
            dir.ends_with("openshell"),
            "expected path ending with 'openshell', got: {dir:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_restricted_sets_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("restricted");
        create_dir_restricted(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn set_file_owner_only_sets_0o600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("secret");
        std::fs::write(&file, "secret-data").unwrap();
        set_file_owner_only(&file).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:04o}");
    }

    #[cfg(unix)]
    #[test]
    fn is_file_permissions_too_open_detects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("open-file");
        std::fs::write(&file, "data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(is_file_permissions_too_open(&file));
    }

    #[cfg(unix)]
    #[test]
    fn is_file_permissions_too_open_accepts_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("restricted-file");
        std::fs::write(&file, "data").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_file_permissions_too_open(&file));
    }

    #[cfg(windows)]
    #[test]
    fn create_dir_restricted_sets_owner_only_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("restricted");
        create_dir_restricted(&dir).unwrap();
        assert!(
            !is_file_permissions_too_open(&dir),
            "expected owner-only ACL on {}",
            dir.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn set_file_owner_only_sets_owner_only_acl() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("secret");
        std::fs::write(&file, "secret-data").unwrap();
        set_file_owner_only(&file).unwrap();
        assert!(
            !is_file_permissions_too_open(&file),
            "expected owner-only ACL on {}",
            file.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_detects_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("open-file");
        std::fs::write(&file, "data").unwrap();
        // Grant Everyone read access, mirroring the Unix 0o644 case: an ACE
        // for a trustee other than the current user.
        let status = std::process::Command::new("icacls")
            .arg(&file)
            .arg("/grant")
            .arg("Everyone:(R)")
            .status()
            .unwrap();
        assert!(status.success(), "icacls grant failed");
        assert!(is_file_permissions_too_open(&file));
    }

    #[cfg(windows)]
    #[test]
    fn is_file_permissions_too_open_accepts_restricted() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("restricted-file");
        std::fs::write(&file, "data").unwrap();
        set_file_owner_only(&file).unwrap();
        assert!(!is_file_permissions_too_open(&file));
    }

    #[test]
    fn normalize_path_collapses_separators() {
        assert_eq!(normalize_path("/usr//lib"), "/usr/lib");
        assert_eq!(normalize_path("/usr/./lib"), "/usr/lib");
        assert_eq!(normalize_path("/tmp/"), "/tmp");
    }

    #[test]
    fn normalize_path_preserves_parent_dir() {
        // normalize_path preserves ".." — validation catches it separately
        assert_eq!(normalize_path("/usr/../etc"), "/usr/../etc");
    }
}
