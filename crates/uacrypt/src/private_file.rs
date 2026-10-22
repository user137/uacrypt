//! Owner-only file creation on Windows (T-300, `docs/DECISIONS.md` D-250). `OpenOptions` cannot
//! pass a security descriptor, so a new file inherits its directory's ACL - `C:\work` grants
//! `BUILTIN\Users` read, so a key or a decrypted plaintext written there is readable by every local
//! user. This creates the file with `CreateFileW` and a protected DACL granting the current user
//! only, in the same call, so no other process can open it in between.

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Memory the system allocated with `LocalAlloc`, freed on drop.
struct LocalMemory(*mut core::ffi::c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a call documented to return `LocalAlloc` memory, once.
        unsafe {
            LocalFree(self.0);
        }
    }
}

/// `create_new` (fails if anything, a symlink included, exists at `path`), write access, the same
/// share mode as `std::fs::File`, and a DACL with one entry: full access for the current user.
pub(crate) fn create_new(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let descriptor = owner_only_descriptor()?;
    let wide = wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is NUL-terminated UTF-16 and `attributes` points at a live descriptor; both
    // outlive the call. A null template handle is allowed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a fresh handle from `CreateFileW`, owned by nobody else.
    Ok(std::fs::File::from(unsafe {
        OwnedHandle::from_raw_handle(handle)
    }))
}

/// `path` as NUL-terminated UTF-16 for `CreateFileW`. Like `std::fs`, a path of 248 units or more
/// goes in its `\\?\` form, which has no `MAX_PATH` limit; `std::path::absolute` resolves it first
/// (separators, `.`, `..`), because the verbatim form is taken literally.
pub(crate) fn wide_path(path: &std::path::Path) -> std::io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    if wide.len() >= 248 {
        let absolute: Vec<u16> = std::path::absolute(path)?
            .as_os_str()
            .encode_wide()
            .collect();
        let verbatim: Vec<u16> = r"\\?\".encode_utf16().collect();
        let device: Vec<u16> = r"\\.\".encode_utf16().collect();
        let unc: Vec<u16> = r"\\".encode_utf16().collect();
        wide = if absolute.starts_with(&verbatim) || absolute.starts_with(&device) {
            absolute
        } else if absolute.starts_with(&unc) {
            r"\\?\UNC\"
                .encode_utf16()
                .chain(absolute[2..].iter().copied())
                .collect()
        } else {
            verbatim.into_iter().chain(absolute).collect()
        };
    }
    wide.push(0);
    Ok(wide)
}

/// `D:P(A;;FA;;;<current user SID>)`: a protected DACL (nothing inherited) with one full-access
/// entry for the user this process runs as.
fn owner_only_descriptor() -> std::io::Result<LocalMemory> {
    let mut raw_token = std::ptr::null_mut();
    // SAFETY: the pseudo-handle from `GetCurrentProcess` needs no closing; `raw_token` is a valid
    // out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a fresh token handle, owned by nobody else.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

    let mut len = 0u32;
    // SAFETY: a size query - a null buffer of length 0 is allowed; it fails with the needed size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut len,
        );
    }
    // u64 elements keep the buffer aligned for `TOKEN_USER`.
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `len` writable bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            len,
            &raw mut len,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so `buffer` starts with an initialised, aligned `TOKEN_USER`.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };

    let mut sid_text = std::ptr::null_mut();
    // SAFETY: `user.User.Sid` points into `buffer`, alive here; `sid_text` is a valid out-pointer.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut sid_text) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let sid_text = LocalMemory(sid_text.cast());
    let mut sddl: Vec<u16> = "D:P(A;;FA;;;".encode_utf16().collect();
    // A SID string is at most 184 characters (15 sub-authorities); 256 bounds the scan.
    let mut terminated = false;
    for i in 0..256 {
        // SAFETY: `ConvertSidToStringSidW` returned a NUL-terminated string; the scan stops at
        // its NUL, which comes before index 256.
        let unit = unsafe { *sid_text.0.cast::<u16>().add(i) };
        if unit == 0 {
            terminated = true;
            break;
        }
        sddl.push(unit);
    }
    if !terminated {
        return Err(std::io::Error::other(
            "SID string longer than 256 characters",
        ));
    }
    sddl.extend(")".encode_utf16().chain(Some(0)));

    let mut descriptor = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated UTF-16; `descriptor` is a valid out-pointer and the size
    // out-pointer may be null.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(LocalMemory(descriptor))
}

#[cfg(test)]
mod tests {
    use super::wide_path;

    fn text(wide: &[u16]) -> String {
        String::from_utf16_lossy(&wide[..wide.len() - 1])
    }

    #[test]
    fn short_paths_pass_through_unchanged() {
        assert_eq!(
            text(&wide_path(std::path::Path::new("out/k.key")).expect("ok")),
            "out/k.key"
        );
    }

    #[test]
    fn long_paths_get_the_verbatim_prefix() {
        let long = format!(r"C:\{}\{}\k.key", "a".repeat(130), "b".repeat(130));
        assert_eq!(
            text(&wide_path(std::path::Path::new(&long)).expect("ok")),
            format!(r"\\?\{long}")
        );
        let unc = format!(r"\\host\share\{}\k.key", "c".repeat(260));
        assert_eq!(
            text(&wide_path(std::path::Path::new(&unc)).expect("ok")),
            format!(r"\\?\UNC\host\share\{}\k.key", "c".repeat(260))
        );
    }

    #[test]
    fn a_nul_in_the_path_is_refused() {
        assert!(wide_path(std::path::Path::new("a\0b")).is_err());
    }
}
