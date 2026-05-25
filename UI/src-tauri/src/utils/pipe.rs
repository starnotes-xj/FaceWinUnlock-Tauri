use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::*;
use windows_core::PCWSTR;

pub struct Client {
    pub handle: HANDLE,
}

impl Client {
    pub fn new(pipe_name: &str) -> Result<Self, String> {
        let wide: Vec<u16> = std::ffi::OsStr::new(pipe_name)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(wide.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|e| format!("CreateFileW failed: {e}"))?;

        Ok(Client { handle })
    }
}

pub fn write(handle: HANDLE, data: String) -> Result<(), String> {
    let bytes = data.as_bytes();
    let mut written = 0u32;
    unsafe { WriteFile(handle, Some(bytes), Some(&mut written), None) }
        .map_err(|e| format!("WriteFile failed: {e}"))?;
    Ok(())
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
