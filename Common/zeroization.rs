use std::ptr;

/// Clear initialized secret bytes with writes the compiler must preserve.
#[inline(never)]
pub fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, aligned pointer into the mutable slice.
        unsafe { ptr::write_volatile(byte, 0) };
    }
}

/// Overwrite an allocation whose contents may not have been initialized yet.
///
/// # Safety
/// If `length` is nonzero, `bytes` must be valid for `length` writable bytes.
#[inline(never)]
#[allow(dead_code)] // Used only for Credential Provider buffers owned by Windows COM.
pub unsafe fn zeroize_raw_bytes(bytes: *mut u8, length: usize) {
    for offset in 0..length {
        // SAFETY: The caller guarantees this pointer range is writable.
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
}

/// Clear a UTF-8 string's allocation before setting its length to zero.
pub fn zeroize_string(value: &mut String) {
    // SAFETY: Every byte is replaced with NUL, which is valid UTF-8, before
    // the mutable Vec borrow ends and before String::clear resets its length.
    unsafe { zeroize_bytes(value.as_mut_vec()) };
    value.clear();
}

/// Clear a UTF-16 buffer, including its terminator, before it is dropped.
#[inline(never)]
#[allow(dead_code)] // The Credential Provider DLL is the only binary using UTF-16 secrets.
pub fn zeroize_wide(values: &mut [u16]) {
    for value in values {
        // SAFETY: `value` is a valid, aligned pointer into the mutable slice.
        unsafe { ptr::write_volatile(value, 0) };
    }
}

#[cfg(test)]
mod tests {
    use super::{zeroize_bytes, zeroize_raw_bytes, zeroize_string, zeroize_wide};

    #[test]
    fn zeroizes_byte_string_and_utf16_buffers() {
        let mut bytes = b"credential".to_vec();
        zeroize_bytes(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));

        let mut raw = *b"raw!";
        // SAFETY: `raw` is a writable allocation covering exactly four bytes.
        unsafe { zeroize_raw_bytes(raw.as_mut_ptr(), raw.len()) };
        assert!(raw.iter().all(|byte| *byte == 0));

        let mut text = String::from("credential");
        let text_length = text.len();
        let text_pointer = text.as_ptr();
        zeroize_string(&mut text);
        assert!(text.is_empty());
        // SAFETY: `clear` preserves the allocation and the original initialized bytes.
        let cleared_text = unsafe { std::slice::from_raw_parts(text_pointer, text_length) };
        assert!(cleared_text.iter().all(|byte| *byte == 0));

        let mut wide = "credential".encode_utf16().collect::<Vec<_>>();
        zeroize_wide(&mut wide);
        assert!(wide.iter().all(|value| *value == 0));
    }
}
