use zeroize::Zeroize;

/// mlock'd 32-byte secret. Never swapped. Zeroized on drop.
/// Intentionally !Clone and !Debug.
pub struct LockedKey {
    buf: Box<[u8; 32]>,
}

impl LockedKey {
    pub fn new(mut raw: [u8; 32]) -> std::io::Result<Self> {
        let mut boxed = Box::new(raw);
        raw.zeroize();
        let r = unsafe { libc::mlock(boxed.as_ptr() as *const libc::c_void, 32) };
        if r != 0 {
            boxed.zeroize();
            return Err(std::io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(boxed.as_ptr() as *mut libc::c_void, 32, libc::MADV_DONTDUMP);
        }
        Ok(Self { buf: boxed })
    }

    /// Closure-only access. Key never leaves the locked page by value.
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.buf)
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.buf.zeroize();
        unsafe {
            libc::munlock(self.buf.as_ptr() as *const libc::c_void, 32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_sees_key() {
        let k = LockedKey::new([0xAB; 32]).unwrap();
        k.with_secret(|s| assert_eq!(s, &[0xAB; 32]));
    }
}
