use std::{ptr::NonNull, slice};

#[repr(C)]
#[derive(Clone, Debug)]
pub struct UnsafeList<T> {
    pub ptr: *mut T,
    pub len: u32,
}

impl<T> UnsafeList<T> {
    pub unsafe fn as_slice(&self) -> &[T] {
        let ptr = if self.ptr.is_null() { NonNull::dangling().as_ptr() } else { self.ptr };
        slice::from_raw_parts(ptr, self.len as usize)
    }
}
