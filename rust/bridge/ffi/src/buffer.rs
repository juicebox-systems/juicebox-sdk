use libc::size_t;
use std::clone::Clone;
use std::ptr;

/// Represents a memory managed reference in Rust
/// that may be converted to an unmanaged reference
#[derive(Debug)]
pub struct ManagedBuffer<Instance: Clone>(pub Vec<Instance>);

impl<Instance: Clone> ManagedBuffer<Instance> {
    /// Converts a managed buffer into an unmanaged buffer. After calling this function,
    /// the caller is responsible for the memory previously managed by this buffer. The
    /// only way to safely free that memory is to convert the UnmanagedBuffer<Instance>
    /// back into a ManagedBuffer<Instance>, allowing the destructor to perform the cleanup.
    pub fn to_unmanaged(self) -> UnmanagedBuffer<Instance> {
        let length = self.0.len();
        UnmanagedBuffer {
            data: Box::into_raw(self.0.into_boxed_slice()) as *const Instance,
            length,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UnmanagedBuffer<Instance: Clone> {
    pub data: *const Instance,
    pub length: size_t,
}

impl<Instance: Clone> UnmanagedBuffer<Instance> {
    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub fn null() -> Self {
        Self {
            data: ptr::null(),
            length: 0,
        }
    }

    /// Converts a managed buffer into an unmanaged buffer. The ownership of the underlying
    /// buffer is effectively transferred to the ManagedBuffer<Instance> which may then deallocate,
    /// reallocate or change the contents of memory pointed to by the buffer at will. Ensure that
    /// nothing else uses the buffer after calling this function.
    pub fn to_managed(self) -> Result<ManagedBuffer<Instance>, &'static str> {
        if self.is_null() {
            return Err("Unmanaged data is unexpectedly null.");
        }

        Ok(ManagedBuffer(unsafe {
            Vec::from_raw_parts(self.data as *mut Instance, self.length, self.length)
        }))
    }

    /// Clones the underlying unmanaged buffer into a new vector. The data referenced by
    /// the unmanaged buffer remains unaltered and unmanaged.
    pub fn to_vec(&self) -> Result<Vec<Instance>, &'static str> {
        if self.length == 0 {
            return Ok(vec![]);
        }

        if self.data.is_null() {
            return Err("Buffer data is unexpectedly null");
        }

        Ok(unsafe { std::slice::from_raw_parts(self.data, self.length) }.to_vec())
    }
}
