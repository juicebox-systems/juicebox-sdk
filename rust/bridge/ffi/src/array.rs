use libc::size_t;
use std::clone::Clone;
use std::ptr;

/// Represents a memory managed reference in Rust
/// that may be converted to an unmanaged reference
#[derive(Debug)]
pub struct ManagedArray<Instance: Clone>(pub Vec<Instance>);

impl<Instance: Clone> ManagedArray<Instance> {
    /// Converts a managed array into an unmanaged array. After calling this function,
    /// the caller is responsible for the memory previously managed by this array. The
    /// only way to safely free that memory is to convert the UnmanagedArray<Instance>
    /// back into a ManagedArray<Instance>, allowing the destructor to perform the cleanup.
    pub fn to_unmanaged(self) -> UnmanagedArray<Instance> {
        let length = self.0.len();
        UnmanagedArray {
            data: Box::into_raw(self.0.into_boxed_slice()) as *const Instance,
            length,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UnmanagedArray<Instance: Clone> {
    pub data: *const Instance,
    pub length: size_t,
}

impl<Instance: Clone> UnmanagedArray<Instance> {
    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub fn null() -> Self {
        Self {
            data: ptr::null(),
            length: 0,
        }
    }

    /// Converts a managed array into an unmanaged array. The ownership of the underlying
    /// array is effectively transferred to the ManagedArray<Instance> which may then deallocate,
    /// reallocate or change the contents of memory pointed to by the array at will. Ensure that
    /// nothing else uses the array after calling this function.
    pub fn to_managed(self) -> Result<ManagedArray<Instance>, &'static str> {
        if self.is_null() {
            return Err("Unmanaged data is unexpectedly null.");
        }

        Ok(ManagedArray(unsafe {
            Vec::from_raw_parts(self.data as *mut Instance, self.length, self.length)
        }))
    }

    /// Clones the underlying unmanaged array into a new vector. The data referenced by
    /// the unmanaged array remains unaltered and unmanaged.
    pub fn to_vec(&self) -> Result<Vec<Instance>, &'static str> {
        if self.length == 0 {
            return Ok(vec![]);
        }

        if self.data.is_null() {
            return Err("Array data is unexpectedly null");
        }

        Ok(unsafe { std::slice::from_raw_parts(self.data, self.length) }.to_vec())
    }
}
