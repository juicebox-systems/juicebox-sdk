use libc::size_t;
use std::ptr;

/// Represents a memory-managed array in Rust that may be converted to an
/// unmanaged array.
#[derive(Debug)]
pub struct ManagedArray<Instance>(pub Vec<Instance>);

impl<Instance> ManagedArray<Instance> {
    /// Converts a managed array into an unmanaged array.
    ///
    /// After calling this function, the caller is responsible for the memory
    /// previously managed by this array. The only way to safely free that
    /// memory is to convert the `UnmanagedArray<Instance>` back into a
    /// `ManagedArray<Instance>`, allowing the destructor to perform the
    /// cleanup.
    pub fn to_unmanaged(self) -> UnmanagedArray<Instance> {
        let length = self.0.len();
        UnmanagedArray {
            data: Box::into_raw(self.0.into_boxed_slice()) as *const Instance,
            length,
        }
    }

    /// Returns an unmanaged array that points into this managed array.
    ///
    /// The managed array must not be dropped while this borrow is outstanding
    /// (Rust lifetimes won't help you here).
    pub fn unmanaged_borrow(&mut self) -> UnmanagedArray<Instance> {
        let length = self.0.len();
        UnmanagedArray {
            data: self.0.as_ptr(),
            length,
        }
    }
}

// Represents a raw array that may be converted to a managed array.
//
// (This is not a triple-slash Rust doc comment because it ends up being
// unhelpful in the C header file.)
#[derive(Debug)]
#[repr(C)]
pub struct UnmanagedArray<Instance> {
    pub data: *const Instance,
    pub length: size_t,
}

impl<Instance> Default for UnmanagedArray<Instance> {
    fn default() -> Self {
        Self::null()
    }
}

impl<Instance> UnmanagedArray<Instance> {
    pub fn is_null(&self) -> bool {
        self.data.is_null()
    }

    pub fn null() -> Self {
        Self {
            data: ptr::null(),
            length: 0,
        }
    }

    /// Converts an unmanaged array into an managed array.
    ///
    /// The ownership of the underlying array is effectively transferred to the
    /// `ManagedArray`, which may then deallocate, reallocate or change the
    /// contents of memory pointed to by the array at will. Ensure that nothing
    /// else uses the array after calling this function.
    pub fn to_managed(self) -> ManagedArray<Instance> {
        assert!(!self.is_null());
        ManagedArray(unsafe {
            Vec::from_raw_parts(self.data as *mut Instance, self.length, self.length)
        })
    }

    /// Returns a slice view of this array.
    pub fn as_slice(&self) -> &[Instance] {
        if self.length == 0 {
            return &[];
        }
        assert!(!self.data.is_null());
        unsafe { std::slice::from_raw_parts(self.data, self.length) }
    }
}

impl<Instance: Clone> UnmanagedArray<Instance> {
    /// Clones the elements of the array into a new vector.
    ///
    /// The unmanaged array remains unaltered and unmanaged.
    pub fn to_vec(&self) -> Vec<Instance> {
        self.as_slice().to_vec()
    }
}
