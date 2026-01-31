/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Rust FFI bindings for libdmabufheap.

use std::ffi::{c_int, c_uint, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use dmabufheap_bindings::{
    BufferAllocator as CBufferAllocator, CreateDmabufHeapBufferAllocator, DmabufHeapAlloc2,
    DmabufHeapAllocSystem2, DmabufHeapCpuSyncEnd2, DmabufHeapCpuSyncStart2, DmabufSetName,
    FreeDmabufHeapBufferAllocator,
};
use errno::{errno, set_errno, Errno};

// Export constants and enum types
pub use dmabufheap_bindings::{
    kDmabufSystemHeapName, kDmabufSystemUncachedHeapName, SyncType, SyncType_kSyncRead,
    SyncType_kSyncReadWrite, SyncType_kSyncWrite,
};

/// Wrap the return value from the FFI call into a Result.
///
/// # Returns
/// Ok(ret) if ret is non-negative, otherwise Err(the appropriate error number)
fn ret_or_err(ret: c_int) -> Result<c_int, Errno> {
    // Some of these functions return -1 and set errno, others return -errno directly.
    // To interpret the return value consistently:
    // - Always clear errno before we call into FFI
    // - When -1 is seen, check if errno is set. If set, return the errno.
    // - Otherwise (-1 is seen but errno is not set, meaning -errno is returned; or another
    //   negative value is seen), return -ret
    // TODO: b/480189347 - Simplify this once the FFI calls only returns -errno.
    if ret >= 0 {
        Ok(ret)
    } else if ret == -1 && errno().0 != 0 {
        Err(errno())
    } else {
        Err(Errno(-ret))
    }
}

/// A safe wrapper around the C BufferAllocator object.
pub struct BufferAllocator {
    /// INVARIANT: ptr comes from CreateDmabufHeapBufferAllocator() and never changes.
    ptr: *mut CBufferAllocator,
}

impl Default for BufferAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl BufferAllocator {
    /// Creates a new BufferAllocator.
    ///
    /// # Panics
    ///
    /// Panics if the allocator could not be created.
    pub fn new() -> Self {
        // SAFETY: Calls into the FFI and takes ownership of the provided pointer.
        // BufferAllocator::drop() drops the ptr.
        let ptr = unsafe { CreateDmabufHeapBufferAllocator() };

        // This is never null; see BufferAllocatorWrapper.cpp
        assert!(!ptr.is_null(), "Failed to create BufferAllocator");
        Self { ptr }
    }

    /// Allocates a dmabuf from the specified heap.
    ///
    /// # Arguments
    ///
    /// * `heap_name` - The name of the heap to allocate from.
    ///   If a NULL byte is in the middle, [libc::EINVAL] is returned.
    /// * `len` - The size of the allocation in bytes.
    ///
    /// # Returns
    ///
    /// a dmabuf file descriptor, or an [errno::Errno] on failure.
    pub fn alloc(&self, heap_name: &str, len: usize) -> Result<OwnedFd, Errno> {
        set_errno(Errno(0));
        let c_heap_name = CString::new(heap_name).map_err(|_| Errno(libc::EINVAL))?;
        // SAFETY: Calls into the FFI with `ptr` from CreateDmabufHeapBufferAllocator().
        // c_heap_name is lent to the call.
        let fd = ret_or_err(unsafe { DmabufHeapAlloc2(self.ptr, c_heap_name.as_ptr(), len, 0) })?;
        // SAFETY: if DmabufHeapAlloc2 returns non-negative number, it is an FD for us to keep.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Sets the name of a dma buffer.
    ///
    /// # Arguments
    ///
    /// * `dmabuf_fd` - The dmabuf file descriptor.
    /// * `name` - The name to set for the dmabuf.
    ///   If a NULL byte is in the middle, [libc::EINVAL] is returned.
    ///
    /// # Returns
    ///
    /// Ok on success, or an [errno::Errno] on failure.
    pub fn set_name(&self, dmabuf_fd: &OwnedFd, name: &str) -> Result<(), Errno> {
        set_errno(Errno(0));
        let c_name = CString::new(name).map_err(|_| Errno(libc::EINVAL))?;
        // SAFETY: Calls into the FFI with `ptr` from CreateDmabufHeapBufferAllocator().
        // fd and c_name are lent to the call.
        ret_or_err(unsafe {
            DmabufSetName(self.ptr, dmabuf_fd.as_raw_fd() as c_uint, c_name.as_ptr())
        })?;
        Ok(())
    }

    /// Allocates a dmabuf from the system heap.
    ///
    /// # Arguments
    ///
    /// * `cpu_access` - Whether CPU access is needed.
    /// * `len` - The size of the allocation in bytes.
    ///
    /// # Returns
    ///
    /// a managed file descriptor, or an [errno::Errno] on failure.
    pub fn alloc_system(&self, cpu_access: bool, len: usize) -> Result<OwnedFd, Errno> {
        set_errno(Errno(0));
        // SAFETY: Calls into the FFI with `ptr` from CreateDmabufHeapBufferAllocator().
        let fd = ret_or_err(unsafe { DmabufHeapAllocSystem2(self.ptr, cpu_access, len, 0) })?;
        // SAFETY: if DmabufHeapAllocSystem2 returns non-negative number, it is an FD for us to
        // keep.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Starts a CPU sync operation.
    ///
    /// # Arguments
    ///
    /// * `dmabuf_fd` - The dmabuf file descriptor.
    /// * `sync_type` - The type of sync operation.
    ///
    /// # Returns
    ///
    /// Ok on success, or an [errno::Errno] on failure.
    pub fn cpu_sync_start(&self, dmabuf_fd: &OwnedFd, sync_type: SyncType) -> Result<(), Errno> {
        set_errno(Errno(0));
        // SAFETY: Calls into the FFI with `ptr` from CreateDmabufHeapBufferAllocator().
        // fd is lent to the call.
        ret_or_err(unsafe {
            DmabufHeapCpuSyncStart2(self.ptr, dmabuf_fd.as_raw_fd() as c_uint, sync_type)
        })?;
        Ok(())
    }

    /// Ends a CPU sync operation.
    ///
    /// # Arguments
    ///
    /// * `dmabuf_fd` - The dmabuf file descriptor.
    /// * `sync_type` - The type of sync operation.
    ///
    /// # Returns
    ///
    /// Ok on success, or an [errno::Errno] on failure.
    pub fn cpu_sync_end(&self, dmabuf_fd: &OwnedFd, sync_type: SyncType) -> Result<(), Errno> {
        set_errno(Errno(0));
        // SAFETY: Calls into the FFI with `ptr` from CreateDmabufHeapBufferAllocator().
        // fd is lent to the call.
        ret_or_err(unsafe {
            DmabufHeapCpuSyncEnd2(self.ptr, dmabuf_fd.as_raw_fd() as c_uint, sync_type)
        })?;
        Ok(())
    }
}

impl Drop for BufferAllocator {
    fn drop(&mut self) {
        // SAFETY: Calls into the FFI with `ptr` from CreateDmabufHeapBufferAllocator().
        unsafe {
            FreeDmabufHeapBufferAllocator(self.ptr);
        }
    }
}
