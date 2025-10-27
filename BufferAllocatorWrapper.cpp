/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <BufferAllocator/BufferAllocator.h>
#include <BufferAllocator/BufferAllocatorWrapper.h>
#include <errno.h>
#include <sys/types.h>

extern "C" {

BufferAllocator* CreateDmabufHeapBufferAllocator() {
    return new BufferAllocator();
}

void FreeDmabufHeapBufferAllocator(BufferAllocator* buffer_allocator) {
    delete buffer_allocator;
};

int DmabufHeapAlloc2(BufferAllocator* buffer_allocator, const char* heap_name, size_t len,
                    unsigned int heap_flags) {
    if (!buffer_allocator) return -EINVAL;
    return buffer_allocator->Alloc(heap_name, len, heap_flags);
}

[[deprecated("ION is not supported. Retained for binary compatibility.")]]
int DmabufHeapAlloc(BufferAllocator* buffer_allocator, const char* heap_name, size_t len,
                    unsigned int heap_flags, size_t) {
    return DmabufHeapAlloc2(buffer_allocator, heap_name, len, heap_flags);
}

int DmabufSetName(BufferAllocator* buffer_allocator, unsigned int dmabuf_fd, const char* name) {
    if (!buffer_allocator) return -EINVAL;
    return buffer_allocator->DmabufSetName(dmabuf_fd, name);
}

int DmabufHeapAllocSystem2(BufferAllocator* buffer_allocator, bool cpu_access, size_t len,
                          unsigned int heap_flags) {
    if (!buffer_allocator) return -EINVAL;
    return buffer_allocator->AllocSystem(cpu_access, len, heap_flags);
}

[[deprecated("ION is not supported. Retained for binary compatibility.")]]
int DmabufHeapAllocSystem(BufferAllocator* buffer_allocator, bool cpu_access, size_t len,
                          unsigned int heap_flags, size_t) {
    return DmabufHeapAllocSystem2(buffer_allocator, cpu_access, len, heap_flags);
}

[[deprecated("ION is not supported. Retained for binary compatibility.")]]
int MapDmabufHeapNameToIonHeap(BufferAllocator* buffer_allocator, const char*, const char*,
                               unsigned int, unsigned int, unsigned int) {
    if (!buffer_allocator) return -EINVAL;
    return 0;
}

int DmabufHeapCpuSyncStart2(BufferAllocator* buffer_allocator, unsigned int dmabuf_fd,
                           SyncType sync_type) {
    if (!buffer_allocator) return -EINVAL;
    return buffer_allocator->CpuSyncStart(dmabuf_fd, sync_type);
}

[[deprecated("ION is not supported. Retained for binary compatibility.")]]
int DmabufHeapCpuSyncStart(BufferAllocator* buffer_allocator, unsigned int dmabuf_fd,
                           SyncType sync_type, int (*)(int, int, void *),
                           void*) {
    return DmabufHeapCpuSyncStart2(buffer_allocator, dmabuf_fd, sync_type);
}

int DmabufHeapCpuSyncEnd2(BufferAllocator* buffer_allocator, unsigned int dmabuf_fd,
                         SyncType sync_type) {
    if (!buffer_allocator) return -EINVAL;
    return buffer_allocator->CpuSyncEnd(dmabuf_fd, sync_type);
}

[[deprecated("ION is not supported. Retained for binary compatibility.")]]
int DmabufHeapCpuSyncEnd(BufferAllocator* buffer_allocator, unsigned int dmabuf_fd,
                         SyncType sync_type, int (*)(int, int, void*),
                         void*) {
    return DmabufHeapCpuSyncEnd2(buffer_allocator, dmabuf_fd, sync_type);
}

[[deprecated("ION is not supported. Retained for binary compatibility.")]]
bool CheckIonSupport() {
    return false;
}

}
