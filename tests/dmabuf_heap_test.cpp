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
#include "dmabuf_heap_test.h"

#include <ion/ion.h>
#include <sys/mman.h>

#include <gtest/gtest.h>

DmaBufHeapTest::DmaBufHeapTest() : allocator(new BufferAllocator()) {
    /*
     * Legacy ion devices may have hardcoded heap IDs that do not
     * match the ion UAPI header. Map heap name 'system' to a heap mask
     * of all 1s so that these devices will allocate from the first
     * available heap when asked to allocate from a heap of name 'system'.
     */
    allocator->MapNameToIonHeap(kDmabufSystemHeapName, "" /* no mapping for non-legacy */,
                                0 /* no mapping for non-legacy ion */,
                                ~0 /* legacy ion heap mask */);
}

TEST_F(DmaBufHeapTest, Allocate) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (size_t size : allocationSizes) {
        SCOPED_TRACE(::testing::Message()
                     << "heap: " << kDmabufSystemHeapName << " size: " << size);
        int fd = allocator->Alloc(kDmabufSystemHeapName, size);
        ASSERT_GE(fd, 0);
        ASSERT_EQ(close(fd), 0);  // free the buffer
    }
}

TEST_F(DmaBufHeapTest, AllocateCached) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (size_t size : allocationSizes) {
        SCOPED_TRACE(::testing::Message()
                     << "heap: " << kDmabufSystemHeapName << " size: " << size);
        int fd = allocator->Alloc(kDmabufSystemHeapName, size, ION_FLAG_CACHED
                                  /* ion heap flags will be ignored if using dmabuf heaps */);
        ASSERT_GE(fd, 0);
        ASSERT_EQ(close(fd), 0);  // free the buffer
    }
}

TEST_F(DmaBufHeapTest, AllocateCachedNeedsSync) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (size_t size : allocationSizes) {
        SCOPED_TRACE(::testing::Message()
                     << "heap: " << kDmabufSystemHeapName << " size: " << size);
        int fd = allocator->Alloc(kDmabufSystemHeapName, size, ION_FLAG_CACHED_NEEDS_SYNC
                                  /* ion heap flags will be ignored if using dmabuf heaps */);
        ASSERT_GE(fd, 0);
        ASSERT_EQ(close(fd), 0);  // free the buffer
    }
}

TEST_F(DmaBufHeapTest, RepeatedAllocate) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (size_t size : allocationSizes) {
        SCOPED_TRACE(::testing::Message()
                     << "heap: " << kDmabufSystemHeapName << " size: " << size);
        for (unsigned int i = 0; i < 1024; i++) {
            SCOPED_TRACE(::testing::Message() << "iteration " << i);
            int fd = allocator->Alloc(kDmabufSystemHeapName, size);
            ASSERT_GE(fd, 0);
            ASSERT_EQ(close(fd), 0);  // free the buffer
        }
    }
}

/*
 * Make sure all heaps always return zeroed pages
 */
TEST_F(DmaBufHeapTest, Zeroed) {
    static const size_t kAllocSizeInBytes = 4096;
    static const size_t kNumFds = 16;

    auto zeroes_ptr = std::make_unique<char[]>(kAllocSizeInBytes);
    int fds[kNumFds];
    for (unsigned int i = 0; i < kNumFds; i++) {
        int map_fd = -1;
        map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        void* ptr = NULL;

        //  Use CpuSyncStart() once ready to use

        ptr = mmap(NULL, kAllocSizeInBytes, PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        memset(ptr, 0xaa, kAllocSizeInBytes);

        //  Use CpuSyncEnd() once ready to use

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        fds[i] = map_fd;
    }

    for (unsigned int i = 0; i < kNumFds; i++) {
        ASSERT_EQ(0, close(fds[i]));
    }

    int map_fd = -1;
    map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
    ASSERT_GE(map_fd, 0);

    void* ptr = NULL;
    ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ, MAP_SHARED, map_fd, 0);
    ASSERT_TRUE(ptr != NULL);

    //  Use CpuSyncStart() once ready to use

    ASSERT_EQ(0, memcmp(ptr, zeroes_ptr.get(), kAllocSizeInBytes));

    //  Use CpuSyncEnd() once ready to use

    ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
    ASSERT_EQ(0, close(map_fd));
}
