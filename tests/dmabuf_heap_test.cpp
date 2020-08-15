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

#include <linux/ion.h>
#include <sys/mman.h>

#include <gtest/gtest.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

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
    int ret = 0, map_fd = -1;
    for (unsigned int i = 0; i < kNumFds; i++) {
        map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        void* ptr = NULL;

        ptr = mmap(NULL, kAllocSizeInBytes, PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        ret = allocator->CpuSyncStart(map_fd, kSyncWrite);
        ASSERT_EQ(0, ret);

        memset(ptr, 0xaa, kAllocSizeInBytes);

        ret = allocator->CpuSyncEnd(map_fd);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        fds[i] = map_fd;
    }

    for (unsigned int i = 0; i < kNumFds; i++) {
        ASSERT_EQ(0, close(fds[i]));
    }

    map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
    ASSERT_GE(map_fd, 0);

    void* ptr = NULL;
    ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ, MAP_SHARED, map_fd, 0);
    ASSERT_TRUE(ptr != NULL);

    ret = allocator->CpuSyncStart(map_fd);
    ASSERT_EQ(0, ret);

    ASSERT_EQ(0, memcmp(ptr, zeroes_ptr.get(), kAllocSizeInBytes));

    ret = allocator->CpuSyncEnd(map_fd);
    ASSERT_EQ(0, ret);

    ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
    ASSERT_EQ(0, close(map_fd));
}

TEST_F(DmaBufHeapTest, TestCpuSync) {
    static const size_t kAllocSizeInBytes = 4096;
    auto vec_sync_type = {kSyncRead, kSyncWrite, kSyncReadWrite};
    for (auto sync_type : vec_sync_type) {
        int map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        void* ptr;
        ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        int ret = allocator->CpuSyncStart(map_fd, sync_type);
        ASSERT_EQ(0, ret);

        ret = allocator->CpuSyncEnd(map_fd);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        ASSERT_EQ(0, close(map_fd));
    }
}

TEST_F(DmaBufHeapTest, TestCpuSyncMismatched) {
    static const size_t kAllocSizeInBytes = 4096;
    auto vec_sync_type = {kSyncRead, kSyncWrite, kSyncReadWrite};
    for (auto sync_type : vec_sync_type) {
        int map_fd1 = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd1, 0);

        int map_fd2 = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd2, 0);

        int ret = allocator->CpuSyncStart(map_fd1, sync_type);
        ASSERT_EQ(0, ret);

        ret = allocator->CpuSyncEnd(map_fd2);
        ASSERT_EQ(-EINVAL, ret);

        ret = allocator->CpuSyncEnd(map_fd1);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, close(map_fd1));
        ASSERT_EQ(0, close(map_fd2));
    }
}

TEST_F(DmaBufHeapTest, TestCpuSyncMismatched2) {
    static const size_t kAllocSizeInBytes = 4096;
    auto vec_sync_type = {kSyncRead, kSyncWrite, kSyncReadWrite};
    for (auto sync_type : vec_sync_type) {
        int map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        int ret = allocator->CpuSyncStart(map_fd, sync_type);
        ASSERT_EQ(0, ret);

        ret = allocator->CpuSyncEnd(map_fd);
        ASSERT_EQ(0, ret);

        /* Should fail since it is missing a CpuSyncStart() */
        ret = allocator->CpuSyncEnd(map_fd);
        ASSERT_EQ(-EINVAL, ret);

        ret = allocator->CpuSyncStart(map_fd, sync_type);
        ASSERT_EQ(0, ret);

        /* Should fail since it is missing a CpuSyncEnd() */
        ret = allocator->CpuSyncStart(map_fd, sync_type);
        ASSERT_EQ(-EINVAL, ret);

        ret = allocator->CpuSyncEnd(map_fd);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, close(map_fd));
    }
}

int CustomCpuSyncStart(int /* ion_fd */, int /* dma_buf fd */,
                       void* /* custom_data pointer */) {
    LOG(INFO) << "In custom cpu sync start callback";
    return 0;
}

int CustomCpuSyncEnd(int /* ion_fd */, int /* dma_buf fd */,
                     void* /* custom_data pointer */) {
    LOG(INFO) << "In custom cpu sync end callback";
    return 0;
}

TEST_F(DmaBufHeapTest, TestCustomLegacyIonSyncCallback) {
    static const size_t allocationSizes[] = {4 * 1024, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (size_t size : allocationSizes) {
        SCOPED_TRACE(::testing::Message()
                     << "heap: " << kDmabufSystemHeapName << " size: " << size);

        int map_fd = allocator->Alloc(kDmabufSystemHeapName, size);
        ASSERT_GE(map_fd, 0);

        void* ptr;
        ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        int ret = allocator->CpuSyncStart(map_fd, kSyncWrite, CustomCpuSyncStart);
        ASSERT_EQ(0, ret);

        memset(ptr, 0xaa, size);

        ret = allocator->CpuSyncEnd(map_fd, CustomCpuSyncEnd);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, size));
        ASSERT_EQ(0, close(map_fd));
    }
}
