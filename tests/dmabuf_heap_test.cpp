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

#include <sys/mman.h>

#include <gtest/gtest.h>

#include <thread>

class DmaBufHeapConcurrentAccessTest : public ::testing::Test {
  public:
    virtual void SetUp() { allocator = new BufferAllocator(); }

    void DoAlloc(bool cpu_access_needed) {
        static const size_t kAllocSizeInBytes = getpagesize();
        int map_fd = allocator->AllocSystem(cpu_access_needed, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        void* ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != MAP_FAILED);

        int ret = allocator->CpuSyncStart(map_fd, kSyncReadWrite);
        ASSERT_EQ(0, ret);

        ret = allocator->CpuSyncEnd(map_fd, kSyncReadWrite);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        ASSERT_EQ(0, close(map_fd));
    }

    void DoConcurrentAlloc() {
        DoAlloc(true /* cpu_access_needed */);
        DoAlloc(false /* cpu_access_needed */);
    }

    virtual void TearDown() { delete allocator; }

    BufferAllocator* allocator = nullptr;
};

static constexpr size_t NUM_CONCURRENT_THREADS = 100;

TEST_F(DmaBufHeapConcurrentAccessTest, ConcurrentAllocTest) {
    std::vector<std::thread> threads(NUM_CONCURRENT_THREADS);
    for (int i = 0; i < NUM_CONCURRENT_THREADS; i++) {
        threads[i] = std::thread(&DmaBufHeapConcurrentAccessTest::DoConcurrentAlloc, this);
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

DmaBufHeapTest::DmaBufHeapTest() : allocator(new BufferAllocator()) {
}

TEST_F(DmaBufHeapTest, Allocate) {
    static const size_t allocationSizes[] =
        {(size_t)getpagesize(), 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (bool cpu_access_needed : {false, true}) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message()
                         << "cpu_access_needed: " << cpu_access_needed << " size: " << size);
            int fd = allocator->AllocSystem(cpu_access_needed, size);
            ASSERT_GE(fd, 0);
            ASSERT_EQ(close(fd), 0);  // free the buffer
        }
    }
}

TEST_F(DmaBufHeapTest, RepeatedAllocate) {
    static const size_t allocationSizes[] =
        {(size_t)getpagesize(), 64 * 1024, 1024 * 1024, 2 * 1024 * 1024};
    for (bool cpu_access_needed : {false, true}) {
        for (size_t size : allocationSizes) {
            SCOPED_TRACE(::testing::Message()
                         << "cpu_access_needed: " << cpu_access_needed << " size: " << size);
            for (unsigned int i = 0; i < 1024; i++) {
                SCOPED_TRACE(::testing::Message() << "iteration " << i);
                int fd = allocator->AllocSystem(cpu_access_needed, size);
                ASSERT_GE(fd, 0);
                ASSERT_EQ(close(fd), 0);  // free the buffer
            }
        }
    }
}

/*
 * Make sure all heaps always return zeroed pages
 */
TEST_F(DmaBufHeapTest, Zeroed) {
    static const size_t kAllocSizeInBytes = getpagesize();
    static const size_t kNumFds = 16;

    auto zeroes_ptr = std::make_unique<char[]>(kAllocSizeInBytes);
    int fds[kNumFds];
    int ret = 0, map_fd = -1;
    for (unsigned int i = 0; i < kNumFds; i++) {
        map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        void* ptr = mmap(NULL, kAllocSizeInBytes, PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != MAP_FAILED);

        ret = allocator->CpuSyncStart(map_fd, kSyncWrite);
        ASSERT_EQ(0, ret);

        memset(ptr, 0xaa, kAllocSizeInBytes);

        ret = allocator->CpuSyncEnd(map_fd, kSyncWrite);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        fds[i] = map_fd;
    }

    for (unsigned int i = 0; i < kNumFds; i++) {
        ASSERT_EQ(0, close(fds[i]));
    }

    map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
    ASSERT_GE(map_fd, 0);

    void* ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ, MAP_SHARED, map_fd, 0);
    ASSERT_TRUE(ptr != MAP_FAILED);

    ret = allocator->CpuSyncStart(map_fd, kSyncRead);
    ASSERT_EQ(0, ret);

    ASSERT_EQ(0, memcmp(ptr, zeroes_ptr.get(), kAllocSizeInBytes));

    ret = allocator->CpuSyncEnd(map_fd, kSyncRead);
    ASSERT_EQ(0, ret);

    ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
    ASSERT_EQ(0, close(map_fd));
}

TEST_F(DmaBufHeapTest, TestCpuSync) {
    static const size_t kAllocSizeInBytes = getpagesize();
    auto vec_sync_type = {kSyncRead, kSyncWrite, kSyncReadWrite};
    for (auto sync_type : vec_sync_type) {
        int map_fd = allocator->Alloc(kDmabufSystemHeapName, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        void* ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != MAP_FAILED);

        int ret = allocator->CpuSyncStart(map_fd, sync_type);
        ASSERT_EQ(0, ret);

        ret = allocator->CpuSyncEnd(map_fd, sync_type);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        ASSERT_EQ(0, close(map_fd));
    }
}

TEST_F(DmaBufHeapTest, TestDeviceCapabilityCheck) {
    auto heap_list = allocator->GetDmabufHeapList();

    ASSERT_TRUE(!heap_list.empty());
}

TEST_F(DmaBufHeapTest, TestDmabufSystemHeapCompliance) {
    auto heap_list = allocator->GetDmabufHeapList();
    ASSERT_TRUE(heap_list.find("system") != heap_list.end());

    for (bool cpu_access_needed : {false, true}) {
        static const size_t kAllocSizeInBytes = getpagesize();
        /*
         * Test that system heap can be allocated from.
         */
        SCOPED_TRACE(::testing::Message() << "cpu_access_needed: " << cpu_access_needed);
        int map_fd = allocator->AllocSystem(cpu_access_needed, kAllocSizeInBytes);
        ASSERT_GE(map_fd, 0);

        /*
         * Test that system heap can be mmapped by the CPU.
         */
        void* ptr = mmap(NULL, kAllocSizeInBytes, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != MAP_FAILED);

        /*
         * Test that the allocated memory is zeroed.
         */
        auto zeroes_ptr = std::make_unique<char[]>(kAllocSizeInBytes);
        int ret = allocator->CpuSyncStart(map_fd, kSyncRead);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, memcmp(ptr, zeroes_ptr.get(), kAllocSizeInBytes));

        ret = allocator->CpuSyncEnd(map_fd, kSyncRead);
        ASSERT_EQ(0, ret);

        ASSERT_EQ(0, munmap(ptr, kAllocSizeInBytes));
        ASSERT_EQ(0, close(map_fd));
    }
}
