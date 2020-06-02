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

#define LOG_TAG "DMABUFHEAPS"

#include <BufferAllocator/BufferAllocator.h>

#include <errno.h>
#include <fcntl.h>
#include <ion/ion.h>
#include <linux/dma-heap.h>
#include <linux/ion_4.12.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

static constexpr char kDmaHeapRoot[] = "/dev/dma_heap/";
static constexpr char kIonDevice[] = "/dev/ion";

int BufferAllocator::GetDmabufHeapFd(const std::string& heap_name) {
    /* check if we have this dmabuf heap open and if so return the fd for it. */
    auto it = dmabuf_heap_fds_.find(heap_name);
    if (it != dmabuf_heap_fds_.end())
        return it->second;
    return -1;
}

int BufferAllocator::OpenDmabufHeap(const std::string& heap_name) {
    /* Check if we have already opened this heap. */
    auto fd = GetDmabufHeapFd(heap_name);
    if (fd < 0) {
        std::string heap_path = kDmaHeapRoot + heap_name;
        fd = TEMP_FAILURE_RETRY(open(heap_path.c_str(), O_RDWR | O_CLOEXEC));
        if (fd < 0) {
            PLOG(ERROR) << "Unable to open dmabuf heap :" << heap_path;
            return -errno;
        }

        dmabuf_heap_fds_.insert({heap_name, android::base::unique_fd(fd)});
    }
    return fd;
}

void BufferAllocator::QueryIonHeaps() {
    uses_legacy_ion_iface_ = ion_is_legacy(ion_fd_);
    if (uses_legacy_ion_iface_) {
        LOG(INFO) << "Using legacy ION heaps";
        return;
    }

    int heap_count;
    int ret = ion_query_heap_cnt(ion_fd_, &heap_count);
    if (ret == 0) {
        ion_heap_info_.resize(heap_count, {});
        ret = ion_query_get_heaps(ion_fd_, heap_count, ion_heap_info_.data());
    }

    // Abort if heap query fails
    CHECK(ret == 0)
            << "Non-legacy ION implementation must support heap information queries";
    LOG(INFO) << "Using non-legacy ION heaps";
}

BufferAllocator::BufferAllocator() {
    if (OpenDmabufHeap("system") < 0) {
        /* Since dmabuf heaps are not supported, try opening /dev/ion. */
        ion_fd_.reset(TEMP_FAILURE_RETRY(open(kIonDevice, O_RDWR | O_CLOEXEC)));
        /*
         * If ion_fd_ is invalid, then neither dmabuf heaps nor ion is supported
         * which is an invalid configuration. Abort in this case.
         */
        CHECK(ion_fd_ >= 0) << "Either dmabuf heaps or ion must be supported";
        QueryIonHeaps();
    } else {
        LOG(INFO) << "Using DMABUF Heaps";
    }
}
