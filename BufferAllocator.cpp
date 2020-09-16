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
#include <linux/dma-buf.h>
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
static constexpr char kIonSystemHeapName[] = "ion_system_heap";

void BufferAllocator::LogInterface(const std::string& interface) {
    if (!logged_interface_) {
        LOG(INFO) << "Using : " << interface;
        logged_interface_ = true;
    }
}

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
        fd = TEMP_FAILURE_RETRY(open(heap_path.c_str(), O_RDONLY | O_CLOEXEC));
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
        LogInterface("Legacy ion heaps");
        MapNameToIonMask(kDmabufSystemHeapName, ION_HEAP_SYSTEM_MASK);
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
    LogInterface("Non-legacy ION heaps");

    /*
     * No error checking here, it is possible that devices may have used another name for
     * the ion system heap.
     */
    MapNameToIonName(kDmabufSystemHeapName, kIonSystemHeapName);
}

BufferAllocator::BufferAllocator() {
    if (OpenDmabufHeap("system") < 0) {
        /* Since dmabuf heaps are not supported, try opening /dev/ion. */
        ion_fd_.reset(TEMP_FAILURE_RETRY(open(kIonDevice, O_RDONLY| O_CLOEXEC)));

        /*
         * If ion_fd_ is invalid, then neither dmabuf heaps nor ion is supported
         * which is an invalid configuration. Abort in this case.
         */
        CHECK(ion_fd_ >= 0) << "Either dmabuf heaps or ion must be supported";
        QueryIonHeaps();
    } else {
        LogInterface("DMABUF Heaps");
    }
}

int BufferAllocator::MapNameToIonMask(const std::string& heap_name, unsigned int ion_heap_mask,
                                      unsigned int ion_heap_flags) {
    if (!ion_heap_mask)
        return -EINVAL;
    IonHeapConfig heap_config = { ion_heap_mask, ion_heap_flags };
    heap_name_to_config_[heap_name] = heap_config;
    return 0;
}

int BufferAllocator::GetIonHeapIdByName(const std::string& heap_name, unsigned int* heap_id) {
    for (auto& it : ion_heap_info_) {
        if (heap_name == it.name) {
            *heap_id = it.heap_id;
            return 0;
        }
    }

    LOG(ERROR) << "No ion heap of name " << heap_name << " exists";
    return -EINVAL;
}

int BufferAllocator::MapNameToIonName(const std::string& heap_name,
                                      const std::string& ion_heap_name,
                                      unsigned int ion_heap_flags) {
    unsigned int ion_heap_id = 0;
    auto ret = GetIonHeapIdByName(ion_heap_name, &ion_heap_id);
    if (ret < 0)
        return ret;

    unsigned int ion_heap_mask = 1 << ion_heap_id;
    IonHeapConfig heap_config = { ion_heap_mask, ion_heap_flags };
    heap_name_to_config_[heap_name] = heap_config;

    return 0;
}

int BufferAllocator::MapNameToIonHeap(const std::string& heap_name,
                                      const std::string& ion_heap_name,
                                      unsigned int ion_heap_flags,
                                      unsigned int legacy_ion_heap_mask,
                                      unsigned int legacy_ion_heap_flags) {
    int ret = 0;

    if (uses_legacy_ion_iface_ || ion_heap_name == "") {
        ret = MapNameToIonMask(heap_name, legacy_ion_heap_mask, legacy_ion_heap_flags);
    } else if (!DmabufHeapsSupported() && !ion_heap_name.empty()) {
        ret = MapNameToIonName(heap_name, ion_heap_name, ion_heap_flags);
    }

    return ret;
}

int BufferAllocator::GetIonConfig(const std::string& heap_name, IonHeapConfig& heap_config) {
    int ret = 0;
    auto it = heap_name_to_config_.find(heap_name);
    if (it != heap_name_to_config_.end()) {
        heap_config = it->second;
    } else {
        if (uses_legacy_ion_iface_) {
            ret = -EINVAL;
        } else {
            unsigned int heap_id;
            ret = GetIonHeapIdByName(heap_name, &heap_id);
            if (ret == 0) {
                heap_config.mask = 1 << heap_id;
                heap_config.flags = 0;
                /* save it so that this lookup does not need to happen again */
                heap_name_to_config_[heap_name] = heap_config;
            }
        }
    }

    if (ret)
        LOG(ERROR) << "No ion heap of name " << heap_name << " exists";
    return ret;
}

int BufferAllocator::DmabufAlloc(const std::string& heap_name, size_t len) {
    int fd = OpenDmabufHeap(heap_name);
    if (fd < 0) {
        LOG(ERROR) << "Unsupported dmabuf heap: " << heap_name << " error: " << fd;
        return fd;
    }

    struct dma_heap_allocation_data heap_data{
        .len = len,  // length of data to be allocated in bytes
        .fd_flags = O_RDWR | O_CLOEXEC,  // permissions for the memory to be allocated
    };

    auto ret = TEMP_FAILURE_RETRY(ioctl(fd, DMA_HEAP_IOCTL_ALLOC, &heap_data));
    if (ret < 0)
        return ret;

    return heap_data.fd;
}

int BufferAllocator::IonAlloc(const std::string& heap_name, size_t len, unsigned int heap_flags, size_t legacy_align) {
    IonHeapConfig heap_config;
    auto ret = GetIonConfig(heap_name, heap_config);
    if (ret)
        return ret;

    int alloc_fd = -1;
    unsigned int flags = heap_config.flags | heap_flags;
    ret = ion_alloc_fd(ion_fd_, len, legacy_align, heap_config.mask, flags, &alloc_fd);
    if (ret) {
        PLOG(ERROR) << "allocation fails for ion heap with mask: " << heap_config.mask
                    << " and flags: " << flags;
        return ret;
    }
    return alloc_fd;
}

int BufferAllocator::Alloc(const std::string& heap_name, size_t len, unsigned int heap_flags, size_t legacy_align) {
    if (DmabufHeapsSupported()) {
        return DmabufAlloc(heap_name, len);
    }

    return IonAlloc(heap_name, len, heap_flags, legacy_align);
}

int BufferAllocator::LegacyIonCpuSync(unsigned int dmabuf_fd,
                                      const CustomCpuSyncLegacyIon& legacy_ion_cpu_sync_custom,
                                      void *legacy_ion_custom_data) {
    if (!legacy_ion_cpu_sync_custom)
        return ion_sync_fd(ion_fd_, dmabuf_fd);

    // dup ion_fd_ so that we retain its ownership.
    int new_ion_fd = TEMP_FAILURE_RETRY(dup(ion_fd_.get()));
    if (new_ion_fd < 0) {
        PLOG(ERROR) << "Unable to dup ion fd. error: " << new_ion_fd;
        return new_ion_fd;
    }

    int ret = legacy_ion_cpu_sync_custom(new_ion_fd, dmabuf_fd, legacy_ion_custom_data);

    close(new_ion_fd);
    return ret;
}

int BufferAllocator::DoSync(unsigned int dmabuf_fd, bool start, SyncType sync_type,
                            const CustomCpuSyncLegacyIon& legacy_ion_cpu_sync_custom,
                            void *legacy_ion_custom_data) {
    if (uses_legacy_ion_iface_) {
        return LegacyIonCpuSync(dmabuf_fd, legacy_ion_cpu_sync_custom,
                                legacy_ion_custom_data);
    }

    struct dma_buf_sync sync = {
        .flags = (start ? DMA_BUF_SYNC_START : DMA_BUF_SYNC_END) |
                static_cast<uint64_t>(sync_type),
    };
    return TEMP_FAILURE_RETRY(ioctl(dmabuf_fd, DMA_BUF_IOCTL_SYNC, &sync));
}

int BufferAllocator::CpuSyncStart(unsigned int dmabuf_fd, SyncType sync_type,
                                  const CustomCpuSyncLegacyIon& legacy_ion_cpu_sync_custom,
                                  void *legacy_ion_custom_data) {
    auto it = fd_last_sync_type_.find(dmabuf_fd);
    if (it != fd_last_sync_type_.end()) {
        LOG(ERROR) << "CpuSyncEnd needs to be invoked for this fd first";
        return -EINVAL;
    }

    int ret = DoSync(dmabuf_fd, true /* start */, sync_type, legacy_ion_cpu_sync_custom,
                     legacy_ion_custom_data);

    if (ret) {
        PLOG(ERROR) << "CpuSyncStart() failure";
    } else {
        fd_last_sync_type_[dmabuf_fd] = sync_type;
    }
    return ret;
}

int BufferAllocator::CpuSyncEnd(unsigned int dmabuf_fd,
                                const CustomCpuSyncLegacyIon& legacy_ion_cpu_sync_custom,
                                void *legacy_ion_custom_data) {
    auto it = fd_last_sync_type_.find(dmabuf_fd);
    if (it == fd_last_sync_type_.end()) {
        LOG(ERROR) << "CpuSyncStart() must be called before CpuSyncEnd()";
        return -EINVAL;
    }

    int ret = DoSync(dmabuf_fd, false /* start */, it->second /* sync_type */,
                     legacy_ion_cpu_sync_custom, legacy_ion_custom_data);
    if (ret) {
        PLOG(ERROR) << "CpuSyncEnd() failure";
    } else {
        fd_last_sync_type_.erase(it);
    }

    return ret;
}
