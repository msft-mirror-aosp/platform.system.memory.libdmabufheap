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

#pragma once

#include <linux/ion_4.12.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/unique_fd.h>

class BufferAllocator{
  public:
    BufferAllocator();
    ~BufferAllocator() {}

    /* Not copyable or movable */
    BufferAllocator(const BufferAllocator&) = delete;
    BufferAllocator& operator=(const BufferAllocator&) = delete;

  private:
    int OpenDmabufHeap(const std::string& name);
    void QueryIonHeaps();
    int GetDmabufHeapFd(const std::string& name);

    /* Stores all open dmabuf_heap handles. */
    std::unordered_map<std::string, android::base::unique_fd> dmabuf_heap_fds_;

    /* saved handle to /dev/ion. */
    android::base::unique_fd ion_fd_;
    /**
     * Stores the queried ion heap data. Struct ion_heap_date is defined
     * as part of the ION UAPI as follows.
     * struct ion_heap_data {
     *   char name[MAX_HEAP_NAME];
     *    __u32 type;
     *    __u32 heap_id;
     *    __u32 reserved0;
     *    __u32 reserved1;
     *    __u32 reserved2;
     * };
     */
    bool uses_legacy_ion_iface_ = false;
    std::vector<struct ion_heap_data> ion_heap_info_;
};
