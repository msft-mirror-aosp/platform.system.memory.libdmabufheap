/*
 *   Copyright 2020 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <BufferAllocator/BufferAllocatorWrapper.h>
#include <errno.h>
#include <ion/ion.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

int legacy_ion_custom_callback(int ion_fd) {
    int ret = 0;
    if (!ion_is_legacy(ion_fd)) {
        perror("error in legacy ion custom callback");
        ret = errno;
    } else {
        printf("in custom legacy ion cpu sync callback\n");
    }

    return ret;
}

void libdmabufheaptest(bool use_custom_callback) {
    const size_t len = 1024 * 1024;
    int fd = -1, ret = 0;
    size_t i = 0;
    unsigned char* ptr = NULL;

    BufferAllocator* bufferAllocator = CreateDmabufHeapBufferAllocator();
    if (!bufferAllocator) {
        printf("unable to get allocator\n");
        return;
    }

    /*
     * Legacy ion devices may have hardcoded heap IDs that do not
     * match the ion UAPI header. Map heap name 'system' to a heap mask
     * of all 1s so that these devices will allocate from the first
     * available heap when asked to allocate from a heap of name 'system'.
     */
    ret = MapDmabufHeapNameToIonHeap(bufferAllocator, kDmabufSystemHeapName,
                                     "" /* no mapping for non-legacy */,
                                     0 /* no mapping for non-legacy ion */,
                                     ~0 /* legacy ion heap mask */, 0 /* legacy ion heap flag */);
    if (ret < 0) {
        printf("MapDmabufHeapNameToIonHeap failed: %d\n", ret);
        return;
    }

    fd = DmabufHeapAlloc(bufferAllocator, kDmabufSystemHeapName, len, 0);
    if (fd < 0) {
        printf("Alloc failed: %d\n", fd);
        return;
    }

    ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap failed\n");
        return;
    }

    ret = DmabufHeapCpuSyncStart(bufferAllocator, fd, kSyncReadWrite,
                                 use_custom_callback ? legacy_ion_custom_callback : NULL);
    if (ret) {
        printf("DmabufHeapCpuSyncStart failed: %d\n", ret);
        return;
    }

    for (i = 0; i < len; i++) {
        ptr[i] = (unsigned char)i;
    }
    for (i = 0; i < len; i++) {
        if (ptr[i] != (unsigned char)i) {
            printf("%s failed wrote %zu read %d from mapped "
                   "memory\n",
                   __func__, i, ptr[i]);
            return;
        }
    }

    ret = DmabufHeapCpuSyncEnd(bufferAllocator, fd,
                               use_custom_callback ? legacy_ion_custom_callback : NULL);
    if (ret) {
        printf("DmabufHeapCpuSyncEnd failed: %d\n", ret);
        return;
    }

    munmap(ptr, len);
    close(fd);

    FreeDmabufHeapBufferAllocator(bufferAllocator);
    printf("PASSED\n");
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    printf("*****running with custom legacy ion cpu sync callback****\n");
    libdmabufheaptest(true);
    printf("****running without custom legacy ion cpu sync callback****\n");
    libdmabufheaptest(false);
    return 0;
}
