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
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

void libdmabufheaptest() {
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
     * Test the DmabufHeapAllocSystem() APIs.
     */
    fd = DmabufHeapAllocSystem2(bufferAllocator, true /* cpu_access */, len, 0);
    if (fd < 0) {
        printf("DmabufHeapAllocSystem() failed: %d cpu_access: true\n", fd);
        return;
    }
    close(fd);

    fd = DmabufHeapAllocSystem2(bufferAllocator, false /* cpu_access */, len, 0);
    if (fd < 0) {
        printf("DmabufHeapAllocSystem() failed: %d cpu_access: false\n", fd);
        return;
    }
    close(fd);

    fd = DmabufHeapAlloc2(bufferAllocator, kDmabufSystemHeapName, len, 0);
    if (fd < 0) {
        printf("Alloc failed: %d\n", fd);
        return;
    }

    ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap failed\n");
        return;
    }

    ret = DmabufHeapCpuSyncStart2(bufferAllocator, fd, kSyncReadWrite);
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

    ret = DmabufHeapCpuSyncEnd2(bufferAllocator, fd, kSyncReadWrite);
    if (ret) {
        printf("DmabufHeapCpuSyncEnd failed: %d\n", ret);
        return;
    }

    munmap(ptr, len);
    close(fd);

    FreeDmabufHeapBufferAllocator(bufferAllocator);
    printf("PASSED\n");
}

int main(int, char*[]) {
    libdmabufheaptest();
    return 0;
}
