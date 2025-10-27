/*
 *   Copyright 2020, 2021 Linaro Ltd.
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>

#define HEAP_DEVPATH "/dev/dma_heap"

#define ONE_MEG (1024 * 1024)
#define NUM_SIZES 4
int sizes[NUM_SIZES] = {4 * 1024, ONE_MEG, 8 * ONE_MEG, 32 * ONE_MEG};

#define NUM_ITERS 5000
#define NSEC_PER_SEC 1000000000LL

int dmabuf_heap_open(char* name) {
    int ret, fd;
    char buf[256];

    ret = sprintf(buf, "%s/%s", HEAP_DEVPATH, name);
    if (ret < 0) {
        printf("sprintf failed!\n");
        return ret;
    }

    fd = open(buf, O_RDWR);
    if (fd < 0) printf("open %s failed!\n", buf);
    return fd;
}

int dmabuf_heap_alloc(int fd, size_t len, unsigned int flags, int* dmabuf_fd) {
    struct dma_heap_allocation_data data = {
            .len = len,
            .fd_flags = O_RDWR | O_CLOEXEC,
            .heap_flags = flags,
    };
    int ret;

    if (dmabuf_fd == NULL) return -EINVAL;

    ret = ioctl(fd, DMA_HEAP_IOCTL_ALLOC, &data);
    if (ret < 0) return ret;
    *dmabuf_fd = (int)data.fd;
    return ret;
}

void dmabuf_sync(int fd, int start_stop) {
    struct dma_buf_sync sync = {0};
    int ret;

    sync.flags = start_stop | DMA_BUF_SYNC_RW;
    ret = ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync);
    if (ret) printf("sync failed %d\n", errno);
}

void dmabuf_heap_bench(char* heap_name, int size) {
    int heap_fd = -1, dmabuf_fd = -1;
    struct timespec ts_start, ts_end;
    long long start, end;
    int ret;
    int i;

    heap_fd = dmabuf_heap_open(heap_name);
    if (heap_fd < 0) return;

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    for (i = 0; i < NUM_ITERS; i++) {
        ret = dmabuf_heap_alloc(heap_fd, size, 0, &dmabuf_fd);
        if (ret) goto out;
        close(dmabuf_fd);
    }
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    start = ts_start.tv_sec * NSEC_PER_SEC + ts_start.tv_nsec;
    end = ts_end.tv_sec * NSEC_PER_SEC + ts_end.tv_nsec;

    printf("dmabuf heap: alloc %d bytes %i times in %lld ns \t %lld ns/call\n", size, NUM_ITERS,
           end - start, (end - start) / NUM_ITERS);
out:
    if (heap_fd >= 0) close(heap_fd);
}

int main(int argc, char* argv[]) {
    char* dmabuf_heap_name;
    int i;
    if (argc < 2) {
        printf("Usage %s <dmabuf heap name>\n", argv[0]);
        return -1;
    }

    dmabuf_heap_name = argv[1];

    printf("Testing dmabuf %s", dmabuf_heap_name);
    printf("\n---------------------------------------------\n");
    for (i = 0; i < NUM_SIZES; i++) {
        dmabuf_heap_bench(dmabuf_heap_name, sizes[i]);
    }

    return 0;
}
