#ifndef EBPF_STATE_H
#define EBPF_STATE_H
#include <stddef.h>

/*
 * State needed to interact with the tracing subsystem and our ebpf
 * script.
 *
 * This state is clearly missing information necessary for a clean
 * shutdown; we expect to just leak file descriptors or mmaped regions
 * until the program exits.
 */
struct ebpf_state {
        size_t ncpu;  /* number of cores (# online == # configured). */
        int ebpf_prog_fd;  /* fd for the eBPF program. */
        int watermark_fd;  /* fd for the array of 1 64-bit signal timestamp. */
        int timestamp_map_fd;  /* fd for the thread-local array of ts. */
        int epoll_fd;  /* woken up when something happened. */
};
#endif /* !EBPF_STATE_H */
