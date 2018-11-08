#include "attach.h"

#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

static inline int perf_event_open(struct perf_event_attr *attr,
                                  pid_t pid, int cpu, int group_fd,
                                  unsigned long flags)
{
        return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

void attach_to_tracepoint_id(const struct ebpf_state *state, int id)
{
        struct perf_event_attr attr = {
                .type = PERF_TYPE_TRACEPOINT,
                .sample_type = PERF_SAMPLE_RAW,
                .sample_period = 1,
                .wakeup_events = 1,
                .config = id,
        };
        int perf_fd;
        int r;

        /*
         * We can't have both pid=-1 and cpu=-1 (any pid and any cpu).
         * However, software events disregard the CPU field, so we can
         * pick an arbitrary (valid) CPU.
         */
        perf_fd = perf_event_open(&attr, /*pid=*/-1, /*cpu=*/0,
                                  /*group=*/-1, /*flags=*/PERF_FLAG_FD_CLOEXEC);
        if (perf_fd < 0) {
                perror("perf_event_open for tracepoint failed");
                exit(1);
        }

        /* Attach our eBPF program to the event. */
        r = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, state->ebpf_prog_fd);
        if (r < 0) {
                perror("ioctl(PERF_EVENT_IOC_SET_BPF) failed");
                exit(1);
        }

        /* Enable the event. */
        r = ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
        if (r < 0) {
                perror("ioctl(PERF_EVENT_IOC_ENABLE) failed");
                exit(1);
        }

        /* Leak the FD to keep triggering the ebpf script. */
        return;
}
