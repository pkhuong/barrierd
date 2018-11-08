#include "setup.h"

#include <asm/unistd.h>
#include <assert.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libbpf-macros.h"

#define RING_PAGE_CNT 1

static size_t page_size = 4096;

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline int perf_event_open(struct perf_event_attr *attr,
                                  pid_t pid, int cpu, int group_fd,
                                  unsigned long flags)
{
        return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/*
 * Returns the fd for a new BPF map. Dies on error.
 */
static int create_map(enum bpf_map_type type, uint32_t key_size,
                      uint32_t value_size, uint32_t max_entries,
                      const char *error_context)
{
        union bpf_attr attr = {
                .map_type = type,
                .key_size = key_size,
                .value_size = value_size,
                .max_entries = max_entries,
        };
        int fd;

        fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0) {
                perror(error_context);
                exit(1);
        }

        return fd;
}

/*
 * Returns the page siez. Dies on error.
 */
static void get_page_size(void)
{
        long size = sysconf(_SC_PAGESIZE);

        if (size < 0) {
                perror("sysconf(_SC_PAGESIZE) failed");
                exit(1);
        }

        page_size = (size_t)size;
        return;
}

/*
 * Returns the number of online processors, which must match the
 * number of configured processors.  Dies on error.
 */
static size_t ncpu(void)
{
        long configured;
        long online;

        configured = sysconf(_SC_NPROCESSORS_CONF);
        if (configured < 0) {
                perror("sysconf(_SC_NPROCESSORS_CONF) failed");
                exit(1);
        }

        online = sysconf(_SC_NPROCESSORS_ONLN);
        if (online < 0) {
                perror("sysconf(_SC_NPROCESSORS_ONLN) failed");
                exit(1);
        }

        assert(configured == online &&
               "All configured processors must be online.");
        return (size_t)configured;
}

/*
 * Returns an fd for the array of 1 timestamp, which marks when the
 * BPF program should send a perf event for wake-up.  Dies on error.
 */
static int watermark_map(void)
{
        return create_map(BPF_MAP_TYPE_ARRAY,
                          sizeof(uint32_t), sizeof(uint64_t), 1,
                          "watermark map failed");
}

/*
 * Returns an fd for the per-CPU array of 1 timestamp, the last time
 * at which we know the CPU was running non-userspace code.  Dies on
 * error.
 */
static int timestamp_map(void)
{
        return create_map(BPF_MAP_TYPE_PERCPU_ARRAY,
                          sizeof(uint32_t), sizeof(uint64_t), 1,
                          "per-CPU map failed");
}

/*
 * Returns a map of perf event queues, one per CPU.  Dies on error.
 */
static int perf_map(size_t ncpu)
{
        return create_map(BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                          sizeof(uint32_t), sizeof(int), ncpu,
                          "perf event map failed");
}

/*
 * Returns a fresh epoll file descriptor.  Dies on error.
 */
static int epoll_create_or_die(void)
{
        int r;

        r = epoll_create1(EPOLL_CLOEXEC);
        if (r < 0) {
                perror("epoll_create failed");
                exit(1);
        }

        return r;
}

/*
 * Returns the file descriptor for a perf software event queue for cpu.
 *
 * The perf queue will send a wake-up on every event.  On return, it
 * is already enabled, and mapped, in order to trigger wake-ups.
 *
 * Dies on error.
 */
static int make_perf_queue(size_t cpu)
{
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
                .sample_period = 1,
                .wakeup_events = 1,
	};
        int queue_fd;

        queue_fd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (queue_fd < 0) {
                perror("perf_event_open failed");
                exit(1);
        }

        /*
         * mmap the perf queue to enable wake-ups in the kernel. No
         * one reads the ring buffer, so we just throw the address
         * away.
         */
        {
                const void *r;

                r = mmap(NULL, (1 + RING_PAGE_CNT) * page_size,
                         PROT_READ, MAP_SHARED,
                         queue_fd, 0);
                if (r == MAP_FAILED) {
                        perror("mmap of perf ring buffer failed");
                        exit(1);
                }
        }

        /*
         * Enable the queue right away, before we forget about the fd.
         */
        {
                int r;

                r = ioctl(queue_fd, PERF_EVENT_IOC_ENABLE, 0);
                if (r < 0) {
                        perror("ioctl(PERF_EVENT_IOC_ENABLE) failed");
                        exit(1);
                }
        }

        return queue_fd;
}

/*
 * Registers the perf queue fd in the state's epoll fd.  Dies on error.
 */
static void add_queue_fd_to_epoll(const struct ebpf_state *state, int queue_fd)
{
        struct epoll_event event = {
                .events = EPOLLIN
        };
        int r;

        r = epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, queue_fd, &event);
        if (r < 0) {
                perror("epoll_ctl failed");
                exit(1);
        }

        return;
}

/*
 * Registers the queue fd as the cpu's fd in the eBPF perf map.
 */
static void set_queue_fd_as_perf_fd(int perf_map_fd, int queue_fd, size_t cpu)
{
        uint32_t key = cpu;
        union bpf_attr attr = {
                .map_fd = perf_map_fd,
                .key    = (uintptr_t)&key,
                .value  = (uintptr_t)&queue_fd,
                .flags  = BPF_ANY,
        };
        int r;

        r = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
        if (r < 0) {
                perror("bpf(BPF_MAP_UPDATE_ELEM) failed");
                exit(1);
        }

        return;
}

/*
 * Creates and attaches a perf event fd for cpu. Once registered, the
 * perf event fd is leaked: we only need it for epoll wake-ups, and we
 * can't close it (that would stop the wake-ups).
 */
static void attach_one_perf_event(const struct ebpf_state *state,
                                  int perf_map_fd,
                                  size_t cpu)
{
        int queue_fd;

        queue_fd = make_perf_queue(cpu);
        add_queue_fd_to_epoll(state, queue_fd);
        set_queue_fd_as_perf_fd(perf_map_fd, queue_fd, cpu);
        return;
}

/*
 * Creates and attaches a perf event fd for all online cpus.
 */
static void attach_perf_events(const struct ebpf_state *state,
                               int perf_map_fd)
{
        for (size_t i = 0; i < state->ncpu; i++) {
                attach_one_perf_event(state, perf_map_fd, i);
        }

        return;
}

/*
 * Attempts to load an eBPF program and returns the corresponding fd.
 *
 * If log_buf is non-NULL, logs the error in that buffer.
 *
 * Returns a non-negative file descriptor on success, -1 on error.
 */
static int load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
                        uint32_t insn_cnt, const char *license,
                        char *log_buf, uint32_t log_buf_sz)
{
	union bpf_attr attr = {
                .prog_type = type,
                .insn_cnt = insn_cnt,
                .insns = (uintptr_t)insns,
                .license = (uintptr_t)license,
                .log_buf = (uintptr_t)log_buf,
                .log_size = (log_buf != NULL) ? 0 : log_buf_sz,
                .log_level = (log_buf != NULL) ? 1 : 0,
                .kern_version = LINUX_VERSION_CODE,
                .prog_flags = BPF_F_STRICT_ALIGNMENT,
        };

        return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

/*
 * Loads our eBPF script, after hooking it up to the map file
 * descriptors in state and to perf_map_fd.
 *
 * Dies with a log of the eBPF message on error.
 */
static int load_ebpf(const struct ebpf_state *state, int perf_map_fd)
{
#if ULONG_MAX < UINT64_MAX
# error "The eBPF program is only expected to work on 64-bit architectures."
#endif
        char *buf;
        size_t bufsz = 65536;
        int per_cpu_map_fd = state->timestamp_map_fd;
        int trigger_map_fd = state->watermark_fd;
        int r;

        const struct bpf_insn prog[] = {
#               include "signal.ebpf.inc"
        };
        
        
        r = load_program(BPF_PROG_TYPE_TRACEPOINT,
                         prog, sizeof(prog) / sizeof(prog[0]),
                         "Dual BSD/GPL", NULL, 0);
        if (r >= 0) {
                return r;
        }

        buf = calloc(bufsz, 1);
        r = load_program(BPF_PROG_TYPE_TRACEPOINT,
                         prog, sizeof(prog) / sizeof(prog[0]),
                         "Dual BSD/GPL", buf, bufsz);
        if (r < 0) {
                perror("bpf(BPF_PROG_LOAD) failed");
                fprintf(stderr, "%.*s\n", (int)bufsz, buf);
                exit(1);
        }

        free(buf);
        return r;
}

void setup(struct ebpf_state *state)
{
        int perf_map_fd;

        memset(state, 0, sizeof(*state));

        get_page_size();
        state->ncpu = ncpu();
        state->watermark_fd = watermark_map();
        state->timestamp_map_fd = timestamp_map();
        state->epoll_fd = epoll_create_or_die();

        perf_map_fd = perf_map(state->ncpu);
        attach_perf_events(state, perf_map_fd);

        state->ebpf_prog_fd = load_ebpf(state, perf_map_fd);
        return;
}
