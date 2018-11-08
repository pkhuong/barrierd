#include <barrierd.h>

#include <asm/unistd.h>
#include <ck_pr.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/futex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "attach.h"
#include "drop.h"
#include "ebpf_state.h"
#include "map.h"
#include "parse_stat.h"
#include "setup.h"

/* Try to use stat if we're stuck for more than 10ms. */
static const uint64_t stat_after_ns = 10 * 1000 * 1000UL;

/* We don't care about improving our timestamp by less than 100 us. */
static const uint64_t min_latency_ns = 100000;

/* Wait for 20ms in epoll before forcibly polling for new data. */
static const int epoll_wait_timeout_ms = 20;

/* Set to true if the VERBOSE environment variable is set. */
static bool verbose = false;

/* Stores the state we need to work with ebpf and tracepoints. */
static struct ebpf_state state;

/* Pre-allocated buffer of timestamps, one per CPU. */
static uint64_t *per_cpu_timestamps;

/* Writable mmap of the barrierd page. */
static struct barrierd_mapped_data *mapped_data;

/*
 * Updated with info from /proc/stat every now and then.
 *
 * NULL if /proc/stat could not be opened.
 */
static struct parse_stat *stat_data;

static inline int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
        return syscall(__NR_bpf, cmd, attr, size);
}

/* Returns the monotonic time (since boot) in nanoseconds. */
static uint64_t now_ns(void)
{
        struct timespec res;
        int r;

        r = clock_gettime(CLOCK_MONOTONIC, &res);
        if (r < 0) {
                perror("clock_gettime failed");
                exit(1);
        }

        return res.tv_sec * (1000 * 1000 * 1000ULL) + res.tv_nsec;
}

/*
 * Stores value in *dst, and wakes up any futex waiters on dst's low
 * order bits.
 */
static void wake_up(uint64_t *dst, uint64_t value)
{
        const void *low_half;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        low_half = dst;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        low_half = (uintptr_t)dst + sizeof(uint32_t);
#else
#error "__BYTE_ORDER__ must be defined."
#endif

        ck_pr_store_64(dst, value);
        ck_pr_fence_store();
        syscall(__NR_futex, low_half, FUTEX_WAKE, INT_MAX,
                /* ignored arguments */ NULL, NULL, 0);
        return;
}

/*
 * Updates the watermark timestamp to ts.
 *
 * On return, the BPF script will signal us via perf whenever the
 * CPU's previous interrupt timestamp was less than ts.
 */
static void set_watermark(uint64_t ts)
{
        uint32_t key = 0;
        union bpf_attr attr = {
            .map_fd = state.watermark_fd,
            .key = (uintptr_t)&key,
            .value = (uintptr_t)&ts,
            .flags = BPF_ANY,
        };
        int r;

        r = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
        if (r < 0) {
                perror("bpf(BPF_MAP_UPDATE_ELEM) failed in set_watermark");
                exit(1);
        }

        return;
}

/*
 * Fetches the per-CPU timestamps from the eBPF array and updates the
 * per-CPU state in mapped_data. Updates the virtual timestamp
 * whenever a change is made to the real-time timestamp.
 *
 * Returns true if any change was made.
 */
static bool update_timestamps(uint64_t vtime)
{
        uint32_t key = 0;
        union bpf_attr attr = {
            .map_fd = state.timestamp_map_fd,
            .key = (uintptr_t)&key,
            .value = (uintptr_t)per_cpu_timestamps,
        };
        int r;
        bool any_change = false;

        r = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
        if (r < 0) {
                perror("bpf(BPF_MAP_LOOKUP_ELEM) failed");
                exit(1);
        }

        for (size_t i = 0; i < state.ncpu; i++) {
                uint64_t prev = mapped_data->per_cpu[i].last_interrupt_ns;
                uint64_t ts = per_cpu_timestamps[i];

                if (stat_data != NULL &&
                    stat_data->per_cpu_stat[i].last_interrupt_ns > ts) {
                        ts = stat_data->per_cpu_stat[i].last_interrupt_ns;
                }

                if (ts <= prev) {
                        continue;
                }

                any_change = true;
                if (verbose) {
                        fprintf(stderr,
                                "CPU %zu -> %" PRIu64 " (%" PRIu64 ").\n", i,
                                ts, ts - prev);
                }

                ck_pr_store_64(&mapped_data->per_cpu[i].last_interrupt_ns, ts);
                ck_pr_store_64(&mapped_data->per_cpu[i].last_interrupt_vtime,
                               vtime);
        }

        ck_pr_fence_store();
        return any_change;
}

/*
 * Computes the new value of last_interrupt_ns and last_interrupt_vtime.
 * If there is any change, updates mapped_data and wakes up any waiter.
 */
static void update_last_interrupt(void)
{
        uint64_t last_ns = UINT64_MAX;
        uint64_t last_vtime = UINT64_MAX;

        for (size_t i = 0; i < state.ncpu; i++) {
                uint64_t ns = mapped_data->per_cpu[i].last_interrupt_ns;
                uint64_t vtime = mapped_data->per_cpu[i].last_interrupt_vtime;

                if (ns < last_ns) {
                        last_ns = ns;
                }

                if (vtime < last_vtime) {
                        last_vtime = vtime;
                }
        }

        if (last_vtime > mapped_data->last_interrupt_vtime) {
                wake_up(&mapped_data->last_interrupt_vtime, last_vtime);
        }

        if (last_ns > mapped_data->last_interrupt_ns) {
                wake_up(&mapped_data->last_interrupt_ns, last_ns);
        }

        return;
}

/*
 * Updates the last_interrupt timestamp data for all CPUs and for the
 * global system.
 *
 * Returns false if nothing happened and we need to wait for more
 * updates.
 *
 * We can only wait on epoll if no change was made to the global
 * last_interrupt_ns: if that is the case, the watermark set in the
 * immediately preceding call to update_data is still valid, and we
 * will not miss any update.  Similar reasoning means that we can only
 * safely advance the virtual time when no CPU's last_interrupt_ns
 * changed.
 *
 * Otherwise, keep spinning.
 */
static bool update_data(void)
{
        uint64_t vtime = mapped_data->vtime;
        uint64_t last_interrupt_ns = mapped_data->last_interrupt_ns;
        bool any_timestamp_change;
        bool global_change;

        any_timestamp_change = update_timestamps(vtime);
        update_last_interrupt();

        global_change = last_interrupt_ns != mapped_data->last_interrupt_ns;

        if (verbose) {
                fprintf(stderr, "change: %s %s.\n",
                        (any_timestamp_change ? "true" : "false"),
                        (global_change ? "true" : "false"));
        }

        if (global_change) {
                set_watermark(mapped_data->last_interrupt_ns);
                return true;
        }

        if (!any_timestamp_change) {
                wake_up(&mapped_data->vtime, vtime + 1);
        }

        /*
         * The watermark that was set before this call to update_data()
         * is still valid; we will not miss any wake-up if we epoll.
         */
        return false;
}

/*
 * Waits on epoll for new perf events (enqueued by our eBPF script).
 *
 * Returns true if we were woken up before the timeout.
 */
static bool wait_for_updates(void)
{
        struct epoll_event events[64];
        uint64_t now = now_ns();
        int r;

        if (mapped_data->last_interrupt_ns + min_latency_ns > now) {
                uint64_t deadline =
                    mapped_data->last_interrupt_ns + min_latency_ns;

                if (verbose) {
                        fprintf(stderr, "usleep for %" PRIu64 "ns.\n",
                                deadline - now);
                }

                /* ns -> us. */
                usleep(1 + (deadline - now) / 1000);
        }

        r = epoll_wait(state.epoll_fd, events,
                       sizeof(events) / sizeof(events[0]),
                       epoll_wait_timeout_ms);

        if (r < 0 && errno != EINTR) {
                perror("epoll_wait failed");
                exit(1);
        }

        if (verbose) {
                fprintf(stderr, "epoll_wait returned %i after %.3f ms.\n", r,
                        (now_ns() - now) * (1e3 / 1e9));
        }

        return r > 0;
}

int main(int argc, char **argv)
{
        if (argc < 2) {
                fprintf(stderr,
                        "Usage: %s mapped_file tracepoint_id*\n\t"
                        "The mapped file will be created if necessary, and"
                        "is associated with a lock file.\n\t"
                        "Find tracepoint ids in "
                        "/sys/kernel/debug/tracing/events/$tracepoint/id.\n",
                        argv[0]);
                exit(1);
        }

        verbose = (getenv("VERBOSE") != NULL);

        setup(&state);

        per_cpu_timestamps = calloc(state.ncpu, sizeof(*per_cpu_timestamps));

        for (int i = 2; i < argc; i++) {
                int id = atoi(argv[i]);

                fprintf(stderr, "Attaching to tracepoint %i.\n", id);
                attach_to_tracepoint_id(&state, id);
        }

        stat_data = parse_stat_create(state.ncpu);
        mapped_data = map_file(argv[1], &state);

        /* The setup is all done. We can drop all but a few syscalls now. */
        drop_privileges();
        fprintf(stderr, "Setup complete.\n");

        /*
         * Guarantee we get wakeups with a watermark in the near
         * future.
         */
        set_watermark(now_ns() + min_latency_ns);
        /* Read /proc/stat at least once. */
        parse_stat_update(stat_data, now_ns());

        for (;;) {
                if (verbose) {
                        fprintf(stderr, "Now: %" PRIu64 ".\n", now_ns());
                }

                if (update_data()) {
                        continue;
                }

                if (verbose) {
                        fprintf(stderr, "Sleep at: %" PRIu64 ".\n", now_ns());
                }

                /* If we woke up and we're not too far behind, loop back. */
                if (wait_for_updates()) {
                        uint64_t last_intr = mapped_data->last_interrupt_ns;
                        uint64_t now = now_ns();

                        if (now > last_intr &&
                            now - last_intr < stat_after_ns) {
                                continue;
                        }
                }

                /* Otherwise, consider the slow /proc/stat update path. */
                parse_stat_update(stat_data, now_ns());
        }

        return 0;
}
