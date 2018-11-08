#ifndef BARRIERD_H
#define BARRIERD_H
/*
 * barrierd creates and updates a mmap-able read-only file that
 * contains a `struct barrierd_mapped_data`.
 *
 * Both last_interrupt_ns and last_interrupt_vtime are updated
 * whenever the oldest time (over all CPUs) at which each CPU was
 * known to be processing an interrupt changes; the low-order half of
 * each field also doubles as a futex word that is woken up whenever
 * the value changes.
 *
 * last_interrupt_ns counts nanoseconds on CLOCK_MONOTONIC,
 * i.e. nanoseconds since boot.
 *
 * last_interrupt_vtime instead tracks the virtual time in `vtime`, a
 * simple counter.
 *
 * In both cases, it is safe to assume a write is visible to all fast
 * paths whenever the last_interrupt_{ns,vtime} value is strictly
 * greater than the CLOCK_MONOTONIC nanoseconds / vtime timestamp when
 * the write was made.
 *
 * Adventurous programmers can also try to be smarted by looking at
 * the last_interrupt_{ns,vtime} value on each cpu.
 *
 * All the uint64_t fields are updated with atomic stores, so no
 * locking is necessary.
 */

#include <stdint.h>

struct barrierd_per_cpu {
        uint64_t last_interrupt_ns;
        uint64_t last_interrupt_vtime;
};

struct barrierd_mapped_data {
        uint64_t ncpu;  /* Number of CPUs in the system. */
        uint64_t vtime; /* Current virtual time. */
        /*
         * The min vtime / CLOCK_MONOTONIC time of the last interrupt
         * on all cpus.  The low half of both fields are futex words,
         * and last_interrupt_ns always changes right after the vtime
         * changes.
         *
         * vtime may suffer from starvation and never advance. Never
         * rely on it for progress.
         */
        uint64_t last_interrupt_ns;
        uint64_t last_interrupt_vtime;
        uint64_t padding[12];
        struct barrierd_per_cpu per_cpu[/* ncpu */];
};
#endif /* !BARRIERD_H */
