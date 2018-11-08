#ifndef PARSE_STAT_H
#define PARSE_STAT_H
/*
 * The parse stat struct keeps track of the last time we read
 * `/proc/stat`, and of the signature for each CPU's timeslice info
 * (since each line should be a list of monotonically increasing
 * integers, the signature is simply a sum of the integers).
 *
 * If we read /proc/stat at some point after $signature_ns, and later
 * detect that /proc/stat has changed for a given cpu, that cpu has
 * processed some kernel code at some point after $signature_ns, and
 * it's safe to bump its last_interrupt timestamp so $signature_ns.
 *
 * parse stat uses a line iterator to parse /proc/stat and decode each
 * CPU's stat line without unexpected resource allocation.  Every time
 * /proc/stat is read, each cpu's signature_ns and signature are
 * updated.  Whenever we observe a change to signature, we can safely
 * update last_interrupt_ns to the old signature's signature_ns.
 *
 * We can't (e)poll for changes to /proc/stat, and generating
 * /proc/stat uses a non-trivial amount of system CPU time, so
 * parse_stat should only be used as a last resort, when we can't make
 * progress via the usual tracepoint eBPF / perf route.
 */
#include <stddef.h>
#include <stdint.h>

#include "line_iterator.h"

struct per_cpu_stat {
        uint64_t last_interrupt_ns;
        uint64_t signature_ns;
        uint64_t signature;
};

struct parse_stat {
        struct line_iterator it;
        uint64_t last_read;
        size_t ncpu;
        struct per_cpu_stat per_cpu_stat[];
};

/*
 * Returns a fresh parse_stat struct for ncpu processors.
 */
struct parse_stat *parse_stat_create(size_t ncpu);

/*
 * Parses /proc/stat to try and detect changes in the per-CPU stats.
 *
 * The call is a no-op if state is NULL, or if now_ns is too close to
 * the last time we read /proc/stat.
 *
 * If any movement is detected, the cpu's
 * per_cpu_stat.last_interrupt_ns is updated.
 */
void parse_stat_update(struct parse_stat *state, uint64_t now_ns);
#endif /* !PARSE_STAT_H */
