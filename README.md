barrierd: low latency near-zero overhead asymmetric barriers
============================================================

Barrierd offers the same functionality as membarrier(2)'s regular
(non-EXPEDITED) asymmetric barriers.  However, by tracking interrupts
instead of waiting for a full RCU grace period, the barrier conditions
are satisfied more quickly (on the order of 2-4 ms on my machine,
rather than 25-80 ms).

barrierd hides all the BPF logic in a daemon, which writes the barrier
timestamp data to an mmap-able file.  The daemon performs each write
with atomic 64-bit stores, so userspace can read the data without
locking. Moreover, the daemon also treats certain fields (documented
in `include/barrierd.h`) as futex words, and wakes up all waiters on
any change to these fields.  Applications are thus able to wait for a
barrier without spinning in userspace.

More details on how interrupt timestamps are useful may be found at
https://www.pvk.ca/XXX.

A sample client is also available at `samples/client.c`.

How to use the daemon
---------------------

The daemon needs `CAP_SYS_ADMIN` (i.e., root) not only for setup, but
also for long-running operations.  The daemon must thus be spawned
with admin capabilities; and once setup is complete, it will use
seccomp to whitelist only a few syscalls in a fine-grained manner (in
particular, the bpf syscall is only allowed to read or write to
pre-created maps).

The daemon should be invoked with the path to a file that will be
mapped by clients, followed by a list of tracepoint ids.  The mappable
file will be created with mode 0644 if necessary, and will be grown as
necessary to fit the number of cpus. The daemon also creates a private
(0600) lock file alongside the mappable file, to ensure mutual
exclusion between daemons.  The id for any tracepoint may be found by
reading `/sys/kernel/debug/tracing/events/$tracepoint/id`, 
where `/sys/kernel/debug` is the default debugfs mountpoint.  Any
tracepoint is valid for correctness; in practice, we want to make
tracepoints are triggered frequently enough (more than once a
millisecond), but not too much.  A reasonable default might be:

* `irq/softirq_entry`
* `irq_vectors/local_timer_entry`
* `sched/sched_switch`
* `raw_syscalls/sys_enter` (might be aggressive)

We can run barrierd with these tracepoints as follows:

    # export TRACE_PATH=/sys/kernel/debug/tracing/events/
    # ./barrierd /tmp/test/public_file \
        `cat $TRACE_PATH/irq/softirq_entry/id` \
        `cat $TRACE_PATH/irq_vectors/local_timer_entry/id` \
        `cat $TRACE_PATH/sched/sched_switch/id`
    Attaching to tracepoint 127.
    Attaching to tracepoint 77.
    Attaching to tracepoint 292.
    Acquiring exclusive lock on /tmp/test/public_file.lock.
    Setup complete.

For more information, export `VERBOSE`:

    # VERBOSE=1 ./barrierd /tmp/test/public_file \
        `cat $TRACE_PATH/irq/softirq_entry/id` \
        `cat $TRACE_PATH/irq_vectors/local_timer_entry/id` \
        `cat $TRACE_PATH/sched/sched_switch/id`
    Attaching to tracepoint 127.
    Attaching to tracepoint 77.
    Attaching to tracepoint 292.
    Acquiring exclusive lock on /tmp/test/public_file.lock.
    Setup complete.
    Now: 26367387883585245.
    CPU 1 -> 26367387883355921 (2827337514).
    CPU 6 -> 26367387883330067 (2827316280).
    CPU 8 -> 26367387883329190 (2827315257).
    CPU 14 -> 26367387883402750 (2827389123).
    CPU 17 -> 26367387883340452 (2827326897).
    CPU 18 -> 26367387883523725 (2827446010).
    CPU 21 -> 26367387883570540 (2827565992).
    change: true false.
    Sleep at: 26367387883603199.
    epoll_wait returned 7 after 0.008 ms.
    Now: 26367387883621874.
    change: false false.
    Sleep at: 26367387883629586.
    epoll_wait returned 1 after 0.043 ms.

`perf stat` will give you an overview of how often any tracepoint
triggers. Make sure to test this on several CPUs, the breakdown of
events varies across cores.

    sudo perf stat -C 5 -e \
        irq:softirq_entry,irq_vectors:local_timer_entry,sched:sched_switch \
        -- sleep 10

     Performance counter stats for 'CPU(s) 5':

             2,435      irq:softirq_entry
             2,733      irq_vectors:local_timer_entry
               655      sched:sched_switch

      10.001568571 seconds time elapsed

The daemon assumes CPU hotplug is not in play: all configured CPUs
must be online, and any offline CPU will stall barriers.

Once the daemon is running, all unprivileged programs (modulo filepath
permissions) may map the client-mappable file (read-only) to wait for
barriers.  See samples/client.c for an example.


    $ ./client /tmp/test/public_file
    Wait on mprotect IPI finished after 0.004 ms.
    Wait on ns finished after 2.383 ms and 2 iter.
    Wait on vtime finished after 9.625 ms and 2 iter (success).
    Wait on RCU membarrier finished after 24.063 ms.
    Wait on mprotect IPI finished after 0.006 ms.
    Wait on ns finished after 0.941 ms and 1 iter.
    Wait on vtime finished after 10.417 ms and 2 iter (success).
    Wait on RCU membarrier finished after 55.095 ms.
    Wait on mprotect IPI finished after 0.002 ms.
    Wait on ns finished after 0.720 ms and 1 iter.
    Wait on vtime finished after 8.190 ms and 2 iter (success).
    Wait on RCU membarrier finished after 29.038 ms.
    Wait on mprotect IPI finished after 0.003 ms.
    Wait on ns finished after 0.052 ms and 1 iter.
    Wait on vtime finished after 8.740 ms and 2 iter (success).
    Wait on RCU membarrier finished after 44.296 ms.
    Wait on mprotect IPI finished after 0.003 ms.
    Wait on ns finished after 0.580 ms and 1 iter.
    Wait on vtime finished after 9.762 ms and 2 iter (success).
    Wait on RCU membarrier finished after 31.217 ms.
    Wait on mprotect IPI finished after 0.002 ms.
    Wait on ns finished after 1.968 ms and 1 iter.
    Wait on vtime finished after 10.208 ms and 2 iter (success).
    Wait on RCU membarrier finished after 51.490 ms.

The fastest way to get a reverse barrier is still to actively trigger
IPIs; however, the overhead scales badly with the number of cores
(each waiter ends up sending an IPI to every core).  After that,
detecting barriers with `last_interrupt_ns` is faster than using
virtual time: it usually completes after a single futex wait, in one
milliseconds or two (the worst case on my machine is 4 milliseconds).
Virtual time is much coarser, and often needs multiple updates over
several milliseconds.  Finally, regular non-expedited membarrier is
even slower than waiting on virtual time, and easily 10x as slow as
waiting on CLOCK_MONOTONIC.

There is value in using `barrierd` over the membarrier syscall.
However, a client should only use virtual time heuristically, e.g., to
eagerly tag items in the middle of a hot loop.  Once the client really
waits on a barrier, virtual time can still be used to optimistically
detect items that have passed a barrier. However, virtual time is
slower to respond than real time, and is vulnerable to starvation; a
client should only rely on real monotonic time to guarantee progress.
