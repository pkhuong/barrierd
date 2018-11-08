#include "drop.h"

#include <linux/bpf.h>
#include <linux/futex.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

static const int fully_allowed_syscalls[] = {
    SCMP_SYS(read),
    SCMP_SYS(clock_gettime),
    SCMP_SYS(clock_nanosleep),
    SCMP_SYS(epoll_wait_old),
    SCMP_SYS(epoll_wait),
    SCMP_SYS(exit),
    SCMP_SYS(futex),
    SCMP_SYS(nanosleep),
    SCMP_SYS(rt_sigreturn),
};

static scmp_filter_ctx ctx = NULL;

/*
 * Fully whitelists every syscall in fully_allowed_syscalls.
 *
 * Returns true on success.
 */
static bool whitelist_syscalls(void)
{
        for (size_t i = 0; i < ARRAY_SIZE(fully_allowed_syscalls); i++) {
                if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW,
                                     fully_allowed_syscalls[i], 0) < 0) {
                        perror("seccomp_rule_add (whitelist_syscalls) failed");
                        return false;
                }
        }

        return true;
}

/* Whitelist this sycall, where the first argument matches any of arg_values. */
static bool whitelist_with_arg(int syscall, const int arg_values[],
                               size_t nvalues, const char *context)
{
        for (size_t i = 0; i < nvalues; i++) {
                if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall, 1,
                                     SCMP_A0(SCMP_CMP_EQ, arg_values[i])) < 0) {
                        perror(context);
                        return false;
                }
        }

        return true;
}

/* Allow write(2) to stdout and stderr. */
static bool whitelist_write(void)
{
        static const int fds[] = {1, 2};

        return whitelist_with_arg(SCMP_SYS(write), fds, sizeof(fds),
                                  "seccomp_rule_add (whitelist_write) failed");
}

/* Allow bpf syscall for BPF_MAP_LOOKUP_ELEM (1) or BPF_MAP_UPDATE_ELEM (2). */
static bool whitelist_bpf(void)
{
        static const int actions[] = {
            BPF_MAP_LOOKUP_ELEM,
            BPF_MAP_UPDATE_ELEM,
        };

        return whitelist_with_arg(SCMP_SYS(bpf), actions, sizeof(actions),
                                  "seccomp_rule_add (whitelist_bpf) failed");
}

/* Allow lseek(?, 0, SEEK_SET). */
static bool whitelist_lseek(void)
{
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 2,
                             SCMP_A1(SCMP_CMP_EQ, 0),
                             SCMP_A2(SCMP_CMP_EQ, SEEK_SET)) >= 0) {
                return true;
        }

        perror("seccomp_rule_add (whitelist_lseek) failed");
        return false;
}

void drop_privileges(void)
{
        ctx = seccomp_init(SCMP_ACT_KILL);

        if (ctx == NULL) {
                fprintf(stderr, "seccomp_init failed.\n");
                return;
        }

        if (!whitelist_syscalls()) {
                goto out;
        }

        if (!whitelist_write()) {
                goto out;
        }

        if (!whitelist_bpf()) {
                goto out;
        }

        if (!whitelist_lseek()) {
                goto out;
        }

        if (seccomp_load(ctx) != 0) {
                perror("seccomp_load failed");
        }

out:
        seccomp_release(ctx);
        return;
}
