#include <barrierd.h>

#include <asm/unistd.h>
#include <assert.h>
#include <ck_pr.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/membarrier.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void *page;
static const struct barrierd_mapped_data *data;

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

static void futex_wait(const uint64_t *word, uint64_t value)
{
        const struct timespec timeout = {
            /* Impose a 10ms timeout. */
            .tv_nsec = 10 * 1000 * 1000UL,
        };
        const void *low_half;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        low_half = word;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        low_half = (uintptr_t)word + sizeof(uint32_t);
#else
#error "__BYTE_ORDER__ must be defined."
#endif

        if (ck_pr_load_64(word) != value) {
                return;
        }

        /*
         * We impose a timeout to protect against missed
         * wake-ups... maybe caused by wraparound on real time?
         */
        syscall(__NR_futex, low_half, FUTEX_WAIT, (uint32_t)value,
                /*timeout=*/&timeout,
                /* ignored arguments */ NULL, 0);
}

static void wait_on_membarrier(bool expedited)
{
        uint64_t begin = now_ns();
        uint64_t end;
        int cmd =
            expedited ? MEMBARRIER_CMD_GLOBAL_EXPEDITED : MEMBARRIER_CMD_GLOBAL;
        int r;

        r = syscall(__NR_membarrier, cmd, 0);
        assert(r == 0);
        end = now_ns();

        printf("Wait on %s membarrier finished after %.3f ms.\n",
               (expedited ? "expedited" : "RCU"), (end - begin) * (1e3 / 1e9));
        return;
}

static void wait_on_mprotect_ipi(void)
{
        uint64_t begin = now_ns();
        uint64_t end;

        mprotect(page, 4096, PROT_READ);
        mprotect(page, 4096, PROT_READ | PROT_WRITE);
        end = now_ns();

        printf("Wait on mprotect IPI finished after %.3f ms.\n",
               (end - begin) * (1e3 / 1e9));
        return;
}

static void wait_on_ns_barrier(void)
{
        uint64_t begin = now_ns();
        uint64_t end;
        size_t i;

        for (i = 0;; i++) {
                uint64_t last_interrupt =
                    ck_pr_load_64(&data->last_interrupt_ns);

                if (last_interrupt > begin) {
                        break;
                }

                futex_wait(&data->last_interrupt_ns, last_interrupt);
        }

        end = now_ns();

        printf("Wait on ns finished after %.3f ms and %zu iter.\n",
               (end - begin) * (1e3 / 1e9), i);
        return;
}

static void wait_on_vtime_barrier(void)
{
        uint64_t begin = now_ns();
        uint64_t end;
        uint64_t vtime_begin = ck_pr_load_64(&data->vtime);
        size_t i;
        bool ok;

        for (i = 0;; i++) {
                uint64_t last_interrupt =
                    ck_pr_load_64(&data->last_interrupt_vtime);

                if (last_interrupt > vtime_begin) {
                        break;
                }

                futex_wait(&data->last_interrupt_vtime, last_interrupt);
        }

        ok = ck_pr_load_64(&data->last_interrupt_ns) > begin;
        end = now_ns();

        printf("Wait on vtime finished after %.3f ms and %zu iter (%s).\n",
               (end - begin) * (1e3 / 1e9), i, (ok ? "success" : "FAIL"));
        return;
}

int main(int argc, char **argv)
{
        int fd;

        if (argc < 2) {
                fprintf(stderr, "Usage: %s [barrierd mappable file].\n",
                        argv[0]);
                return 1;
        }

        fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
                perror("open");
                return 1;
        }

        /* We don't care about the per-CPU data */
        data = mmap(NULL, sizeof(*data), PROT_READ, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED) {
                perror("mmap");
                return 1;
        }
        close(fd);

        /* Open a page for mprotect IPIs. */
        page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        assert(page != MAP_FAILED);

        for (;;) {
                usleep(1e5 * random() / RAND_MAX);
                wait_on_mprotect_ipi();
                usleep(1e5 * random() / RAND_MAX);
                wait_on_ns_barrier();
                usleep(1e5 * random() / RAND_MAX);
                wait_on_vtime_barrier();
                usleep(1e5 * random() / RAND_MAX);
                wait_on_membarrier(false);
        }

        return 0;
}
