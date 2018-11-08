#include "parse_stat.h"

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PATH "/proc/stat"

#define MIN_NS_BETWEEN_READS (10 * 1000 * 1000UL)

struct parse_stat *parse_stat_create(size_t ncpu)
{
        struct parse_stat *ret;
        int fd;

        fd = open(PATH, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                perror("Failed to open " PATH);
                return NULL;
        }

        ret = calloc(1, sizeof(*ret) + ncpu * sizeof(ret->per_cpu_stat[0]));
        line_iterator_init(&ret->it, fd);
        ret->ncpu = ncpu;
        return ret;
}

static void update_stat(struct parse_stat *stat, size_t cpu, uint64_t now_ns,
                        uint64_t signature)
{
        struct per_cpu_stat *per_cpu;

        assert(cpu < stat->ncpu);
        per_cpu = &stat->per_cpu_stat[cpu];
        if (signature != per_cpu->signature && per_cpu->signature != 0) {
                per_cpu->last_interrupt_ns = per_cpu->signature_ns;
        }

        per_cpu->signature = signature;
        per_cpu->signature_ns = now_ns;
        return;
}

/* Checks whether the first line in /proc/stat matches the header. */
static bool confirm_header(struct parse_stat *stat)
{
        size_t linesz;
        const char *line = line_iterator_next(&stat->it, &linesz);

        if (line == NULL) {
                return false;
        }

        /* The first line should be "cpu ..." */
        if (linesz < 3) {
                return false;
        }

        if (line[0] != 'c' || line[1] != 'p' || line[2] != 'u') {
                return false;
        }

        return line[3] == ' ' || line[3] == '\0';
}

/* Returns true if we successfully parsed a CPU stat line. */
static bool
parse_stat_line(struct parse_stat *stat, size_t *OUT_cpu, uint64_t *OUT_sum)
{
        size_t linesz;
        const char *line = line_iterator_next(&stat->it, &linesz);
        long cpu;
        uint64_t sum = 0;

        *OUT_cpu = 0;
        *OUT_sum = 0;
        if (line == NULL) {
                return false;
        }

        /* The line should be "cpu$n ..." */
        if (linesz < 3 || line[0] != 'c' || line[1] != 'p' || line[2] != 'u') {
                return false;
        }

        {
                char *endptr;

                cpu = strtol(&line[3], &endptr, 10);
                if (cpu < 0) {
                        fprintf(stderr, "Found negative CPU id %ld\n", cpu);
                        return false;
                }

                line = endptr;
        }

        while (line[0] != '\0') {
                char *endptr;

                sum += strtoll(line, &endptr, 10);
                line = endptr;
                while (line[0] != '\0' && (line[0] < '0' || line[0] > '9')) {
                        line++;
                }
        }

        *OUT_cpu = cpu;
        *OUT_sum = sum;
        return true;
}

void parse_stat_update(struct parse_stat *stat, uint64_t now_ns)
{
        if (stat == NULL || now_ns < stat->last_read ||
            stat->last_read - now_ns < MIN_NS_BETWEEN_READS) {
                return;
        }

        stat->last_read = now_ns;

        line_iterator_reset(&stat->it);
        if (!confirm_header(stat)) {
                fprintf(stderr, "Unexpected header in /proc/stat.\n");
                return;
        }

        {
                size_t cpu;
                uint64_t sum;
                while (parse_stat_line(stat, &cpu, &sum)) {
                        update_stat(stat, cpu, now_ns, sum);
                }
        }
        return;
}
