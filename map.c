#include "map.h"

#include <assert.h>
#include <ck_pr.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Builds a lock file for path and acquires it for exclusive access.
 *
 * We do not use the path itself because we want other processes to
 * have access to that file (it will be mmapped by applications), and
 * any process with read access could lock the file exclusively.
 */
static void lock_file(const char *path)
{
        char *lock_file = NULL;
        int fd;
        int r;

        r = asprintf(&lock_file, "%s.lock", path);
        if (r < 0) {
                perror("asprintf failed");
                exit(1);
        }

        fd = open(lock_file, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) {
                perror("open(lock_file) failed");
                exit(1);
        }

        fprintf(stderr, "Acquiring exclusive lock on %s.\n", lock_file);
        r = flock(fd, LOCK_EX);
        if (r < 0) {
                perror("flock(LOCK_EX) failed");
                exit(1);
        }

        /* Leak the lock file's fd to keep the lock until shutdown. */
        free(lock_file);
        return;
}

/*
 * Ensures the file behind fd has size at least desired_size (+ rounding).
 *
 * Must be called with the corresponding lock file held.
 */
static void ensure_fd_size(int fd, size_t desired_size)
{
        struct stat sb;
        int r;

        r = fstat(fd, &sb);
        if (r < 0) {
                perror("fstat failed");
                exit(1);
        }

        /* Round up to 4096 bytes. */
        desired_size = (desired_size + 4095) & ~4095ULL;
        if (sb.st_size >= 0 && (size_t)sb.st_size >= desired_size) {
                return;
        }

        assert((off_t)desired_size > 0);
        r = ftruncate(fd, (off_t)desired_size);
        if (r < 0) {
                perror("ftruncate failed");
                exit(1);
        }

        return;
}

/*
 * mmaps the data fd, after making sure the backing file is large
 * enough for the number of CPUs in state.
 */
static struct barrierd_mapped_data *
map_data_fd(int data_fd, const struct ebpf_state *state)
{
        struct barrierd_mapped_data *ret;
        const size_t total_size = sizeof(struct barrierd_mapped_data) +
                                  state->ncpu * sizeof(struct barrierd_per_cpu);

        ensure_fd_size(data_fd, total_size);
        ret = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_LOCKED | MAP_POPULATE, data_fd, 0);
        if (ret == MAP_FAILED) {
                perror("mmap(data_fd) failed");
                exit(1);
        }

        if (mlock(ret, total_size) != 0) {
                perror("ignoring failed mlock");
        }

        return ret;
}

struct barrierd_mapped_data *
map_file(const char *path, const struct ebpf_state *state)
{
        struct barrierd_mapped_data *ret;
        int data_fd;

        data_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (data_fd < 0) {
                perror("open(data_path) failed");
                exit(1);
        }

        lock_file(path);
        ret = map_data_fd(data_fd, state);
        close(data_fd);

        ck_pr_store_64(&ret->ncpu, state->ncpu);
        return ret;
}
