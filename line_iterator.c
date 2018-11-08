#include "line_iterator.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define MIN_READ_SIZE 4096

void line_iterator_init(struct line_iterator *it, int fd)
{
        memset(it, 0, sizeof(*it));

        assert(fd >= 0);
        it->fd = fd;
        it->eof = false;
        return;
}

void line_iterator_reset(struct line_iterator *it)
{
        off_t r;
        int fd = it->fd;

        r = lseek(fd, 0, SEEK_SET);
        assert(r >= 0);

        line_iterator_init(it, fd);
        return;
}

/* Find the next complete line in buffer, or NULL if none. */
static const char *extract_line(struct line_iterator *it, size_t *OUT_size)
{
        const char *ret;

        for (size_t i = 0; it->consumed + i < it->remaining; i++) {
                if (it->buf[it->consumed + i] != '\n') {
                        continue;
                }

                ret = &it->buf[it->consumed];
                it->buf[it->consumed + i] = '\0';
                *OUT_size = i + 1;
                it->consumed += i + 1;
                return ret;
        }

        *OUT_size = 0;
        return NULL;
}

/*
 * If there's at least MIN_READ_SIZE empty space left in the buffer,
 * try to refill it from the fd.
 */
static void refill(struct line_iterator *it)
{
        size_t buffered = it->remaining - it->consumed;
        ssize_t r;

        assert(it->consumed <= it->remaining);
        if (it->eof) {
                return;
        }

        if (sizeof(it->buf) - (it->remaining - it->consumed) < MIN_READ_SIZE) {
                return;
        }

        memmove(it->buf, &it->buf[it->consumed], buffered);
        it->consumed = 0;
        it->remaining = buffered;

        for (;;) {
                r = read(it->fd, &it->buf[it->remaining],
                         sizeof(it->buf) - it->remaining);
                if (r == 0) {
                        it->eof = true;
                        return;
                }

                if (r > 0) {
                        it->remaining += (size_t)r;
                        return;
                }

                if (errno == EINTR) {
                        continue;
                }

                perror("read failed");
                exit(1);
        }

        return;
}

const char *line_iterator_next(struct line_iterator *it, size_t *OUT_size)
{
        const char *ret;

        ret = extract_line(it, OUT_size);
        if (ret != NULL) {
                return ret;
        }

        refill(it);
        ret = extract_line(it, OUT_size);
        if (ret != NULL) {
                return ret;
        }

        /*
         * Failed to find a complete line after refill. This is either
         * eof, or a very long line, and that's equivalent to EOF.
         */
        it->eof = true;
        *OUT_size = 0;
        return NULL;
}
