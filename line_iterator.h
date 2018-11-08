#ifndef FOR_LINES_H
#define FOR_LINES_H
/*
 * A line iterator provides buffered line input over a raw file
 * descriptor.  The buffering is fixed and preallocated in buf.  Any
 * line that spans more than 4K will be treated as EOF instead of
 * extending the buffer.
 */
#include <stdbool.h>
#include <stddef.h>

struct line_iterator {
        size_t consumed;
        size_t remaining;
        int fd;
        bool eof;
        char padding[64 - sizeof(int) - 2 * sizeof(size_t)];
        char buf[4096 * 3];
};

/*
 * Initialises the iterator with fd.
 */
void line_iterator_init(struct line_iterator *it, int fd);

/*
 * Rewinds the iterator to the beginning of the file.
 */
void line_iterator_reset(struct line_iterator *it);

/*
 * Returns a pointer to the next line, and outputs the number of
 * characters in that line to *OUT_size.  Returns NULL on EOF.
 *
 * Advance the iterator to the next line.
 *
 * Treats any line that spans more than 4K as EOF.
 */
const char *line_iterator_next(struct line_iterator *it, size_t *OUT_size);
#endif /* !FOR_LINES_H */
