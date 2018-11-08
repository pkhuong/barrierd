#ifndef MAP_H
#define MAP_H
#include <barrierd.h>

#include "ebpf_state.h"

/*
 * Ensures the data file at path exists, acquires the lock file at
 * path.lock, and ensures the data file is large enough for the number
 * of cpus in state.
 *
 * Returns a writable mmap buffer for the data file.  Dies on error.
 */
struct barrierd_mapped_data *
map_file(const char *path, const struct ebpf_state *state);
#endif /* !MAP_H */
