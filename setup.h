#ifndef SETUP_H
#define SETUP_H
#include "ebpf_state.h"

/*
 * Populates `state` with live file descriptors. Some data will be
 * leaked: we expect only one ebpf_state per process.
 *
 * Aborts the process on failure.
 */
void setup(struct ebpf_state *state);
#endif /* !SETUP_H */
