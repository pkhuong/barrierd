#ifndef ATTACH_H
#define ATTACH_H
#include "ebpf_state.h"

/*
 * Attaches our ebpf signal program to tracepoint #id.
 *
 * Aborts the process on failure.
 *
 * TODO: try raw tracepoints.
 */
void attach_to_tracepoint_id(const struct ebpf_state *state, int id);
#endif /* !ATTACH_H */
