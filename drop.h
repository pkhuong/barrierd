#ifndef DROP_H
#define DROP_H
/*
 * Drops privileges via seccomp filters. We need fine-grained syscall
 * filtering instead of simply dropping to a safe users to allow BPF
 * map reads.
 *
 * Logs failure to stderr and returns silently on failure.
 *
 * TODO: consider per-fd permissions on lseek and read?
 * TODO: should we abort unless insecure mode explicitly opted in?
 */
void drop_privileges(void);
#endif /* !DROP_H */
