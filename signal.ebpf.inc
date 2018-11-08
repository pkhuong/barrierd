/*
 * This file defines an eBPF program that records timestamps when each
 * CPU was in kernel mode (not executing code in userspace), and that
 * signals perf events conditionally to wake up a listening daemon. It
 * is provided under a dual BSD/GPLv2 license. When using or
 * redistributing this software, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 * Copyright (c) 2018 Paul Khuong (pvk@pvk.ca).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * BSD License:
 *
 * Copyright (c) 2018 Paul Khuong.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Summary of the bytecode
 * =======================
 *
 * On any event: stores the current timestamp in the CPU's array, and
 * enqueues a perf event if the previous timestamp was less than or
 * equal to trigger_map[0].
 *
 * The event is conditional to let userspace define the set of CPUs it
 * cares about: we only want to be woken up for a CPU the first time
 * its timestamp crosses the previous min quiescent time.
 *
 * This additional complexity in the eBPF program means userspace is
 * free to ask for a wakeup on every event, without risking event
 * storms.
 */

#define BPF_CALL_FN(function)                                           \
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_##function)

/*
 * Result: r0
 * Args: r1, r2, r3, r4, r5
 * Callee-save: r6, r7, r8, r9
 * frame pointer: r10 (read-only).
 *
 * ctxp: context from arg1 into r6
 * nilp: pointer to 0 in r7
 * prev: previous ts in r8
 * curp: pointer to current ts in r9
 */
#define res BPF_REG_0

#define arg1 BPF_REG_1
#define arg2 BPF_REG_2
#define arg3 BPF_REG_3
#define arg4 BPF_REG_4
#define arg5 BPF_REG_5

#define fp BPF_REG_10

#define ctxp BPF_REG_6
#define nilp BPF_REG_7
#define prev BPF_REG_8
#define curp BPF_REG_9

/*
 * # Stash the context
 *    000: mov64 ctxp, arg1
 */
        BPF_MOV64_REG(ctxp, arg1),
/*
 * # Set up the pointer to 0
 *    001: st_dw fp[-8], 0
 *    002: mov64 nilp, fp
 *    003: add64 nilp, -8
 */
	BPF_ST_MEM(BPF_DW, fp, -8, 0),
        BPF_MOV64_REG(nilp, fp),
        BPF_ALU64_IMM(BPF_ADD, nilp, -8),
/*
 * # curp = &bpf_ktime_get_ns
 *    004: call ktime_get_ns
 *    005: st_dw fp[-16], res
 *    006: mov64 curp, fp
 *    007: add64 curp, -16
 */
        BPF_CALL_FN(ktime_get_ns),
        BPF_STX_MEM(BPF_DW, fp, res, -16),
        BPF_MOV64_REG(curp, fp),
        BPF_ALU64_IMM(BPF_ADD, curp, -16),
/*
 * # prev = *bpf_map_lookup_elem(per_cpu_map_fd, nilp)
 *    008: ld_map_fd arg1, $per_cpu_map_fd
 *    010: mov64 arg2, nilp
 *    011: call bpf_map_lookup_elem  # ($per_cpu_map_fd, nilp)
 *    012: jeq res, 0, OUT           # offset: 28 - 12 - 1 = 16
 *    013: ld_dw prev, res
 */
        BPF_LD_MAP_FD(arg1, per_cpu_map_fd),
        BPF_MOV64_REG(arg2, nilp),
        BPF_CALL_FN(map_lookup_elem),
                BPF_JMP_IMM(BPF_JEQ, res, 0, 15),
        BPF_LDX_MEM(BPF_DW, prev, res, 0),
/*
 * # bpf_map_update_elem(per_cpu_map_fd, &nilp, &now, BPF_ANY);
 *    014: ld_map_fd arg1, $per_cpu_map_fd
 *    016: mov64 arg2, nilp
 *    017: mov64 arg3, curp
 *    018: mov64 arg4, BPF_ANY
 *    019: call bpf_map_update_elem
 */
        BPF_LD_MAP_FD(arg1, per_cpu_map_fd),
        BPF_MOV64_REG(arg2, nilp),
        BPF_MOV64_REG(arg3, curp),
        BPF_MOV64_IMM(arg4, BPF_ANY),
        BPF_CALL_FN(map_update_elem),
/*
 * # prev = bpf_map_lookup_elem(trigger_map_fd, &nilp)
 * # if prev <= trigger, signal perf
 *    020: ld_map_fd arg1, $trigger_map_fd
 *    022: mov64 arg2, nilp
 *    023: call bpf_map_lookup_elem  # (trigger_map_fd, nilp)
 *    024: jeq res, 0, OUT           # offset: 4 - 1
 *    025: ld_dw res, res
 *    026: jle prev, res, SIGNAL     # offset: 3 - 1
 *    027: mov64 res, 0
 * OUT
 *    028: exit
 */
        BPF_LD_MAP_FD(arg1, trigger_map_fd),
        BPF_MOV64_REG(arg2, nilp),
        BPF_CALL_FN(map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, res, 0, 3),
        BPF_LDX_MEM(BPF_DW, res, res, 0),
        BPF_JMP_REG(BPF_JLE, prev, res, 2),
        BPF_MOV64_IMM(res, 0),
        BPF_EXIT_INSN(),
/* SIGNAL
 * # bpf_perf_event_output(ctx, perf_map_fd, BPF_F_CURRENT_CPU,
 *                         curp, sizeof(u64))
 *    029: mov64 arg1, ctxp
 *    030: ld_map_fd arg2, $perf_map_fd
 *    032: mov64 arg3, BPF_F_CURRENT_CPU
 *    033: mov64 arg4, curp
 *    034: mov64 arg5, 8
 *    035: call bpf_perf_event_output
 *    036: exit
 */
        BPF_MOV64_REG(arg1, ctxp),
        BPF_LD_MAP_FD(arg2, perf_map_fd),
        BPF_LD_IMM64(arg3, BPF_F_CURRENT_CPU),
        BPF_MOV64_REG(arg4, curp),
        BPF_MOV64_IMM(arg5, sizeof(uint64_t)),
        BPF_CALL_FN(perf_event_output),
        BPF_EXIT_INSN(),

#undef res

#undef arg1
#undef arg2
#undef arg3
#undef arg4
#undef arg5

#undef fp

#undef ctxp
#undef nilp
#undef prev
#undef curp
