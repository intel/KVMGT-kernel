/*
 * vGT ftrace header
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of Version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(_VGT_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _VGT_TRACE_H_

#include <linux/types.h>
#include <linux/stringify.h>
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM vgt
#define TRACE_SYSTEM_STRING __stringify(TRACE_SYSTEM)

TRACE_EVENT(vgt_mmio_rw,
		TP_PROTO(bool write, u32 vm_id, u32 offset, void *pd,
			int bytes),

		TP_ARGS(write, vm_id, offset, pd, bytes),

		TP_STRUCT__entry(
			__field(bool, write)
			__field(u32, vm_id)
			__field(u32, offset)
			__field(int, bytes)
			__field(u64, value)
			),

		TP_fast_assign(
			__entry->write = write;
			__entry->vm_id = vm_id;
			__entry->offset = offset;
			__entry->bytes = bytes;

			memset(&__entry->value, 0, sizeof(u64));
			memcpy(&__entry->value, pd, bytes);
		),

		TP_printk("VM%u %s offset 0x%x data 0x%llx byte %d\n",
				__entry->vm_id,
				__entry->write ? "write" : "read",
				__entry->offset,
				__entry->value,
				__entry->bytes)
);

#define MAX_CMD_STR_LEN	200
TRACE_EVENT(vgt_command,
		TP_PROTO(u8 vm_id, u8 ring_id, u32 ip_gma, u32 *cmd_va, u32 cmd_len, bool ring_buffer_cmd),

		TP_ARGS(vm_id, ring_id, ip_gma, cmd_va, cmd_len, ring_buffer_cmd),

		TP_STRUCT__entry(
			__field(u8, vm_id)
			__field(u8, ring_id)
			__field(int, i)
			__array(char,tmp_buf, MAX_CMD_STR_LEN)
			__array(char, cmd_str, MAX_CMD_STR_LEN)
			),

		TP_fast_assign(
			__entry->vm_id = vm_id;
			__entry->ring_id = ring_id;
			__entry->cmd_str[0] = '\0';
			snprintf(__entry->tmp_buf, MAX_CMD_STR_LEN, "VM(%d) Ring(%d): %s ip(%08x) ", vm_id, ring_id, ring_buffer_cmd ? "RB":"BB", ip_gma);
			strcat(__entry->cmd_str, __entry->tmp_buf);
			entry->i = 0;
			while (cmd_len > 0) {
				if (cmd_len >= 8) {
					snprintf(__entry->tmp_buf, MAX_CMD_STR_LEN, "%08x %08x %08x %08x %08x %08x %08x %08x ",
						cmd_va[__entry->i], cmd_va[__entry->i+1], cmd_va[__entry->i+2], cmd_va[__entry->i+3],
						cmd_va[__entry->i+4],cmd_va[__entry->i+5],cmd_va[__entry->i+6],cmd_va[__entry->i+7]);
					__entry->i += 8;
					cmd_len -= 8;
					strcat(__entry->cmd_str, __entry->tmp_buf);
				} else if (cmd_len >= 4) {
					snprintf(__entry->tmp_buf, MAX_CMD_STR_LEN, "%08x %08x %08x %08x ",
						cmd_va[__entry->i], cmd_va[__entry->i+1], cmd_va[__entry->i+2], cmd_va[__entry->i+3]);
					__entry->i += 4;
					cmd_len -= 4;
					strcat(__entry->cmd_str, __entry->tmp_buf);
				} else if (cmd_len >= 2) {
					snprintf(__entry->tmp_buf, MAX_CMD_STR_LEN, "%08x %08x ", cmd_va[__entry->i], cmd_va[__entry->i+1]);
					__entry->i += 2;
					cmd_len -= 2;
					strcat(__entry->cmd_str, __entry->tmp_buf);
				} else if (cmd_len == 1) {
					snprintf(__entry->tmp_buf, MAX_CMD_STR_LEN, "%08x ", cmd_va[__entry->i]);
					__entry->i += 1;
					cmd_len -= 1;
					strcat(__entry->cmd_str, __entry->tmp_buf);
				}
			}
			strcat(__entry->cmd_str, "\n");
		),

		TP_printk("%s", __entry->cmd_str)
);

#endif /* _VGT_TRACE_H_ */

/* This part must be out of protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
