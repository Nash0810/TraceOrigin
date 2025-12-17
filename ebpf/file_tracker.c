/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* File and Log Tracker - Traces file operations and captures stdout/stderr logs
 * Hooks: tracepoint/syscalls/sys_enter_openat, tracepoint/syscalls/sys_enter_write
 * Strategy: Log-based correlation (capture package manager output from fd=1/2)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16
#define MAX_PATH_LEN 256
#define LOG_BUF_SIZE 256

/* File event */
struct file_event {
	__u32 pid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	char path[MAX_PATH_LEN];
	__u32 flags;
	__u64 timestamp_ns;
	__u32 event_type;  /* 0 = file open, 1 = file write */
};

/* Log event - stdout/stderr capture */
struct log_event {
	__u32 pid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	__u32 fd;              /* File descriptor (1=stdout, 2=stderr) */
	char log_data[LOG_BUF_SIZE];
	__u32 log_size;
	__u64 timestamp_ns;
};

/* eBPF Maps */
BPF_PERF_OUTPUT(events);

/* Map to track active package manager PIDs */
BPF_HASH(tracked_pids, __u32, __u64);

/* Map to buffer log lines per PID (for reassembly of split writes) */
BPF_HASH(log_buffers, __u32, char[512]);

/* Hook: sys_enter_openat - Trace file creation */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	/* Check if this PID is tracked */
	__u64 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	if (!tracked) {
		return 0;
	}

	struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = 0;  /* File open */
	event->flags = ((__u32)ctx->args[2]);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	/* Get filename from second argument */
	char *filename_ptr = (char *)ctx->args[1];
	bpf_probe_read_user_str(&event->path, sizeof(event->path), filename_ptr);

	/* Only track if O_CREAT flag is set (0x40 on x86) */
	if (event->flags & 0x40) {
		bpf_ringbuf_submit(event, 0);
	} else {
		bpf_ringbuf_discard(event, 0);
	}

	return 0;
}

/* Hook: sys_enter_write - Capture stdout/stderr for log parsing */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	/* Check if this PID is tracked */
	__u64 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	if (!tracked) {
		return 0;
	}

	/* Only capture stdout (fd=1) and stderr (fd=2) */
	__u32 fd = (__u32)ctx->args[0];
	if (fd != 1 && fd != 2) {
		return 0;
	}

	__u32 count = (__u32)ctx->args[2];
	if (count == 0 || count > LOG_BUF_SIZE)
		return 0;

	struct log_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->fd = fd;
	event->log_size = count < LOG_BUF_SIZE ? count : LOG_BUF_SIZE;
	event->timestamp_ns = bpf_ktime_get_ns();

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	/* Read log data from userspace */
	void *buf_ptr = (void *)ctx->args[1];
	bpf_probe_read_user(event->log_data, event->log_size, buf_ptr);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

/* Hook: sched_process_exec - Track package managers */
SEC("tp/sched/sched_process_exec")
int track_package_manager(struct trace_event_raw_sched_process_exec *ctx) {
	__u32 pid = ctx->pid;

	/* Check if this is a package manager process */
	char comm[COMM_LEN] = {};
	__builtin_memcpy(&comm, &ctx->comm, sizeof(comm));

	/* Quick package manager check */
	if ((comm[0] == 'p' && comm[1] == 'i') ||   /* pip, pip3 */
	    (comm[0] == 'n' && comm[1] == 'p') ||   /* npm, pnpm */
	    (comm[0] == 'a' && comm[1] == 'p') ||   /* apt, apk */
	    (comm[0] == 'y' && comm[1] == 'a') ||   /* yarn */
	    (comm[0] == 'g' && comm[1] == 'o') ||   /* go */
	    (comm[0] == 'c' && comm[1] == 'a') ||   /* cargo */
	    (comm[0] == 'm' && comm[1] == 'v') ||   /* mvn */
	    (comm[0] == 'g' && comm[1] == 'r') ||   /* gradle */
	    (comm[0] == 'g' && comm[1] == 'e') ||   /* gem */
	    (comm[0] == 'b' && comm[1] == 'u')) {   /* bundle */

		/* Track this PID */
		__u64 tracking_time = bpf_ktime_get_ns();
		bpf_map_update_elem(&tracked_pids, &pid, &tracking_time, BPF_ANY);
	}

	return 0;
}

/* Hook: sched_process_exit - Cleanup when process exits */
SEC("tp/sched/sched_process_template")
int cleanup_on_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u32 pid = ctx->pid;

	/* Remove from tracking */
	bpf_map_delete_elem(&tracked_pids, &pid);

	/* Cleanup log buffer */
	bpf_map_delete_elem(&log_buffers, &pid);

	return 0;
}
