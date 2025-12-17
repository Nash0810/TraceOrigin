/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Process Tracker - Detects package manager process execution
 * Hooks: tracepoint/syscalls/sys_enter_execve
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16
#define MAX_ARGV_LEN 256
#define TASK_COMM_LEN 16

/* Event structure sent to userspace */
struct exec_event {
	__u32 pid;
	__u32 ppid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	char argv[MAX_ARGV_LEN];
	__u64 timestamp_ns;
};

/* eBPF Maps */
BPF_PERF_OUTPUT(events);

/* Tracked package managers */
const char package_managers[][16] = {
	"pip", "pip3",
	"npm", "yarn", "pnpm",
	"apt", "apt-get", "apk",
	"gem", "bundle",
	"go", "cargo",
	"mvn", "gradle",
	"composer", "nuget",
	"mix", "hex",
};

/* Check if process is a package manager */
static __always_inline int is_package_manager(char *comm) {
	#pragma unroll
	for (int i = 0; i < sizeof(package_managers) / sizeof(package_managers[0]); i++) {
		if (comm[0] == package_managers[i][0] &&
		    comm[1] == package_managers[i][1]) {
			// Early match on first 2 chars for performance
			return 1;
		}
	}
	return 0;
}

/* Parse command line arguments from userspace memory */
static __always_inline int read_argv(unsigned long argv_ptr, char *buf, size_t sz) {
	const char **argv = (const char **)argv_ptr;
	const char *arg = NULL;
	int i = 0;

	#pragma unroll
	for (int j = 0; j < 3; j++) {  // Read first 3 arguments
		bpf_probe_read_user(&arg, sizeof(arg), (void *)&argv[j]);
		if (!arg)
			break;
		
		int ret = bpf_probe_read_user_str(buf + i, sz - i, (void *)arg);
		if (ret > 0) {
			i += ret - 1;
			if (i < sz - 1) {
				buf[i++] = ' ';
			}
		}
	}

	return i;
}

/* Main hook: sys_enter_execve */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	/* Get process name */
	char comm[COMM_LEN] = {};
	bpf_get_current_comm(&comm, sizeof(comm));

	/* Quick filter: Check if this looks like a package manager */
	if (!is_package_manager(comm)) {
		return 0;
	}

	/* Get parent PID */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return 0;

	__u32 ppid = 0;
	bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);

	/* Get cgroup ID for container isolation */
	__u64 cgroup_id = bpf_get_current_cgroup_id();

	/* Prepare event */
	struct exec_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->ppid = ppid;
	event->cgroup_id = cgroup_id;
	event->timestamp_ns = bpf_ktime_get_ns();
	
	__builtin_memcpy(&event->comm, &comm, sizeof(comm));

	/* Get argv - Read from ctx->args[1] which points to argv array */
	unsigned long argv_ptr = ctx->args[1];
	int argv_len = read_argv(argv_ptr, event->argv, sizeof(event->argv));

	bpf_ringbuf_submit(event, 0);

	return 0;
}
