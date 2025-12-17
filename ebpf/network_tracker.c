/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Network Tracker - Traces TCP connections made by package managers
 * Hooks: kprobe/tcp_v4_connect (start) and kprobe/tcp_close (end)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define COMM_LEN 16

/* Network connection event */
struct net_event {
	__u32 pid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	__u32 saddr;            /* Source IP (network byte order) */
	__u32 daddr;            /* Destination IP */
	__u16 dport;            /* Destination port */
	__u16 sport;            /* Source port */
	__u64 timestamp_ns;
	__u32 event_type;       /* 0 = connect start, 1 = connect end */
};

/* eBPF Maps */
BPF_PERF_OUTPUT(events);

/* Map to track active package manager PIDs */
BPF_HASH(tracked_pids, __u32, __u64);

/* Helper: IP address to string format (for debugging) */
static __always_inline char *ip_to_str(__u32 ip) {
	/* Stored in network byte order (big-endian) */
	return (char *)(unsigned long)ip;
}

/* Hook: tcp_v4_connect - Called when TCP connection starts */
SEC("kprobe/tcp_v4_connect")
int trace_tcp_v4_connect(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	/* Check if this PID is tracked (is it a package manager?) */
	__u64 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	if (!tracked) {
		return 0;
	}

	/* Get socket from first parameter */
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	/* Prepare event */
	struct net_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = 0;  /* Connection start */

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	/* Extract connection details using BPF CO-RE */
	bpf_probe_read_kernel(&event->daddr, sizeof(__u32),
			      &sk->__sk_common.skc_daddr);
	bpf_probe_read_kernel(&event->dport, sizeof(__u16),
			      &sk->__sk_common.skc_dport);
	bpf_probe_read_kernel(&event->saddr, sizeof(__u32),
			      &sk->__sk_common.skc_rcv_saddr);
	bpf_probe_read_kernel(&event->sport, sizeof(__u16),
			      &sk->__sk_common.skc_sport);

	/* Convert port from network byte order to host byte order */
	event->dport = bpf_ntohs(event->dport);
	event->sport = bpf_ntohs(event->sport);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

/* Hook: tcp_cleanup_ulp - Called when TCP connection closes */
SEC("kprobe/tcp_cleanup_ulp")
int trace_tcp_close(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	/* Check if this PID is tracked */
	__u64 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	if (!tracked) {
		return 0;
	}

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	/* Prepare close event */
	struct net_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = 1;  /* Connection end */

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_probe_read_kernel(&event->daddr, sizeof(__u32),
			      &sk->__sk_common.skc_daddr);
	bpf_probe_read_kernel(&event->dport, sizeof(__u16),
			      &sk->__sk_common.skc_dport);

	event->dport = bpf_ntohs(event->dport);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

/* Hook: sched_process_exec - Record package manager start for tracking */
SEC("tp/sched/sched_process_exec")
int trace_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
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
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
	__u32 pid = ctx->pid;

	/* Remove from tracking */
	bpf_map_delete_elem(&tracked_pids, &pid);

	return 0;
}
