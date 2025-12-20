/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* HTTP Parser - Captures HTTP requests to extract URLs
 * Hooks: kprobe/tcp_sendmsg for HTTP/1.1 requests
 * Note: HTTPS traffic is encrypted; for MVP we capture from logs and heuristics
 */

/* Target architecture for kprobes - MUST come before includes */
#define __TARGET_ARCH_x86 1

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define HTTP_BUF_SIZE 256
#define COMM_LEN 16

/* HTTP/URL event */
struct http_event {
	__u32 pid;
	__u64 cgroup_id;
	char comm[COMM_LEN];
	char url[HTTP_BUF_SIZE];
	char host[128];
	__u64 timestamp_ns;
	__u32 method;  /* 0=GET, 1=POST, 2=PUT, 3=DELETE, 4=OTHER */
};

/* eBPF Maps */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 512);
} tracked_pids SEC(".maps");

/* HTTP method detection */
static __always_inline __u32 detect_http_method(char *buf) {
	if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T')
		return 0;  // GET
	if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S')
		return 1;  // POST
	if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T')
		return 2;  // PUT
	if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L')
		return 3;  // DELETE
	return 4;  // OTHER
}

/* Hook: tcp_sendto - Capture HTTP requests */
SEC("kprobe/tcp_sendmsg")
int trace_http_send(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	/* Check if this PID is tracked */
	__u64 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
	if (!tracked) {
		return 0;
	}

	/* Get socket buffer */
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk)
		return 0;

	/* Get message data */
	char *buf = (char *)PT_REGS_PARM2(ctx);
	size_t len = (size_t)PT_REGS_PARM3(ctx);

	if (len == 0 || len > HTTP_BUF_SIZE)
		return 0;

	/* Read buffer from kernel space */
	char temp_buf[HTTP_BUF_SIZE] = {};
	bpf_probe_read_kernel(temp_buf, len > HTTP_BUF_SIZE ? HTTP_BUF_SIZE : len, buf);

	/* Check if this looks like an HTTP request (starts with GET, POST, etc) */
	__u32 method = detect_http_method(temp_buf);
	if (method > 4) {
		return 0;  // Not an HTTP request
	}

	struct http_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->pid = pid;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->timestamp_ns = bpf_ktime_get_ns();
	event->method = method;

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	/* Extract URL - format: "GET /path HTTP/1.1" */
	int url_start = 0;
	int url_end = 0;
	int in_url = 0;

	#pragma unroll
	for (int i = 0; i < HTTP_BUF_SIZE && i < len; i++) {
		if (!in_url && temp_buf[i] == ' ') {
			in_url = 1;
			url_start = i + 1;
			continue;
		}
		if (in_url && temp_buf[i] == ' ') {
			url_end = i;
			break;
		}
	}

	if (in_url && url_end > url_start) {
		int url_len = url_end - url_start;
		if (url_len > HTTP_BUF_SIZE)
			url_len = HTTP_BUF_SIZE;

		/* Manual copy instead of __builtin_memcpy */
		#pragma unroll
		for (int j = 0; j < HTTP_BUF_SIZE; j++) {
			if (j >= url_len)
				break;
			event->url[j] = temp_buf[url_start + j];
		}
	}

	/* Extract Host header (simplified - looks for "Host: " pattern) */
	/* Manual host search since bpf_strstr is not available */
	#pragma unroll
	for (int i = 0; i < len - 6 && i < HTTP_BUF_SIZE - 6; i++) {
		if (temp_buf[i] == 'H' && temp_buf[i+1] == 'o' && 
		    temp_buf[i+2] == 's' && temp_buf[i+3] == 't' &&
		    temp_buf[i+4] == ':' && temp_buf[i+5] == ' ') {
			int offset = i + 6;
			int j = 0;
			while (j < 127 && offset + j < len && temp_buf[offset + j] != '\r') {
				event->host[j] = temp_buf[offset + j];
				j++;
			}
			break;
		}
	}

	bpf_ringbuf_submit(event, 0);

	return 0;
}

/* Hook: sys_enter_execve - Track package managers for HTTP */
SEC("tracepoint/syscalls/sys_enter_execve")
int track_pm_http(struct trace_event_raw_sys_enter *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	char comm[COMM_LEN] = {};
	bpf_get_current_comm(&comm, sizeof(comm));

	/* Check if package manager */
	if ((comm[0] == 'p' && comm[1] == 'i') ||   /* pip, pip3 */
	    (comm[0] == 'n' && comm[1] == 'p') ||   /* npm, pnpm */
	    (comm[0] == 'a' && comm[1] == 'p') ||   /* apt, apk */
	    (comm[0] == 'y' && comm[1] == 'a') ||   /* yarn */
	    (comm[0] == 'c' && comm[1] == 'u')) {   /* curl, composer */

		__u64 tracking_time = bpf_ktime_get_ns();
		bpf_map_update_elem(&tracked_pids, &pid, &tracking_time, BPF_ANY);
	}

	return 0;
}

/* Hook: sched_process_exit - Cleanup on exit */
SEC("tp/sched/sched_process_template")
int cleanup_http_tracking(struct trace_event_raw_sched_process_template *ctx) {
	__u32 pid = ctx->pid;
	bpf_map_delete_elem(&tracked_pids, &pid);
	return 0;
}
