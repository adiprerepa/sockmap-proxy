#include <stdint.h>

// #include "bpf.h"
// #include "bpf_helpers.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") sock_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 20,
};

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// #ifndef NDEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                                    \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})
// #else
// #define bpf_debug(fmt, ...)                                                    \
// 	{                                                                      \
// 	}                                                                      \
// 	while (0)
// #endif

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{

	uint16_t remote_port_h = bpf_ntohl(skb->remote_port);
	bpf_debug("Remote Port %d, Local Port %d\n", remote_port_h, skb->local_port);
	// bpf_printk("Remote Port %d, Local Port %d\n", remote_port_h, skb->local_port);
	if (skb->local_port == 50000) {
		return bpf_sk_redirect_map(skb, &sock_map, 1, 0);
	} else {
		return bpf_sk_redirect_map(skb, &sock_map, 0, 0);
	}
}
