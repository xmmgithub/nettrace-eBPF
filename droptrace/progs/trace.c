#include "common.h"

SEC("tp_btf/kfree_skb")
int BPF_PROG(trace_kfree_skb, struct sk_buff *skb, void *location,
	     int reason)
{
	ARGS_INIT();

	if (ARGS_GET(snmp_mode)) {
		do_snmp(reason);
		goto out;
	}

	if (ARGS_CHECK(reason, reason))
		goto out;

	event_t event = { .reason = reason };
	if (probe_parse_skb(skb, &event.pkt))
		goto out;

	event.pkt.ts = bpf_ktime_get_ns();
	if (ARGS_ENABLED(limit) && is_limited(event.pkt.ts))
		goto out;

	event.location = (u64)location;
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
out:
	return 0;
}
