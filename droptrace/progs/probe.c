#include "common.h"

SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct kfree_skb_args *args)
{
	int reason = args->reason;
	ARGS_INIT();

	if (ARGS_GET(snmp_mode)) {
		do_snmp(reason);
		goto out;
	}

	if (ARGS_CHECK(reason, reason))
		goto out;

	event_t event = { .reason = reason };
	if (probe_parse_skb(args->skb, &event.pkt))
		goto out;

	event.pkt.ts = bpf_ktime_get_ns();
	if (ARGS_ENABLED(limit) && is_limited(event.pkt.ts))
		goto out;

	event.location = (u64)args->location;
	bpf_perf_event_output(args, &m_event, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
out:
	return 0;
}
