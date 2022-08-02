#include <kheaders.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <bpf_tracing.h>
#include <skb_utils.h>

#include "shared.h"

bpf_args_t _bpf_args = {
	.current_budget = 1024
};

struct kfree_skb_args {
	u64 pad;
	void *skb;
	void *location;
	unsigned short protocol;
	int reason;
};

static inline void do_snmp(int reason)
{
	if (reason >= SKB_DROP_REASON_MAX || reason < 0)
		return;
	_bpf_args.snmp_reasons[reason]++;
}

static __always_inline bool is_limited(u64 ts)
{
	ARGS_INIT();

	if (_bpf_args.current_budget) {
		_bpf_args.current_budget--;
		return false;
	}

	u64 dela = ((ts - _bpf_args.last_ts) / 1000) * bpf_args->limit / 1000000;
	if (dela) {
		if (dela > bpf_args->limit_bucket)
			dela = bpf_args->limit_bucket;
		_bpf_args.current_budget = dela - 1;
		return false;
	}
	return true;
}

char _license[] SEC("license") = "GPL";
