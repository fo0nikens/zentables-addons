#ifndef _XT_ZENSET_H
#define _XT_ZENSET_H

#include <linux/types.h>
#include <linux/netfilter/ipset/ip_set.h>

#define ZENSET_PROXY_PROTOCOL	(IPSET_INV_MATCH << 1)

struct xt_zenset_info {
	ip_set_id_t index;
	__u8 dim;
	__u8 flags;
};

struct xt_zenset_info_match {
	struct xt_zenset_info match_set;
	struct ip_set_counter_match packets;
	struct ip_set_counter_match bytes;
	__u32 flags;
};

#endif /*_XT_ZENSET_H*/
