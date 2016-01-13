/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 * Copyright (C) 2016      Zenedge Inc <www.zenedge.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module which implements the set match for netfilter/iptables. */

#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter/x_tables.h>
#include <linux/inet.h>
#include <net/ip.h>

#include "xt_zenset.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lourival Vieira Neto <lourival@zenedge.com>");
MODULE_DESCRIPTION("Zenedge: IP set match module");

#define tcp_datalen(skb)	\
	(ntohs(ip_hdr(skb)->tot_len) - (ip_hdrlen(skb) + tcp_hdrlen(skb)))

struct sk_buff *
proxy_skb(const struct sk_buff *skb, const struct xt_action_param *par)
{
	const char preamble[] = "PROXY TCP4 ";
	size_t preamble_len = sizeof(preamble) - 1;
	unsigned int max_addr = sizeof("255.255.255.255");
	struct sk_buff *skbp = NULL;
	unsigned char *data = NULL;
	struct iphdr *iph = ip_hdr(skb);

	if ((iph->protocol != IPPROTO_TCP) ||
	    (tcp_datalen(skb) < preamble_len + max_addr))
		return NULL;

	data = skb_transport_header(skb) + tcp_hdrlen(skb);
	if(strncmp(data, preamble, preamble_len) != 0)
		return NULL;

	skbp = pskb_copy((struct sk_buff *) skb, GFP_ATOMIC);
	if (!skbp)
		return NULL;

	data += preamble_len;
	if (!in4_pton(data, max_addr, (u8 *) &ip_hdr(skbp)->saddr, ' ', NULL)) {
		kfree_skb(skbp);
		return NULL;
	}

	return skbp;
}

static inline int
match_set(ip_set_id_t index, const struct sk_buff *skb,
	  const struct xt_action_param *par,
	  struct ip_set_adt_opt *opt, int inv)
{
	if (ip_set_test(index, skb, par, opt))
		inv = !inv;

	return inv;
}

#define ADT_OPT(n, f, d, fs, cfs, t)	\
struct ip_set_adt_opt n = {		\
	.family	= f,			\
	.dim = d,			\
	.flags = fs,			\
	.cmdflags = cfs,		\
	.ext.timeout = t,		\
}

static int
zenset_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_zenset_info_match *info = par->matchinfo;
	ip_set_id_t index;

	index = ip_set_nfnl_get_byindex((par)->net, info->match_set.index);

	if (index == IPSET_INVALID_ID) {
		pr_warn("Cannot find set identified by id %u to match\n",
			info->match_set.index);
		return -ENOENT;
	}
	if (info->match_set.dim > IPSET_DIM_MAX) {
		pr_warn("Protocol error: set match dimension is over the limit!\n");
		ip_set_nfnl_put((par)->net, info->match_set.index);
		return -ERANGE;
	}

	return 0;
}

static void
zenset_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_zenset_info_match *info = par->matchinfo;

	ip_set_nfnl_put((par)->net, info->match_set.index);
}

static bool
match_counter(u64 counter, const struct ip_set_counter_match *info)
{
	switch (info->op) {
	case IPSET_COUNTER_NONE:
		return true;
	case IPSET_COUNTER_EQ:
		return counter == info->value;
	case IPSET_COUNTER_NE:
		return counter != info->value;
	case IPSET_COUNTER_LT:
		return counter < info->value;
	case IPSET_COUNTER_GT:
		return counter > info->value;
	}
	return false;
}

static bool
zenset_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_zenset_info_match *info = par->matchinfo;

	ADT_OPT(opt, par->family, info->match_set.dim,
		info->match_set.flags, info->flags, UINT_MAX);
	int ret;
	struct sk_buff *skbp = (info->match_set.flags & ZENSET_PROXY_PROTOCOL) ?
		proxy_skb(skb, par) : NULL;

	if (info->packets.op != IPSET_COUNTER_NONE ||
	    info->bytes.op != IPSET_COUNTER_NONE)
		opt.cmdflags |= IPSET_FLAG_MATCH_COUNTERS;

	ret = match_set(info->match_set.index, skbp ? skbp : skb, par, &opt,
			info->match_set.flags & IPSET_INV_MATCH);
	if (skbp)
		kfree_skb(skbp);

	if (!(ret && opt.cmdflags & IPSET_FLAG_MATCH_COUNTERS))
		return ret;

	if (!match_counter(opt.ext.packets, &info->packets))
		return false;
	return match_counter(opt.ext.bytes, &info->bytes);
}

static struct xt_match zenset_mt_reg __read_mostly = {
	.name		= "zenset",
	.revision       = 0,
	.family		= NFPROTO_IPV4,
	.match		= zenset_match,
	.matchsize	= sizeof(struct xt_zenset_info_match),
	.checkentry	= zenset_checkentry,
	.destroy	= zenset_destroy,
	.me		= THIS_MODULE
};

static int __init xt_zenset_init(void)
{
	return xt_register_match(&zenset_mt_reg);
}

static void __exit xt_zenset_fini(void)
{
	xt_unregister_match(&zenset_mt_reg);
}

module_init(xt_zenset_init);
module_exit(xt_zenset_fini);
