/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 * Copyright (C) 2016      Zenedge Inc <www.zenedge.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Shared library add-on to iptables to add IP set matching. */
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>

#include <xtables.h>

#include "xt_zenset.h"
#include "libxt_zenset.h"

static void
zenset_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			"You must specify `--match-set' with proper arguments");
}

static void
print_match(const char *prefix, const struct xt_zenset_info *info)
{
	int i;
	char setname[IPSET_MAXNAMELEN];

	get_set_byid(setname, info->index);
	printf("%s %s %s",
	       (info->flags & IPSET_INV_MATCH) ? " !" : "",
	       prefix,
	       setname);
	for (i = 1; i <= info->dim; i++) {
		printf("%s%s",
		       i == 1 ? " " : ",",
		       info->flags & (1 << i) ? "src" : "dst");
	}
}

static void
zenset_help(void)
{
	printf("set match options:\n"
	       " [!] --match-set name flags [--return-nomatch]\n"
	       "   [! --update-counters] [! --update-subcounters] [--proxy-protocol]\n"
	       "   [[!] --packets-eq value | --packets-lt value | --packets-gt value\n"
	       "   [[!] --bytes-eq value | --bytes-lt value | --bytes-gt value\n"
	       "		 'name' is the set name from to match,\n"
	       "		 'flags' are the comma separated list of\n"
	       "		 'src' and 'dst' specifications.\n");
}

static const struct option zenset_opts[] = {
	{.name = "match-set",		.has_arg = true,	.val = '1'},
	{.name = "set",			.has_arg = true,	.val = '2'},
	{.name = "return-nomatch",	.has_arg = false,	.val = '3'},
	{.name = "update-counters",	.has_arg = false,	.val = '4'},
	{.name = "packets-eq",		.has_arg = true,	.val = '5'},
	{.name = "packets-lt",		.has_arg = true,	.val = '6'},
	{.name = "packets-gt",		.has_arg = true,	.val = '7'},
	{.name = "bytes-eq",		.has_arg = true,	.val = '8'},
	{.name = "bytes-lt",		.has_arg = true,	.val = '9'},
	{.name = "bytes-gt",		.has_arg = true,	.val = '0'},
	{.name = "update-subcounters",	.has_arg = false,	.val = 'a'},
	{.name = "proxy-protocol",	.has_arg = false,	.val = 'b'},
	XT_GETOPT_TABLEEND,
};

static uint64_t
parse_counter(const char *opt)
{
	uintmax_t value;

	if (!xtables_strtoul(opt, NULL, &value, 0, UINT64_MAX))
		xtables_error(PARAMETER_PROBLEM,
			      "Cannot parse %s as a counter value\n",
			      opt);
	return (uint64_t)value;
}

static int
zenset_parse(int c, char **argv, int invert, unsigned int *flags,
	     const void *entry, struct xt_entry_match **match)
{
	struct xt_zenset_info_match *info =
		(struct xt_zenset_info_match *) (*match)->data;

	switch (c) {
	case 'b':
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "--proxy-protocol flag cannot be inverted\n");
		info->match_set.flags |= ZENSET_PROXY_PROTOCOL;
		break;
	case 'a':
		if (invert)
			info->flags |= IPSET_FLAG_SKIP_SUBCOUNTER_UPDATE;
		break;
	case '0':
		if (info->bytes.op != IPSET_COUNTER_NONE)
			xtables_error(PARAMETER_PROBLEM,
				      "only one of the --bytes-[eq|lt|gt]"
				      " is allowed\n");
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "--bytes-gt option cannot be inverted\n");
		info->bytes.op = IPSET_COUNTER_GT;
		info->bytes.value = parse_counter(optarg);
		break;
	case '9':
		if (info->bytes.op != IPSET_COUNTER_NONE)
			xtables_error(PARAMETER_PROBLEM,
				      "only one of the --bytes-[eq|lt|gt]"
				      " is allowed\n");
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "--bytes-lt option cannot be inverted\n");
		info->bytes.op = IPSET_COUNTER_LT;
		info->bytes.value = parse_counter(optarg);
		break;
	case '8':
		if (info->bytes.op != IPSET_COUNTER_NONE)
			xtables_error(PARAMETER_PROBLEM,
				      "only one of the --bytes-[eq|lt|gt]"
				      " is allowed\n");
		info->bytes.op = invert ? IPSET_COUNTER_NE : IPSET_COUNTER_EQ;
		info->bytes.value = parse_counter(optarg);
		break;
	case '7':
		if (info->packets.op != IPSET_COUNTER_NONE)
			xtables_error(PARAMETER_PROBLEM,
				      "only one of the --packets-[eq|lt|gt]"
				      " is allowed\n");
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "--packets-gt option cannot be inverted\n");
		info->packets.op = IPSET_COUNTER_GT;
		info->packets.value = parse_counter(optarg);
		break;
	case '6':
		if (info->packets.op != IPSET_COUNTER_NONE)
			xtables_error(PARAMETER_PROBLEM,
				      "only one of the --packets-[eq|lt|gt]"
				      " is allowed\n");
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "--packets-lt option cannot be inverted\n");
		info->packets.op = IPSET_COUNTER_LT;
		info->packets.value = parse_counter(optarg);
		break;
	case '5':
		if (info->packets.op != IPSET_COUNTER_NONE)
			xtables_error(PARAMETER_PROBLEM,
				      "only one of the --packets-[eq|lt|gt]"
				      " is allowed\n");
		info->packets.op = invert ? IPSET_COUNTER_NE : IPSET_COUNTER_EQ;
		info->packets.value = parse_counter(optarg);
		break;
	case '4':
		if (invert)
			info->flags |= IPSET_FLAG_SKIP_COUNTER_UPDATE;
		break;
	case '3':
		if (invert)
			xtables_error(PARAMETER_PROBLEM,
				      "--return-nomatch flag cannot be inverted\n");
		info->flags |= IPSET_FLAG_RETURN_NOMATCH;
		break;
	case '2':
		fprintf(stderr,
			"--set option deprecated, please use --match-set\n");
	case '1':		/* --match-set <set> <flag>[,<flag> */
		if (info->match_set.dim)
			xtables_error(PARAMETER_PROBLEM,
				      "--match-set can be specified only once");
		if (invert)
			info->match_set.flags |= IPSET_INV_MATCH;

		if (!argv[optind]
		    || argv[optind][0] == '-'
		    || argv[optind][0] == '!')
			xtables_error(PARAMETER_PROBLEM,
				      "--match-set requires two args.");

		if (strlen(optarg) > IPSET_MAXNAMELEN - 1)
			xtables_error(PARAMETER_PROBLEM,
				      "setname `%s' too long, max %d characters.",
				      optarg, IPSET_MAXNAMELEN - 1);

		get_set_byname(optarg, &info->match_set);
		parse_dirs(argv[optind], &info->match_set);
		DEBUGP("parse: set index %u\n", info->match_set.index);
		optind++;

		*flags = 1;
		break;
	}

	return 1;
}

static void
zenset_print_counter(const struct ip_set_counter_match *c, const char *name,
		    const char *sep)
{
	switch (c->op) {
	case IPSET_COUNTER_EQ:
		printf(" %s%s-eq %llu", sep, name, c->value);
		break;
	case IPSET_COUNTER_NE:
		printf(" ! %s%s-eq %llu", sep, name, c->value);
		break;
	case IPSET_COUNTER_LT:
		printf(" %s%s-lt %llu", sep, name, c->value);
		break;
	case IPSET_COUNTER_GT:
		printf(" %s%s-gt %llu", sep, name, c->value);
		break;
	}
}

static void
zenset_print_matchinfo(const struct xt_zenset_info_match *info,
		       const char *opt, const char *sep)
{
	print_match(opt, &info->match_set);
	if (info->flags & IPSET_FLAG_RETURN_NOMATCH)
		printf(" %sreturn-nomatch", sep);
	if ((info->flags & IPSET_FLAG_SKIP_COUNTER_UPDATE))
		printf(" ! %supdate-counters", sep);
	if ((info->flags & IPSET_FLAG_SKIP_SUBCOUNTER_UPDATE))
		printf(" ! %supdate-subcounters", sep);
	zenset_print_counter(&info->packets, "packets", sep);
	zenset_print_counter(&info->bytes, "bytes", sep);
}

/* Prints out the matchinfo. */
static void
zenset_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_zenset_info_match *info = (const void *)match->data;

	zenset_print_matchinfo(info, "match-set", "");
}

static void
zenset_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_zenset_info_match *info = (const void *)match->data;

	zenset_print_matchinfo(info, "--match-set", "--");
}

static struct xtables_match zenset_mt_reg = {
	.name		= "zenset",
	.version	= XTABLES_VERSION,
	.revision       = 0,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct xt_zenset_info_match)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_zenset_info_match)),
	.help		= zenset_help,
	.parse		= zenset_parse,
	.final_check	= zenset_check,
	.print		= zenset_print,
	.save		= zenset_save,
	.extra_opts	= zenset_opts,
};

static __attribute__((constructor)) void zenset_mt_ldr(void)
{
	xtables_register_match(&zenset_mt_reg);
}
