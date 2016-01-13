/*
 *	"RESET" target extension for iptables
 *	Copyright © Jan Engelhardt, 2008
 *	Copyright (C) 2016 Zenedge Inc <www.zenedge.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <stdio.h>
#include <getopt.h>
#include <xtables.h>
#include "compat_user.h"

static void reset_tg_help(void)
{
	printf("RESET takes no options\n\n");
}

static int reset_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static void reset_tg_check(unsigned int flags)
{
}

static struct xtables_target reset_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "RESET",
	.family        = NFPROTO_UNSPEC,
	.help          = reset_tg_help,
	.parse         = reset_tg_parse,
	.final_check   = reset_tg_check,
};

static __attribute__((constructor)) void reset_tg_ldr(void)
{
	xtables_register_target(&reset_tg_reg);
}
