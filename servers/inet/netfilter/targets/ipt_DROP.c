/*
 * This is a module which is used for dropping packets.
 */
#include <sys/types.h>
#include <net/gen/in.h>
#include <net/gen/ip_hdr.h>
#include <net/gen/icmp.h>
#include <net/gen/tcp.h>
#include <net/gen/udp.h>
#include <net/gen/icmp_hdr.h>
#include <net/gen/tcp_hdr.h>
#include <net/gen/udp_hdr.h>
#include <net/gen/route.h>
#include <errno.h>
#include <sk_buff.h>
#include <ip_tables.h>
#include <net_device.h>
#include <macros.h>
#include "ipt_DROP.h"

#include <stdio.h>

static unsigned int
ipt_drop_target(struct sk_buff **pskb,
	       unsigned int hooknum,
	       const struct net_device *in,
	       const struct net_device *out,
	       const void *targinfo,
	       void *userinfo)
{
	return NF_DROP;
}

static struct ipt_target ipt_log_reg
= { { NULL, NULL }, "DROP", ipt_drop_target, NULL, NULL,
    NULL };

int ipt_register_target_DROP(void)
{
	if (ipt_register_target(&ipt_log_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_target_DROP(void)
{
	ipt_unregister_target(&ipt_log_reg);
}
