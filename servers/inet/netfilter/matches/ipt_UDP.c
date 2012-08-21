/*
 * This is a module which is used for comparing UDP options
 */
#include <sys/types.h>
#include <net/gen/in.h>
#include <net/gen/udp.h>
#include <net/gen/udp_hdr.h>
#include <errno.h>
#include <sk_buff.h>
#include <ip_tables.h>
#include <net_device.h>
#include "ipt_UDP.h"
#include <macros.h>
#include <stdio.h>
#include <string.h>

#define DEBUGP printf

static int
port_match(u16_t min, u16_t max, u16_t port, int invert)
{
	int ret;

	ret = (port >= min && port <= max) ^ invert;
        return ret;
}

static int
ipt_udp_match(const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const void *matchinfo,
		int offset,
		const void *hdr,
		u16_t datalen,
		int *hotdrop)
{
	const struct udp_hdr *udp = hdr;
	const struct ipt_udp *udpinfo = matchinfo;
	
	if (offset == 0 && datalen < sizeof(struct udp_hdr)) {
		/* We've been asked to examine this packet, and we
		can't.  Hence, no choice but to drop. */
#ifdef _DEBUG
		DEBUGP("Dropping evil UDP tinygram.\n");
#endif
		*hotdrop = 1;
		return 0;
	}
	
	/* Must not be a fragment. */
	return !offset
		&& port_match(udpinfo->spts[0], udpinfo->spts[1],
			ntohs(udp->uh_src_port),
			!!(udpinfo->invflags & IPT_UDP_INV_SRCPT))
		&& port_match(udpinfo->dpts[0], udpinfo->dpts[1],
			ntohs(udp->uh_dst_port),
			!!(udpinfo->invflags & IPT_UDP_INV_DSTPT));
}




static int
ipt_udp_checkentry(const char *tablename,
                      const struct ipt_ip *ip,
		      void *matchinfo,
		      unsigned int matchinfosize,
		      unsigned int hook_mask)
{
  return 1;
}

static struct ipt_match ipt_udp_reg
= { { NULL, NULL }, "UDP", ipt_udp_match, ipt_udp_checkentry, NULL,
    NULL };

int ipt_register_match_UDP(void)
{
	if (ipt_register_match(&ipt_udp_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_match_UDP(void)
{
	ipt_unregister_match(&ipt_udp_reg);
}
