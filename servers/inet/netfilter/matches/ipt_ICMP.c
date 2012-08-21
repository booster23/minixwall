/*
 * This is a module which is used for comparing ICMP options.
 */
#include <sys/types.h>
#include <net/gen/in.h>
#include <net/gen/ip_hdr.h>
#include <net/gen/icmp.h>
#include <net/gen/icmp_hdr.h>
#include <errno.h>
#include <sk_buff.h>
#include <ip_tables.h>
#include <net_device.h>
#include "ipt_ICMP.h"
#include <macros.h>
#include <stdio.h>
#include <string.h>

#define DEBUGP printf

/* Returns 1 if the type and code is matched by the range, 0 otherwise */
static int
icmp_type_code_match(u8_t test_type, u8_t min_code, u8_t max_code,
		                     u8_t type, u8_t code, int invert)
{
	return ((test_type == 0xFF)
	 	|| (type == test_type && code >= min_code && code <= max_code))
		^ invert;
}


static int
ipt_icmp_match(const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const void *matchinfo,
		int offset,
		const void *hdr,
		u16_t datalen,
		int *hotdrop)
{
	const struct icmp_hdr *icmp = hdr;
	const struct ipt_icmp *icmpinfo = matchinfo;
	
	if (offset == 0 && datalen < 2)
	{
		/* We've been asked to examine this packet, and we
		*                    can't.  Hence, no choice but to drop. */
#ifdef _DEBUG
		DEBUGP("Dropping evil ICMP tinygram.\n");
#endif
		*hotdrop = 1;
		return 0;
	}
	
	/* Must not be a fragment. */
	return !offset
		&& icmp_type_code_match(icmpinfo->type,
					icmpinfo->code[0],
					icmpinfo->code[1],
					icmp->ih_type, icmp->ih_code,
					!!(icmpinfo->invflags&IPT_ICMP_INV));
}




static int
ipt_icmp_checkentry(const char *tablename,
                      const struct ipt_ip *ip,
		      void *matchinfo,
		      unsigned int matchinfosize,
		      unsigned int hook_mask)
{
  return 1;
}

static struct ipt_match ipt_icmp_reg
= { { NULL, NULL }, "ICMP", ipt_icmp_match, ipt_icmp_checkentry, NULL,
    NULL };

int ipt_register_match_ICMP(void)
{
	if (ipt_register_match(&ipt_icmp_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_match_ICMP(void)
{
	ipt_unregister_match(&ipt_icmp_reg);
}
