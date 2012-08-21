/*
 * This is a module returns always match hit
 */
#include <sys/types.h>
#include <net/gen/in.h>
#include <errno.h>
#include <sk_buff.h>
#include <ip_tables.h>
#include <net_device.h>
#include "ipt_ANY.h"
#include <macros.h>
#include <stdio.h>
#include <string.h>

#if 1
#define DEBUGP printf
#else
#define DEBUGP(format, args)
#endif

static int
ipt_any_match(const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const void *matchinfo,
		int offset,
		const void *hdr,
		u16_t datalen,
		int *hotdrop)
{
  return 1;
}

static int
ipt_any_checkentry(const char *tablename,
                      const struct ipt_ip *ip,
		      void *matchinfo,
		      unsigned int matchinfosize,
		      unsigned int hook_mask)
{
  return 1;
}

static struct ipt_match ipt_any_reg
= { { NULL, NULL }, "ANY", ipt_any_match, ipt_any_checkentry, NULL,
    NULL };

int ipt_register_match_ANY(void)
{
	if (ipt_register_match(&ipt_any_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_match_ANY(void)
{
	ipt_unregister_match(&ipt_any_reg);
}
