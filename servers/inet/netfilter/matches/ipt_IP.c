/*
 * This is a module which is used for logging packets.
 */
#include <sys/types.h>
#include <net/gen/in.h>
#include <net/gen/ip_hdr.h>
#include <errno.h>
#include <sk_buff.h>
#include <ip_tables.h>
#include <net_device.h>
#include "ipt_IP.h"
#include <macros.h>
#include <stdio.h>
#include <string.h>

#define DEBUGP printf
#define min(a,b) (a<b?a:b)

static int
ipt_ip_match(const struct sk_buff *skb,
	     const struct net_device *in,
	     const struct net_device *out,
	     const void *matchinfo,
	     int offset,
	     const void *hdr,
	     u16_t datalen,
	     int *hotdrop)
{
	size_t i;
	unsigned long ret;
	struct ip_hdr *ip;
	struct ipt_ip *ipinfo;
	char indev[IF_NAMESIZE], outdev[IF_NAMESIZE];
	int isfrag;

	ip=skb->nh.iph;
	ipinfo=(struct ipt_ip*)matchinfo;
	strncpy((char*)indev,in->name,IF_NAMESIZE);
	strncpy((char*)outdev,out->name,IF_NAMESIZE);
	isfrag=(ip->ih_flags_fragoff&IH_MORE_FRAGS)>0?1:0;

#define FWINV(bool,invflg) ((bool) ^ !!(ipinfo->invflags & invflg))
	if (FWINV((ip->ih_src&ipinfo->smsk.s_addr) != ipinfo->src.s_addr,
		IPT_INV_SRCIP)
 		|| FWINV((ip->ih_dst&ipinfo->dmsk.s_addr) != ipinfo->dst.s_addr,
		IPT_INV_DSTIP))
	{
#ifdef _DEBUG
		DEBUGP("Source or dest mismatch.\n");
		DEBUGP("SRC: %u.%u.%u.%u. Mask: %u.%u.%u.%u. Target: %u.%u.%u.%u.%s\n",
				NIPQUAD(ip->ih_src),
				NIPQUAD(ipinfo->smsk.s_addr),
				NIPQUAD(ipinfo->src.s_addr),
				ipinfo->invflags & IPT_INV_SRCIP ? " (INV)" : "");
		DEBUGP("DST: %u.%u.%u.%u Mask: %u.%u.%u.%u Target: %u.%u.%u.%u.%s\n",
				NIPQUAD(ip->ih_dst),
				NIPQUAD(ipinfo->dmsk.s_addr),
				NIPQUAD(ipinfo->dst.s_addr),
				ipinfo->invflags & IPT_INV_DSTIP ? " (INV)" : "");
#endif
		return 0;
	}			

	for (i = 0, ret = 0; i < min(strlen(indev),strlen(ipinfo->iniface_mask)); i++)
	{
		ret |= (indev[i] != ipinfo->iniface[i])
		        	&& ipinfo->iniface_mask[i];
	}

	if (FWINV(ret != 0, IPT_INV_VIA_IN))
	{
#ifdef _DEBUG
		DEBUGP("VIA in mismatch (%s vs %s).%s\n",
		indev, ipinfo->iniface,
		ipinfo->invflags&IPT_INV_VIA_IN ?" (INV)":"");
#endif
		return 0;
	}

	for (i = 0, ret = 0; i < min(strlen(outdev),strlen(ipinfo->outiface_mask)); i++)
	{
		ret |= (outdev[i] != ipinfo->outiface[i])
		        	&& ipinfo->outiface_mask[i];
	}
	
	if (FWINV(ret != 0, IPT_INV_VIA_OUT))
	{
#ifdef _DEBUG
		DEBUGP("VIA out mismatch (%s vs %s).%s\n",
		outdev, ipinfo->outiface,
		ipinfo->invflags&IPT_INV_VIA_OUT ?" (INV)":"");
#endif
		return 0;
	}
	
	/* Check specific protocol */
	if (ipinfo->proto
		&& FWINV(ip->ih_proto != ipinfo->proto, IPT_INV_PROTO))
	{
#ifdef _DEBUG
		DEBUGP("Packet protocol %d does not match %d.%s\n",
		ip->ih_proto, ipinfo->proto,
		ipinfo->invflags&IPT_INV_PROTO ? " (INV)":"");
#endif
		return 0;
	}

	/* If we have a fragment rule but the packet is not a fragment
	*          * then we return zero */
	if (FWINV((ipinfo->flags&IPT_F_FRAG) && !isfrag, IPT_INV_FRAG))
	{
#ifdef _DEBUG
		DEBUGP("Fragment rule but not fragment.%s\n",
		ipinfo->invflags & IPT_INV_FRAG ? " (INV)" : "");
#endif
		return 0;
	}
	
	return 1;
}

static int
ipt_ip_checkentry(const char *tablename,
                      const struct ipt_ip *ip,
		      void *matchinfo,
		      unsigned int matchinfosize,
		      unsigned int hook_mask)
{
  return 1;
}

static struct ipt_match ipt_ip_reg
= { { NULL, NULL }, "IP", ipt_ip_match, ipt_ip_checkentry, NULL,
    NULL };

int ipt_register_match_IP(void)
{
	if (ipt_register_match(&ipt_ip_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_match_IP(void)
{
	ipt_unregister_match(&ipt_ip_reg);
}
