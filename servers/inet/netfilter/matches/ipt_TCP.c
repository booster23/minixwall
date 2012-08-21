/*
 * This is a module which is used for comparing TCP options
 */
#include <sys/types.h>
#include <net/gen/in.h>
#include <net/gen/tcp.h>
#include <net/gen/tcp_hdr.h>
#include <errno.h>
#include <sk_buff.h>
#include <ip_tables.h>
#include <net_device.h>
#include "ipt_TCP.h"
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
tcp_find_option(u8_t option,
                const struct tcp_hdr *tcp,
                u16_t datalen,
		int invert,
		int *hotdrop)
{
	        unsigned int i = sizeof(struct tcp_hdr);
		const u8_t *opt = (u8_t *)tcp;
			
#ifdef _DEBUG
		DEBUGP("tcp_match: finding option\n");
#endif
		/* If we don't have the whole header, drop packet. */
		if (tcp->th_data_off * 4 < sizeof(struct tcp_hdr) ||
			tcp->th_data_off * 4 > datalen)
		{
			*hotdrop = 1;
			return 0;
		}
		
		while (i < tcp->th_data_off * 4)
		{
			if (opt[i] == option) return !invert;
			if (opt[i] < 2) i++;
			else i += opt[i+1]?0:1;
		}

		return invert;
}

static int
ipt_tcp_match(const struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		const void *matchinfo,
		int offset,
		const void *hdr,
		u16_t datalen,
		int *hotdrop)
{
	const struct tcp_hdr *tcp = hdr;
	const struct ipt_tcp *tcpinfo = matchinfo;
	
	/* To quote Alan:
	
	Don't allow a fragment of TCP 8 bytes in. Nobody normal
	causes this. Its a cracker trying to break in by doing a
	flag overwrite to pass the direction checks.
	*/

	if (offset == 1)
	{
#ifdef _DEBUG
		DEBUGP("Dropping evil TCP offset=1 frag.\n");
#endif
		*hotdrop = 1;
		return 0;
	}
       	else if (offset == 0 && datalen < sizeof(struct tcp_hdr))
	{
		/* We've been asked to examine this packet, and we
		*                    can't.  Hence, no choice but to drop. */
#ifdef _DEBUG
		DEBUGP("Dropping evil TCP offset=0 tinygram.\n");
#endif
		*hotdrop = 1;
		return 0;
	}

	/* FIXME: Try tcp doff >> packet len against various stacks --RR */

#define FWINVTCP(bool,invflg) ((bool) ^ !!(tcpinfo->invflags & invflg))

	/* Must not be a fragment. */
	return !offset
		&& port_match(tcpinfo->spts[0], tcpinfo->spts[1],
			ntohs(tcp->th_srcport),
			!!(tcpinfo->invflags & IPT_TCP_INV_SRCPT))
		&& port_match(tcpinfo->dpts[0], tcpinfo->dpts[1],
			ntohs(tcp->th_dstport),
			!!(tcpinfo->invflags & IPT_TCP_INV_DSTPT))
		&& FWINVTCP((((unsigned char *)tcp)[13]
			& tcpinfo->flg_mask)
			== tcpinfo->flg_cmp,
			IPT_TCP_INV_FLAGS)
		&& (!tcpinfo->option
			|| tcp_find_option(tcpinfo->option, tcp, datalen,
					tcpinfo->invflags
					& IPT_TCP_INV_OPTION,
					hotdrop));
}




static int
ipt_tcp_checkentry(const char *tablename,
                      const struct ipt_ip *ip,
		      void *matchinfo,
		      unsigned int matchinfosize,
		      unsigned int hook_mask)
{
  return 1;
}

static struct ipt_match ipt_tcp_reg
= { { NULL, NULL }, "TCP", ipt_tcp_match, ipt_tcp_checkentry, NULL,
    NULL };

int ipt_register_match_TCP(void)
{
	if (ipt_register_match(&ipt_tcp_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_match_TCP(void)
{
	ipt_unregister_match(&ipt_tcp_reg);
}
