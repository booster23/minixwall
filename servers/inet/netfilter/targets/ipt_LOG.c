/*
 * This is a module which is used for logging packets.
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
#include "ipt_LOG.h"

#include <stdio.h>

#if 1
#define DEBUGP printf
#else
#define DEBUGP(format, args)
#endif

/* FIXME: move to ip.h like in 2.5 */
struct ahhdr {
	u8_t    nexthdr;
	u8_t    hdrlen;
	u16_t   reserved;
	u32_t   spi;
	u32_t   seq_no;
};

struct esphdr {
	u32_t   spi;
	u32_t   seq_no;
};

/* One level of recursion won't kill us */
static void dump_packet(const struct ipt_log_info *info,
			struct ip_hdr *iph, unsigned int len, int recurse)
{
	void *protoh = (u32_t *)iph + (iph->ih_vers_ihl & IH_IHL_MASK);
	unsigned int datalen = len - (iph->ih_vers_ihl & IH_IHL_MASK) * 4;

	/* Important fields:
	 * TOS, len, DF/MF, fragment offset, TTL, src, dst, options. */
	/* Max length: 40 "SRC=255.255.255.255 DST=255.255.255.255 " */
	printf("SRC=%u.%u.%u.%u DST=%u.%u.%u.%u ",
	       NIPQUAD(iph->ih_src), NIPQUAD(iph->ih_dst));

	/* Max length: 46 "LEN=65535 TOS=0xFF PREC=0xFF TTL=255 ID=65535 " */
	printf("LEN=%u TOS=0x%02X PREC=0x%02X TTL=%u ID=%u ",
	       ntohs(iph->ih_length), iph->ih_tos & IPTOS_TOS_MASK,
	       iph->ih_tos & IPTOS_PREC_MASK, iph->ih_ttl, ntohs(iph->ih_id));

	/* Max length: 6 "CE DF MF " */
	if (ntohs(iph->ih_flags_fragoff) & IP_CE)
		printf("CE ");
	if (ntohs(iph->ih_flags_fragoff) & IP_DF)
		printf("DF ");
	if (ntohs(iph->ih_flags_fragoff) & IP_MF)
		printf("MF ");

	/* Max length: 11 "FRAG:65535 " */
	if (ntohs(iph->ih_flags_fragoff) & IH_FRAGOFF_MASK & IP_OFFSET)
		printf("FRAG:%u ", ntohs(iph->ih_flags_fragoff) & IH_FRAGOFF_MASK & IP_OFFSET);

	if ((info->logflags & IPT_LOG_IPOPT)
	    && (iph->ih_vers_ihl & IH_IHL_MASK) * 4 > sizeof(struct ip_hdr)
	    && (iph->ih_vers_ihl & IH_IHL_MASK) * 4 <= len) {
		unsigned int i;

		/* Max length: 127 "OPT (" 15*4*2chars ") " */
		printf("OPT (");
		for (i = sizeof(struct ip_hdr); i < (iph->ih_vers_ihl & IH_IHL_MASK) * 4; i++)
			printf("%02X", ((u8_t *)iph)[i]);
		printf(") ");
	}

	switch (iph->ih_proto) {
	case IPPROTO_TCP: {
		struct tcp_hdr *tcph = protoh;

		/* Max length: 10 "PROTO=TCP " */
		printf("PROTO=TCP ");

		if (ntohs(iph->ih_flags_fragoff) & IH_FRAGOFF_MASK & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (datalen < sizeof (*tcph)) {
			printf("INCOMPLETE [%u bytes] ", datalen);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		printf("SPT=%u DPT=%u ",
		       ntohs(tcph->th_srcport), ntohs(tcph->th_dstport));
		/* Max length: 30 "SEQ=4294967295 ACK=4294967295 " */
		if (info->logflags & IPT_LOG_TCPSEQ)
			printf("SEQ=%u ACK=%u ",
			       ntohl(tcph->th_seq_nr), ntohl(tcph->th_ack_nr));
		/* Max length: 13 "WINDOW=65535 " */
		printf("WINDOW=%u ", ntohs(tcph->th_window));
		/* Max length: 9 "RES=0x3F " */
		/*printf("RES=0x%02x ", (u8_t)(ntohl(tcp_flag_word(tcph) & TCP_RESERVED_BITS) >> 22));
		*/
		/* Max length: 32 "CWR ECE URG ACK PSH RST SYN FIN " */
		if (tcph->th_flags & THF_CWR)
			printf("CWR ");
		if (tcph->th_flags & THF_ECE)
			printf("ECE ");
		if (tcph->th_flags & THF_URG)
			printf("URG ");
		if (tcph->th_flags & THF_ACK)
			printf("ACK ");
		if (tcph->th_flags & THF_PSH)
			printf("PSH ");
		if (tcph->th_flags & THF_RST)
			printf("RST ");
		if (tcph->th_flags & THF_SYN)
			printf("SYN ");
		if (tcph->th_flags & THF_FIN)
			printf("FIN ");
		/* Max length: 11 "URGP=65535 " */
		printf("URGP=%u ", ntohs(tcph->th_urgptr));

		if ((info->logflags & IPT_LOG_TCPOPT)
		    && tcph->th_data_off * 4 > sizeof(struct tcp_hdr)
		    && tcph->th_data_off * 4 <= datalen) {
			unsigned int i;

			/* Max length: 127 "OPT (" 15*4*2chars ") " */
			printf("OPT (");
			for (i =sizeof(struct tcp_hdr); i < tcph->th_data_off * 4; i++)
				printf("%02X", ((u8_t *)tcph)[i]);
			printf(") ");
		}
		break;
	}
	case IPPROTO_UDP: {
		struct udp_hdr *udph = protoh;

		/* Max length: 10 "PROTO=UDP " */
		printf("PROTO=UDP ");

		if (ntohs(iph->ih_flags_fragoff) & IH_FRAGOFF_MASK & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (datalen < sizeof (*udph)) {
			printf("INCOMPLETE [%u bytes] ", datalen);
			break;
		}

		/* Max length: 20 "SPT=65535 DPT=65535 " */
		printf("SPT=%u DPT=%u LEN=%u ",
		       ntohs(udph->uh_src_port), ntohs(udph->uh_dst_port),
		       ntohs(udph->uh_length));
		break;
	}
	case IPPROTO_ICMP: {
		struct icmp_hdr *icmph = protoh;
		static size_t required_len[NR_ICMP_TYPES+1]
			= { 4,                             /* 0 echo reply */
			    32,                            /* 1 ??? */
			    32,                            /* 2 ??? */
			    8 + sizeof(struct ip_hdr) + 8, /* 3 dest unreach */
			    8 + sizeof(struct ip_hdr) + 8, /* 4 source quench */
			    8 + sizeof(struct ip_hdr) + 8, /* 5 redirect */
			    32,                            /* 6 ??? */
			    32,                            /* 7 ??? */
			    4,                             /* 8 echo */
			    32,                            /* 9 ??? */
			    32,                            /* 10 ??? */
			    8 + sizeof(struct ip_hdr) + 8, /* 11 time exc'd */
			    8 + sizeof(struct ip_hdr) + 8, /* 12 param probl */
			    20,                            /* 13 timestamp */
			    20,                            /* 14 stamp reply */
			    12,                            /* 15 info req */ 
			    12,                            /* 16 info rep */ 
			    };

		/* Max length: 11 "PROTO=ICMP " */
		printf("PROTO=ICMP ");

		if (ntohs(iph->ih_flags_fragoff) & IH_FRAGOFF_MASK & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (datalen < 4) {
			printf("INCOMPLETE [%u bytes] ", datalen);
			break;
		}

		/* Max length: 18 "TYPE=255 CODE=255 " */
		printf("TYPE=%u CODE=%u ", icmph->ih_type, icmph->ih_code);

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (icmph->ih_type <= NR_ICMP_TYPES
		    && required_len[icmph->ih_type]
		    && datalen < required_len[icmph->ih_type]) {
			printf("INCOMPLETE [%u bytes] ", datalen);
			break;
		}

		switch (icmph->ih_type) {
		case ICMP_TYPE_ECHO_REPL:
		case ICMP_TYPE_ECHO_REQ:
			/* Max length: 19 "ID=65535 SEQ=65535 " */
			printf("ID=%u SEQ=%u ",
			       ntohs(icmph->ih_hun.ihh_idseq.iis_id),
			       ntohs(icmph->ih_hun.ihh_idseq.iis_seq));
			break;

		case ICMP_TYPE_PARAM_PROBLEM:
			/* Max length: 14 "PARAMETER=255 " */
			printf("PARAMETER=%u ",
			       ntohl(icmph->ih_hun.ihh_gateway) >> 24);
			break;
		case ICMP_TYPE_REDIRECT:
			/* Max length: 24 "GATEWAY=255.255.255.255 " */
			printf("GATEWAY=%u.%u.%u.%u ", NIPQUAD(icmph->ih_hun.ihh_gateway));
			/* Fall through */
		case ICMP_TYPE_DST_UNRCH:
		case ICMP_TYPE_SRC_QUENCH:
		case ICMP_TYPE_TIME_EXCEEDED:
			/* Max length: 3+maxlen */
			if (recurse) {
				printf("[");
				dump_packet(info,
					    (struct ip_hdr *)(icmph + 1),
					    datalen-sizeof(struct icmp_hdr),
					    0);
				printf("] ");
			}

			/* Max length: 10 "MTU=65535 " */
			if (icmph->ih_type == ICMP_TYPE_DST_UNRCH
			    && icmph->ih_code == ICMP_FRAGM_AND_DF)
				printf("MTU=%u ", ntohs(icmph->ih_hun.ihh_mtu.im_mtu));
		}
		break;
	}
	/* Max Length */
	case IPPROTO_AH: {
		struct ahhdr *ah = protoh;

		/* Max length: 9 "PROTO=AH " */
		printf("PROTO=AH ");

		if (ntohs(iph->ih_flags_fragoff) & IH_FRAGOFF_MASK & IP_OFFSET)
			break;

		/* Max length: 25 "INCOMPLETE [65535 bytes] " */
		if (datalen < sizeof (*ah)) {
			printf("INCOMPLETE [%u bytes] ", datalen);
			break;
		}

		/* Length: 15 "SPI=0xF1234567 " */
		printf("SPI=0x%x ", ntohl(ah->spi) );
		break;
	}
	/* Max length: 10 "PROTO 255 " */
	default:
		printf("PROTO=%u ", iph->ih_proto);
	}

	/* Proto    Max log string length */
	/* IP:      40+46+6+11+127 = 230 */
	/* TCP:     10+max(25,20+30+13+9+32+11+127) = 252 */
	/* UDP:     10+max(25,20) = 35 */
	/* ICMP:    11+max(25, 18+25+max(19,14,24+3+n+10,3+n+10)) = 91+n */
	/* ESP:     10+max(25)+15 = 50 */
	/* AH:      9+max(25)+15 = 49 */
	/* unknown: 10 */

	/* (ICMP allows recursion one level deep) */
	/* maxlen =  IP + ICMP +  IP + max(TCP,UDP,ICMP,unknown) */
	/* maxlen = 230+   91  + 230 + 252 = 803 */
}

static unsigned int
ipt_log_target(struct sk_buff **pskb,
	       unsigned int hooknum,
	       const struct net_device *in,
	       const struct net_device *out,
	       const void *targinfo,
	       void *userinfo)
{
	struct ip_hdr *iph = (*pskb)->nh.iph;
	const struct ipt_log_info *loginfo = targinfo;
	char level_string[4] = "< >";

	level_string[1] = '0' + (loginfo->level % 8);
	printf(level_string);
	printf("%s IN=%s OUT=%s ",
	       loginfo->prefix,
	       in ? in->name : "",
	       out ? out->name : "");
	if (in && !out) {
		/* MAC logging for input chain only. */
		printf("MAC=");
		if ((*pskb)->dev && (*pskb)->dev->hard_header_len && (*pskb)->mac.raw != (void*)iph) {
			int i;
			unsigned char *p = (*pskb)->mac.raw;
			for (i = 0; i < (*pskb)->dev->hard_header_len; i++,p++)
				printf("%02x%c", *p,
				       i==(*pskb)->dev->hard_header_len - 1
				       ? ' ':':');
		} else
			printf(" ");
	}

	dump_packet(loginfo, iph, (*pskb)->len, 1);

	printf("\n");

	return IPT_CONTINUE;
}

static int ipt_log_checkentry(const char *tablename,
			      const struct ipt_entry *e,
			      void *targinfo,
			      unsigned int targinfosize,
			      unsigned int hook_mask)
{
	const struct ipt_log_info *loginfo = targinfo;

	return 1;
}

static struct ipt_target ipt_log_reg
= { { NULL, NULL }, "LOG", ipt_log_target, ipt_log_checkentry, NULL,
    NULL };

int ipt_register_target_LOG(void)
{
	if (ipt_register_target(&ipt_log_reg))
		return -EINVAL;

	return 0;
}

void ipt_unregister_target_LOG(void)
{
	ipt_unregister_target(&ipt_log_reg);
}
