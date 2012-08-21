#ifndef MACROS_H
#define MACROS_H MACROS_H

#define _MINIX_SOURCE 1
#include <stddef.h>
#include <sys/types.h>
#include <net/hton.h>

#define NIPADDR_A(ipaddr) ((ntohl(ipaddr)>>24) & 0xff)
#define NIPADDR_B(ipaddr) ((ntohl(ipaddr)>>16) & 0xff)
#define NIPADDR_C(ipaddr) ((ntohl(ipaddr)>>8) & 0xff)
#define NIPADDR_D(ipaddr) ((ntohl(ipaddr)) & 0xff)
#define NIPQUAD(ipaddr) NIPADDR_A(ipaddr),\
			NIPADDR_B(ipaddr),\
			NIPADDR_C(ipaddr),\
			NIPADDR_D(ipaddr)

#define IPTOS_TOS_MASK 0x1e
#define IPTOS_PREC_MASK 0xe0

#define TCP_FLAG_CWR htonl(0x00800000)
#define	TCP_FLAG_ECE htonl(0x00400000)
#define	TCP_FLAG_URG htonl(0x00200000)
#define	TCP_FLAG_ACK htonl(0x00100000)
#define	TCP_FLAG_PSH htonl(0x00080000)
#define	TCP_FLAG_RST htonl(0x00040000)
#define	TCP_FLAG_SYN htonl(0x00020000)
#define	TCP_FLAG_FIN htonl(0x00010000)
#define	TCP_RESERVED_BITS htonl(0x0F000000)
#define	TCP_DATA_OFFSET htonl(0xF0000000)


/* to come into include/net/gen/tcp_hdr.h later */
#define THF_ECE 0x40 
#define THF_CWR 0x80 
/* - */

/* to come into include/net/gen/icmp.h later */
#define NR_ICMP_TYPES 18     /* number of ICMP types */
/* - */

/* to come into include/net/gen/in.h later */
#define IPPROTO_ESP 50       /* Encapsulation Security Payload protocol */
#define IPPROTO_AH 51        /* Authentication Header protocol       */
/* - */

#define IP_CE 0x08
#define IP_DF 0x04
#define IP_MF 0x02
#define IP_OFFSET 0x1fff

#endif 

