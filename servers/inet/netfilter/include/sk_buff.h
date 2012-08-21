#ifndef SKBUFF_H
#define SKBUFF_H SKBUFF_H

#include <sys/types.h>
#include <net/gen/in.h>
#include <net/gen/ether.h>
#include <net/gen/icmp.h>
#include <net/gen/tcp.h>
#include <net/gen/udp.h>
#include <net/gen/ip_hdr.h>
#include <net/gen/eth_hdr.h>
#include <net/gen/tcp_hdr.h>
#include <net/gen/udp_hdr.h>
#include <net/gen/icmp_hdr.h>
#include <net_device.h>

struct sk_buff {
  struct sk_buff *next;
  struct sk_buff *prev;
  struct net_device *dev;        /* network device                        */
  struct net_device *real_dev;   /* real network device (in encapsulated) */
  int len;                       /* buffer length                         */

  union {
    eth_hdr_t *ethernet;
    unsigned char *raw;
  } mac;

  union {
    ip_hdr_t *iph;
    unsigned char *raw;
  } nh;

  union {
    icmp_hdr_t *ih;
    tcp_hdr_t *th;
    udp_hdr_t *uh;
    unsigned char *raw;
  } h;

  unsigned char *head;
  unsigned char *data;
  unsigned char *tail;
};

#endif
