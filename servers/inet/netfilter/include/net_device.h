#ifndef NET_DEVICE_H
#define NET_DEVICE_H NET_DEVICE_H

#define IF_NAMESIZE    16

struct net_device
{
  char name[IF_NAMESIZE];           /* interface name             */
  unsigned short hard_header_len;   /* hardware header length     */
};

#endif
