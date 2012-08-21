#ifndef NFDEFS_H
#define NFDEFS_H NFDEFS_H

/* IP Hooks */
#define NF_IP_PRE_ROUTING	1
#define NF_IP_LOCAL_IN		2
#define NF_IP_FORWARD		3
#define NF_IP_POST_ROUTING      4
#define NF_IP_LOCAL_OUT		5
#define NF_IP_NUMHOOKS 		5

/* Netfilter initialzing ioctl codes */
#define IOCTL_NF_INIT_INET   100
#define IOCTL_NF_INIT_IPTABLES 101

/* Inet daemon related ioctl codes */
#define IOCTL_NF_ETH_IN      2000
#define IOCTL_NF_ETH_OUT     2001
#define IOCTL_NF_PACK_SIZE   2002
#define IOCTL_NF_CONTAINS    2003
#define NF_LAYER_ETH         1
#define NF_LAYER_IP          2
#define IOCTL_NF_HOOK        2004
#define IOCTL_NF_PROCESS     2005
#define IOCTL_NF_SIZE        10
#define IOCTL_NF_DATA        11
#define IOCTL_NF_GETDATA     12

/* Iptables related ioctl codes */
#define IOCTL_IPT_SET_TABLE  1000
#define IOCTL_IPT_SET_CHAIN  1001
#define IOCTL_IPT_SET_MATCH  1002
#define IOCTL_IPT_SET_MATCHINFO  1003
#define IOCTL_IPT_SET_IP_MATCHINFO  1004
#define IOCTL_IPT_SET_TARGINFO  1005
#define IOCTL_IPT_SET_TARGET 1006
#define IOCTL_IPT_APPEND     1007
#define IOCTL_IPT_DELETE     1008
#define IOCTL_IPT_DELETE_RULE 1009
#define IOCTL_IPT_INSERT     1010
#define IOCTL_IPT_REPLACE    1011
#define IOCTL_IPT_NEW        1012
#define IOCTL_IPT_FLUSH      1013
#define IOCTL_IPT_SET_POLICY 1014
#define IOCTL_IPT_ZERO       1015
#define NF_TABLE_FILTER      2
#define NF_TABLE_NAT         3
#define NF_TABLE_MANGLE      1

#endif
