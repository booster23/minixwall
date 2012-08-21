#ifndef NFCORE_H
#define NFCORE_H
#include <sys/types.h>
#include <ip_tables.h>

enum nftable {NFT_FILTER,NFT_NAT,NFT_MANGLE};
#define MAX_ENTRIES_PER_CHAIN 16
#define MAX_LOCAL_IPS 8

void nfCoreInit(void);
void inetRegisterLocalIP(int a, int b, int c, int d);
int inetCheckLocalIP(int a, int b, int c, int d);
void inetEthIn(char *ethername);
void inetEthOut(char *ethername);
void inetSetPackSize(int size);
void inetSetDataSize(int size);
int inetGetDataSize(void);
void inetHook(unsigned int hook);
int inetData(char *address);
void inetContainLayers(int layerid);
int inetProcess(void);
int inetGetData(char *address);
int iptablesNewChain(const struct ipt_table *table,
                     const char *name,
		     int policy,
		     int builtin,
		     int hooknum);
int chainExists(const struct ipt_table *table, const char *name);
struct ipt_chain *getChain(const struct ipt_table *table, const char *name);
int iptablesSelectTable(enum nftable table);
int iptablesSelectChain(char *name);
int iptablesSelectTarget(char *name);
int iptablesSelectL3Match(char *name);
int iptablesSetL3MatchInfo(void *matchinfo);
int iptablesSetIPMatchInfo(void *matchinfo);
int iptablesSetTargInfo(void *targinfo);
int iptablesSetPolicy(int policy);
int iptablesAppendRule(void);
int iptablesDeleteRule(int index);
int iptablesFlushChain(void);

#endif
