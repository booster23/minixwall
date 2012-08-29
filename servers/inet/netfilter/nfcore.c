/*
 *  MINIX-3 network filter - filtering core module
 *
 *  (C) 2007 Brian Schueler (brian.schueler@gmx.de)
 *  
 *      As part of the diploma thesis:
 *      Analysis and Porting of a network 
 *      filtering architecture on Minix-3
 *      under supervision of
 *      Prof. Dr. rer. nat. Ruediger Weis
 *      at the University of Applied Sciences Berlin
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <nfdefs.h>
#include <ip_tables.h>
#include <net_device.h>
#include <sk_buff.h>
#include <buffer.h>
#include <list.h>
#include <nfcore.h>
#include <macros.h>

#include "matches/ipt_IP.h"
#include "matches/ipt_TCP.h"
#include "matches/ipt_UDP.h"
#include "matches/ipt_ICMP.h"
#include "matches/ipt_ANY.h"

#include "targets/ipt_ACCEPT.h"
#include "targets/ipt_DROP.h"
#include "targets/ipt_LOG.h"

#define min(a,b) (a<=b?a:b)

static int inetLocalIPcount;
char inetLocalIPs[MAX_LOCAL_IPS][4];
char currInIf[IF_NAMESIZE];
char currOutIf[IF_NAMESIZE];
struct buffer currData;
char *afterData;
static int currDataSize;
static int currPackSize;
static int currLayerID;
unsigned int hooknum;

struct ipt_table *selectedTable;
struct ipt_chain *selectedChain;
struct ipt_chain *jumpChain;
struct ipt_match *selectedL3Match;
struct ipt_target *selectedTarget;
struct ipt_ip IPMatchInfo;
unsigned char L3MatchInfo[MATCHINFO_MAXSIZE];
unsigned char targetInfo[TARGINFO_MAXSIZE];

static struct ipt_target* target_mods[32];
static struct ipt_match* match_mods[32];
static int targetmodcounter;
static int matchmodcounter;
static struct ipt_table tab_filter, tab_nat, tab_mangle;

void nfCoreInit(void)
{
#ifdef _DEBUG
  printf("nfCoreInit()\n");
#endif
  targetmodcounter=0;
  matchmodcounter=0;
  afterData=NULL;
  currData.next=NULL;
  currData.data=NULL;
  currDataSize=0;
  currPackSize=0;
  currInIf[0]='\0';
  currOutIf[0]='\0';
  inetLocalIPcount=0;

  /* register the match functions */
  ipt_register_match_IP();    /* must be first */
  ipt_register_match_TCP();
  ipt_register_match_UDP();
  ipt_register_match_ICMP();
  ipt_register_match_ANY();

  /* register the target functions */
  ipt_register_target_LOG();
  ipt_register_target_ACCEPT();
  ipt_register_target_DROP();

  /* name the three tables */
  strcpy(tab_filter.name,"filter");
  strcpy(tab_nat.name,"nat");
  strcpy(tab_mangle.name,"mangle");
  INIT_LIST_HEAD(&tab_filter.list);
  INIT_LIST_HEAD(&tab_nat.list);
  INIT_LIST_HEAD(&tab_mangle.list);

  /* Add the standard chains used for packet filtering */
  iptablesNewChain(&tab_filter,"INPUT",NF_ACCEPT,1,NF_IP_LOCAL_IN);
  iptablesNewChain(&tab_filter,"OUTPUT",NF_ACCEPT,1,NF_IP_FORWARD);
  iptablesNewChain(&tab_filter,"FORWARD",NF_ACCEPT,1,NF_IP_LOCAL_OUT);

  /* Add the standard chains used for address translation */
  iptablesNewChain(&tab_nat,"PREROUTING",NF_ACCEPT,1,NF_IP_PRE_ROUTING);
  iptablesNewChain(&tab_nat,"POSTROUTING",NF_ACCEPT,1,NF_IP_POST_ROUTING);
  iptablesNewChain(&tab_nat,"OUTPUT",NF_ACCEPT,1,NF_IP_LOCAL_OUT);

  /* Add the standard chains used for packet mangeling */
  iptablesNewChain(&tab_mangle,"PREROUTING",NF_ACCEPT,1,NF_IP_PRE_ROUTING);
  iptablesNewChain(&tab_mangle,"INPUT",NF_ACCEPT,1,NF_IP_LOCAL_IN);
  iptablesNewChain(&tab_mangle,"FORWARD",NF_ACCEPT,1,NF_IP_FORWARD);
  iptablesNewChain(&tab_mangle,"OUTPUT",NF_ACCEPT,1,NF_IP_LOCAL_OUT);
  iptablesNewChain(&tab_mangle,"POSTROUTING",NF_ACCEPT,1,NF_IP_POST_ROUTING);
}

/*******************************************************************
 * inetRegisterLocalIP                                             *
 *                                                                 *
 * Tells netfilter the local IP addresses for later decisions      *
 * on which is FORWARDED or not.                                   *
 *                                                                 *
 * Parameters:  int  a                IP address byte 1            *
 *              int  b                IP address byte 2            *
 *              int  c                IP address byte 3            *
 *              int  d                IP address byte 4            *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetRegisterLocalIP(int a, int b, int c, int d)
{
#ifdef _DEBUG
  printf("inetRegisterLocalIP()\n");
#endif
  if (!inetCheckLocalIP(a,b,c,d))
  {
     if (inetLocalIPcount<MAX_LOCAL_IPS)
     {
        printf("MinixWall: Registered device IP address: %d.%d.%d.%d\n",
               a,b,c,d);
        inetLocalIPs[inetLocalIPcount][0]=(char)a;
        inetLocalIPs[inetLocalIPcount][1]=(char)b;
        inetLocalIPs[inetLocalIPcount][2]=(char)c;
        inetLocalIPs[inetLocalIPcount][3]=(char)d;
        inetLocalIPcount++;
     }
     else
     {
        printf("MinixWall: Error registering device IP address.\n");
     }
  }
}

/*******************************************************************
 * inetCheckLocalIP                                                *
 *                                                                 *
 * Checks wether the given IP address is a local IP addresses      *
 *                                                                 *
 * Parameters:  int  a                IP address byte 1            *
 *              int  b                IP address byte 2            *
 *              int  c                IP address byte 3            *
 *              int  d                IP address byte 4            *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
int inetCheckLocalIP(int a, int b, int c, int d)
{
   int i;
#ifdef _DEBUG
  printf("inetCheckLocalIP()\n");
#endif
   for (i=0; i<inetLocalIPcount;i++)
   {
      if ( (inetLocalIPs[i][0]==(char)a)&&
           (inetLocalIPs[i][1]==(char)b)&&
           (inetLocalIPs[i][2]==(char)c)&&
           (inetLocalIPs[i][3]==(char)d) )
      {
	 return 1;
      }
   }
   return 0;
}

/*******************************************************************
 * inetEthIn                                                       *
 *                                                                 *
 * Tells netfilter the network interface on which the              *
 * current packet arrived.                                         *
 *                                                                 *
 * Parameters:  char* ethername       ethernet interface name      *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetEthIn(char *ethername)
{
#ifdef _DEBUG
  printf("inetEthIn(): in\n");
#endif
  if( ethername == NULL ){
    strncpy(currInIf,"",31);
#ifdef _DEBUG
    printf("inetEthIn(): ethername was NULL\n");
#endif
  }else{
  strncpy(currInIf,(char*)ethername,31);
  }
  clearBuffers(&currData);
  if (afterData) { free(afterData); afterData=NULL; };
#ifdef _DEBUG
  printf("inetEthIn(): out\n");
#endif
}

/*******************************************************************
 * inetEthOut                                                      *
 *                                                                 *
 * Tells netfilter the network interface on which the              *
 * current packet leaves.                                          *
 *                                                                 *
 * Parameters:  char* ethername       ethernet interface name      *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetEthOut(char *ethername)
{
#ifdef _DEBUG
  printf("inetEthOut(): in\n");
#endif
  if( ethername == NULL ){
    strncpy(currOutIf,"",31);
#ifdef _DEBUG
    printf("inetEthOut(): enthername was NULL\n");
#endif
  }else{
    strncpy(currOutIf,(char*)ethername,31);
  }
  clearBuffers(&currData);
  if (afterData) { free(afterData); afterData=NULL; };
#ifdef _DEBUG
  printf("inetEthOut(): out\n");
#endif
}

/*******************************************************************
 * inetSetPackSize                                                 *
 *                                                                 *
 * Tells netfilter the network packet size of currently arrived    *
 * packet.                                                         *
 *                                                                 *
 * Parameters:  int size              network packet length        *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetSetPackSize(int size)
{
#ifdef _DEBUG
  printf("inetSetPackSizeze()\n");
#endif
  currPackSize=size;
}

/*******************************************************************
 * inetSetDataSize                                                 *
 *                                                                 *
 * Prepares netfilter to fetch a number of data bytes              *
 *                                                                 *
 * Parameters:  int size              data buffer length           *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetSetDataSize(int size)
{
#ifdef _DEBUG
  printf("inetSetDataSize()\n");
#endif
  currDataSize=size;
}

/*******************************************************************
 * inetGetDataSize                                                 *
 *                                                                 *
 * Gets the size of the last block                                 *
 *                                                                 *
 * Parameters:  -                                                  *
 *                                                                 *
 * Returns:     int                  number of bytes               * 
 *                                                                 *
 *******************************************************************/
int inetGetDataSize(void)
{
#ifdef _DEBUG
  printf("inetGetDataSize()\n");
#endif
  return currDataSize;
}

/*******************************************************************
 * inetData                                                        *
 *                                                                 *
 * Transfers a data block from the outer space to the buffer       *
 *                                                                 *
 * Parameters:  char *address        address of the buffer         *
 *                                                                 *
 * Returns:     int                  0: OK                         * 
 *                                   1: out of memory              *
 *                                                                 *
 *******************************************************************/
int inetData(char *address)
{
#ifdef _DEBUG
  printf("inetData()\n");
#endif
  if (!appendBuffer(&currData,address,currDataSize))
  {
    printf("nfcore.c: inetData(): out of memory\n");
    return 0;
  }
  return 1;
}

/*******************************************************************
 * inetHook                                                        *
 *                                                                 *
 * Sets the hook which the network filter passes                   *
 *                                                                 *
 * Parameters:  unsigned int hooknum   hook number                 *
 *                                       NF_IP_PRE_ROUTING         *
 *                                       NF_IP_LOCAL_IN            *
 *                                       NF_IP_FORWARD             *
 *                                       NF_IP_LOCAL_OUT           *
 *                                       NF_IP_POST_ROUTING        *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetHook(unsigned int hook)
{
#ifdef _DEBUG
  printf("inetHook()\n");
#endif
  hooknum=hook;
}

/*******************************************************************
 * inetGetData                                                     *
 *                                                                 *
 * Gets the manipulated packet back                                *
 *                                                                 *
 * Parameters:  char **address       returned buffer               *
 *                                                                 *
 * Returns:     int                  size of the data buffer       * 
 *                                                                 *
 *******************************************************************/
int inetGetData(char *address)
{
#ifdef _DEBUG
  printf("inetGetData()\n");
#endif
  currInIf[0]=0;
  currOutIf[0]=0;
  currLayerID=-1;
  hooknum=-1; currDataSize = getTotalBufSize(&currData);
  /* copy the output buffer to the caller */
  if (address != NULL) memcpy(address,afterData,currDataSize);
  if (afterData) { free(afterData); afterData=NULL; };
  return currDataSize;
}

/*******************************************************************
 * inetContainLayers                                               *
 *                                                                 *
 * Sets the beginning of the header of the network packet          *
 *                                                                 *
 * Parameters:  int layerid          layer to begin with           *
 *                                     NF_LAYER_ETH  ethernet l.   *
 *                                     NF_LAYER_IP   IP layer      *
 *                                                                 *
 * Returns:     -                                                  * 
 *                                                                 *
 *******************************************************************/
void inetContainLayers(int layerid)
{
#ifdef _DEBUG
  printf("inetContainLayers()\n");
#endif
  currLayerID = layerid;
}

/*******************************************************************
 * inetProcess                                                     *
 *                                                                 *
 * Let the firewall do its' work. F                                *
 *                                                                 *
 * Parameters:  -                                                  *
 *                                                                 *
 * Returns:     int                       verdict of the firewall  * 
 *                                                                 *
 *******************************************************************/
int inetProcess(void)
{
  struct sk_buff *pskb=NULL;
  struct net_device in;
  struct net_device out;
  char *targinfo=NULL;
  void *matchinfo=NULL;
  void *userinfo=NULL;
  char *tempDataBuf=NULL;
  int verdict=IPT_CONTINUE;
  int hotdrop=0;
  int tabnum=0;
  int i;
  int offset;
  struct ipt_chain *chain,*lastchain;
#ifdef _DEBUG
  printf("inetProcess(): in\n");
#endif
  /* bond all data snipsets of current data buffer for use for a sk_buff */
  tempDataBuf = (char*) malloc(getTotalBufSize(&currData) * sizeof(char));

#ifdef _DEBUG
  printf("inetProcess(): currData.size: %d\n",currData.size);
  printf("             : currData->data: %08x\n",&currData.data);
  printf("             : currData->next: %08x\n",&currData.next);
  printf("             : currData groesse: %d\n",getTotalBufSize(&currData));
#endif

  if (tempDataBuf == NULL)
  {
    printf("nfcore.c: inetProcess(): tempDataBuf: out of memory while \
allocating %d bytes\n", getTotalBufSize(&currData) * sizeof(char));
    return -1;
  }

#ifdef _DEBUG
#endif

  bondBuffers(tempDataBuf,&currData);

  /* prepare layers to be processed */
  pskb=(struct sk_buff*)malloc(sizeof(struct sk_buff));
  if (pskb == NULL)
  {
    free (tempDataBuf);
    printf("nfcore.c: inetProcess(): pskb: out of memory while allocating \
%d bytes\n", sizeof(struct sk_buff));
    return -1;
  }
  strcpy(in.name,currInIf);
  strcpy(out.name,currOutIf);
  pskb->dev=&in;
 
  offset=0;
  switch (currLayerID)
  {
    case NF_LAYER_ETH:
         pskb->dev->hard_header_len = sizeof(struct eth_hdr);
         pskb->mac.raw = (void*)(tempDataBuf);
         pskb->nh.raw = (void*)(tempDataBuf + sizeof(struct eth_hdr));
         pskb->h.raw = (void*)(tempDataBuf + sizeof(struct eth_hdr) +
                                             sizeof(struct ip_hdr));
	 break;
    case NF_LAYER_IP:
         pskb->dev->hard_header_len = 0;
         pskb->mac.raw = (void*)(tempDataBuf);
         pskb->nh.raw = (void*)(tempDataBuf);
         pskb->h.raw = (void*)(tempDataBuf + sizeof(struct ip_hdr));
         break;
  }

  /* for all 3 tables */
  for ( tabnum=0; tabnum<3; tabnum++ )
  {
    char hookName[32]="";
    struct ipt_table *table;
    //struct iot_chain *chin;

    /* set table to be used */
    switch (tabnum)
    {
      case 0 : table=&tab_mangle; break;
      case 1 : table=&tab_nat;    break;
      case 2 : table=&tab_filter; break;
      default: table=NULL;        break;
    }

    /* select current hook */
    switch (hooknum)
    {
      case NF_IP_PRE_ROUTING :  strcpy (hookName, "PREROUTING");  break;
      case NF_IP_LOCAL_IN    :  strcpy (hookName, "INPUT");       break;
      case NF_IP_FORWARD     :  strcpy (hookName, "FORWARD");     break;
      case NF_IP_POST_ROUTING:  strcpy (hookName, "POSTROUTING"); break;
      case NF_IP_LOCAL_OUT   :  strcpy (hookName, "OUTPUT");      break;
      default                :  printf ("netfilter.c: inetProcess(): \
wrong Hook number"); break;
    }

#ifdef _DEBUG
    printf("Hook:%s, processing %s:\n", hookName,table->name);
    printf("-------------------------\n");
#endif
    chain=getChain(table,hookName);

    if (chain != NULL)
    {
      lastchain=chain;
      verdict=IPT_CONTINUE;
      /* go through the entries */
      for ( i=0; (i<MAX_ENTRIES_PER_CHAIN)&&(!hotdrop)&&(verdict<0); i++ )
      {
        if (chain->entry[i]!=NULL)
	{
#ifdef _DEBUG
	  printf("%s[%d]: ", chain->name, i);
#endif

          /* inspect IP information */
          if (match_mods[0]->match(pskb,
                                   &in,
                                   &out,
                                   &chain->entry[i]->ip,
                                   offset,
                                   pskb->nh.iph,
                                   currPackSize,
                                   &hotdrop))
	  {
#ifdef _DEBUG
	    printf("IP match, ");
#endif
	    matchinfo=chain->entry[i]->l3match;

            /* check for protocol specific information */
	    if (chain->entry[i]->match!=NULL)
	    {
              if (chain->entry[i]->match->match(pskb,
                                                &in,
                                                &out,
                                                matchinfo,
                                                offset,
                                                pskb->h.raw,
                                                currPackSize,
                                                &hotdrop))
	      {
		targinfo=chain->entry[i]->targinfo;
#ifdef _DEBUG
	        printf("L3 match, ");
#endif

                /* increment packet and byte counters */
	        chain->entry[i]->counters.pcnt++;
	        chain->entry[i]->counters.bcnt+=getTotalBufSize(&currData);

                /* execute the target function and get verdict */
	        verdict=chain->entry[i]->target->target(&pskb,
                                                        hooknum,
                                                        &in,
                                                        &out,
                                                        targinfo,
                                                        userinfo);
#ifdef _DEBUG
	        printf("verdict=%d\n",verdict);
#endif
	      } 
	    }
	    else
	    {
              /* increment packet and byte counters */
	      chain->entry[i]->counters.pcnt++;
	      chain->entry[i]->counters.bcnt+=getTotalBufSize(&currData);

              /* execute the target function and get verdict */
	      verdict=chain->entry[i]->target->target(&pskb,
                                                      hooknum,
                                                      &in,
                                                      &out,
                                                      targinfo,
                                                      userinfo);
#ifdef _DEBUG
	      printf("verdict=%d\n",verdict);
#endif
	    }
	  }
	}
	else i=MAX_ENTRIES_PER_CHAIN;
#ifdef _DEBUG
	printf("\n");
#endif
      }
    }
#ifdef _DEBUG
    printf("-------------------------\n");
#endif
  }
  /* hot drop ! */
  if (hotdrop) verdict=NF_DROP;

  /* If none verdict was spoken, the chain policy (verdict) is taken */
  if ((verdict < 0)&&(lastchain)) verdict=lastchain->defaultverdict;

  /* prepare the output buffer */
  afterData = malloc(getTotalBufSize(&currData));
  if (afterData == NULL)
  {
    free(pskb);
    free(tempDataBuf);
    printf("nfcore.c: inetProcess(): afterData: out of memory while allocating \
%d bytes\n", getTotalBufSize(&currData));
    return -1;
  }
  memcpy(afterData,pskb,getTotalBufSize(&currData));
  free(pskb);
  free(tempDataBuf);
#ifdef _DEBUG
  printf("Final verdict=%d \n",verdict);
#endif
  return verdict;
}

/*******************************************************************
 * iptablesNewChain                                                *
 *                                                                 *
 * Create a new chain in a given table and register a hook for it. *
 *                                                                 *
 * Parameters:  struct ipt_table *table      Table to put chain in *
 *              char *name                   chain name            *
 *              int policy                   firewall policy for   *
 *                                           this chain            *
 *                                             NF_ACCEPT           *
 *                                             (pass packet)       *
 *                                             NF_DROP             *
 *                                             (eat packet)        *
 *                                             IPT_RETURN          *
 *                                             (return to caller   *
 *                                              chain - NOT USED   *
 *                                              FOR BUILTIN ONES)  *
 *              int builtin                  1=built-in chain      *
 *                                           0=user chain          *
 *              int hooknum                  hook number to        *
 *                                           register chain to     *
 *                                                                 *
 * Returns:     int error code               0:OK                  *
 *                                           1:Chain already in    *
 *                                             table               *
 *                                           2:out of memory       *
 *                                                                 *
 *******************************************************************/
int iptablesNewChain(const struct ipt_table *table,
                     const char *name,
		     int policy,
		     int builtin,
		     int hooknum)
{
#ifdef _DEBUG
  printf("iptablesNewChain()\n");
#endif
   if (chainExists(table,name))
   {
     return 1;
   }
   else
   {
     struct ipt_chain *newchain;

     newchain=(struct ipt_chain*) malloc(sizeof(struct ipt_chain));
     strncpy(newchain->name,name,IPT_CHAIN_MAXNAMELEN);
     newchain->entry=(struct ipt_entry**)malloc((MAX_ENTRIES_PER_CHAIN+1)*
                                         sizeof(struct ipt_entry*));
     if (newchain->entry == NULL)
     {
       printf("nfcore.c: iptablesNewChain(): out of memory while allocating \
%d bytes\n", (MAX_ENTRIES_PER_CHAIN+1)*sizeof(struct ipt_entry*));
       return 2;
     }
     newchain->entry[0]=NULL;
     newchain->defaultverdict=policy;
     list_add((struct list_head*)newchain,(struct list_head*)&table->list);
     if (builtin) printf("MinixWall: Initialized built-in chain %s:%s\n",table->name,name);
             else printf("MinixWall: Added chain %s:%s\n",table->name,name);
   }
   return 0;
}


int chainExists(const struct ipt_table *table, const char *name)
{
#ifdef _DEBUG
  printf("chainExists()\n");
#endif
  if ( getChain( table, name )) return 1;
  return 0;
}

struct ipt_chain *getChain(const struct ipt_table *table, const char *name)
{
#ifdef _DEBUG
  printf("getChain()\n");
#endif
  if (!list_empty((struct list_head*)&table->list))
  {
    struct list_head *pos;

    /* search for chain in given table by name */
    list_for_each(pos,&table->list)
    {
      if ( strcmp( ((struct ipt_chain*)pos)->name,name)==0 )
      { 
	return (struct ipt_chain*)pos;
      }
    }
  }
  return NULL;
}

int iptablesSelectTable(enum nftable table)
{
#ifdef _DEBUG
  printf("iptablesSelectTable()\n");
#endif
  switch(table)
  {
    case NF_TABLE_FILTER:
		      selectedTable=&tab_filter;
		      break;
    case NF_TABLE_NAT:
		      selectedTable=&tab_nat;
		      break;
    case NF_TABLE_MANGLE:
		      selectedTable=&tab_mangle;
		      break;
    default:
		      printf("nfcore: iptablesSelectTable(): invalid table: %d\n",table);
		      return 0;
  }
  return 1;
}

int iptablesSelectChain(char *name)
{
#ifdef _DEBUG
  printf("iptablesSelectChain()\n");
#endif
  if ( !chainExists( selectedTable, name ) ) return 0;
  selectedChain= getChain( selectedTable, name);
  return 1;
}

int iptablesSelectL3Match(char *name)
{
  int i;
#ifdef _DEBUG
  printf("iptablesSelectL3Match()\n");
#endif
  selectedL3Match=NULL;
  for (i=0; i<matchmodcounter; i++)
  {
    if (strcmp(match_mods[i]->name,name)==0)
    {
      selectedL3Match=match_mods[i];
      return 1;
    }
  }
  printf("Match %s not found.\n",name);
  return 0;
}

int iptablesSelectTarget(char *name)
{
  int i;
#ifdef _DEBUG
  printf("iptablesSelectTarget()\n");
#endif
  selectedTarget=NULL;
  for (i=0; i<targetmodcounter; i++)
  {
    if (strcmp(target_mods[i]->name,name)==0)
    {
      selectedTarget=target_mods[i];
      return 1;
    }
  }
  jumpChain=getChain(selectedTable,name);
  if (jumpChain != NULL) return 1;

  return 0;
}

int iptablesSetL3MatchInfo(void *matchinfo)
{
#ifdef _DEBUG
  printf("iptablesSetL3MatchInfo()\n");
#endif
  memcpy(&L3MatchInfo,matchinfo,MATCHINFO_MAXSIZE);
  return 1;
}

int iptablesSetIPMatchInfo(void *matchinfo)
{
#ifdef _DEBUG
  printf("iptablesSetIPMatchInfo()\n");
#endif
  memcpy(&IPMatchInfo,matchinfo,sizeof(struct ipt_ip));
  return 1;/* match_mods[0]->checkentry(selectedTable->name,&IPMatchInfo,
				  &IPMatchInfo,sizeof(struct ipt_ip),0);*/
}

int iptablesSetTargInfo(void *targinfo)
{
#ifdef _DEBUG
  printf("iptablesSetTargInfo()\n");
#endif
  memcpy(&targetInfo,targinfo,TARGINFO_MAXSIZE);
  return 1; /*selectedTarget->checkentry(selectedTable->name,NULL,
	                           targinfo,TARGINFO_MAXSIZE,0);*/
}

int addEntry(struct ipt_chain *chain, struct ipt_entry *entry)
{
  int i;
#ifdef _DEBUG
  printf("addEntry()\n");
#endif
  for (i=0; (i<MAX_ENTRIES_PER_CHAIN) && (chain->entry[i]!=NULL); i++);
  if (i < MAX_ENTRIES_PER_CHAIN)
  {
    chain->entry[i]=entry;
    chain->entry[i+1]=NULL;
    printf("MinixWall: Entry added: chain=%s, pos=%d, src=%d.%d.%d.%d/%d.%d.%d.%d, \
dst=%d.%d.%d.%d/%d.%d.%d.%d, proto=%d, target=%s\n",
	    chain->name,
	    i,
	    NIPQUAD(entry->ip.src.s_addr),
	    NIPQUAD(entry->ip.smsk.s_addr),
	    NIPQUAD(entry->ip.dst.s_addr),
	    NIPQUAD(entry->ip.dmsk.s_addr),
	    entry->ip.proto,
	    entry->target->name
	  );
    return 1;
  }
  return 0;
}

int delEntry(struct ipt_chain *chain, int index)
{
  int i;
#ifdef _DEBUG
  printf("delEntry()\n");
#endif
  for (i=0; (i<MAX_ENTRIES_PER_CHAIN) && (chain->entry[i]!=NULL); i++)
  {
    if (i==index)
    {
      printf("MinixWall: Entry removed: chain=%s, pos=%d, src=%d.%d.%d.%d/%d.%d.%d.%d, \
dst=%d.%d.%d.%d/%d.%d.%d.%d, proto=%d, target=%s\n",
	    chain->name,
	    i,
	    NIPQUAD(chain->entry[i]->ip.src.s_addr),
	    NIPQUAD(chain->entry[i]->ip.smsk.s_addr),
	    NIPQUAD(chain->entry[i]->ip.dst.s_addr),
	    NIPQUAD(chain->entry[i]->ip.dmsk.s_addr),
	    chain->entry[i]->ip.proto,
	    chain->entry[i]->target->name
            );
      /* remove the entry */
      free(chain->entry[i]->l3match);
      free(chain->entry[i]->targinfo);
      free(chain->entry[i]);
      /* move the following entries one up */
      for (; (i<MAX_ENTRIES_PER_CHAIN-1) && (chain->entry[i]!=NULL); i++)
      {
	chain->entry[i]=chain->entry[i+1];
      }
      chain->entry[MAX_ENTRIES_PER_CHAIN-1]=NULL;
      return 1;
    }
  }
  return 0;
}
  
int iptablesAppendRule()
{
  struct ipt_entry *newentry;
#ifdef _DEBUG
  printf("iptablesAppendRule()\n");
#endif
  newentry=(struct ipt_entry*) malloc(sizeof(struct ipt_entry));
  memcpy(&newentry->ip,&IPMatchInfo,sizeof(struct ipt_ip));
  newentry->l3match=(void*)malloc(MATCHINFO_MAXSIZE);
  memcpy(newentry->l3match,&L3MatchInfo,MATCHINFO_MAXSIZE);
  newentry->targinfo=(void*)malloc(TARGINFO_MAXSIZE);
  memcpy(newentry->targinfo,&targetInfo,TARGINFO_MAXSIZE);
  newentry->nfcache=0;
  newentry->comefrom=0;
  newentry->counters.pcnt=0;
  newentry->counters.bcnt=0;
  newentry->jumpchain=jumpChain;
  newentry->match=selectedL3Match;
  newentry->target=selectedTarget;
  addEntry(selectedChain,newentry);
  return 0;
}

int iptablesDeleteRule(index)
int index;
{
#ifdef _DEBUG
  printf("iptablesDeleteRule()\n");
#endif
  return delEntry(selectedChain,index);
}

int iptablesFlushChain( void )
{
#ifdef _DEBUG
  printf("iptablesFlushChain()\n");
#endif
   while (delEntry(selectedChain,0));
   return 1;
}
	
int iptablesZeroCounters( void )
{
   int i;
#ifdef _DEBUG
  printf("iptablesZeroCounters()\n");
#endif
   for (i=0; (i<MAX_ENTRIES_PER_CHAIN) && (selectedChain->entry[i]!=NULL); i++)
   {
     selectedChain->entry[i]->counters.pcnt=0;
     selectedChain->entry[i]->counters.bcnt=0;
   }
   return 1;
}
	
int iptablesSetPolicy( policy )
int policy;
{
#ifdef _DEBUG
  printf("iptablesSetPolicy()\n");
#endif
  selectedChain->defaultverdict=policy;
  return 1;
}

/* Register Target */
int
ipt_register_target(struct ipt_target *target)
{
#ifdef _DEBUG
  printf("ipt_register_target()\n");
#endif
  printf("MinixWall: target registered: %s\n",target->name);
  target_mods[targetmodcounter++]=target;
  return targetmodcounter;
}

/* Unregister Target */
void
ipt_unregister_target(struct ipt_target *target)
{
#ifdef _DEBUG
  printf("ipt_unregister_target\n");
#endif
}

/* Register Match */
int
ipt_register_match(struct ipt_match *match)
{
  printf("MinixWall: match registered: %s\n",match->name);
  match_mods[matchmodcounter++]=match;
  return matchmodcounter;
}

/* Unregister Match */
void
ipt_unregister_match(struct ipt_match *match)
{
#ifdef _DEBUG
  printf("ipt_unregister_match\n");
#endif
}
