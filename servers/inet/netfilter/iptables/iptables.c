/*
 *  MINIX-3 network filter - firewall control tool
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <nfdefs.h>
#include <ip_tables.h>
#include <../targets/ipt_LOG.h>
#include <net/gen/in.h>
#include <net/gen/inet.h>

#define PROTO_ANY 0
#define PROTO_TCP 6
#define PROTO_ICMP 1
#define PROTO_UDP 17
#define __IPTVERSION__ "0.0.4beta"

enum tokenSelect {T_NONE, T_TABLENAME, T_CHAINNAME, T_SOURCE, T_DEST, \
                  T_TARGET, T_INSERT, T_APPEND, T_CREATE, T_DELETE, \
		  T_DELETENUM, \
		  T_REMOVE, T_FLUSH, T_INIF, T_OUTIF, T_PROTO, T_TARGETOPTS, \
                  T_ZERO, T_PROTOOPTS, T_FRAG, T_POLICY, T_POLICYNAME};
enum protTokenSelect {P_NONE, P_SPORT, P_DPORT, P_ICMPTYPE, P_ICMPCODE};
enum targTokenSelect {J_NONE, J_LOGPREFIX};
enum actionSelect {A_NONE, A_APPEND, A_CREATE, A_DELETE, A_INSERT, \
                   A_REMOVE, A_FLUSH, A_ZERO, A_POLICY};

enum tokenSelect token;
enum actionSelect action;
enum protTokenSelect prottoken;
enum targTokenSelect targtoken;
int tokenOption;
int tableset, protoset;

void printHelp( void )
{
   printf("iptables: [-t <tab>] <-[ADINFXZ]> <chain> [-p <proto>] [opts] -j <target> [opts]\n");
   printf("\n");
   printf("          actions: -A <chain>          append to chain\n");
   printf("                   -D <chain> <n>      delete rule\n");
   printf("                   -I <chain> <n>      insert rule at position\n");
   printf("                   -N <chain>          create user chain\n");
   printf("                   -F <chain>          flush chain\n");
   printf("                   -X <chain>          remove (empty) user chain\n");
   printf("                   -Z <chain>          reset all counters in chain\n");
   printf("                   -P <chain> <policy> set the policy for a chain\n");
   printf("\n");
   printf("          options: -s [!] ipaddr/mask  source IP range\n");
   printf("                   -d [!] ipaddr/mask  destination IP range\n");
   printf("                   -f [!] 1            fragmented packet match\n");
   printf("                   -i [!] in_iface     incoming interface\n");
   printf("                   -o [!] out_iface    outgoing interface\n");
   printf("                   --sport [!] <a:b>   source port range (tcp,udp)\n");
   printf("                   --dport [!] <a:b>   destination port range (tcp,udp)\n");
   printf("                   --icmp-type a [b:c] icmp type/code\n");
   printf("\n");
   printf("          LOG:     --log-prefix <str>  logging prefix string\n");
   printf("\n");
   printf("MinixWall - The Internet firewall for MINIX - ");
   printf("Version ");
   printf(__IPTVERSION__);
   printf("\nby Brian Schueler <bschueler@beuth-hochschule.de>\n");
}

void setAction(enum actionSelect act)
{
  if (action==A_NONE) { action = act; return; }
  printf("action error\n");
  exit(2);
}

void setToken(enum tokenSelect tkn)
{
  if (token==T_NONE) { tokenOption=0; token = tkn; return; }
  printf("option error\n");
  exit(2);
}

void setProtToken(enum protTokenSelect tkn)
{
  if (prottoken==P_NONE) { tokenOption=0; prottoken = tkn; return; }
  printf("match info option error\n");
  exit(2);
}

void setTargToken(enum targTokenSelect tkn)
{
  if (targtoken==P_NONE) { tokenOption=0; targtoken = tkn; return; }
  printf("target info option error\n");
  exit(2);
}

int setIF(char *interface, char *name)
{
  if (strlen(interface)==0)
  {
    strncpy(interface,name,32);
    return 1;
  }
  return 0;
}

unsigned char b2m(int bits)
{
  int i=128;
  int ret=0;
  while (i>=1)
  {
    if (bits > 0) ret+=i;
    bits--;
    i=i/2;
  }
  return ret;
}

int setIP(in_addr_t *ipaddr, in_addr_t *mask, char *name)
{
  char ip[32]="";
  char m[32]="";

  memset(ip,0,32);
  memset(m,0,32);
  if (index(name,'/'))
  {
     strncpy(ip,name,(index(name,'/')-name));
     strcpy(m,index(name,'/')+1);
     if ( !inet_aton(ip,ipaddr) )
     {
       printf("invalid IP address: %s\n",ip);
       exit(2);
     }
     if ( strlen(m)<3 )
     {
       int maskbits=atoi(m);
       int j;

       if ( (maskbits<0) || (maskbits>32) )
       {
         printf("invalid mask bit size: %d\n",maskbits);
         exit(2);
       }
       for (j=0;j<4;j++)
       {
	 ((char*)mask)[j]=b2m(maskbits-8*j);
       }
     }
     else
     {
       if ( !inet_aton(m,mask) )
       {
         printf("invalid network mask: %s\n",m);
         exit(2);
       }
     }
  }
  else
  {
     if ( !inet_aton(name,ipaddr) )
     {
       printf("invalid IP address: %s\n",name);
       exit(2);
     }
     inet_aton("255.255.255.255",mask);
  }
  return 1;
}

int setRange(unsigned short *start, unsigned short *end, char *name)
{
  char s[32]="";
  char e[32]="";

  memset(s,0,32);
  memset(e,0,32);
  if (index(name,':'))
  {
     strncpy(s,name,(index(name,':')-name));
     strcpy(e,index(name,':')+1);
     *start=atoi(s);
     *end=atoi(e);
  }
  else
  {
     strncpy(s,name,32);
     *start=atoi(s);
     *end=atoi(s);
  }
  return 1;
}

void setPolicy(int *policy, char *pol)
{
  if (strlen(pol)==0)
  {
    printf("no policy given\n");
    exit(2);
  }
  if (strcmp(pol,"ACCEPT")==0) { *policy=NF_ACCEPT; return; }
  if (strcmp(pol,"DROP")==0) { *policy=NF_DROP; return; }
  printf("unknown policy: %s\n",pol);
  exit(2);
}

void setChainName(char *chain, char *name)
{
  if (strlen(chain)==0)
  {
    strncpy(chain,name,32);
    return;
  }
  printf("chain parameter misuse\n");
}

void setTargetName(char *target, char *name)
{
  if (strlen(target)==0)
  {
    strncpy(target,name,32);
    return;
  }
  printf("target parameter misuse\n");
  exit(2);
}

void setTable(int *table, char *name)
{
  if (tableset)
  {
    printf("table parameter misuse\n");
    exit(2);
  }
  tableset=1;
  if ( strcmp(name,"filter") == 0 ) { *table=NF_TABLE_FILTER; return; };
  if ( strcmp(name,"nat") == 0 )    { *table=NF_TABLE_NAT; return; };
  if ( strcmp(name,"mangle") == 0 ) { *table=NF_TABLE_MANGLE; return; };
  printf("no such table: %s\n",name);
  exit(2);
}

void setProto(int *proto, char *name)
{
  if (protoset)
  {
    printf("proto parameter misuse\n");
    exit(2);
  }
  protoset=1;
  if ( strcmp(name,"tcp") == 0 )  { *proto=PROTO_TCP; return; };
  if ( strcmp(name,"udp") == 0 )  { *proto=PROTO_UDP; return; };
  if ( strcmp(name,"icmp") == 0 ) { *proto=PROTO_ICMP; return; };
  if ( strcmp(name,"any") == 0 ) { *proto=PROTO_ANY; return; };
  printf("no such protocol: %s\n",name);
  exit(2);
}

int main (int argc, char **argv)
{
  int fd;
  struct ipt_tcp      tcp_matchinfo;
  struct ipt_udp      udp_matchinfo;
  struct ipt_ip       ip_matchinfo;
  struct ipt_icmp     icmp_matchinfo;
  struct ipt_log_info log_targinfo;
  int i;

  int table=NF_TABLE_FILTER;     /* def: filter table */
  char chainName[32]="";         /* chain name must be set */
  in_addr_t source;     
  in_addr_t sourcemask;
  int sourceinv=0;               /* def: no intversion */
  in_addr_t dest;     
  in_addr_t destmask;
  int destinv=0;                 /* def: no inverseion */
  int proto=PROTO_ANY;           /* def: any protocol */
  char inif[32]="";              /* def: any input device */
  int inifinv=0;                 /* def: no inversion */
  char outif[32]="";             /* def: any output device */
  int outifinv=0;                /* def: no inversion */
  char target[32]="";            /* target must be set */
  int insertpos=1;               /* def: insert on first position */
  int fragment=0;                /* def: fragment or not */
  int fragmentinv=0;             /* def: no inversion */
  char matchName[32]="ANY";

  int policy=-1;

  unsigned short sport_start=0;    /* source port beginning */
  unsigned short sport_end=65535;  /* source port end */
  int sportinv=0;
  unsigned short dport_start=0;    /* destination port beginning */
  unsigned short dport_end=65535;  /* destination port end */
  int dportinv=0;
  unsigned short icmptype=0;
  unsigned short icmpcode_start=0;
  unsigned short icmpcode_end=0;
  int icmpinv=0;
  
  char logprefix[30]="";           /* Logging prefix */
  
  int targoptsindex=0;
  int protooptsindex=0;
  int protooptsindexend=0;
  int deleteindex=0;

  source=inet_addr("0.0.0.0");
  sourcemask=inet_addr("0.0.0.0");
  dest=inet_addr("0.0.0.0");
  destmask=inet_addr("0.0.0.0");
  action=A_NONE;
  token=T_NONE;
  prottoken=P_NONE;
  tableset=0;
  protoset=0;

  if (argc<=1) { printHelp(); exit(0); }
  for (i=1;i<argc;i++)
  {
    tokenOption=1;    /* to be unset by setToken */

    /* Actions */
    if (strcmp(argv[i],"-A")==0) { setAction(A_APPEND); setToken(T_APPEND); }
    if (strcmp(argv[i],"-I")==0) { setAction(A_INSERT); setToken(T_INSERT); }
    if (strcmp(argv[i],"-N")==0) { setAction(A_CREATE); setToken(T_CREATE); }
    if (strcmp(argv[i],"-X")==0) { setAction(A_REMOVE); setToken(T_REMOVE); }
    if (strcmp(argv[i],"-D")==0) { setAction(A_DELETE); setToken(T_DELETE); }
    if (strcmp(argv[i],"-F")==0) { setAction(A_FLUSH); setToken(T_FLUSH); }
    if (strcmp(argv[i],"-Z")==0) { setAction(A_ZERO); setToken(T_ZERO); }
    if (strcmp(argv[i],"-P")==0) { setAction(A_POLICY); setToken(T_POLICY); }

    /* IP options */
    if (strcmp(argv[i],"-t")==0) { setToken(T_TABLENAME); }
    if (strcmp(argv[i],"-s")==0) { setToken(T_SOURCE); }
    if (strcmp(argv[i],"-d")==0) { setToken(T_DEST); }
    if (strcmp(argv[i],"-f")==0) { setToken(T_FRAG); }
    if (strcmp(argv[i],"-p")==0) { setToken(T_PROTO); }
    if (strcmp(argv[i],"-i")==0) { setToken(T_INIF); }
    if (strcmp(argv[i],"-o")==0) { setToken(T_OUTIF); }
    if (strcmp(argv[i],"-j")==0) { setToken(T_TARGET); }

    /* protocol related options */
    if (strcmp(argv[i],"--sport")==0) { setProtToken(P_SPORT); }
    if (strcmp(argv[i],"--dport")==0) { setProtToken(P_DPORT); }
    if (strcmp(argv[i],"--icmp-type")==0) { setProtToken(P_ICMPTYPE); }

    /* target related options */
    if (strcmp(argv[i],"--log-prefix")==0) { setTargToken(J_LOGPREFIX); }

    if (tokenOption)
    {
      if (token == T_NONE)
      {
        printf("unknown parameter: %s\n",argv[i]);
        exit(1);
      }
      if (token == T_TABLENAME)
      {
        setTable(&table,argv[i]);
        token=T_NONE;
      }

      if (token == T_ZERO)
      {
        setChainName(chainName,argv[i]);
        token=T_NONE;
      }

      if (token == T_APPEND)
      {
        setChainName(chainName,argv[i]);
        token=T_NONE;
      }

      if (token == T_FLUSH)
      {
        setChainName(chainName,argv[i]);
        token=T_NONE;
      }

      if (token == T_DELETENUM)
      {
        deleteindex=atoi(argv[i]);
	if (deleteindex<=0)
	{
	  printf("illegal delete index\n");
	  exit(2);
	}
        token=T_NONE;
      }

      if (token == T_DELETE)
      {
        setChainName(chainName,argv[i]);
        token=T_DELETENUM;
      }

      if (token == T_POLICYNAME)
      {
        setPolicy(&policy,argv[i]);
        token=T_NONE;
      }

      if (token == T_POLICY)
      {
	if (i==argc-1)
	{
	  printf("policy argument needed\n");
	  exit(2);
	}
        setChainName(chainName,argv[i]);
        token=T_POLICYNAME;
      }

      if (token == T_TABLENAME)
      {
        if (action!=A_NONE)
        {
          printf("table option must be the first parameter\n");
          exit(2);
        }
        setTable(&table,argv[i]);
        token=T_NONE;
      }

      if (token == T_FRAG)
      {
        if (strcmp(argv[i],"!")==0) { fragmentinv=!fragmentinv; }
        else
        {
          fragment=atoi(argv[i]);
          token=T_NONE;
        }
      }

      if (token == T_SOURCE)
      {
        if (strcmp(argv[i],"!")==0) { sourceinv=!sourceinv; }
        else
        {
          setIP(&source,&sourcemask,argv[i]);
          token=T_NONE;
        }
      }

      if (token == T_DEST)
      {
        if (strcmp(argv[i],"!")==0) { destinv=!destinv; }
        else
        {
          setIP(&dest,&destmask,argv[i]);
          token=T_NONE;
        }
      }

      if (token == T_INIF)
      {
        if (strcmp(argv[i],"!")==0) { inifinv=!inifinv; }
        else
        {
          setIF(inif,argv[i]);
          token=T_NONE;
        }
      }

      if (token == T_OUTIF)
      {
        if (strcmp(argv[i],"!")==0) { outifinv=!outifinv; }
        else
        {
          setIF(outif,argv[i]);
          token=T_NONE;
        }
      }

      if (token == T_PROTO)
      {
        setProto(&proto,argv[i]);
	token=T_PROTOOPTS;
      }

      if (token == T_TARGET)
      {
        setTargetName(target,argv[i]);
	token=T_TARGETOPTS;
      }

      if (token == T_TARGETOPTS)
      {
        if (targoptsindex==0) targoptsindex=i;
	if (targtoken==J_LOGPREFIX) 
	{
	  if (strcmp(target,"LOG")!=0)
	  {
	    printf("option --log-prefix only valid on LOG target\n");
	    exit(2);
	  }
	  strncpy(logprefix,argv[i],30);
	}
      }

      if (token == T_PROTOOPTS)
      {
        if (protooptsindex==0) protooptsindex=i;
	if (prottoken==P_SPORT) 
	{
	  if ((proto!=PROTO_TCP)&&(proto!=PROTO_UDP))
	  {
	    printf("source port range only valid on -p tcp and -p udp\n");
	    exit(2);
	  }
          if (strcmp(argv[i],"!")==0) { sportinv=!sportinv; }
	  else { setRange(&sport_start,&sport_end,argv[i]); }
	}
	if (prottoken==P_DPORT) 
	{
	  if ((proto!=PROTO_TCP)&&(proto!=PROTO_UDP))
	  {
	    printf("destination port range only valid on -p tcp and -p udp\n");
	    exit(2);
	  }
          if (strcmp(argv[i],"!")==0) { dportinv=!dportinv; }
	  else { setRange(&dport_start,&dport_end,argv[i]); }
	}
	if (prottoken==P_ICMPCODE) 
	{
	  setRange(&icmpcode_start,&icmpcode_end,argv[i]);
	  prottoken=P_NONE;
	}
	if (prottoken==P_ICMPTYPE) 
	{
	  if (proto!=PROTO_ICMP)
	  {
	    printf("icmp type only valid on -p icmp\n");
	    exit(2);
	  }
          if (strcmp(argv[i],"!")==0) { icmpinv=!icmpinv; }
	  else { setRange(&icmptype,&icmptype,argv[i]); prottoken=P_ICMPCODE; }
	}
      }

      if ((token == T_PROTOOPTS) && (strncmp(argv[i+1],"-",1)==0) &&
		                    (!strncmp(argv[i+1],"--",2)==0))
      {
        protooptsindexend=i-1;
	token=T_NONE;
      }

    }
  }

  switch (proto)
  {
    case PROTO_TCP: strcpy(matchName,"TCP"); break;
    case PROTO_UDP: strcpy(matchName,"UDP"); break;
    case PROTO_ICMP: strcpy(matchName,"ICMP"); break;
    case PROTO_ANY: strcpy(matchName,"ANY"); break;
    default: break;
  }
  fd=open("/dev/netfilter0",O_RDWR);

  if (fd<=0) {
    printf("could not open netfilter device\n");
    return 1;
  }

  ioctl(fd,IOCTL_IPT_SET_TABLE,NULL);
  write(fd,&table,sizeof(int));
  ioctl(fd,IOCTL_IPT_SET_CHAIN,NULL);
  if (!write(fd,chainName,strlen(chainName)+1))
  {
    printf("no such chain: %s\n",chainName);
    close(fd);
    exit(3);
  };

  ioctl(fd,IOCTL_IPT_SET_MATCH,NULL);
  if (!write(fd,matchName,strlen(matchName)+1))
  {
    printf("no such match: %s\n",matchName);
    close(fd);
    exit(3);
  };

  memcpy(&ip_matchinfo.src,&source,sizeof(in_addr_t));
  memcpy(&ip_matchinfo.smsk,&sourcemask,sizeof(in_addr_t));
  memcpy(&ip_matchinfo.dst,&dest,sizeof(in_addr_t));
  memcpy(&ip_matchinfo.dmsk,&destmask,sizeof(in_addr_t));
  strcpy(ip_matchinfo.iniface,inif);
  strcpy(ip_matchinfo.outiface,outif);
  strcpy((char*)ip_matchinfo.iniface_mask,inif);
  strcpy((char*)ip_matchinfo.outiface_mask,outif);
  ip_matchinfo.proto=proto;
  ip_matchinfo.flags=fragment;
  ip_matchinfo.invflags=(inifinv?IPT_INV_VIA_IN:0) ||
			(outifinv?IPT_INV_VIA_OUT:0) ||
			(sourceinv?IPT_INV_SRCIP:0) ||
			(destinv?IPT_INV_DSTIP:0) ||
			(fragmentinv?IPT_INV_FRAG:0); 

  tcp_matchinfo.spts[0]=sport_start;
  tcp_matchinfo.spts[1]=sport_end;
  tcp_matchinfo.dpts[0]=dport_start;
  tcp_matchinfo.dpts[1]=dport_end;
  tcp_matchinfo.option=0;
  tcp_matchinfo.flg_mask=0;
  tcp_matchinfo.flg_cmp=0;
  tcp_matchinfo.invflags=(sportinv?IPT_TCP_INV_SRCPT:0) ||
                         (dportinv?IPT_TCP_INV_DSTPT:0); 

  udp_matchinfo.spts[0]=sport_start;
  udp_matchinfo.spts[1]=sport_end;
  udp_matchinfo.dpts[0]=dport_start;
  udp_matchinfo.dpts[1]=dport_end;
  udp_matchinfo.invflags=(sportinv?IPT_UDP_INV_SRCPT:0) ||
                         (dportinv?IPT_UDP_INV_DSTPT:0); 

  icmp_matchinfo.type=icmptype;
  icmp_matchinfo.code[0]=icmpcode_start;
  icmp_matchinfo.code[1]=icmpcode_end;
  icmp_matchinfo.invflags=icmpinv;

  if (action==A_APPEND)
  {
    switch(proto)
    {
      case PROTO_TCP:  ioctl(fd,IOCTL_IPT_SET_MATCHINFO,NULL);
                       write(fd,&tcp_matchinfo,sizeof(struct ipt_tcp));
                       break;
      case PROTO_UDP:  ioctl(fd,IOCTL_IPT_SET_MATCHINFO,NULL);
                       write(fd,&udp_matchinfo,sizeof(struct ipt_udp));
                       break;
      case PROTO_ICMP: ioctl(fd,IOCTL_IPT_SET_MATCHINFO,NULL);
                       write(fd,&icmp_matchinfo,sizeof(struct ipt_icmp));
                       break;
      default:         break;
    }
    printf("1. ioctl\n");
    ioctl(fd,IOCTL_IPT_SET_IP_MATCHINFO,NULL);
    printf("1. write\n");
    write(fd,&ip_matchinfo,sizeof(struct ipt_ip));
    printf("2. ioctl\n");
    ioctl(fd,IOCTL_IPT_SET_TARGET,NULL);
    printf("2. write\n");
    if (!write(fd,target,strlen(target)+1))
    {
      printf("no such target: %s\n",target);
      close(fd);
      exit(3);
    }
    strncpy(log_targinfo.prefix, logprefix,30);
    printf("3. ioctl\n");
    ioctl(fd,IOCTL_IPT_SET_TARGINFO,NULL);
    printf("3. write\n");
    write(fd,&log_targinfo,sizeof(log_targinfo));
    printf("4. ioctl\n");
    ioctl(fd,IOCTL_IPT_APPEND,NULL);
    printf("4. write > fd,0,1 <\n");
    write(fd,0,1);
    printf("leaving append_if\n");
  }
  if (action==A_POLICY)
  {
    ioctl(fd,IOCTL_IPT_SET_POLICY,NULL);
    write(fd,&policy,sizeof(policy));
  }
  if (action==A_DELETE)
  {
    ioctl(fd,IOCTL_IPT_DELETE_RULE,NULL);
    deleteindex--;
    if (!write(fd,&deleteindex,sizeof(deleteindex)))
    {
      printf("illegal delete index: %d\n",++deleteindex);
      close(fd);
      exit(3);
    }     
  }
  if (action==A_FLUSH)
  {
    ioctl(fd,IOCTL_IPT_FLUSH,NULL);
    write(fd,0,1);
  }
  if (action==A_ZERO)
  {
    ioctl(fd,IOCTL_IPT_ZERO,NULL);
    write(fd,0,1);
  }

  close(fd);
  return 0;
}

