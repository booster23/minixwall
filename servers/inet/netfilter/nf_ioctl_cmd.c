/*
 *  MINIX-3 network filter - execute IP tables commands
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
 *  -----
 *
 * The driver supports the following operations (using message format m2):
 *
 *    m_type      DEVICE    IO_ENDPT     COUNT    POSITION  ADRRESS
 * ----------------------------------------------------------------
 * |  DEV_OPEN  | device  | proc nr |         |         |         |
 * |------------+---------+---------+---------+---------+---------|
 * |  DEV_CLOSE | device  | proc nr |         |         |         |
 * |------------+---------+---------+---------+---------+---------|
 * |  DEV_READ  | device  | proc nr |  bytes  |         | buf ptr |
 * |------------+---------+---------+---------+---------+---------|
 * |  DEV_WRITE | device  | proc nr |  bytes  |         | buf ptr |
 * |------------+---------+---------+---------+---------+---------|
 * |  DEV_IOCTL | device  | proc nr |func code|         | buf ptr |
 * ----------------------------------------------------------------
 *
 * The file contains one entry point:
 *
 *   main:	main entry when driver is brought up
 *	
 */

#include <minix/config.h>
#include <sys/ansi.h>
#include <minix/type.h>
#include <minix/com.h>
#include <minix/dmap.h>
#include <minix/callnr.h>
#include <sys/types.h>
#include <minix/const.h>
#include <minix/syslib.h>
#include <minix/devio.h>
#include <minix/sysutil.h>
#include <minix/bitmap.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h>

#include <nfdefs.h>
#include <nfcore.h>
#include "nf_ioctl_cmd.h"

/*===========================================================================*
 *				nf_ioctl_cmd
 *===========================================================================*/
int nf_ioctl_cmd( request, data)
int request;
void* data;
{
	int ret=0;

	switch(request)
	{
		case IOCTL_IPT_SET_TABLE:
			ret=iptablesSelectTable((enum nftable)*((int*)data));
			break;
		case IOCTL_IPT_SET_CHAIN:
			ret=iptablesSelectChain((char*)data);
			break;
		case IOCTL_IPT_SET_MATCH:
			ret=iptablesSelectL3Match((char*)data);
			break;
		case IOCTL_IPT_SET_TARGET:
			ret=iptablesSelectTarget((char*)data);
			break;
		case IOCTL_IPT_SET_MATCHINFO:
			ret=iptablesSetL3MatchInfo((void*)data);
			break;
		case IOCTL_IPT_SET_IP_MATCHINFO:
			ret=iptablesSetIPMatchInfo((void*)data);
			break;
		case IOCTL_IPT_SET_TARGINFO:
			ret=iptablesSetTargInfo((void*)data);
			break;
		case IOCTL_IPT_APPEND:
			ret=iptablesAppendRule();
			break;
		case IOCTL_IPT_SET_POLICY:
			ret=iptablesSetPolicy((int)*((int*)data));
			break;
		case IOCTL_IPT_INSERT:
			break;
		case IOCTL_IPT_DELETE:
			break;
		case IOCTL_IPT_DELETE_RULE:
                        ret=iptablesDeleteRule((int)*((int*)data));
			break;
		case IOCTL_IPT_FLUSH:
                        ret=iptablesFlushChain();
			break;
		case IOCTL_IPT_ZERO:
                        ret=iptablesZeroCounters();
			break;
		default:
			printf("dev_ioctl: unknown request from iptables: %d\n",
				request);
			break;
	}
	return ret;
}

