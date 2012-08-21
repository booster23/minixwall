# Makefile for inet.

# Directories
g = generic
n = netfilter

# to compile with debug output: make EXTRA=-D_DEBUG

# Programs, flags, and libraries
CPPFLAGS = -I. -I./netfilter/include -D_MINIX -D__NBSD_LIBC -D_NETBSD_SOURCE $(EXTRA)
CFLAGS = -O -fno-builtin -Wno-sign-compare \
         -I. -I./netfilter/include \
         $(CPPFLAGS) -DARGS\(a\)=a -Wall
LDFLAGS = -static -D_MINIX -D__NBSD_LIBC
LIBS = -lchardriver -lsys -lc -lminlib -lcompat_minix

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

TARGOBJS = $n/targets/ipt_ACCEPT.o \
	$n/targets/ipt_DROP.o \
	$n/targets/ipt_LOG.o

MATCHOBJS = $n/matches/ipt_IP.o \
	$n/matches/ipt_TCP.o \
	$n/matches/ipt_UDP.o \
	$n/matches/ipt_ICMP.o \
	$n/matches/ipt_ANY.o

OBJ = 	buf.o clock.o inet.o inet_config.o \
	mnx_eth.o mq.o qp.o sr.o \
	$g/udp.o $g/arp.o $g/eth.o $g/event.o \
	$g/icmp.o $g/io.o $g/ip.o $g/ip_ioctl.o \
	$g/ip_lib.o $g/ip_read.o $g/ip_write.o \
	$g/ipr.o $g/rand256.o $g/tcp.o $g/tcp_lib.o \
	$g/tcp_recv.o $g/tcp_send.o $g/ip_eth.o \
	$g/ip_ps.o $g/psip.o $g/nf.o $n/nf_ioctl_cmd.o \
	$n/nfcore.o $n/buffer.o \
	queryparam.o

all:	inet iptables

inet:	$(OBJ) ${TARGOBJS} ${MATCHOBJS}
	$(CC) -o $@ $(LDFLAGS) $(OBJ) ${MATCHOBJS} ${TARGOBJS} version.c $(LIBS)

iptables:
	cd $n/iptables ; $(MAKE)

install: inet iptables
	install -c inet /usr/sbin/inet
	install -c $n/iptables/iptables /usr/sbin/iptables

clean:
	rm -f $(OBJ) ${MATCHOBJS} ${TARGOBJS} inet *.bak *.d *.o
	cd $n/iptables ; $(MAKE) clean

depend: 
	touch .depend
	/usr/bin/mkdep -- `which $(CC)` -E $(CPPFLAGS) *.c generic/*.c netfilter/*.c

# Include generated dependencies.
include .depend
