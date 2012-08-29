# Makefile for the minix netfilter

# directories
u = /usr
i = $u/include
s = $i/sys
m = $i/minix
b = $i/ibm
d = ..

# programs, flags, etc.
CFLAGS = -I$i -Iinclude
#LDFLAGS = -i
LDFLAGS = 
LIBS = -lsys -lutil

TARGOBJS = targets/ipt_ACCEPT.o targets/ipt_DROP.o targets/ipt_LOG.o
MATCHOBJS = matches/ipt_IP.o matches/ipt_TCP.o matches/ipt_UDP.o matches/ipt_ICMP.o matches/ipt_ANY.o


# build netfilter code
all build:  nf_ioctl_cmd iptables/iptables
nf_ioctl_cmd:	_matches _targets nf_ioctl_cmd.c buffer.o nfcore.o 
	$(CC) -c $(CFLAGS) nf_ioctl_cmd.c

buffer.o: buffer.c include/buffer.h
	$(CC) -c $(CFLAGS) buffer.c

nfcore.o: nfcore.c include/nfcore.h
	$(CC) -c $(CFLAGS) nfcore.c

iptables/iptables: 
	cd iptables ; $(MAKE) all

_matches: 
	cd matches ; $(MAKE) all

_targets: 
	cd targets ; $(MAKE) all

# install with other drivers
install:	_targets netfilter iptables/iptables
	cd iptables ; $(MAKE) install
	install -o root -c netfilter /usr/sbin/netfilter
	[ -c /dev/netfilter ] || mknod /dev/netfilter c 20 0

# clean up local files
clean:
	cd matches ; $(MAKE) clean
	cd targets ; $(MAKE) clean
	cd iptables ; $(MAKE) clean
	rm -f *.o *.bak netfilter netfilter.exe

depend: 
	/usr/bin/mkdep "$(CC) -E $(CPPFLAGS)" *.c > .depend

# Include generated dependencies.
include .depend

