# Makefile for the minix netfilter

# directories
u = /usr
i = $u/include
s = $i/sys
m = $i/minix
b = $i/ibm
d = ..

# programs, flags, etc.
CFLAGS = -I$i -I../include
LDFLAGS = -i
LIBS =

# build local binary
all build:  iptables
iptables:	iptables.o 
	$(CC) -o $@ $(LDFLAGS) iptables.o $(LIBS)

iptables.o: iptables.c
	$(CC) -c $(CFLAGS) iptables.c

# install
install: iptables
	install -o root -c iptables /usr/sbin/iptables

# clean up local files
clean:
	rm -f *.o *.bak iptables iptables.exe


