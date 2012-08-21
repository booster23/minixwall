INCLUDE = ../include
CFLAGS = -I$(INCLUDE)
MATCHES = ipt_IP.o ipt_TCP.o ipt_UDP.o ipt_ICMP.o ipt_ANY.o

all build: $(MATCHES)
clean:
	rm -f *.o *.obj

ipt_IP.o: ipt_IP.c ipt_IP.h
	$(CC) -c $(CFLAGS) ipt_IP.c

ipt_TCP.o: ipt_TCP.c ipt_TCP.h
	$(CC) -c $(CFLAGS) ipt_TCP.c

ipt_UDP.o: ipt_UDP.c ipt_UDP.h
	$(CC) -c $(CFLAGS) ipt_UDP.c

ipt_ICMP.o: ipt_ICMP.c ipt_ICMP.h
	$(CC) -c $(CFLAGS) ipt_ICMP.c

ipt_ANY.o: ipt_ANY.c ipt_ANY.h
	$(CC) -c $(CFLAGS) ipt_ANY.c
