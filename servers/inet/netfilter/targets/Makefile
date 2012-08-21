INCLUDE = ../include
CFLAGS = -I$(INCLUDE)
TARGETS = ipt_ACCEPT.o ipt_DROP.o ipt_LOG.o

all build: $(TARGETS)
clean:
	rm -f *.o *.obj

ipt_ACCEPT.o: ipt_ACCEPT.c ipt_ACCEPT.h
	$(CC) -c $(CFLAGS) ipt_ACCEPT.c

ipt_DROP.o: ipt_DROP.c ipt_DROP.h
	$(CC) -c $(CFLAGS) ipt_DROP.c

ipt_LOG.o: ipt_LOG.c ipt_LOG.h
	$(CC) -c $(CFLAGS) ipt_LOG.c
