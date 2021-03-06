
# Makefile for arch-dependent kernel code
.include <bsd.own.mk>

.PATH:	${.CURDIR}/arch/${ARCH}
SRCS+=	arch_do_vmctl.c \
	arch_clock.c \
	do_int86.c \
	do_iopenable.c \
	do_readbios.c \
	do_sdevio.c \
	exception.c \
	i8259.c \
	io_inb.S \
	io_inl.S \
	io_intr.S \
	io_inw.S \
	io_outb.S \
	io_outl.S \
	io_outw.S \
	klib.S \
	klib16.S \
	multiboot.S \
	memory.c \
	oxpcie.c \
	protect.c \
	arch_system.c \
	pre_init.c

.ifdef CONFIG_SMP
SRCS += arch_smp.c trampoline.S
.endif


