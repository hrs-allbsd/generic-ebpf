.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf_dev

TARGET!=uname -m
IDENT!=	uname -i

CFLAGS+=-I$(KSRC)/sys/$(TARGET)/compile/$(IDENT) \
	-I../../ \
	-Wall \
	-std=c99

KMOD=	ebpf-dev
SRCS+=	ebpf_dev_freebsd.c \
	ebpf_dev.c

realinstall:
	cp ebpf-dev.ko $(DESTDIR)

.include <bsd.kmod.mk>
