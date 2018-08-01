.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf ${.CURDIR}/../../$(MACHINE)/$(MACHINE_ARCH)

IDENT!=	uname -i

CFLAGS+=-I$(KSRC)/sys/$(MACHINE)/compile/$(IDENT) \
	-I../../ \
	-Wall \
	-std=c99

KMOD=	ebpf

CORES+=	ebpf_obj.c \
	ebpf_freebsd.c \
	ebpf_loader.c \
	ebpf_verifer.c \
	ebpf_vm.c \
	ebpf_prog.c \
	ebpf_allocator.c \
	ebpf_map.c

MAPS+=	ebpf_map_bad.c \
	ebpf_map_array.c \
	ebpf_map_hashtable.c

.if $(MACHINE) == "amd64"
CORES+=	ebpf_jit_x86_64.c
.endif

SRCS=	$(CORES) $(MAPS)

realinstall:
	install ebpf.ko $(DESTDIR)

.include <bsd.kmod.mk>
