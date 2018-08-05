BASE=	../../..
.include <bsd.own.mk>

.PATH: ${BASE}/sys/dev/ebpf ${BASE}/sys/$(MACHINE)/$(MACHINE_ARCH)

IDENT!=	uname -i

CFLAGS+=-I$(KSRC)/sys/$(MACHINE)/compile/$(IDENT) \
	-I${BASE}/sys \
	-I${BASE} \
	-Wall \
	-std=c99

KMOD=	ebpf

CORES+=	ebpf_obj.c \
	ebpf_freebsd.c \
	ebpf_loader.c \
	ebpf_verifer.c \
	ebpf_vm_isa.c \
	ebpf_vm.c \
	ebpf_prog.c \
	ebpf_allocator.c \
	ebpf_map.c

MAPS+=	ebpf_map_bad.c \
	ebpf_map_array.c \
	ebpf_map_hashtable.c

ebpf_verifier.o: ${VMISA_H}
ebpf_vm.o: ${VMISA_H}

.if $(MACHINE) == "amd64"
CORES+=	ebpf_jit_x86_64.c
.endif

SRCS=	$(CORES) $(MAPS)

realinstall:
	install ebpf.ko $(DESTDIR)

.include <bsd.kmod.mk>
