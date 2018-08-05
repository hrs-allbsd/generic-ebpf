.CURDIR?=	$(PWD)
UNAME_s!=	uname -s
SHLIB_FreeBSD=	.so
SHLIB_Linux=	.so
SHLIB_Darwin=	.dylib
SHLIB=		$(SHLIB_$(UNAME_s))

KMODLOAD_FreeBSD=	kldload
KMODUNLOAD_FreeBSD=	kldunload
KMODLOAD_Linux=		insmod
KMODUNLOAD_Linux=	rmmod
KMODLOAD=	$(KMODLOAD_$(UNAME_s))
KMODUNLOAD=	$(KMODUNLOAD_$(UNAME_s))

CC?=		cc

GTESTPATH?=	${BASE}/extern/googletest
GTESTOBJS?=	${GTESTPATH}/googletest/make/gtest_main.o \
		${GTESTPATH}/googletest/make/gtest-all.o

LIBEBPFDIR?=	${BASE}/${UNAME_s}/ebpf/user
LIBEBPF=	${LIBEBPFDIR}/libebpf${SHLIB}
EBPFKMODDIR?=	${BASE}/${UNAME_s}/ebpf/kernel
EBPFDEVKMODDIR?=${BASE}/${UNAME_s}/ebpf_dev
LIBGBPFDIR?=	${BASE}/tools/libgbpf
LIBGBPF=	${LIBGBPFDIR}/libgbpf.a
VMISA_H=	${BASE}/sys/sys/ebpf_vm_isa.h
VMISA_C=	${BASE}/sys/dev/epbf/ebpf_vm_isa.c

#DEBUG_FLAGS=	-g -DDEBUG_VERBOSE
DEBUG_FLAGS=	-g

CXXFLAGS+=	${DEBUG_FLAGS}
CFLAGS+=	${DEBUG_FLAGS}

MAKE_CMD=	env ${MAKE_ENV} ${MAKE} ${.MAKEFLAGS} ${MAKE_ARGS}

all:
clean:
	rm -f ${CLEANFILES}
.PHONY:	all clean

${LIBEBPF}:
	cd $(LIBEBPFDIR) && ${MAKE_CMD} libebpf${SHLIB}
${LIBGBPF}:
	cd $(LIBGBPFDIR) && ${MAKE_CMD} libgbpf.a
${GTESTPATH}/googletest/make/gtest_main.o:
	cd $(GTESTPATH)/googletest/make && ${MAKE_CMD} gtest_main.o
${GTESTPATH}/googletest/make/gtest-all.o:
	cd $(GTESTPATH)/googletest/make && ${MAKE_CMD} gtest-all.o
${VMISA_H}: ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def \
	${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk
	cd ${BASE}/sys/sys && ${MAKE_CMD} ebpf_vm_isa.h
ebpf_vm_isa.h: ebpf_vm_isa.def ebpf_vm_isa.awk
	awk -v defineonly=1 -f ${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk \
	    < ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def > $@
${VMISA_C}: ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def \
	${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk
	cd ${BASE}/sys/sys && ${MAKE_CMD} ebpf_vm_isa.c
ebpf_vm_isa.c: ebpf_vm_isa.def ebpf_vm_isa.awk
	awk -v defineonly=0 -f ${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk \
	    < ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def > $@
CLEANFILES+=	${VMISA_H} ${VMISA_C}
