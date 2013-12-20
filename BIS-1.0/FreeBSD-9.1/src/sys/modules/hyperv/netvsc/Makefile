#$FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/hyperv/netvsc

KMOD=	hv_netvsc

SRCS=	hv_net_vsc.c \
	hv_netvsc_drv_freebsd.c \
	hv_rndis_filter.c
SRCS+=	device_if.h bus_if.h

CFLAGS+=-I${.CURDIR}/../../../dev/hyperv/include \
	-I${.CURDIR}/../../../dev/hyperv/netvsc

#DEBUG_FLAGS+= -g

.include <bsd.kmod.mk>
