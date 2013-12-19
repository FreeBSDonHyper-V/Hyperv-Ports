# $FreeBSD$

.PATH:	${.CURDIR}/../../../dev/hyperv/utilities

KMOD=	 hv_utils

SRCS =  hv_util.c hv_kvp.c
SRCS+=	device_if.h bus_if.h

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I${.CURDIR}/../../../dev/hyperv/vmbus \
	 -I${.CURDIR}/../../../dev/hyperv/netvsc

#DEBUG_FLAGS+= -g

.include <bsd.kmod.mk>
