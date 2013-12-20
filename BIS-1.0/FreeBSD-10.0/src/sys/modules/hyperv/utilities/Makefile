# $FreeBSD$

.PATH:	${.CURDIR}/../../../dev/hyperv/utilities

KMOD=	 hv_kvp

SRCS =  hv_kvp.c

SRCS+=	device_if.h bus_if.h

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I${.CURDIR}/../../../dev/hyperv/vmbus

#DEBUG_FLAGS+= -g

.include <bsd.kmod.mk>
