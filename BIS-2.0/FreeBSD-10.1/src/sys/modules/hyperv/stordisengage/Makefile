#$FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/hyperv/stordisengage

KMOD=	 hv_ata_pci_disengage

SRCS =	hv_ata_pci_disengage.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_ata.h ata_if.h

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include
#DEBUG_FLAGS+= -g

.include <bsd.kmod.mk>
