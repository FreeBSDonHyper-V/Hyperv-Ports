# $FreeBSD: head/emulators/hyperv-is/Makefile 370396 2014-10-07 20:27:29Z marino $

USES=		kmod uidfix
.include <bsd.port.pre.mk>

PORTNAME=	hyperv-is
PORTVERSION=	1.1
PORTREVISION=	2
CATEGORIES=	emulators
.if ${OSREL} ==	"10.1" 
MASTER_SITES=	https://github.com/junfangV/hyperv-is-test/raw/master/ports/
.else
MASTER_SITES=	https://github.com/${MSLINK}/
.endif
DISTNAME=	${DNAME}

MAINTAINER=	bsdic@microsoft.com
COMMENT=	FreeBSD Integration Service on Hyper-v

ONLY_FOR_ARCHS=	amd64 i386

.if ${OSREL} ==	"10.1" 
KMODDIR = /boot/kernel/
.endif

#USES=		kmod uidfix
BIS=		${PORTVERSION}
MSBASE=		FreeBSDonHyper-V/Hyperv-Ports/raw/hyperv-is-master
MSLINK=		${MSBASE}/BIS-${BIS}/FreeBSD-${OSREL}/ports
MAKE_ARGS=	BINDIR=${PREFIX}/sbin MANDIR=${PREFIX}/man/man
PKGMESSAGE=	${FILESDIR}/${PMSG}


FILE_84=	hyperv-is-8.4.${BIS}
FILE_91=	hyperv-is-9.1.${BIS}
FILE_92=	hyperv-is-9.2.${BIS}
FILE_93=	hyperv-is-9.3.${BIS}
FILE_100=	hv-kvp-${BIS}
FILE_101=	hyperv-is-10.1.${BIS}
DNAME=		${FILE_${OSREL:S/.//}}

.if empty(DNAME)
IGNORE=	 needless to install on FreeBSD-${OSREL}  
.endif

.if ${OSREL} ==	"10.1" 
PREFIX= /usr/
.endif

.if ${OPSYS} != FreeBSD
IGNORE=		${OPSYS} not supported
.endif

.if ${OSREL} == "10.0"
BIS=		1.0
PLIST_SUB=	A="@comment " B="" C="@comment " 
PMSG=		pkg-message.B
.else
.if ${OSREL} ==	"10.1" 
WRKSRC=		${WRKDIR}/hyperv-is-${PORTVERSION}
PLIST_SUB=	A="@comment " B="@comment " C=""
PMSG=		pkg-message.C
.else
CC=		gcc -w
WRKSRC=		${WRKDIR}/hyperv-is-${PORTVERSION}
PLIST_SUB=	C="@comment " B="@comment " A=""
PMSG=		pkg-message.A
.endif
.endif



post-patch:
.if ${OSREL} !=	"10.1" 
	@${REINPLACE_CMD} -e "s,/usr/sbin/,${PREFIX}/sbin/,g" \
		${WRKSRC}/etc/rc.d/hv_kvpd
.endif

pre-install:
.if ${OSREL} ==	"10.1" 
	@${MKDIR} ${STAGEDIR}${PREFIX} \
	     ${STAGEDIR}/var/db/hyperv/scripts
.else
	@${MKDIR} ${STAGEDIR}${PREFIX} \
	        ${STAGEDIR}/etc/rc.d \
		${STAGEDIR}/usr/local/hyperv/scripts
.endif

post-install:
.if ${OSREL} !=	"10.1" 
	${RM} ${STAGEDIR}/boot/kernel/linker.hints
	${MV} ${STAGEDIR}/etc/rc.d/* ${STAGEDIR}${PREFIX}/etc/rc.d
.if ${PREFIX} != /usr/local
	${MV} ${STAGEDIR}/usr/local/* ${STAGEDIR}${PREFIX}
.endif
.endif

.include <bsd.port.post.mk>
