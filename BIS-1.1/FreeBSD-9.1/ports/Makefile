# $FreeBSD$
USES+=uidfix
#NO_STAGE="YES"
PORTNAME=	hyperv-ic
PORTVERSION=	1.0
CATEGORIES=	kld
MASTER_SITES=	https://github.com/FreeBSDonHyper-V/Hyperv-Ports/raw/hyperv-ic-master/BIS-1.0/FreeBSD-9.1/ports/

MAINTAINER=	bsdic@microsoft.com
COMMENT=	Hyper-V Integration Service 

FETCH_ARGS=	-Fpr

CC=clang
CXX=clang++
CPP=clang-cpp

ONLY_FOR_ARCHS=	amd64 i386

pre-install:
	@PKG_PREFIX=${STAGEDIR}${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL

post-install:
	${STRIP_CMD} ${STAGEDIR}/boot/kernel/*.ko
	@PKG_PREFIX=${STAGEDIR}${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL
post-deinstall:
	@PKG_PREFIX=${STAGEDIR}${PREFIX} ${SH} ${PKGDEINSTALL} ${PKGNAME} POST-DEINSTALL

.include <bsd.port.mk>
