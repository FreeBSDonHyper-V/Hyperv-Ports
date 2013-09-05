# $FreeBSD$

PORTNAME=	hyperv
PORTVERSION=	1.0
#PORTREVISION=	0
#PORTEPOCH=	0
CATEGORIES=	kld
MASTER_SITES=	SF

MAINTAINER=	v-savar@microsoft.com
COMMENT=	Hyper-V Drivers

CC=clang
CXX=clang++
CPP=clang-cpp

MAN1 =		hyperv.1

ONLY_FOR_ARCHS=	amd64 i386

HYPERV_DISTFILES?=${PORTSDIR}/distfiles/

pre-fetch:
	@${ECHO} "Copying the Source to DISTFILES "
	${CP} hyperv-1.0.tar.gz ${HYPERV_DISTFILES}

pre-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL

post-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL
	@${INSTALL_MAN} ${WRKSRC}/docs/hyperv.1 ${PREFIX}/man/man1/hyperv.1

post-deinstall:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGDEINSTALL} ${PKGNAME} POST-DEINSTALL

.include <bsd.port.mk>
