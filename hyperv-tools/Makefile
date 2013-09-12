# $FreeBSD$

PORTNAME=	hyperv-tools
PORTVERSION=	1.0
CATEGORIES=	kld
MASTER_SITES=	https://github.com/FreeBSDonHyper-V/Hyperv-Ports/raw/packages/hyperv-tools/

MAINTAINER=	v-savar@microsoft.com
COMMENT=	Hyper-V Drivers

FETCH_ARGS=	-Fpr

CC=clang
CXX=clang++
CPP=clang-cpp

ONLY_FOR_ARCHS=	amd64 i386

pre-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL

post-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL

post-deinstall:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGDEINSTALL} ${PKGNAME} POST-DEINSTALL

.include <bsd.port.mk>
