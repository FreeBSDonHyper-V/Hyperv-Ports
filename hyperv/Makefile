# $FreeBSD$

PORTNAME=	hyperv
PORTVERSION=	1.0
CATEGORIES=	kld
MASTER_SITES=	https://github.com/FreeBSDonHyper-V/Hyperv-Ports/raw/packages/hyperv/

MAINTAINER=	v-savar@microsoft.com
COMMENT=	Hyper-V Drivers

FETCH_ARGS=	-Fpr

# Need to add check for FreeBSD 9.1 RELEASE Only
CC=clang
CXX=clang++
CPP=clang-cpp

MAN1 =		hyperv.1

ONLY_FOR_ARCHS=	amd64 i386

pre-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL

post-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL
	@${INSTALL_MAN} ${WRKSRC}/docs/hyperv.1 ${PREFIX}/man/man1/hyperv.1

post-deinstall:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGDEINSTALL} ${PKGNAME} POST-DEINSTALL

.include <bsd.port.mk>
