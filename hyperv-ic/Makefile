# $FreeBSD$

PORTNAME=	hyperv-ic
PORTVERSION=	1.0
CATEGORIES=	kld
MASTER_SITES=	https://github.com/FreeBSDonHyper-V/Hyperv-Ports/raw/packages/hyperv-ic/

MAINTAINER=	bsdic@microsoft.com
COMMENT=	Hyper-V Integration Components

FETCH_ARGS=	-Fpr

CC?=clang
CXX?=clang++
CPP?=clang-cpp

ONLY_FOR_ARCHS=	amd64 i386

.include <bsd.port.pre.mk>

.if ${OSVERSION} != 901000
BROKEN=	Only for FreeBSD 9.1 Release
.endif

pre-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL

post-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL

post-deinstall:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGDEINSTALL} ${PKGNAME} POST-DEINSTALL

.include <bsd.port.post.mk>
