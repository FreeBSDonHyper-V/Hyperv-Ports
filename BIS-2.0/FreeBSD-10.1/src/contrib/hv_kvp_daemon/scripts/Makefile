# $FreeBSD hyperv-ic Makefile  $

.include <bsd.own.mk>

HV_KVP_DAEMON_DISTDIR?= ${.CURDIR}/../../../../contrib/hv_kvp_daemon
.PATH: ${HV_KVP_DAEMON_DISTDIR}

FILES= hv_get_dhcp_info hv_get_dns_info hv_set_ifconfig

FILESDIR=       /usr/local/hyperv/scripts
FILESMODE=      755

beforeinstall:
	chmod 755 ${HV_KVP_DAEMON_DISTDIR}/kvp-install
	${SH} ${HV_KVP_DAEMON_DISTDIR}/kvp-install PRE-INSTALL

.include <bsd.prog.mk>
