mod_auth_netgroups.la: mod_auth_netgroups.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_netgroups.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_auth_netgroups.la
