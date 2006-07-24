mod_auth_redirssl.la: mod_auth_redirssl.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_redirssl.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_auth_redirssl.la
