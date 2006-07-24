/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/* The section for the Configure script:
MODULE-DEFINITION-START
Name: auth_redirssl
MODULE-DEFINITION-END
*/

/********
Add to Configuration file:
	LoadModule auth_redirssl_module /path/to/mod_auth_redirssl.so

Note - place that LoadModule line in the config file PRIOR to loading of mod_auth and mod_access.

Usage in auth config files or in Location/Directory section of virtual server:

	AuthRedirSSL on/off

If module is enabled, and the request coming is requires authentication, will redirect to
the SSL server URL for the current virtual host automatically. Note, do not enable this on
the SSL side of the server or else it will never respond to any requests since it will 
enter a redirect loop.

Comments/questions/etc. to nneul@umr.edu

********/

/*
 * External authentication module by nneul@umr.edu
 * Modifications, suggestions, and improvements by <  >
 */

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "ap_compat.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

/*
 * Structure for configuration
 */
typedef struct {
	int enabled;
} auth_redirssl_config_rec;

static void *create_auth_redirssl_config(apr_pool_t *p, char *d)
{
	auth_redirssl_config_rec *conf = ap_pcalloc(p, sizeof(*conf));
	conf->enabled = 0;
	return conf;
}

/*
 * Commands that this module can handle
 */
static const command_rec auth_redirssl_cmds[] = {
	AP_INIT_FLAG("AuthRedirSSL", ap_set_flag_slot, 
		(void *) APR_OFFSETOF(auth_redirssl_config_rec, enabled),
		OR_AUTHCFG, 
		"Set to 'yes' to enable forcing of auth requests to redirect to SSL virtual server" ),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA auth_redirssl_module;

/*
 * Check to see if we should force a redirect
 */

int auth_redirssl_check(request_rec * r)
{
    auth_redirssl_config_rec *conf = ap_get_module_config
        (r->per_dir_config, &auth_redirssl_module);

    if (!conf->enabled)
        return DECLINED;

    if ( ap_auth_type(r) )
    {
        char *target;

	target = apr_pstrcat(r->pool, "https://", r->hostname, r->uri, NULL);

        if (r->args) {
            target = apr_pstrcat(r->pool, target, "?", r->args, NULL);
        }

	apr_table_setn(r->headers_out, "Location", target);
	return HTTP_MOVED_TEMPORARILY;
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_translate_name(auth_redirssl_check,NULL,NULL,APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA auth_redirssl_module = {
	STANDARD20_MODULE_STUFF,
	create_auth_redirssl_config, /* dir config creater */
	NULL,                       /* dir merger --- default is to override */
	NULL,                       /* server config */
	NULL,                       /* merge server config */
	auth_redirssl_cmds,                  /* command apr_table_t */
	register_hooks              /* register hooks */
};
