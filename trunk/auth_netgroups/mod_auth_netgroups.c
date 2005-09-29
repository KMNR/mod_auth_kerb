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
Name: auth_netgroups
ConfigStart
        case `umr_arch` in
                redhat* | solaris*) 
                        LIBS="$LIBS -lnsl"
                        echo " + adding -lnsl for mod_auth_netgroups"
                        ;;
        esac
ConfigEnd
MODULE-DEFINITION-END
*/

/********
Add to Configuration file:
	AddModule modules/extra/mod_auth_netgroups.o

Usage in auth config files:

	AuthNetgroups on/off

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
 * Structure for the module itself
 */


/*
 * Structure for configuration
 */
typedef struct {
	int enabled;
} auth_netgroups_config_rec;

static void *create_auth_netgroups_config(apr_pool_t *p, char *d)
{
	auth_netgroups_config_rec *conf = ap_pcalloc(p, sizeof(*conf));
	conf->enabled = 0;
	return conf;
}


/*
 * Commands that this module can handle
 */
static const command_rec auth_netgroups_cmds[] = {
	AP_INIT_FLAG("AuthNetgroups", ap_set_flag_slot, 
		(void *) APR_OFFSETOF(auth_netgroups_config_rec, enabled),
		OR_AUTHCFG, 
		"Set to 'yes' to enable checking nis netgroup membership" ),
	{ NULL }
};

module AP_MODULE_DECLARE_DATA auth_netgroups_module;

/*
 * Authenticate a user
 */

int auth_netgroups_checkauth(request_rec * r)
{
    auth_netgroups_config_rec *conf = ap_get_module_config
        (r->per_dir_config, &auth_netgroups_module);

    char *user = r->user;

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;

    int m = r->method_number;
    const char *t;
    char *w;
    char *domain = NULL;
	int x;

    if (!reqs_arr) {
        return OK;
    }
    reqs = (require_line *)reqs_arr->elts;

    if (!conf->enabled)
        return DECLINED;

    for (x = 0; x < reqs_arr->nelts; x++)
    {
        if (!(reqs[x].method_mask & (1 << m)))
            continue;

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        if (!strcmp(w, "group"))
        {
            while (t[0])
            {
                w = ap_getword_white(r->pool, &t);
                if (innetgr(w, NULL, user, NULL))
                {
                    return OK;
                }
            }
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
                "user %s failed (%s): %s", user, reqs[x].requirement, r->uri);
            ap_note_basic_auth_failure(r);
            return HTTP_UNAUTHORIZED;
        }
    }
    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(auth_netgroups_checkauth,NULL,NULL,APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA auth_netgroups_module = {
	STANDARD20_MODULE_STUFF,
	create_auth_netgroups_config, /* dir config creater */
	NULL,                       /* dir merger --- default is to override */
	NULL,                       /* server config */
	NULL,                       /* merge server config */
	auth_netgroups_cmds,                  /* command apr_table_t */
	register_hooks              /* register hooks */
};
