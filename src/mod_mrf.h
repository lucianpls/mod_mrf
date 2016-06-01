/*
* mod_mrf header file
* Lucian Plesea
* (C) 2016
*/

#if !defined(MOD_MRF_H)
#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_core.h>
#include <http_main.h>
#include <http_request.h>
#include <http_log.h>

#include <apr.h>
#include <apr_lib.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_uri.h>
#include <apr_portable.h>

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#define APR_WANT_BYTEFUNC
#include <apr_want.h>

#if defined(WIN32)
#define CMD_FUNC (cmd_func)
#endif

#if defined(APLOG_USE_MODULE)
APLOG_USE_MODULE(mrf);
#endif

typedef struct {
    char *the_mrf;     // The mrf file name
} mrf_conf;

extern module AP_MODULE_DECLARE_DATA mrf_module;

#endif