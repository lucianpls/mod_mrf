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

struct sz {
    apr_int64_t x, y, z, c;
};

typedef struct {
    // The mrf data file name
    char *datafname;     
    // The mrf index file name
    char *idxfname;
    // Forced mime-type, default is autodetected
    char *mime_type;
    // Full raster size in pixels
    struct sz size;
    // Page size in pixels
    struct sz pagesize;
    // Empty tile, if provided
    apr_uint32_t *empty;
    apr_int64_t esize;
    apr_off_t eoffset;

    // ETag support
    apr_uint64_t seed;

} mrf_conf;

extern module AP_MODULE_DECLARE_DATA mrf_module;

#endif