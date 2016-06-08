/*
* mod_mrf header file
* Lucian Plesea
* (C) 2016
*/

#if !defined(MOD_MRF_H)
#include <httpd.h>
#include <http_config.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_core.h>
#include <http_request.h>
#include <http_log.h>

#include <apr_strings.h>

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include <apr_want.h>

#if defined(WIN32)
#define CMD_FUNC (cmd_func)
#endif

// signatures in big endian, to autodetect tile type
#define PNG_SIG 0x89504e47
#define JPEG_SIG 0xffd8ffe0
#define LERC_SIG 0x436e745a

// This one is not a type, just an encoding
#define GZIP_SIG 0x436e745a

// Conversion to and from network order, endianess depenent

#if (APR_IS_BIGENDIAN == 0) // Little endian
#if defined(WIN32) // Windows
#define ntoh32(v) _byteswap_ulong(v)
#define hton32(v) _byteswap_ulong(v)
#define ntoh64(v) _byteswap_uint64(v)
#define hton64(v) _byteswap_uint64(v)
#else // Assume linux
#define ntoh32(v) __builtin_bswap32(v)
#define hton32(v) __builtin_bswap32(v)
#define ntoh64(v) __builtin_bswap64(v)
#define hton64(v) __builtin_bswap64(v)
#endif
#else // Big endian, do nothing
#define ntoh32(v)  (v)
#define ntoh64(v)  (v)
#define hton32(v)  (v)
#define hton64(v)  (v)
#endif

#if defined(APLOG_USE_MODULE)
APLOG_USE_MODULE(mrf);
#endif

struct sz {
    apr_int64_t x, y, z, c;
};

struct rset {
    apr_off_t offset;
    // in tiles
    int width;
    // in tiles
    int height;
};

typedef struct {
    apr_uint64_t offset;
    apr_uint64_t size;
} TIdx;

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

    // Levels to skip at the top
    int skip_levels;
    int n_levels;
    struct rset *rsets;

    // Empty tile, if provided
    apr_uint32_t *empty;
    apr_int64_t esize;
    apr_off_t eoffset;

    // Turns the module functionality off
    int enabled;

    // ETag initializer
    apr_uint64_t seed;

} mrf_conf;

extern module AP_MODULE_DECLARE_DATA mrf_module;

#endif