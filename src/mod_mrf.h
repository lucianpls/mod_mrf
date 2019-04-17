/*
* mod_mrf header file
* Lucian Plesea
* (C) 2016-2019
*/

#if !defined(MOD_MRF_H)
#include <ahtse.h>

struct mrf_conf {
    // array of guard regexp, one of them has to match
    apr_array_header_t *arr_rxp;
    apr_array_header_t *source;
    AHTSE::source_t idx;

    // Forced mime-type, default is autodetected
    char *mime_type;
    // Full raster size in pixels
    AHTSE::sz size;
    // Page size in pixels
    AHTSE::sz pagesize;

    // Levels to skip at the top
    int skip_levels;
    int n_levels;
    AHTSE::rset *rsets;

    AHTSE::storage_manager empty;
    apr_off_t eoffset;

    // Turns the module functionality off
    int enabled;
    // If set, only secondary requests are allowed
    int indirect;

    // Used on remote data, how many times to try
    int tries;

    // ETag initializer
    apr_uint64_t seed;
    // Buffer for the emtpy tile etag
    char eETag[16];
};

extern module AP_MODULE_DECLARE_DATA mrf_module;

#endif
