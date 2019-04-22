/*
* An OnEarth module that serves tiles from an MRF
* Lucian Plesea
* (C) 2016-2019
*/

#include <ahtse.h>
#include "receive_context.h"

#include <algorithm>
#include <cmath>
#include <http_log.h>
#include <http_request.h>

#define CMD_FUNC (cmd_func)

using namespace std;
NS_AHTSE_USE

struct mrf_conf {
    // array of guard regexp, one of them has to match
    apr_array_header_t *arr_rxp;

    // The raster represented by this MRF configuration
    TiledRaster raster;

    // At least one source, but there could be more
    apr_array_header_t *source;

    // The MRF index file, required
    vfile_t idx;

    // Used for redirect, how many times to try
    // defaults to 5
    int retries;

    // If set, only secondary requests are allowed
    int indirect;
};

extern module AP_MODULE_DECLARE_DATA mrf_module;

#if defined(APLOG_USE_MODULE)
APLOG_USE_MODULE(mrf);
#endif

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    mrf_conf *c =
        (mrf_conf *)apr_pcalloc(p, sizeof(mrf_conf));
    c->retries = 5;
    return c;
}

static const char *set_regexp(cmd_parms *cmd, mrf_conf *c, 
    const char *pattern)
{
    return add_regexp_to_array(cmd->pool, &c->arr_rxp, pattern);
}

// Parse a comma separated list of sources, add the entries to the array arr
// Source may include offset and size, white space separated
static const char *parse_sources(cmd_parms *cmd, const char *src, 
    apr_array_header_t *arr, bool redir = false)
{
    apr_array_header_t *inputs = tokenize(cmd->temp_pool, src, ',');
    for (int i = 0; i < inputs->nelts; i++) {
        vfile_t *entry = &APR_ARRAY_PUSH(arr, vfile_t);
        memset(entry, 0, sizeof(vfile_t));
        char *input = APR_ARRAY_IDX(inputs, i, char *);

        char *fname = ap_getword_white_nc(arr->pool, &input);
        if (!fname || strlen(fname) < 1)
            return "Missing source name";

        if (redir) { // Check that it is absolute and add :/
            if (fname[0] != '/')
                return apr_pstrcat(cmd->pool, "Only absolute redirects as allowed, ",
                    fname, " is not absolute", NULL);
            fname = apr_pstrcat(arr->pool, ":/", fname, NULL);
        }

        entry->name = fname;

        // See if there are more arguments, should be offset and size
        if (*input != 0) entry->range.offset = strtoull(input, &input, 0);
        if (*input != 0) entry->range.size = strtoull(input, &input, 0);
    }
    return nullptr;
}

#define parse_redirects(cmd, src, arr) parse_sources(cmd, src, arr, true)

static const char *file_set(cmd_parms *cmd, void *dconf, const char *arg)
{
    ap_assert(sizeof(apr_off_t) == 8);
    mrf_conf *c = (mrf_conf *)dconf;
    const char *err_message;
    apr_table_t *kvp = readAHTSEConfig(cmd->temp_pool, arg, &err_message);
    if (NULL == kvp)
        return err_message;

    err_message = configRaster(cmd->pool, kvp, c->raster);
    if (err_message)
        return err_message;

    // Got the parsed kvp table, parse the configuration items
    const char *line;
    c->source = apr_array_make(cmd->pool, 1, sizeof(vfile_t));

    // The DataFile, multiple times, includes redirects
    if ((NULL != (line = apr_table_getm(cmd->temp_pool, kvp, "DataFile"))) &&
        (NULL != (line = parse_sources(cmd, line, c->source))))
        return line;

    // Old style redirects go at the end
    if ((NULL != (line = apr_table_getm(cmd->temp_pool, kvp, "Redirect"))) &&
        (NULL != (line = parse_redirects(cmd, line, c->source))))
        return line;

    line = apr_table_get(kvp, "RetryCount");
    c->retries = 1 + (line ? atoi(line) : 0);
    if ((c->retries < 1) || (c->retries > 100))
        return "Invalid RetryCount value, should be 0 to 99";

    // Index file can also be provided, there could be a default
    line = apr_table_get(kvp, "IndexFile");
    c->idx.name = apr_pstrdup(cmd->pool, line);

    // If an emtpy tile is not provided, it falls through, which results in a 404 error
    // If provided, it has an optional size and offset followed by file name which 
    // defaults to datafile read the empty tile
    // Default file name is the name of the first data file, if provided
    const char *datafname = NULL;
    for (int i = 0; i < c->source->nelts; i++)
        if (NULL != (datafname = APR_ARRAY_IDX(c->source, i, vfile_t).name))
            break;

    const char *efname = datafname;
    line = apr_table_get(kvp, "EmptyTile");
    if (line && strlen(line) && (err_message = readFile(cmd->pool, c->raster.missing.empty, line)))
       return err_message;

    // Set the index file name based on the first data file, if there is only one
    if (!c->idx.name) {
        if (!datafname)
            return "Missing IndexFile or DataFile directive";
        c->idx.name = apr_pstrdup(cmd->pool, datafname);
        char *last;
        char *token = apr_strtok(c->idx.name, ".", &last); // strtok destroys the idxfile
        while (*last != 0 && token != NULL)
            token = apr_strtok(NULL, ".", &last);
        memcpy(c->idx.name, datafname, strlen(datafname)); // Get a new copy
        if (token != NULL && strlen(token) == 3)
            memcpy(token, "idx", 3);
    }

    return NULL;
}

// An open file handle and the matching file name, to be used as a note
struct file_note {
    const char *key;
    apr_file_t *pfh;
};

static const apr_int32_t open_flags = APR_FOPEN_READ | APR_FOPEN_BINARY | APR_FOPEN_LARGEFILE;

// Quiet error
#define REQ_ERR_IF(X) if (X) {\
    return HTTP_BAD_REQUEST; \
}

// Logged error
#define SERR_IF(X, msg) if (X) { \
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", msg);\
    return HTTP_INTERNAL_SERVER_ERROR; \
}

// Return the first source which contains the index, adjusts the index offset if necessary
static const vfile_t *pick_source(const apr_array_header_t *sources, range_t *index) {
    for (int i = 0; i < sources->nelts; i++) {
        vfile_t *source = &APR_ARRAY_IDX(sources, i, vfile_t);
        if ((source->range.offset == 0 && source->range.size == 0)
            || (index->offset >= source->range.offset 
                && (source->range.size == 0
                    || index->offset - source->range.offset + index->size <= source->range.size)))
        {
            index->offset -= source->range.offset;
            return source;
        }
    }
    return NULL;
}

// Like pread, except not really thread safe
static int vfile_pread(request_rec *r, void *ptr, int size, apr_off_t offset, const vfile_t *fh) {
    auto  cfg = get_conf<mrf_conf>(r, &mrf_module);
    const char *name = fh->name;

    bool redirect = (strlen(name) > 3 && name[0] == ':' && name[1] == '/');

    if (redirect) {
        // Remote file, just use a range request
        // TODO: S3 authorized requests

        // Skip the ":/" used to mark a redirect
        name = fh->name + 2;

        ap_filter_rec_t *receive_filter = ap_get_output_filter_handle("Receive");
        if (!receive_filter) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "Can't find receive filter, did you load mod_receive?");
            return 0;
        }

        // Get a buffer for the received image
        receive_ctx rctx;
        rctx.buffer = reinterpret_cast<char *>(ptr);
        rctx.maxsize = size;
        rctx.size = 0;

        // Data file is on a remote site a range request redirect with a range header
        char *Range = apr_psprintf(r->pool,
            "bytes=%" APR_UINT64_T_FMT "-%" APR_UINT64_T_FMT,
            offset, offset + size);

        // S3 may return less than requested, so we retry the request a couple of times
        int tries = cfg->retries;
        bool failed = false;
        apr_time_t now = apr_time_now();
        do {
            request_rec *sr = ap_sub_req_lookup_uri(name, r, r->output_filters);
            apr_table_setn(sr->headers_in, "Range", Range);
            ap_filter_t *rf = ap_add_output_filter_handle(receive_filter, &rctx,
                sr, sr->connection);
            int status = ap_run_sub_req(sr);
            ap_remove_output_filter(rf);
            ap_destroy_sub_req(sr);

            if ((status != APR_SUCCESS || sr->status != HTTP_PARTIAL_CONTENT
                || rctx.size != static_cast<int>(size))
                && (0 == tries--))
            {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Can't fetch data from %s, took %" APR_TIME_T_FMT "us",
                    name, apr_time_now() - now);
                failed = true;
            }
        } while (!failed && rctx.size != static_cast<int>(size));

        return rctx.size;
    }

    // Local file, open, seek, read, close
    apr_pool_t *pool = r->pool;
    apr_file_t *pfh;
    apr_status_t stat = apr_file_open(&pfh, name, open_flags, 0, pool);
    if (stat != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "Can't open file %s", name);
            return 0; // No read
    }

    apr_size_t sz = size;
    try {
        stat = apr_file_seek(pfh, APR_SET, &offset);
        if (stat != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "Seek error in %s offset %" APR_OFF_T_FMT, name, offset);
            sz = 0;
            throw 0; // No read
        }

        sz = size;
        stat = apr_file_read(pfh, ptr, &sz);
    }
    catch (int &e) {
        sz = e;
        apr_file_close(pfh); // Close the file
    }

    // return whatever was read
    return static_cast<int>(sz);
}

// Indirect read of index, returns error message or null
static const char *read_index(request_rec *r, range_t *idx, apr_off_t offset) {
    auto  cfg = get_conf<mrf_conf>(r, &mrf_module);
    static int size = sizeof(range_t);

    if (size != vfile_pread(r, idx, size, offset, &cfg->idx))
        return "Read error";

    idx->offset = be64toh(idx->offset);
    idx->size = be64toh(idx->size);
    return nullptr;
}

static int handler(request_rec *r) {
    if (r->args || r->method_number != M_GET)
        return DECLINED;

    auto cfg = get_conf<mrf_conf>(r, &mrf_module);
    if ((cfg->indirect && !r->main) || !requestMatches(r, cfg->arr_rxp))
        return DECLINED;

    apr_array_header_t *tokens = tokenize(r->pool, r->uri, '/');
    if (tokens->nelts < 3)
        return DECLINED; // At least Level Row Column

    // Use a xyzc structure, with c being the level
    // Input order is M/Level/Row/Column, with M being optional
    sz tile;
    memset(&tile, 0, sizeof(tile));

    // Need at least three numerical arguments
    tile.x = apr_atoi64(*(char **)apr_array_pop(tokens)); REQ_ERR_IF(errno);
    tile.y = apr_atoi64(*(char **)apr_array_pop(tokens)); REQ_ERR_IF(errno);
    tile.l = apr_atoi64(*(char **)apr_array_pop(tokens)); REQ_ERR_IF(errno);

    const TiledRaster &raster(cfg->raster);

    // We can ignore the error on this one, defaults to zero
    // The parameter before the level can't start with a digit for an extra-dimensional MRF
    if (raster.size.z != 1 && tokens->nelts)
        tile.z = apr_atoi64(*(char **)apr_array_pop(tokens));

    // Don't allow access to levels less than zero, send the empty tile instead
    if (tile.l < 0)
        return sendEmptyTile(r, raster.missing);

    tile.l += raster.skip;
    // Check for bad requests, outside of the defined bounds
    REQ_ERR_IF(tile.l >= raster.n_levels);
    rset *level = raster.rsets + tile.l;
    REQ_ERR_IF(tile.x >= level->w || tile.y >= level->h);

    // Offset of the index entry for this tile
    apr_off_t tidx_offset = level->offset +
        sizeof(range_t) * (tile.x + level->w * (tile.z * level->h + tile.y));

    range_t index;
    const char *message;
    SERR_IF((message = read_index(r, &index, tidx_offset)),
        message);

    // MRF index record is in network order
    if (index.size < 4) // Need at least four bytes for signature check
        return sendEmptyTile(r, raster.missing);

    if (MAX_TILE_SIZE < index.size) { // Tile is too large, log and send error code
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Tile too large in %s", 
            cfg->idx.name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // Check for conditional ETag here, no need to get the data
    char ETag[16];
    // Try to distribute the bits a bit to generate an ETag
    tobase32(raster.seed ^ (index.size << 40) ^ index.offset, ETag);
    if (etagMatches(r, ETag)) {
        apr_table_set(r->headers_out, "ETag", ETag);
        return HTTP_NOT_MODIFIED;
    }

    // Now for the data part
    const vfile_t *src = pick_source(cfg->source, &index);
    const char *name = (src && src->name) ? src->name : nullptr;
    if (!name)
        SERR_IF(true, apr_psprintf(r->pool, "No data file configured for %s", r->uri));

    apr_size_t size = static_cast<apr_size_t>(index.size);
    storage_manager img(apr_palloc(r->pool, size), size);

    SERR_IF(img.buffer,
        "Memory allocation error in mod_mrf");
    SERR_IF(img.size != vfile_pread(r, img.buffer, img.size, index.offset, src),
        "Data read error");

    // Looks fine, set the outgoing etag and then the image
    apr_table_set(r->headers_out, "ETag", ETag);
    return sendImage(r, img);
}

static const command_rec cmds[] = {
    AP_INIT_FLAG(
    "MRF_Indirect",
    CMD_FUNC ap_set_flag_slot,
    (void *)APR_OFFSETOF(mrf_conf, indirect),
    ACCESS_CONF,
    "If set, this configuration only responds to subrequests"
    ),

    AP_INIT_TAKE1(
    "MRF_RegExp",
    (cmd_func)set_regexp,
    0, // Self-pass argument
    ACCESS_CONF, // availability
    "Regular expression that the URL has to match.  At least one is required."
    ),

    AP_INIT_TAKE1(
    "MRF_ConfigurationFile",
    CMD_FUNC file_set, // Callback
    0, // Self-pass argument
    ACCESS_CONF, // availability
    "The configuration file for this module"
    ),

    { NULL }
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA mrf_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    0, // No dir_merge
    0, // No server_config
    0, // No server_merge
    cmds, // configuration directives
    register_hooks // processing hooks
};
