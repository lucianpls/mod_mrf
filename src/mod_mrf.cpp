/*
* An OnEarth module that serves tiles from an MRF
* Lucian Plesea
* (C) 2016
*/

#include "mod_mrf.h"

#include <algorithm>
#include <cmath>

using namespace std;

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    mrf_conf *c =
        (mrf_conf *)apr_pcalloc(p, sizeof(mrf_conf));
    return c;
}

//
// Tokenize a string into a table
//  
static apr_array_header_t* tokenize(apr_pool_t *p, const char *s, char sep = '/')
{
    apr_array_header_t* arr = apr_array_make(p, 10, sizeof(char *));
    while (sep == *s) s++;
    char *val;
    while (*s && (val = ap_getword(p, &s, sep))) {
        char **newelt = (char **)apr_array_push(arr);
        *newelt = val;
    }
    return arr;
}


// Returns a table read from a file, or NULL and an error message
static apr_table_t *read_pKVP_from_file(apr_pool_t *pool, const char *fname, char **err_message)

{
    // Should parse it here and initialize the configuration structure
    ap_configfile_t *cfg_file;
    apr_status_t s = ap_pcfg_openfile(&cfg_file, pool, fname);

    if (APR_SUCCESS != s) { // %pm means print status error string
        *err_message = apr_psprintf(pool, "%s - %pm", fname, s);
        return NULL;
    }

    char buffer[MAX_STRING_LEN];
    apr_table_t *table = apr_table_make(pool, 8);
    // This can return ENOSPC if lines are too long
    while (APR_SUCCESS == (s = ap_cfg_getline(buffer, MAX_STRING_LEN, cfg_file))) {
        if ((strlen(buffer) == 0) || buffer[0] == '#')
            continue;
        const char *value = buffer;
        char *key = ap_getword_white(pool, &value);
        apr_table_add(table, key, value);
    }

    ap_cfg_closefile(cfg_file);
    if (s == APR_ENOSPC) {
        *err_message = apr_psprintf(pool, "%s lines should be smaller than %d", fname, MAX_STRING_LEN);
        return NULL;
    }

    return table;
}

// Returns NULL if it worked as expected, returns a four integer value from "x y", "x y z" or "x y z c"
static char *get_xyzc_size(apr_pool_t *p, struct sz *size, const char *value, const char*err_prefix) {
    char *s;
    if (!value)
        return apr_psprintf(p, "%s directive missing", err_prefix);
    size->x = apr_strtoi64(value, &s, 0);
    size->y = apr_strtoi64(s, &s, 0);
    size->c = 3;
    size->z = 1;
    if (errno == 0 && *s) { // Read optional third and fourth integers
        size->z = apr_strtoi64(s, &s, 0);
        if (*s)
            size->c = apr_strtoi64(s, &s, 0);
    } // Raster size is 4 params max
    if (errno || *s)
        return apr_psprintf(p, "%s incorrect", err_prefix);
    return NULL;
}

// Converts a 64bit value into 13 trigesimal chars
static void uint64tobase32(apr_uint64_t value, char *buffer, int flag = 0) {
    static char letters[] = "0123456789abcdefghijklmnopqrstuv";
    // From the bottom up
    for (int i = 0; i < 13; i++, value >>= 5)
        buffer[12 - i] = letters[value & 0x1f];
    buffer[0] |= flag << 4; // empty flag goes in top bit
}

// Return the value from a base 32 character
// Returns a negative value if char is not a valid base32 char
static int b32(unsigned char c) {
    if (c - '0' < 10) return c - '0';
    if (c - 'A' < 32) return c - 'A';
    if (c - 'a' < 32) return c - 'a';
    return -1;
}

static apr_uint64_t base32decode(unsigned char *s, int *flag) {
    apr_int64_t value = 0;
    if (*s == '"') s++; // Skip initial quotes
    // first char carries the flag
    int v = b32(*s++);
    *flag = v >> 4; // pick up the flag
    value = v & 0xf; // Only 4 bits
    for (; *s != 0; s++) {
        v = b32(*s);
        if (v < 0) break; // Stop at first non base 32 char
        value = (value << 5) + v;
    }
    return value;
}

static void mrf_init(apr_pool_t *p, mrf_conf *c) {
    struct rset level;
    level.width = 1 + (c->size.x - 1) / c->pagesize.x;
    level.height = 1 + (c->size.y - 1) / c->pagesize.y;
    level.offset = 0;
    // How many levels we have
    c->n_levels = 1 + ilogb(max(level.height, level.width) -1);
    c->rsets = (struct rset *)apr_pcalloc(p, sizeof(rset) * c->n_levels);

    // Populate rsets from the bottom, the way tile protcols count levels
    struct rset *r = c->rsets + c->n_levels - 1;
    for (int i = 0; i < c->n_levels; i++) {
        *r = level;
        // Prepare for the next level, assuming powers of two
        level.offset += sizeof(TIdx) * level.width * level.height;
        level.width = 1 + (level.width - 1) / 2;
        level.height = 1 + (level.height - 1) / 2;
    }
    // MRF has one tile at the top
    ap_assert(c->rsets->height == 1 && c->rsets->width == 1);
}

/*
 Read the configuration file, which is a key-value text file, with one key per line
 comment lines that start with #
 empty lines are allowed, as well as continued lines if the first one ends with \
 However, every line is limited to the Apache max string size, defaults to 8192 chars

 Unknown keys, or keys that are misspelled are silently ignored
 Keys are not case sensitive, but values are
 Keys and values are space separated.  The last value per line, if it is a string, may contain spaces

 Supported keys:

  Size X Y <Z> <C>
  Mandatory, the size in pixels of the input MRF.  Z defaults to 1 and C defaults to 3 (usually not meaningful)

  PageSize X Y <1> <C>
  Optional, the pagesize in pixels.  Z has to be 1 if C is provided, which has to match the C value from size

  DataFile string
  Mandatory, the data file of the MRF.
  
  IndexFile string
  Optional, The index file name.
  If not provided it uses the data file name if its extension is not three letters.  
  Otherwise it uses the datafile name with the extension changed to .idx
 
  MimeType string
  Optional.  Defaults to autodetect

  EmptyTile <Size> <Offset> <FileName>
  Optional.  By default it ignores the request if a tile is missing
  First number is assumed to be the size, second is offset
  If filename is not provided, it uses the data file name

  SkippedLevels <N>
  Optional, how many levels to ignore, at the top of the MRF pyramid
  For example a GCS pyramid will have to skip the one tile level, so this should be 1
 
  ETagSeed base32_string
  Optional, 64 bits in base32 digits.  Defaults to 0
  The empty tile ETag will be this value but bit 64 (65th bit) is set. All the other tiles
  have ETags that depend on this one and bit 64 is zero
*/

static const char *mrf_file_set(cmd_parms *cmd, void *dconf, const char *arg)
{
    ap_assert(sizeof(apr_off_t) == 8);
    mrf_conf *c = (mrf_conf *)dconf;
    char *err_message;
    apr_table_t *kvp = read_pKVP_from_file(cmd->temp_pool, arg, &err_message);
    if (NULL == kvp) return err_message;

    // Got the parsed kvp table, parse the configuration items
    const char *line;
    char *err_prefix;

    line = apr_table_get(kvp, "Size");
    if (!line)
        return apr_psprintf(cmd->temp_pool, "%s Size directive is mandatory", arg);
    err_prefix = apr_psprintf(cmd->temp_pool, "%s Size", arg);
    err_message = get_xyzc_size(cmd->temp_pool, &(c->size), line, err_prefix);
    if (err_message) return err_message;

    // PageSize is optional, use reasonable defaults
    c->pagesize.x = c->pagesize.z = 512;
    c->pagesize.c = c->size.c;
    c->pagesize.z = 1;
    line = apr_table_get(kvp, "PageSize");
    if (line) {
        err_prefix = apr_psprintf(cmd->temp_pool, "%s PageSize", arg);
        err_message = get_xyzc_size(cmd->temp_pool, &(c->pagesize), line, err_prefix);
        if (err_message) return err_message;
    }
    if (c->pagesize.c != c->size.c || c->pagesize.z != 1)
        return apr_psprintf(cmd->temp_pool, "%s PageSize has invalid parameters", arg);

    // Initialize the run-time structures
    mrf_init(cmd->pool, c);

    // The DataFile is optional, if provided the index file is the same thing with the extension removed
    line = apr_table_get(kvp, "DataFile");

    // Data and index in the same location by default
    if (line) { // If the data file has a three letter extension, change it to idx for the index
        c->datafname = apr_pstrdup(cmd->pool, line);
        c->idxfname  = apr_pstrdup(cmd->pool, line);
        char *last;
        char *token = apr_strtok(c->idxfname, ".", &last); // strtok destroys the idxfile
        while (*last != 0 && token != NULL)
            token = apr_strtok(NULL, ".", &last);
        memcpy(c->idxfname, c->datafname, strlen(c->datafname)); // Get a new copy
        if (token != NULL && strlen(token) == 3)
            memcpy(token, "idx", 3);
    }

    // Index file can also be provided
    line = apr_table_get(kvp, "IndexFile");
    if (line)
        c->idxfname = apr_pstrdup(cmd->pool, line);

    // Mime type is autodetected if not provided
    line = apr_table_get(kvp, "MimeType");
    if (line)
        c->mime_type = apr_pstrdup(cmd->pool, line);

    // Skip levels, from the top of the MRF
    line = apr_table_get(kvp, "SkippedLevels");
    if (line)
        c->skip_levels = apr_atoi64(line);

    // If an emtpy tile is not provided, it falls through
    // If provided, it has an optional size and offset followed by file name which defaults to datafile
    // read the empty tile
    const char *efname = c->datafname;
    line = apr_table_get(kvp, "EmptyTile");
    if (line) {
        char *last;
        c->esize = apr_strtoi64(line, &last, 0);
        // Might be an offset, or offset then file name
        if (last != line) 
            apr_strtoff(&(c->eoffset), last, &last, 0);
        // If there is anything left, it's the file name
        if (*last != 0)
            efname = last;
    }

    // If we're provided a file name or a size, pre-read the empty tile in the 
    if (apr_strnatcmp(efname, c->datafname) || c->esize) {
        apr_file_t *efile;
        apr_off_t offset = c->eoffset;
        apr_status_t stat;

        // Use the temp pool for the file open, it will close it for us
        if (!c->esize) { // Don't know the size, get it from the file
            apr_finfo_t finfo;
            stat = apr_stat(&finfo, efname, APR_FINFO_CSIZE, cmd->temp_pool);
            if (APR_SUCCESS != stat)
                return apr_psprintf(cmd->pool, "Can't stat %s %pm", efname, stat);
            c->esize = (apr_uint64_t)finfo.csize;
        }
        stat = apr_file_open(&efile, efname, APR_FOPEN_READ | APR_FOPEN_BINARY, 0, cmd->temp_pool);
        if (APR_SUCCESS != stat)
            return apr_psprintf(cmd->pool, "Can't open empty file %s, loaded from %s: %pm", 
                efname, arg, stat);
        c->empty = (apr_uint32_t *) apr_palloc(cmd->pool, c->esize);
        stat = apr_file_seek(efile, APR_SET, &offset);
        if (APR_SUCCESS != stat)
            return apr_psprintf(cmd->pool, "Can't seek empty tile %s: %pm", efile, stat);
        apr_size_t size = (apr_size_t)c->esize;
        stat = apr_file_read(efile, c->empty, &size);
        if (APR_SUCCESS != stat)
            return apr_psprintf(cmd->pool, "Can't read from %s, loaded from %s: %pm",
                efname, arg, stat);
        apr_file_close(efile);
    }

    line = apr_table_get(kvp, "ETagSeed");
    // Ignore the flag
    int flag;
    c->seed = base32decode((unsigned char *)line, &flag);
    return NULL;
}

static int send_image(request_rec *r, apr_uint32_t *buffer, apr_size_t size) {
    // TODO: Send the image
    mrf_conf *cfg = (mrf_conf *)ap_get_module_config(r->per_dir_config, &mrf_module);
    if (cfg->mime_type)
        ap_set_content_type(r, cfg->mime_type);
    else
        switch (hton32(*buffer)) {
        case JPEG_SIG:
            ap_set_content_type(r, "image/jpeg");
            break;
        case PNG_SIG:
            ap_set_content_type(r, "image/png");
            break;
        default: // LERC goes here too
            ap_set_content_type(r, "application/octet-stream");
    }
    // Is it gzipped content?
    if (GZIP_SIG == hton32(*buffer))
        apr_table_setn(r->headers_out, "Content-Encoding", "gzip");

    // TODO: Set headers, as chosen by user
    ap_set_content_length(r, size);
    ap_rwrite(buffer, size, r);
    return OK;
}

// Returns the empty tile if defined
static int send_empty_tile(request_rec *r) {
    mrf_conf *cfg = (mrf_conf *)ap_get_module_config(r->per_dir_config, &mrf_module);
    if (!cfg->empty) return DECLINED;
    return send_image(r, cfg->empty, cfg->esize);
}

// For now just open the file
apr_status_t open_file(request_rec *r, apr_file_t **pfh, const char *name)
{
    return apr_file_open(pfh, name, 
        APR_FOPEN_READ | APR_FOPEN_BINARY | APR_FOPEN_LARGEFILE, NULL, r->pool);
}

#define REQ_ERR_IF(X) if (X) return HTTP_BAD_REQUEST
#define SERR_IF(X) if (X) return HTTP_INTERNAL_SERVER_ERROR

static int handler(request_rec *r)
{
    // Only get and no arguments
    if (r->method != M_GET) return DECLINED;
    if (r->args) return DECLINED;

    mrf_conf *cfg = (mrf_conf *)ap_get_module_config(r->per_dir_config, &mrf_module);
    if (!cfg || !cfg->enabled) return DECLINED;

    // TODO: add a guard regexp here

    apr_array_header_t *tokens = tokenize(r->pool, r->uri, '/');
    if (tokens->nelts < 3) return DECLINED; // At least Level Row Column

    // Use a xyzc structure, with c being the level
    // Input order is M/Level/Row/Column, with M being optional
    sz tile;

    // Need at least three numerical arguments
    tile.x = apr_atoi64((char *)apr_array_pop(tokens)); REQ_ERR_IF(errno);
    tile.y = apr_atoi64((char *)apr_array_pop(tokens)); REQ_ERR_IF(errno);
    tile.c = apr_atoi64((char *)apr_array_pop(tokens)); REQ_ERR_IF(errno);

    // We can ignore the error on this one, defaults to zero
    if (tokens->nelts)
        tile.z = apr_atoi64((char *)apr_array_pop(tokens));

    tile.c += cfg->skip_levels;
    REQ_ERR_IF(tile.c > cfg->n_levels);
    rset *level = cfg->rsets + tile.c;
    REQ_ERR_IF(tile.x >= level->width || tile.y >= level->height);

    // Offset of the index entry for this tile
    apr_off_t tidx_offset = level->offset +
        sizeof(TIdx) * (tile.x + level->width * (tile.z * level->height + tile.y));

    apr_file_t *idxf, *dataf;
    SERR_IF(open_file(r, &idxf, cfg->idxfname));
    SERR_IF(open_file(r, &dataf, cfg->datafname));
    SERR_IF(apr_file_seek(idxf, APR_SET, &tidx_offset));
    TIdx index;
    apr_size_t read_size = sizeof(index);
    SERR_IF(apr_file_read(idxf, &index, &read_size));
    SERR_IF(read_size != sizeof(index));

    // MRF index record is in network order
    index.size = ntoh64(index.size);
    index.size = ntoh64(index.offset);

    if (index.size < 4) // Need at least four bytes for signature check
        send_empty_tile(r);

    // TODO: Check ETag conditional

    // We got the tile index, and is not empty
    apr_uint32_t *buffer = (apr_uint32_t *) apr_palloc(r->pool, index.size);
    SERR_IF(!buffer);
    SERR_IF(apr_file_seek(dataf, APR_SET, (apr_off_t *)&index.offset));
    read_size = index.size;
    SERR_IF(apr_file_read(dataf, buffer, &read_size));
    SERR_IF(read_size != index.size);
    return send_image(r, buffer, read_size);
}

static const command_rec mrf_cmds[] =
{
    AP_INIT_FLAG(
        "OE_MRF",
        CMD_FUNC ap_set_flag_slot,
        (void *)APR_OFFSETOF(mrf_conf, enabled),
        ACCESS_CONF,
        "mod_mrf enable"
    ),

    AP_INIT_TAKE1(
        "OE_MRF_ConfigurationFile",
        CMD_FUNC mrf_file_set, // Callback
        0, // Self-pass argument
        ACCESS_CONF, // availability
        "The configuration file for this module"
    ),

    { NULL }
};


// Return OK or DECLINED, anything else is error
static int check_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
    return DECLINED;
    // This gets called once for the whole server, it would have to check the configuration for every folder
}

static void mrf_register_hooks(apr_pool_t *p)

{
    ap_hook_handler(handler, NULL, NULL, APR_HOOK_FIRST);
//    ap_hook_check_config(check_config, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA mrf_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config, 
    0, // No dir_merge
    0, // No server_config
    0, // No server_merge
    mrf_cmds, // configuration directives
    mrf_register_hooks // processing hooks
};
