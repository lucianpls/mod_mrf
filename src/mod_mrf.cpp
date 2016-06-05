/*
* An OnEarth module that serves tiles from an MRF
* Lucian Plesea
* (C) 2016
*/

#include "mod_mrf.h"

static void *create_dir_config(apr_pool_t *p, char *dummy)
{
    mrf_conf *c =
        (mrf_conf *)apr_pcalloc(p, sizeof(mrf_conf));
    return c;
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

//
// Read the configuration file, which is a key-value text file, with one key per line
// comment lines that start with #
// empty lines are allowed, as well as continued lines if the first one ends with \
// However, every line is limited to the Apache max string size, defaults to 8192 chars
//
// Unknown keys, or keys that are misspelled are silently ignored
// Keys are not case sensitive, but values are
// Keys and values are space separated.  The last value per line, if it is a string, may contain spaces
//
// Supported keys:
//
//  Size X Y <Z> <C>
//  Mandatory, the size in pixels of the input MRF.  Z defaults to 1 and C defaults to 3 (usually not meaningful)
//
//  PageSize X Y <1> <C>
//  Optional, the pagesize in pixels.  Z has to be 1 if C is provided, which has to match the C value from size
//
//  DataFile string
//  Mandatory, the data file of the MRF.
//  
//  IndexFile string
//  Optional, The index file name.
//  If not provided it uses the data file name if its extension is not three letters.  
//  Otherwise it uses the datafile name with the extension changed to .idx
// 
//  MimeType string
//  Optional.  Defaults to autodetect
//
//  EmptyTile <Size> <Offset> <FileName>
//  Optional.  By default it ignores the request if a tile is missing
//  First number is assumed to be the size, second is offset
//  If filename is not provided, it uses the data file name
// 

static const char *mrf_file_set(cmd_parms *cmd, void *dconf, const char *arg)
{
    mrf_conf *c = (mrf_conf *)dconf;
    char *err_message;
    apr_table_t *kvp = read_pKVP_from_file(cmd->temp_pool, arg, &err_message);
    if (NULL == kvp) return err_message;

    // Got the parsed kvp table, parse the configuration items
    const char *line;
    char *err_prefix;

    line = apr_table_get(kvp, "Size");
    if (!line)
        return apr_psprintf(cmd->temp_pool, "%s Size directive is mandatory");
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

        // Use the temp pool for the file open, it will close it for us
        if (!c->esize) { // Don't know the size, get it from the file
            apr_finfo_t fstatus;
            if (APR_SUCCESS == apr_stat(&fstatus, efname, APR_FINFO_CSIZE, cmd->temp_pool))
                c->esize = (apr_uint64_t)fstatus.csize;
            else
                return apr_psprintf(cmd->pool, "Can't stat %s", efname);
        }
        if (APR_SUCCESS != apr_file_open(&efile, efname, APR_FOPEN_READ | APR_FOPEN_BINARY, 0, cmd->temp_pool))
            return apr_psprintf(cmd->pool, "Can't open empty file %s, loaded from %s: %s", 
                efname, arg, strerror(errno));
        c->empty = (apr_uint32_t *) apr_palloc(cmd->pool, c->esize);
        apr_size_t size = (apr_size_t)c->esize;
        if (APR_SUCCESS != apr_file_read(efile, c->empty, &size))
            return apr_psprintf(cmd->pool, "Can't read from %s, loaded from %s: %s",
                efname, arg, strerror(errno));
        apr_file_close(efile);
    }

    return NULL;
}

static const command_rec mrf_cmds[] =
{
    AP_INIT_TAKE1(
    "OE_MRF_ConfigurationFile",
    CMD_FUNC mrf_file_set, // Callback
    0, // Self-pass argument
    ACCESS_CONF, // availability
    "The configuration file for this module"
    ),

    { NULL }
};

static int handler(request_rec *r)
{
    mrf_conf *cfg = (mrf_conf *)ap_get_module_config(r->per_dir_config, &mrf_module);

    return DECLINED;
}

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
