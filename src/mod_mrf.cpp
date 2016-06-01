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

static const char *mrf_file_set(cmd_parms *cmd, void *dconf, const char *arg)
{
    mrf_conf *c = (mrf_conf *)dconf;
    c->the_mrf = apr_pstrdup(cmd->pool, arg);
    // Should parse it here and initialize the configuration structure
    return NULL;
}

static const command_rec mrf_cmds[] =
{
    AP_INIT_TAKE1(
    "MRF_FILE",
    CMD_FUNC mrf_file_set, // Callback
    0, // Self-pass argument
    ACCESS_CONF, // availability
    "Where is the MRF metadata file"
    ),

    { NULL }
};

static int handler(request_rec *r)
{
    mrf_conf *cfg = (mrf_conf *)ap_get_module_config(r->per_dir_config, &mrf_module);

    return DECLINED;
}

static void mrf_register_hooks(apr_pool_t *p)

{
    ap_hook_handler(handler, NULL, NULL, APR_HOOK_FIRST);
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
