/*
* mod_mrf header file
* Lucian Plesea
* (C) 2016
*/

#if !defined(MOD_MRF_H)
#include <httpd.h>
#include <http_config.h>

#if defined(WIN32)
#define CMD_FUNC (cmd_func)
#endif

#if defined(APLOG_USE_MODULE)
APLOG_USE_MODULE(mrf);
#endif

extern module AP_MODULE_DECLARE_DATA mrf_module;

#endif