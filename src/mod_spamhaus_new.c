/*
 *
 * Date:        2018/02/11
 * Info:        mod_spamhaus_new Apache 2.4 module
 * Contact:     mailto: <info [at] kaufmann-automotive.ch>
 * Version:     0.8
 * Authors:     Luca Ercoli <luca.e [at] seeweb.it> (based on mod_spamhaus)
 *              Rainer Kaufmann <info [at] kaufmann-automotive.ch>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 */


#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>


#define MODULE_NAME		"mod_spamhaus_new"
#define MODULE_VERSION		"0.8"
#define WHITELIST_SIZE		2048
#define UNAFFECTED_SIZE		64
#define ENTRY_SIZE		64
#define DEF_CACHE_SIZE		2048
#define MAX_CACHE_SIZE		16384	

#define STR_HELPER(x)		#x
#define STR(x)			STR_HELPER(x)

module AP_MODULE_DECLARE_DATA spamhaus_new_module;

static void *spamhaus_create_config(apr_pool_t *p, server_rec *s);
static void *spamhaus_create_dir_config(apr_pool_t *p, char *path);
static int spamhaus_handler(request_rec *r);
static int spamhaus_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void register_hooks(apr_pool_t *p);

int check_whitelist(char *conf, request_rec *r);
int check_unaffected(char *conf, request_rec *r);
void update_list(char *list, int listsize, char *filename);
void add_cache(char *ip, int cached_ip_size);
void get_file_mtime(request_rec *r, char* filename, time_t* mtime);

char listwhitelist[WHITELIST_SIZE][ENTRY_SIZE];
char listunaffected[UNAFFECTED_SIZE][ENTRY_SIZE];

time_t whitelist_mtime, old_whitelist_mtime;
time_t unaffected_mtime, old_unaffected_mtime;

int cached_ip_idx;
char cached_ip[MAX_CACHE_SIZE][15];

typedef struct {
	char *methods;
	char *whitelist;
	char *unaffected;
	char *dnshost;
	int cached_ip_size;
	char *c_err;
} mod_config;


static mod_config *create_config(apr_pool_t *p)
{
	mod_config *cfg = (mod_config *)apr_pcalloc(p, sizeof (*cfg));

	cfg->methods = "POST,PUT,OPTIONS";
	cfg->whitelist = NULL;
	cfg->unaffected = NULL;
	cfg->dnshost = "sbl-xbl.spamhaus.org";
	cfg->cached_ip_size = DEF_CACHE_SIZE;
	cfg->c_err = "Access Denied! Your IP address is blacklisted because of malicious behavior in the past.";
	return cfg;
}


/* per-server configuration structure */
static void *spamhaus_create_config(apr_pool_t *p, server_rec *s)
{
	return create_config(p);
}


/* per-directory configuration structure */
static void *spamhaus_create_dir_config(apr_pool_t *p, char *path)
{
	return create_config(p);
}


void update_list(char *list, int listsize, char *filename)
{
	int i = 0;
	FILE *file;

	memset(list, 0, listsize);

	file = fopen(filename, "r");
	if(file)
	{
		while (!feof(file) && (i < (listsize - ENTRY_SIZE)))
		{
			char *p = fgets((list + (i * ENTRY_SIZE)), ENTRY_SIZE, file);
			i++;
		}
		fclose(file);
	}
}


int check_whitelist(char *filename, request_rec *r)
{
	unsigned long first;
	unsigned long last;
	unsigned long mask;
	char ippi[16];
	struct in_addr in;
	char *brokenfeed;
	unsigned bitmask;
	unsigned long a, b, c, d;
	int a_min, b_min, c_min, d_min, a_max, b_max, c_max, d_max;
	int a_useragent_ip, b_useragent_ip, c_useragent_ip, d_useragent_ip;

	get_file_mtime(r, filename, &whitelist_mtime);

	if (whitelist_mtime != old_whitelist_mtime)
	{
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Reloading whitelist %s", filename);
		old_whitelist_mtime = whitelist_mtime;
		update_list(&listwhitelist[0][0], sizeof(listwhitelist), filename);
	}

	for (int i = 0; i < WHITELIST_SIZE; i++)
	{
		if (listwhitelist[i][0] == 0) break;

		brokenfeed = strchr(&listwhitelist[i * ENTRY_SIZE][0], '\n');
		if ( brokenfeed ) *brokenfeed = 0;

		if ( (strchr(&listwhitelist[i * ENTRY_SIZE][0],'/') == NULL ) )
		{
			if ( strcmp(&listwhitelist[i * ENTRY_SIZE][0], r->useragent_ip) == 0 ) return 1;
		}
		else
		{
			a = b = c = d = 0;
			bitmask = 0;
			memset(ippi, 0, sizeof(ippi));
			sscanf(&listwhitelist[i * ENTRY_SIZE][0], "%[^/]/%u", ippi, &bitmask);
			sscanf(ippi, "%lu.%lu.%lu.%lu", &a, &b, &c, &d);

			first = (a << 24) + (b << 16) + (c << 8) + d;

			mask = (0xFFFFFFFF << (32 - bitmask));

			last = first + (~mask);
			first = htonl(first);
			last = htonl(last);

			in.s_addr = first;

			sscanf(inet_ntoa(in), "%d.%d.%d.%d", &a_min, &b_min, &c_min, &d_min);

			in.s_addr = last;

			sscanf(inet_ntoa(in), "%d.%d.%d.%d", &a_max, &b_max, &c_max, &d_max);
			sscanf(r->useragent_ip, "%d.%d.%d.%d", &a_useragent_ip, &b_useragent_ip, &c_useragent_ip, &d_useragent_ip);

			if (
				((d_useragent_ip <= d_max) && (d_useragent_ip >= d_min)) &&
				((c_useragent_ip <= c_max) && (c_useragent_ip >= c_min)) &&
				((b_useragent_ip <= b_max) && (b_useragent_ip >= b_min)) &&
				((a_useragent_ip <= a_max) && (a_useragent_ip >= a_min))
			   ) return 1;
		}
	}
	return 0;
}


int check_unaffected(char *filename, request_rec *r)
{
	char *brokenfeed;

	get_file_mtime(r, filename, &unaffected_mtime);

	if (unaffected_mtime != old_unaffected_mtime)
	{
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Reloading list of unaffected domains %s", filename);
		old_unaffected_mtime = unaffected_mtime;
		update_list(&listunaffected[0][0], sizeof(listunaffected), filename);
	}

	for (int i = 0; i < UNAFFECTED_SIZE; i++)
	{
		if (listunaffected[i][0] == 0) break;

		brokenfeed = strchr(&listunaffected[i * ENTRY_SIZE][0], '\n');
		if ( brokenfeed ) *brokenfeed = 0;

		if ( strcmp(&listunaffected[i * ENTRY_SIZE][0], r->hostname) == 0 ) return 1;
	}
	return 0;
}


void add_cache(char *ip, int cached_ip_size)
{
	for (int i = 0; i < cached_ip_size; i++)
		if (strcmp(cached_ip[i], ip) == 0 )
			return;

	strncpy(cached_ip[cached_ip_idx], ip, sizeof(cached_ip[0]));
	cached_ip_idx++;
	cached_ip_idx %= cached_ip_size;
}


void get_file_mtime(request_rec *r, char* filename, time_t* mtime)
{
	struct stat statdata;

	if ( (filename == NULL) || (mtime == NULL) || (r == NULL) )
		return;

	if (stat(filename, &statdata) == -1)
	{
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Stat for %s failed. %s", filename, strerror(errno));
	}
	else
	{
		*mtime = statdata.st_mtime;
	}
}


static int spamhaus_handler(request_rec *r)
{
	mod_config *cfg = (mod_config *)ap_get_module_config(r->per_dir_config, &spamhaus_new_module);

	if (strstr(cfg->methods, r->method) != NULL)
	{
		struct hostent *hp;
		char lookup_ip[512];
		int oct1, oct2, oct3, oct4;

		for (int i = 0; i < cfg->cached_ip_size; i++)
			if (strcmp(cached_ip[i], r->useragent_ip) == 0)
				return DECLINED;

		sscanf(r->useragent_ip, "%d.%d.%d.%d",&oct1, &oct2, &oct3, &oct4);
		snprintf(lookup_ip, sizeof(lookup_ip), "%d.%d.%d.%d.%s", oct4, oct3, oct2, oct1, cfg->dnshost);

		hp = gethostbyname(lookup_ip);

		if (hp != NULL)
		{
			struct in_addr addr;
			addr.s_addr = *(u_long *)hp->h_addr_list[0];

			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, MODULE_NAME ": request from %s: %s", r->useragent_ip, r->uri);

			sscanf(inet_ntoa(addr),"%d.%d.%d.%d", &oct1, &oct2, &oct3, &oct4);

			if (oct1 != 127)
			{
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": address %s is blacklisted but it's not in the 127.0.0.0/8 range. POSSIBLE WILD-CARDING TYPOSQUATTERS ATTACK! IP address will not get filtered", r->useragent_ip);
				return DECLINED;
			}

			if ( cfg->whitelist != NULL )
			{
				if ( check_whitelist(cfg->whitelist, r) )
				{
					ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": address %s is whitelisted. Allow connection to %s%s", r->useragent_ip, r->hostname, r->uri);
					add_cache(r->useragent_ip, cfg->cached_ip_size);
					return DECLINED;
				}
			}

			if ( cfg->unaffected != NULL )
			{
				if ( check_unaffected(cfg->unaffected, r) )
				{
					ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": domain %s is not checked. Allow connection to %s%s", r->hostname, r->hostname, r->uri);
					add_cache(r->useragent_ip, cfg->cached_ip_size);
					return DECLINED;
				}
			}

			ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": address %s is blacklisted. Deny connection to %s%s", lookup_ip, r->hostname, r->uri);
			r->content_type = "text/plain"; 
			ap_custom_response(r, HTTP_UNAUTHORIZED, cfg->c_err); 
			return HTTP_UNAUTHORIZED;
		}
	}

	add_cache(r->useragent_ip, cfg->cached_ip_size);
	return DECLINED;
}


static const char *whitelist_conf(cmd_parms *parms, void *dummy, const char *arg)
{
	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

	cfg->whitelist = (char *)arg;

	update_list(&listwhitelist[0][0], sizeof(listwhitelist), cfg->whitelist);
	return NULL;
}


static const char *unaffected_conf(cmd_parms *parms, void *dummy, const char *arg)
{
        mod_config *cfg = (mod_config *)dummy;
        ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

        cfg->unaffected = (char *)arg;

        update_list(&listunaffected[0][0], sizeof(listunaffected), cfg->unaffected);
        return NULL;
}


static const char *dns_to_query(cmd_parms *parms, void *dummy, const char *arg)
{
	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

	cfg->dnshost = (char *)arg;
	return NULL;
}


static const char *looking_for(cmd_parms *parms, void *dummy, const char *arg)
{
	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

	cfg->methods = (char *)arg;
	return NULL;
}


static const char *cachesize(cmd_parms *parms, void *dummy, const char *arg)
{
	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

	cfg->cached_ip_size = atoi(arg);

	if (cfg->cached_ip_size <= 0) cfg->cached_ip_size = DEF_CACHE_SIZE;
	if (cfg->cached_ip_size > MAX_CACHE_SIZE) cfg->cached_ip_size = MAX_CACHE_SIZE; 
	return NULL;
}


static const char *custom_err_cfg(cmd_parms *parms, void *dummy, const char *arg)
{
	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

	cfg->c_err = (char *)arg;
	return NULL;
}


static command_rec spamhaus_cmds[] = {
	AP_INIT_TAKE1("MS_Methods", looking_for, NULL, RSRC_CONF, "HTTP methods to monitor. Default Value: POST,PUT,OPTIONS"),
	AP_INIT_TAKE1("MS_Dns", dns_to_query, NULL, RSRC_CONF, "Blacklist name server (Default: sbl-xbl.spamhaus.org)"),
	AP_INIT_TAKE1("MS_WhiteList", whitelist_conf, NULL, RSRC_CONF, "The path of your whitelist file"),
	AP_INIT_TAKE1("MS_UnaffectedDomains", unaffected_conf, NULL, RSRC_CONF, "The path of your unaffected domains file"),
	AP_INIT_TAKE1("MS_CacheSize", cachesize, NULL, RSRC_CONF, "Number of cache entries. Default: " STR(DEF_CACHE_SIZE) " Max:" STR(MAX_CACHE_SIZE)),
	AP_INIT_TAKE1("MS_CustomError", custom_err_cfg, NULL, RSRC_CONF, "Custom error message"),
	{NULL}
};


static int spamhaus_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	// Init
	whitelist_mtime = old_whitelist_mtime = unaffected_mtime = old_unaffected_mtime = (time_t)0;
	cached_ip_idx = 0;
	memset(cached_ip, 0, sizeof(cached_ip));
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, MODULE_NAME " " MODULE_VERSION " started.");
	return OK;
}


static void register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(spamhaus_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_access_checker(spamhaus_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA spamhaus_new_module = {
	STANDARD20_MODULE_STUFF,
	spamhaus_create_dir_config, /* create per-dir config structures    */
	NULL,                       /* merge  per-dir config structures    */
	spamhaus_create_config,     /* create per-server config structures */
	NULL,                       /* merge  per-server config structures */
	spamhaus_cmds,              /* table of config file commands       */
	register_hooks
};
