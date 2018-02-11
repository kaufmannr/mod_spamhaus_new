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


#define MODULE_NAME       "mod_spamhaus_new"
#define MODULE_VERSION    "0.8"
#define DEF_CACHE_SIZE    2048
#define MAX_CACHE_SIZE    16384
#define DEV_CACHE_TIME_S  172800

#define STR_HELPER(x)     #x
#define STR(x)            STR_HELPER(x)

module AP_MODULE_DECLARE_DATA spamhaus_new_module;

static void *spamhaus_create_config(apr_pool_t *p, server_rec *s);
static void *spamhaus_create_dir_config(apr_pool_t *p, char *path);
static int spamhaus_handler(request_rec *r);
static int spamhaus_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void register_hooks(apr_pool_t *p);

int check_whitelist(apr_pool_t *p, char *conf, request_rec *r);
int check_unaffected(apr_pool_t *p, char *conf, request_rec *r);
void update_whitelist(apr_pool_t *p, char *filename);
void update_unaffected(apr_pool_t *p, char *filename);
void add_cache(apr_pool_t *p, char *ip, int cache_ip_size, int cache_ip_validity);
void get_file_mtime(request_rec *r, char* filename, time_t* mtime);

time_t old_whitelist_mtime, old_unaffected_mtime;

apr_hash_t *hash_whitelist;
apr_hash_t *hash_unaffected;
apr_hash_t *hash_remote_ip;

typedef struct
{
  char *methods;
  char *whitelist;
  char *unaffected;
  char *dnshost;
  int cache_ip_size;
  int cache_ip_validity;
  char *c_err;
} mod_config_t;

typedef struct
{
  char ip[15];
  time_t stamp;
} ip_t;

typedef struct
{
  char domain[64];
} unaffected_t;

/* Preset module configuration */
static mod_config_t *create_config(apr_pool_t *p)
{
  mod_config_t *cfg = (mod_config_t *)apr_pcalloc(p, sizeof (*cfg));

  cfg->methods = "POST,PUT,OPTIONS";
  cfg->whitelist = NULL;
  cfg->unaffected = NULL;
  cfg->dnshost = "sbl-xbl.spamhaus.org";
  cfg->cache_ip_size = DEF_CACHE_SIZE;
  cfg->cache_ip_validity = DEV_CACHE_TIME_S;
  cfg->c_err = "Access Denied! Your IP address is blacklisted because of malicious behavior in the past.";
  return cfg;
}


/* Per-server configuration structure */
static void *spamhaus_create_config(apr_pool_t *p, server_rec *s)
{
  return create_config(p);
}


/* Per-directory configuration structure */
static void *spamhaus_create_dir_config(apr_pool_t *p, char *path)
{
  return create_config(p);
}

/* Update useragent_ip whitelist from file */
void update_whitelist(apr_pool_t *p, char *filename)
{
  FILE *file;
  char *nl;
  
  apr_hash_clear(hash_whitelist);

  file = fopen(filename, "r");
  if(file)
  {
    while (!feof(file))
    {
      ip_t *entry = apr_palloc(p, sizeof(ip_t));
      if (entry == NULL)
        return;

      memset(entry->ip, 0, sizeof(entry->ip));
      char *l = fgets(entry->ip, sizeof(entry->ip), file);
      nl = strchr(entry->ip, '\n');
      if ( nl != NULL ) *nl = 0;
      apr_hash_set(hash_whitelist, entry->ip, APR_HASH_KEY_STRING, entry);
    }
    fclose(file);
  }
}

/* Update unaffected domain list from file */
void update_unaffected(apr_pool_t *p, char *filename)
{
  FILE *file;
  char *nl;

  apr_hash_clear(hash_unaffected);

  file = fopen(filename, "r");
  if(file)
  {
    while (!feof(file))
    { 
      unaffected_t *entry = apr_palloc(p, sizeof(unaffected_t));
      if (entry == NULL)
        return;

      memset(entry->domain, 0, sizeof(entry->domain));
      char *l = fgets(entry->domain, sizeof(entry->domain), file);
      nl = strchr(entry->domain, '\n');
      if ( nl != NULL ) *nl = 0;
      apr_hash_set(hash_unaffected, entry->domain, APR_HASH_KEY_STRING, entry);
    }
    fclose(file);
  }
}

/* Check if useragent_ip is in our whitelist */
int check_whitelist(apr_pool_t *p, char *filename, request_rec *r)
{
  time_t whitelist_mtime = (time_t)0;
  unsigned long first, last, mask;
  char ippi[16];
  struct in_addr in;
  unsigned bitmask;
  unsigned long a, b, c, d;
  int a_min, b_min, c_min, d_min, a_max, b_max, c_max, d_max;
  int a_useragent_ip, b_useragent_ip, c_useragent_ip, d_useragent_ip;
  apr_hash_index_t *hidx = NULL;
  ip_t *entry;

  get_file_mtime(r, filename, &whitelist_mtime);

  if (whitelist_mtime != old_whitelist_mtime)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Reloading whitelist %s", filename);
    old_whitelist_mtime = whitelist_mtime;
    update_whitelist(p, filename);
  }

  /* Scan complete whitelist */
  for (hidx = apr_hash_first(p, hash_whitelist); hidx; hidx = apr_hash_next(hidx))
  {
    apr_hash_this(hidx, NULL, NULL, (void*)&entry);

    if ( (strchr(entry->ip, '/') == NULL ) )
    {
      if ( strcmp(entry->ip, r->useragent_ip) == 0 )
        return 1;
    }
    else
    {
      a = b = c = d = 0;
      bitmask = 0;
      memset(ippi, 0, sizeof(ippi));
      sscanf(entry->ip, "%[^/]/%u", ippi, &bitmask);
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

      if ( (d_useragent_ip <= d_max) && (d_useragent_ip >= d_min) &&
           (c_useragent_ip <= c_max) && (c_useragent_ip >= c_min) &&
           (b_useragent_ip <= b_max) && (b_useragent_ip >= b_min) &&
           (a_useragent_ip <= a_max) && (a_useragent_ip >= a_min) )
        return 1;
    }
  }
  return 0;
}

/* Check if requested hostname is an unaffected domain */
int check_unaffected(apr_pool_t *p, char *filename, request_rec *r)
{
  time_t unaffected_mtime = (time_t)0;
  unaffected_t *entry;

  get_file_mtime(r, filename, &unaffected_mtime);

  if (unaffected_mtime != old_unaffected_mtime)
  {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Reloading list of unaffected domains %s", filename);
    old_unaffected_mtime = unaffected_mtime;
    update_unaffected(p, filename);
  }

  entry = apr_hash_get(hash_unaffected, r->hostname, APR_HASH_KEY_STRING);
  return (entry != NULL);
}

/* Add a looked up remote_ip to our cache actualize timestamps and handle max cache size */
void add_cache(apr_pool_t *p, char *ip, int cache_ip_size, int cache_ip_validity)
{
  int hash_size;
  apr_hash_index_t *hidx = NULL;
  ip_t *entry;

  /* If cache too big, delete first 50 entries */
  hash_size = apr_hash_count(hash_remote_ip);
  while ((hash_size + 50) > cache_ip_size)
  {
    hidx = apr_hash_first(p, hash_remote_ip);
    if (hidx == NULL)
      break;

    apr_hash_this(hidx, NULL, NULL, (void*)&entry);
    apr_hash_set(hash_remote_ip, entry->ip, APR_HASH_KEY_STRING, NULL);
    hash_size--;
  }

  /* Add IP to cache */
  entry = apr_hash_get(hash_remote_ip, ip, APR_HASH_KEY_STRING);
  if (entry == NULL)
  {
    /* Create new entry */
    entry = apr_palloc(p, sizeof(ip_t));
    if (entry == NULL)
      return;

    memset(entry->ip, 0, sizeof(entry->ip));
    apr_cpystrn(entry->ip, ip, sizeof(entry->ip));
  }
  entry->stamp = apr_time_now();
  apr_hash_set(hash_remote_ip, entry->ip, APR_HASH_KEY_STRING, entry);
}

/* Get file modification time and store it in mtime */
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

/* Check the site request */
static int spamhaus_handler(request_rec *r)
{
  mod_config_t *cfg = (mod_config_t *)ap_get_module_config(r->per_dir_config, &spamhaus_new_module);

  if (strstr(cfg->methods, r->method) != NULL)
  {
    struct hostent *hp;
    char lookup_ip[512];
    int oct1, oct2, oct3, oct4;
    apr_pool_t *p = NULL;
    ip_t *entry;

    apr_pool_create(&p, NULL);

    /* IP already exists in cache? */
    entry = apr_hash_get(hash_remote_ip, r->useragent_ip, APR_HASH_KEY_STRING);
    if (entry != NULL)
    {
      /* Entry exired? */
      if (entry->stamp > (apr_time_now() - cfg->cache_ip_validity))
      {
        /* Not expired, actualize timestamp */
        entry->stamp = apr_time_now();
        return DECLINED;
      }
    }

    /* Lookup remote_ip */
    sscanf(r->useragent_ip, "%d.%d.%d.%d",&oct1, &oct2, &oct3, &oct4);
    snprintf(lookup_ip, sizeof(lookup_ip), "%d.%d.%d.%d.%s", oct4, oct3, oct2, oct1, cfg->dnshost);

    hp = gethostbyname(lookup_ip);

    if (hp != NULL)
    {
      struct in_addr addr;
      addr.s_addr = *(u_long *)hp->h_addr_list[0];

      sscanf(inet_ntoa(addr),"%d.%d.%d.%d", &oct1, &oct2, &oct3, &oct4);

      if (oct1 != 127)
      {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": address %s is blacklisted but it's not in the 127.0.0.0/8 range. POSSIBLE WILD-CARDING TYPOSQUATTERS ATTACK! IP address will not get filtered", r->useragent_ip);
        return DECLINED;
      }

      if ( cfg->whitelist != NULL )
      {
        if ( check_whitelist(p, cfg->whitelist, r) )
        {
          ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": address %s is whitelisted. Allow connection to %s%s", r->useragent_ip, r->hostname, r->uri);
          add_cache(p, r->useragent_ip, cfg->cache_ip_size, cfg->cache_ip_validity);
          return DECLINED;
        }
      }

      if ( cfg->unaffected != NULL )
      {
        if ( check_unaffected(p, cfg->unaffected, r) )
        {
          ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": domain %s is not checked. Allow connection to %s%s", r->hostname, r->hostname, r->uri);
          /* Add NOT no cache */
          return DECLINED;
        }
      }

      ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, MODULE_NAME ": address %s is blacklisted. Deny connection to %s%s", lookup_ip, r->hostname, r->uri);
      r->content_type = "text/plain"; 
      ap_custom_response(r, HTTP_UNAUTHORIZED, cfg->c_err);
      /* Add NOT no cache */
      return HTTP_UNAUTHORIZED;
    }
    add_cache(p, r->useragent_ip, cfg->cache_ip_size, cfg->cache_ip_validity);
  }
  return DECLINED;
}

/* Get the ip address whitelist from configuration file */
static const char *whitelist_conf(cmd_parms *parms, void *dummy, const char *arg)
{
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

  cfg->whitelist = (char *)arg;
  return NULL;
}

/* Get the list of unaffected domains from configuration file */
static const char *unaffected_conf(cmd_parms *parms, void *dummy, const char *arg)
{
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

  cfg->unaffected = (char *)arg;
  return NULL;
}

/* Get the DNSBL address from configuration file */
static const char *dns_to_query(cmd_parms *parms, void *dummy, const char *arg)
{
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

  cfg->dnshost = (char *)arg;
  return NULL;
}

/* Get the http methods that should be checked from configuration file */
static const char *looking_for(cmd_parms *parms, void *dummy, const char *arg)
{
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

  cfg->methods = (char *)arg;
  return NULL;
}

/* Get cache size from configuration file */
static const char *cachesize(cmd_parms *parms, void *dummy, const char *arg)
{
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

  cfg->cache_ip_size = atoi(arg);

  if (cfg->cache_ip_size <= 0) cfg->cache_ip_size = DEF_CACHE_SIZE;
  if (cfg->cache_ip_size > MAX_CACHE_SIZE) cfg->cache_ip_size = MAX_CACHE_SIZE; 
  return NULL;
}

/* Get cache validity from configuration file */
static const char *cachevalidity(cmd_parms *parms, void *dummy, const char *arg)
{ 
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);
  
  cfg->cache_ip_validity = atoi(arg);
  
  if (cfg->cache_ip_validity <= 0) cfg->cache_ip_validity = DEV_CACHE_TIME_S;
  return NULL;
}

/* Get custom error message from configuration file */
static const char *custom_err_cfg(cmd_parms *parms, void *dummy, const char *arg)
{
  mod_config_t *cfg = (mod_config_t *)dummy;
  ap_get_module_config(parms->server->module_config, &spamhaus_new_module);

  cfg->c_err = (char *)arg;
  return NULL;
}

/* Configuration variables */
static command_rec spamhaus_cmds[] = {
  AP_INIT_TAKE1("MS_Methods", looking_for, NULL, RSRC_CONF, "HTTP methods to monitor. Default Value: POST,PUT,OPTIONS"),
  AP_INIT_TAKE1("MS_Dns", dns_to_query, NULL, RSRC_CONF, "Blacklist name server (Default: sbl-xbl.spamhaus.org)"),
  AP_INIT_TAKE1("MS_WhiteList", whitelist_conf, NULL, RSRC_CONF, "The path of your whitelist file"),
  AP_INIT_TAKE1("MS_UnaffectedDomains", unaffected_conf, NULL, RSRC_CONF, "The path of your unaffected domains file"),
  AP_INIT_TAKE1("MS_CacheSize", cachesize, NULL, RSRC_CONF, "Number of cache entries. Default: " STR(DEF_CACHE_SIZE) " Max:" STR(MAX_CACHE_SIZE)),
  AP_INIT_TAKE1("MS_CacheValidity", cachevalidity, NULL, RSRC_CONF, "Time in seconds for which cache entries are valid. Default: " STR(DEV_CACHE_TIME_S)),
  AP_INIT_TAKE1("MS_CustomError", custom_err_cfg, NULL, RSRC_CONF, "Custom error message"),
  {NULL}
};

/* Called on module init */
static int spamhaus_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  /* Init static variables, create hash tables for ip whitelist, unaffected domains and ip lookup cache */
  old_whitelist_mtime = old_unaffected_mtime = (time_t)0;
  hash_whitelist = apr_hash_make(p);
  hash_unaffected = apr_hash_make(p);
  hash_remote_ip = apr_hash_make(p);
  ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, MODULE_NAME " " MODULE_VERSION " started.");
  return OK;
}

/* Register Apache callbacks */
static void register_hooks(apr_pool_t *p)
{
  ap_hook_post_config(spamhaus_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_access_checker(spamhaus_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Define Apache module configuration structure */
module AP_MODULE_DECLARE_DATA spamhaus_new_module = {
  STANDARD20_MODULE_STUFF,
  spamhaus_create_dir_config, /* Create per-dir config structures    */
  NULL,                       /* Merge  per-dir config structures    */
  spamhaus_create_config,     /* Create per-server config structures */
  NULL,                       /* Merge  per-server config structures */
  spamhaus_cmds,              /* Table of config file commands       */
  register_hooks
};
