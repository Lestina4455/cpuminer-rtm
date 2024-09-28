/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014-2016 Tanguy Pruvot
 * Copyright 2016-2020 Jay D Dee
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

/*
 *   Change log
 *
 *   2016-01-14: v 1.9-RC inititial limited release combining
 *                cpuminer-multi 1.2-prev, darkcoin-cpu-miner 1.3,
 *                and cp3u 2.3.2 plus some performance optimizations.
 *
 *   2016-02-04: v3.1 algo_gate implemntation
 */

#include <cpuminer-config.h>
#define _GNU_SOURCE

#include "sysinfos.c"
#include <curl/curl.h>
#include <inttypes.h>
#include <jansson.h>
#include <math.h>
#include <memory.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#endif

#ifdef _MSC_VER
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

// GCC 9 warning sysctl.h is deprecated
#if (__GNUC__ < 9)
#include <sys/sysctl.h>
#endif

#endif // HAVE_SYS_SYSCTL_H
#endif // _MSC_VER ELSE

#ifndef WIN32
#include <sys/resource.h>
#endif

#include "algo-gate-api.h"
#include "miner.h"

#ifdef WIN32
#include "compat/winansi.h"
// BOOL WINAPI ConsoleHandler(DWORD);
#endif
#ifdef _MSC_VER
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

#define LP_SCANTIME 60

algo_gate_t algo_gate;

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_benchmark_extended = false;
bool opt_redirect = true;
bool opt_extranonce = true;
bool want_longpoll = false;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = true; // pretty useless
bool have_stratum = false;
bool allow_mininginfo = true;
bool use_syslog = false;
bool use_colors = true;
static bool opt_background = false;
bool opt_quiet = false;
bool opt_randomize = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
static int opt_time_limit = 0;
int opt_timeout = 300;
static int opt_scantime = 5;
const int min_scantime = 1;
// static const bool opt_time = true;
enum algos opt_algo = ALGO_NULL;
char *opt_param_key = NULL;
int opt_param_n = 0;
int opt_param_r = 0;
int opt_n_threads = 0;
bool opt_sapling = false;

// Windows doesn't support 128 bit affinity mask.
// Need compile time and run time test.
#if defined(__linux) && defined(GCC_INT128)
#define AFFINITY_USES_UINT128 1
static uint128_t opt_affinity = -1;
static bool affinity_uses_uint128 = true;
#else
static uint64_t opt_affinity = -1;
static bool affinity_uses_uint128 = false;
#endif

int opt_priority = 0; // deprecated
int num_cpus = 1;
int num_cpugroups = 1;
char *rpc_url = NULL;
;
char *rpc_userpass = NULL;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
char *coinbase_address;
char *opt_data_file = NULL;
bool opt_verify = false;

// pk_buffer_size is used as a version selector by b58 code, therefore
// it must be set correctly to work.
const int pk_buffer_size_max = 26;
int pk_buffer_size = 25;
static unsigned char pk_script[26] = {0};
static size_t pk_script_size = 0;
static char coinbase_sig[101] = {0};
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int dev_stratum_thr_id = -1;
int api_thr_id = -1;
bool stratum_need_reset = false;
bool dev_stratum_need_reset = false;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum;
struct stratum_ctx dev_stratum;
double opt_diff_factor = 1.0;
double opt_target_factor = 1.0;
uint32_t zr5_pok = 0;
bool opt_stratum_stats = false;
bool opt_hash_meter = false;
uint32_t submitted_share_count = 0;
uint32_t accepted_share_count = 0;
uint32_t rejected_share_count = 0;
uint32_t stale_share_count = 0;
uint32_t solved_block_count = 0;
double *thr_hashrates;
double global_hashrate = 0.;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;
uint32_t opt_work_size = 0;
double gr_bench_hashes = 0.;
double gr_bench_time = 0.;
// When should the first dev mining begin.
const struct timeval first_dev = {300, 0}; // First Dev mining after.
struct timeval dev_start;
// How often should it occur.
const struct timeval dev_interval = {3600, 0};
// Dev fee - 1% of time.
const double dev_fee = 0.01;
bool dev_mining = false;

// conditional mining
bool conditional_state[MAX_CPUS] = {0};
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;

// Dev pool data.
const char *dev_address = "3BJRcW4EfNKntEELGDfkqVjFVByqEAwBm3";
const char *dev_userpass = "3BJRcW4EfNKntEELGDfkqVjFVByqEAwBm3:c=BTC";
// Dev pools. In case of no pools available user pool will be used.
const char *dev_pools[5] = {"stratum+tcp://ghostrider.asia.mine.zergpool.com:5354",
                            "stratum+tcp://ghostrider.mine.zergpool.com:5354",
                            "stratum+tcp://ghostrider.sea.mine.zpool.ca:5354",
                            "stratum+tcp://ghostrider.eu.mine.zpool.ca:5354",
                            "stratum+tcp://ghostrider.na.mine.zpool.ca:5354"};

// API
static bool opt_api_enabled = false;
char *opt_api_allow = NULL;
int opt_api_listen = 0;
int opt_api_remote = 0;
char *default_api_allow = "127.0.0.1";
int default_api_listen = 4048;

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
pthread_cond_t sync_cond;

static struct timeval session_start;
static struct timeval five_min_start;
static uint64_t session_first_block = 0;
static double latency_sum = 0.;
static uint64_t submit_sum = 0;
static uint64_t accept_sum = 0;
static uint64_t stale_sum = 0;
static uint64_t reject_sum = 0;
static uint64_t solved_sum = 0;
static double norm_diff_sum = 0.;
static uint32_t last_block_height = 0;
static double highest_share = 0;   // highest accepted share diff
static double lowest_share = 9e99; // lowest accepted share diff
static double last_targetdiff = 0.;
#if !(defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32))
static uint32_t hi_temp = 0;
static uint32_t prev_temp = 0;
#endif

static char const short_options[] =
#ifdef HAVE_SYSLOG_H
    "S"
#endif
    "a:b:Bc:CDf:hK:m:n:N:p:Px:qr:R:s:t:T:o:u:O:V";

static struct work g_work __attribute__((aligned(64))) = {{0}};
time_t g_work_time = 0;
pthread_rwlock_t g_work_lock;
static bool submit_old = false;
char *lp_id;

static void workio_cmd_free(struct workio_cmd *wc);

static void format_affinity_map(char *map_str, uint64_t map) {
  int n = num_cpus < 64 ? num_cpus : 64;
  int i;

  for (i = 0; i < n; i++) {
    if (map & 1)
      map_str[i] = '!';
    else
      map_str[i] = '.';
    map >>= 1;
  }
  memset(&map_str[i], 0, 64 - i);
}

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void) {
  struct sched_param param;
  param.sched_priority = 0;
#ifdef SCHED_IDLE
  if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
    sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#ifdef __BIONIC__
#define pthread_setaffinity_np(tid, sz, s)                                     \
  {} /* only do process affinity */
#endif

// Linux affinity can use int128.
#if AFFINITY_USES_UINT128
static void affine_to_cpu_mask(int id, uint128_t mask)
#else
static void affine_to_cpu_mask(int id, uint64_t mask)
#endif
{
  cpu_set_t set;
  CPU_ZERO(&set);
  uint8_t ncpus = (num_cpus > 256) ? 256 : num_cpus;

  for (uint8_t i = 0; i < ncpus; i++) {
    // cpu mask
#if AFFINITY_USES_UINT128
    if ((mask & ((uint128_t)1 << i)))
      CPU_SET(i, &set);
#else
    if ((ncpus > 64) || (mask & (1 << i)))
      CPU_SET(i, &set);
#endif
  }
  if (id == -1) {
    // process affinity
    sched_setaffinity(0, sizeof(&set), &set);
  } else {
    // thread only
    pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
  }
}

#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) {}

// Windows CPU groups to manage more than 64 CPUs.
static void affine_to_cpu_mask(int id, uint64_t mask) {
  bool success;
  unsigned long last_error;
  //   BOOL success;
  //   DWORD last_error;

  if (id == -1)
    success = SetProcessAffinityMask(GetCurrentProcess(), mask);

    // Are Windows CPU Groups supported?
#if _WIN32_WINNT == 0x0601
  else if (num_cpugroups == 1)
    success = SetThreadAffinityMask(GetCurrentThread(), mask);
  else {
    // Find the correct cpu group
    int cpu = id % num_cpus;
    int group;
    for (group = 0; group < num_cpugroups; group++) {
      int cpus = GetActiveProcessorCount(group);
      if (cpu < cpus)
        break;
      cpu -= cpus;
    }

    if (opt_debug)
      applog(LOG_DEBUG, "Binding thread %d to cpu %d on cpu group %d (mask %x)",
             id, cpu, group, (1ULL << cpu));

    GROUP_AFFINITY affinity;
    affinity.Group = group;
    affinity.Mask = 1ULL << cpu;
    success = SetThreadGroupAffinity(GetCurrentThread(), &affinity, NULL);
  }
#else
  else
    success = SetThreadAffinityMask(GetCurrentThread(), mask);
#endif

  if (!success) {
    last_error = GetLastError();
    applog(LOG_WARNING, "affine_to_cpu_mask for %u returned %x", id,
           last_error);
  }
}

#else
static inline void drop_policy(void) {}
static void affine_to_cpu_mask(int id, unsigned long mask) {}
#endif

// not very useful, just index the arrray directly.
// but declaring this function in miner.h eliminates
// an annoying compiler warning for not using a static.
const char *algo_name(enum algos a) { return algo_names[a]; }

void get_currentalgo(char *buf, int sz) {
  snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

void proper_exit(int reason) {
#ifdef WIN32
  if (opt_background) {
    HWND hcon = GetConsoleWindow();
    if (hcon) {
      // unhide parent command line windows
      ShowWindow(hcon, SW_SHOWMINNOACTIVE);
    }
  }
#endif
  exit(reason);
}

uint32_t *get_stratum_job_ntime() { return (uint32_t *)stratum.job.ntime; }

void work_free(struct work *w) {
  if (w->txs)
    free(w->txs);
  if (w->workid)
    free(w->workid);
  if (w->job_id)
    free(w->job_id);
  if (w->xnonce2)
    free(w->xnonce2);
}

void work_copy(struct work *dest, const struct work *src) {
  memcpy(dest, src, sizeof(struct work));
  if (src->txs)
    dest->txs = strdup(src->txs);
  if (src->workid)
    dest->workid = strdup(src->workid);
  if (src->job_id)
    dest->job_id = strdup(src->job_id);
  if (src->xnonce2) {
    dest->xnonce2 = (uchar *)malloc(src->xnonce2_len);
    memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
  }
}

int std_get_work_data_size() { return STD_WORK_DATA_SIZE; }

// Default
bool std_le_work_decode(struct work *work) {
  int i;
  const int adata_sz = algo_gate.get_work_data_size() / 4;
  const int atarget_sz = ARRAY_SIZE(work->target);

  for (i = 0; i < adata_sz; i++)
    work->data[i] = le32dec(work->data + i);
  for (i = 0; i < atarget_sz; i++)
    work->target[i] = le32dec(work->target + i);
  return true;
}

bool std_be_work_decode(struct work *work) {
  int i;
  const int adata_sz = algo_gate.get_work_data_size() / 4;
  const int atarget_sz = ARRAY_SIZE(work->target);

  for (i = 0; i < adata_sz; i++)
    work->data[i] = be32dec(work->data + i);
  for (i = 0; i < atarget_sz; i++)
    work->target[i] = le32dec(work->target + i);
  return true;
}

static bool work_decode(const json_t *val, struct work *work) {
  const int data_size = algo_gate.get_work_data_size();
  const int target_size = sizeof(work->target);

  if (unlikely(!jobj_binary(val, "data", work->data, data_size))) {
    applog(LOG_ERR, "JSON invalid data");
    return false;
  }
  if (unlikely(!jobj_binary(val, "target", work->target, target_size))) {
    applog(LOG_ERR, "JSON invalid target");
    return false;
  }

  if (unlikely(!algo_gate.work_decode(work)))
    return false;

  if (!allow_mininginfo)
    net_diff = algo_gate.calc_network_diff(work);

  work->targetdiff = hash_to_diff(work->target);
  stratum_diff = last_targetdiff = work->targetdiff;
  work->sharediff = 0;
  algo_gate.decode_extra_data(work, &net_blocks);

  return true;
}

// good alternative for wallet mining, difficulty and net hashrate
static const char *info_req =
    "{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo(CURL *curl, struct work *work) {
  if (have_stratum || !allow_mininginfo || !dev_mining)
    return false;

  int curl_err = 0;
  json_t *val =
      json_rpc_call(curl, rpc_url, rpc_userpass, info_req, &curl_err, 0);

  if (!val && curl_err == -1) {
    allow_mininginfo = false;
    applog(LOG_NOTICE,
           "\"getmininginfo\" not supported, some stats not available");
    return false;
  }

  json_t *res = json_object_get(val, "result");
  // "blocks": 491493 (= current work height - 1)
  // "difficulty": 0.99607860999999998
  // "networkhashps": 56475980
  if (res) {
    json_t *key = json_object_get(res, "difficulty");
    if (key) {
      if (json_is_object(key))
        key = json_object_get(key, "proof-of-work");
      if (json_is_real(key))
        net_diff = work->targetdiff = json_real_value(key);
    }

    key = json_object_get(res, "networkhashps");
    if (key) {
      if (json_is_integer(key))
        net_hashrate = (double)json_integer_value(key);
      else if (json_is_real(key))
        net_hashrate = (double)json_real_value(key);
    }

    key = json_object_get(res, "blocks");
    if (key && json_is_integer(key))
      net_blocks = json_integer_value(key);

    if (opt_debug)
      applog(LOG_INFO, "Mining info: diff %.5g, net_hashrate %f, height %d",
             net_diff, net_hashrate, net_blocks);

    if (!work->height) {
      // complete missing data from getwork
      work->height = (uint32_t)net_blocks + 1;
      if (work->height > g_work.height)
        restart_threads();
    } // res
  }
  json_decref(val);
  return true;
}

// hodl needs 4 but leave it at 3 until gbt better understood
//#define BLOCK_VERSION_CURRENT 3
#define BLOCK_VERSION_CURRENT 4

static bool gbt_work_decode(const json_t *val, struct work *work) {
  int i, n;
  uint32_t version, curtime, bits;
  uint32_t prevhash[8];
  uint32_t target[8];
  unsigned char final_sapling_hash[32];
  int cbtx_size;
  uchar *cbtx = NULL;
  int tx_count, tx_size;
  uchar txc_vi[9];
  uchar(*merkle_tree)[32] = NULL;
  bool coinbase_append = false;
  bool submit_coinbase = false;
  bool version_force = false;
  bool version_reduce = false;
  json_t *tmp, *txa;
  bool rc = false;

  // Segwit BEGIN
  bool segwit = false;
  tmp = json_object_get(val, "rules");
  if (tmp && json_is_array(tmp)) {
    n = json_array_size(tmp);
    for (i = 0; i < n; i++) {
      const char *s = json_string_value(json_array_get(tmp, i));
      if (!s)
        continue;
      if (!strcmp(s, "segwit") || !strcmp(s, "!segwit"))
        segwit = true;
    }
  }
  // Segwit END

  tmp = json_object_get(val, "mutable");
  if (tmp && json_is_array(tmp)) {
    n = (int)json_array_size(tmp);
    for (i = 0; i < n; i++) {
      const char *s = json_string_value(json_array_get(tmp, i));
      if (!s)
        continue;
      if (!strcmp(s, "coinbase/append"))
        coinbase_append = true;
      else if (!strcmp(s, "submit/coinbase"))
        submit_coinbase = true;
      else if (!strcmp(s, "version/force"))
        version_force = true;
      else if (!strcmp(s, "version/reduce"))
        version_reduce = true;
    }
  }

  tmp = json_object_get(val, "height");
  if (!tmp || !json_is_integer(tmp)) {
    applog(LOG_ERR, "JSON invalid height");
    goto out;
  }
  work->height = (int)json_integer_value(tmp);

  tmp = json_object_get(val, "version");
  if (!tmp || !json_is_integer(tmp)) {
    applog(LOG_ERR, "JSON invalid version");
    goto out;
  }
  version = (uint32_t)json_integer_value(tmp);
  // yescryptr8g uses block version 5 and sapling.
  if (opt_sapling)
    work->sapling = true;
  if ((version & 0xffU) > BLOCK_VERSION_CURRENT) {
    if (version_reduce)
      version = (version & ~0xffU) | BLOCK_VERSION_CURRENT;
    else if (have_gbt && allow_getwork && !version_force) {
      applog(LOG_DEBUG, "Switching to getwork, gbt version %d", version);
      have_gbt = false;
      goto out;
    } else if (!version_force) {
      applog(LOG_ERR, "Unrecognized block version: %u", version);
      goto out;
    }
  }

  if (unlikely(
          !jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash)))) {
    applog(LOG_ERR, "JSON invalid previousblockhash");
    goto out;
  }

  tmp = json_object_get(val, "curtime");
  if (!tmp || !json_is_integer(tmp)) {
    applog(LOG_ERR, "JSON invalid curtime");
    goto out;
  }
  curtime = (uint32_t)json_integer_value(tmp);

  if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
    applog(LOG_ERR, "JSON invalid bits");
    goto out;
  }

  if (work->sapling) {
    if (unlikely(!jobj_binary(val, "finalsaplingroothash", final_sapling_hash,
                              sizeof(final_sapling_hash)))) {
      applog(LOG_ERR, "JSON invalid finalsaplingroothash");
      goto out;
    }
  }

  /* find count and size of transactions */
  txa = json_object_get(val, "transactions");
  if (!txa || !json_is_array(txa)) {
    applog(LOG_ERR, "JSON invalid transactions");
    goto out;
  }
  tx_count = (int)json_array_size(txa);
  tx_size = 0;
  for (i = 0; i < tx_count; i++) {
    const json_t *tx = json_array_get(txa, i);
    const char *tx_hex = json_string_value(json_object_get(tx, "data"));
    if (!tx_hex) {
      applog(LOG_ERR, "JSON invalid transactions");
      goto out;
    }
    tx_size += (int)(strlen(tx_hex) / 2);
  }

  /* build coinbase transaction */
  tmp = json_object_get(val, "coinbasetxn");
  if (tmp) {
    const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
    cbtx_size = cbtx_hex ? (int)strlen(cbtx_hex) / 2 : 0;
    cbtx = (uchar *)malloc(cbtx_size + 100);
    if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
      applog(LOG_ERR, "JSON invalid coinbasetxn");
      goto out;
    }
  } else {
    int64_t cbvalue;
    if (!pk_script_size) {
      if (allow_getwork) {
        applog(LOG_INFO, "No payout address provided, switching to getwork");
        have_gbt = false;
      } else
        applog(LOG_ERR, "No payout address provided");
      goto out;
    }
    tmp = json_object_get(val, "coinbasevalue");
    if (!tmp || !json_is_number(tmp)) {
      applog(LOG_ERR, "JSON invalid coinbasevalue");
      goto out;
    }
    cbvalue = (int64_t)(json_is_integer(tmp) ? json_integer_value(tmp)
                                             : json_number_value(tmp));
    cbtx = (uchar *)malloc(256);
    le32enc((uint32_t *)cbtx, 1);                 /* version */
    cbtx[4] = 1;                                  /* in-counter */
    memset(cbtx + 5, 0x00, 32);                   /* prev txout hash */
    le32enc((uint32_t *)(cbtx + 37), 0xffffffff); /* prev txout index */
    cbtx_size = 43;
    /* BIP 34: height in coinbase */
    for (n = work->height; n; n >>= 8)
      cbtx[cbtx_size++] = n & 0xff;
    /* If the last byte pushed is >= 0x80, then we need to add
       another zero byte to signal that the block height is a
       positive number.  */
    if (cbtx[cbtx_size - 1] & 0x80)
      cbtx[cbtx_size++] = 0;
    cbtx[42] = cbtx_size - 43;
    cbtx[41] = cbtx_size - 42;                           /* scriptsig length */
    le32enc((uint32_t *)(cbtx + cbtx_size), 0xffffffff); /* sequence */
    cbtx_size += 4;

    // Segwit BEGIN
    // cbtx[cbtx_size++] = 1; /* out-counter */
    cbtx[cbtx_size++] = segwit ? 2 : 1; /* out-counter */
    /
