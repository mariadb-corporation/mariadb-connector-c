/************************************************************************************
  Copyright (C) 2026 MariaDB plc

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with this library; if not see <http://www.gnu.org/licenses>
  or write to the Free Software Foundation, Inc.,
  51 Franklin St., Fifth Floor, Boston, MA 02110, USA

 *************************************************************************************/

#ifdef HAVE_TLS

#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>
#include <string.h>
#include <ma_hash.h>
#include <ma_crypt.h>
#include <ma_session_cache.h>

/*
  How many sessions of one connection identity are kept.

  New TLS 1.3 connection is issued two session tickets, every resumed
  connection consumes a ticket and is issued a new one. So a list once
  populated neither grows nor shrinks, and its length follows the number of
  connections that are opened at the same time.

  Unless all session tickets are refused: then every connection consumes one,
  adds two and the list keeps growing. This could be caused by an old server
  or by a load balancer that sends the connection to a new server every time.
  Thus we need to limit the max number of saved sessions and drop the rest.
*/
#define MA_TLS_MAX_CACHED_SESSIONS 1024

/* One TLS session ticket, linked in a list */
typedef struct st_ma_tls_session
{
  struct st_ma_tls_session *next;
  SSL_SESSION *session;
  time_t not_after;                         /* session have expiration time*/
} MA_TLS_SESSION;

#define MA_PLUGIN_NAME_LEN 64

/* One cache entry element. Nothing of it is ever handed out by reference, so
   it may be freed at any time. */
typedef struct st_ma_cache_entry
{
  /* A FIFO queue of TLS sessions. tls_tail points at the next pointer the
     next session goes into - at tls itself when the queue is empty. */
  MA_TLS_SESSION *tls, **tls_tail;
  unsigned int tls_count;

  uchar key[MA_SHA256_HASH_SIZE];
} MA_CACHE_ENTRY;

static MA_HASHTBL session_cache;
static pthread_mutex_t LOCK_session_cache;

/* Unlink the oldest session. Freed by the caller outside the lock. */
static MA_TLS_SESSION *ma_tls_session_remove_first(MA_CACHE_ENTRY *entry)
{
  MA_TLS_SESSION *tls= entry->tls;

  if (tls)
  {
    if (!(entry->tls= tls->next))
      entry->tls_tail= &entry->tls;
    entry->tls_count--;
    tls->next= NULL;
  }
  return tls;
}

/* Used when freeing cache entry and to delete expired tls sessions outside the lock */
static void ma_tls_session_free_list(MA_TLS_SESSION *tls)
{
  while (tls)
  {
    MA_TLS_SESSION *next= tls->next;
    ma_tls_session_free(tls->session);  /* NULL when it was handed out */
    free(tls);
    tls= next;
  }
}

/* The entry of a connection identity, created when there is none.
   The lock must be held. */
static MA_CACHE_ENTRY *ma_cache_entry_find_or_add(const uchar *key)
{
  MA_CACHE_ENTRY *entry;

  if ((entry= ma_hashtbl_search(&session_cache, key, MA_SHA256_HASH_SIZE)))
    return entry;

  /* once per connection identity, this one is not on the hot path */
  if (!(entry= (MA_CACHE_ENTRY *)calloc(1, sizeof(MA_CACHE_ENTRY))))
    return NULL;

  memcpy(entry->key, key, MA_SHA256_HASH_SIZE);
  entry->tls_tail= &entry->tls;

  if (ma_hashtbl_insert(&session_cache, (uchar *)entry))
  {
    free(entry);
    entry= NULL;
  }
  return entry;
}

static void ma_cache_entry_delete(void *record)
{
  MA_CACHE_ENTRY *entry= (MA_CACHE_ENTRY *)record;
  ma_tls_session_free_list(entry->tls);
  free(entry);
}

static my_bool ma_session_cache_create(void)
{
  return ma_hashtbl_init(&session_cache, 0, offsetof(MA_CACHE_ENTRY, key),
                         MA_SHA256_HASH_SIZE, NULL, ma_cache_entry_delete, 0);
}

void ma_session_cache_init(void)
{
  if (ma_session_cache_create())
    return;
  pthread_mutex_init(&LOCK_session_cache, NULL);
}

void ma_session_cache_deinit(void)
{
  if (!ma_hashtbl_inited(&session_cache))
    return;
  ma_hashtbl_free(&session_cache);
  pthread_mutex_destroy(&LOCK_session_cache);
}

SSL_SESSION *ma_tls_session_take(const uchar *key)
{
  SSL_SESSION *ssl_session= NULL;
  MA_TLS_SESSION *tls, *freeme= NULL;
  MA_CACHE_ENTRY *entry;
  time_t now= time(NULL);

  if (!ma_hashtbl_inited(&session_cache))
    return NULL;

  pthread_mutex_lock(&LOCK_session_cache);
  if ((entry= ma_hashtbl_search(&session_cache, key, MA_SHA256_HASH_SIZE)))
  {
    while (!ssl_session && (tls= ma_tls_session_remove_first(entry)))
    {
      if (tls->not_after > now)
      {
        ssl_session= tls->session;
        tls->session= NULL;
      }
      tls->next= freeme;
      freeme= tls;
    }
  }
  pthread_mutex_unlock(&LOCK_session_cache);

  ma_tls_session_free_list(freeme);
  return ssl_session;
}

void ma_tls_session_add(const uchar *key, SSL_SESSION *ssl_session,
                        time_t not_after)
{
  MA_TLS_SESSION *tls, *freeme= NULL;
  MA_CACHE_ENTRY *entry;

  if (!ma_hashtbl_inited(&session_cache) ||
      !(tls= (MA_TLS_SESSION *)malloc(sizeof(MA_TLS_SESSION))))
  {
    ma_tls_session_free(ssl_session);
    return;
  }

  tls->session= ssl_session;
  tls->not_after= not_after;
  tls->next= NULL;

  pthread_mutex_lock(&LOCK_session_cache);

  if (!(entry= ma_cache_entry_find_or_add(key)))
    goto err;

  if (entry->tls_count >= MA_TLS_MAX_CACHED_SESSIONS)
    freeme= ma_tls_session_remove_first(entry);

  *entry->tls_tail= tls;
  entry->tls_tail= &tls->next;
  entry->tls_count++;

  tls= freeme;
err:
  pthread_mutex_unlock(&LOCK_session_cache);
  ma_tls_session_free_list(tls);
}

void ma_tls_session_clear(const uchar *key)
{
  MA_TLS_SESSION *freeme= NULL;
  MA_CACHE_ENTRY *entry;

  if (!ma_hashtbl_inited(&session_cache))
    return;

  pthread_mutex_lock(&LOCK_session_cache);
  if ((entry= ma_hashtbl_search(&session_cache, key, MA_SHA256_HASH_SIZE)))
  {
    freeme= entry->tls;
    entry->tls= NULL;
    entry->tls_tail= &entry->tls;
    entry->tls_count= 0;
  }
  pthread_mutex_unlock(&LOCK_session_cache);

  ma_tls_session_free_list(freeme);
}

static void cache_key_add_int(MA_HASH_CTX *ctx, uint32 value)
{
  ma_hash_input(ctx, (const uchar *)&value, sizeof(value));
}

/* A NULL string must not hash equal to an empty one: ssl_ca=NULL means
   "use the default verify paths", ssl_ca="" does not */
static void cache_key_add_str(MA_HASH_CTX *ctx, const char *str)
{
  size_t len= str ? strlen(str) : (size_t)-1;
  cache_key_add_int(ctx, (uint32)len);
  if (str)
    ma_hash_input(ctx, (const uchar *)str, len);
}

/*
  Build the cache key of a connection.

  Everything that decides what the server is and who we are to it has to be
  part of the key: a resumed handshake exchanges and verifies no certificate
  at all, and an entry must only ever be used by the account that filled it.
*/
my_bool ma_session_cache_key(MYSQL *mysql, uchar *key)
{
  struct st_mysql_options_extension *ext= mysql->options.extension;
  MA_HASH_CTX *ctx;

  if (!(ctx= ma_hash_new(MA_HASH_SHA256)))
    return 1;

  cache_key_add_str(ctx, mysql->user);
  cache_key_add_str(ctx, mysql->passwd);
  cache_key_add_str(ctx, mysql->host);
  cache_key_add_int(ctx, mysql->port);
  cache_key_add_str(ctx, mysql->unix_socket);
  cache_key_add_int(ctx, mysql->options.protocol);
  cache_key_add_str(ctx, mysql->options.ssl_ca);
  cache_key_add_str(ctx, mysql->options.ssl_capath);
  cache_key_add_str(ctx, mysql->options.ssl_cert);
  cache_key_add_str(ctx, mysql->options.ssl_key);
  cache_key_add_str(ctx, mysql->options.ssl_cipher);
  cache_key_add_str(ctx, ext->ssl_crl);
  cache_key_add_str(ctx, ext->ssl_crlpath);
  cache_key_add_str(ctx, ext->tls_version);
  cache_key_add_str(ctx, ext->tls_fp);
  cache_key_add_str(ctx, ext->tls_fp_list);
  cache_key_add_int(ctx, ext->tls_cipher_strength);
  cache_key_add_int(ctx, ext->tls_allow_invalid_server_cert);
  ma_hash_input(ctx, (const uchar *)&ext->tls_verification_callback,
                     sizeof(ext->tls_verification_callback));

  ma_hash_result(ctx, key);
  ma_hash_free(ctx);
  return 0;
}

#endif /* HAVE_TLS */
