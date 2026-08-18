/************************************************************************************
  Copyright (C) 2014, 2026 MariaDB plc

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

/*
 * this is the abstraction layer for communication via SSL.
 * The following SSL libraries/variants are currently supported:
 * - openssl
 * - gnutls
 * - schannel (windows only)
 * 
 * Different SSL variants are implemented as plugins
 * On Windows schannel is implemented as (standard)
 * built-in plugin.
 */

#ifdef HAVE_TLS

#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>
#include <string.h>
#include <errmsg.h>
#include <ma_pvio.h>
#include <ma_tls.h>
#include <mysql/client_plugin.h>
#include <mariadb/ma_io.h>
#include <ma_hash.h>
#include <ma_crypt.h>

#ifdef HAVE_NONBLOCK
#include <mariadb_async.h>
#include <ma_context.h>
#endif

#define MAX_FINGERPRINT_LEN 128;

/* Errors should be handled via pvio callback function */
my_bool ma_tls_initialized= FALSE;
unsigned int mariadb_deinitialize_ssl= 1;

const char *tls_protocol_version[]=
  {"SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "Unknown"};

/*
  TLS session cache.

  An entry is removed from the cache when it is handed out: a TLS 1.3 ticket
  is meant to be used once, and a resumed connection is issued a new one, so
  the cache refills itself. A configuration can have more than one entry -
  a full handshake yields two sessions, a resumed one a single.

  The cache is therefore not bounded by the number of connections, but by
  the number of configurations connected to, of which a client has few.

  Unless the sessions are refused: then every connection consumes one entry
  and publishes the two of a full handshake. A server can do that on
  purpose, and a load balancer without session affinity does it by itself -
  its backends do not share ticket keys, and the key cannot tell them
  apart. Dropping the whole cache once it grows this large is enough,
  nothing but performance depends on it.
*/

#define MA_TLS_SESSION_CACHE_MAX 1024
/* How many sessions of one handshake are kept. Only TLS 1.3 gives more than
   one, and only in a full handshake, as many as the server's
   SSL_CTX_set_num_tickets, two by default */
#define MA_TLS_MAX_RECEIVED_SESSIONS 4

static MA_HASHTBL tls_session_cache;
static pthread_mutex_t LOCK_tls_session_cache;

/* This struct is stored in the tls_session_cache */
typedef struct st_ma_tls_session
{
  SSL_SESSION *session;      /* one reference owned, NULL once handed out */
  time_t not_after;
  uchar key[MA_SHA256_HASH_SIZE];
} MA_TLS_SESSION;

/*
  Sessions arrive early during the handshake so they are stored in the
  MARIADB_TLS and only added to the cache once the connection succeeded.
  Afterwards - with 0-RTT the server sends the session during the normal
  query traffic - they go straight to the cache.
*/
struct st_ma_tls_received_sessions
{
  MA_TLS_SESSION *session[MA_TLS_MAX_RECEIVED_SESSIONS];
  unsigned int session_count;
  my_bool authenticated;                        /* session can be cached */
  uchar key[MA_SHA256_HASH_SIZE];
};

static void ma_tls_session_delete(void *record)
{
  MA_TLS_SESSION *entry= (MA_TLS_SESSION *)record;
  /* Handing an entry out clears the session, the reference moved on */
  if (entry->session)
    ma_tls_session_free(entry->session);
  free(entry);
}

static my_bool ma_tls_session_cache_create(void)
{
  return ma_hashtbl_init(&tls_session_cache, 0, offsetof(MA_TLS_SESSION, key),
                         MA_SHA256_HASH_SIZE, NULL, ma_tls_session_delete, 0);
}

void ma_tls_session_cache_init(void)
{
  if (ma_tls_session_cache_create())
    return;
  pthread_mutex_init(&LOCK_tls_session_cache, NULL);
}

void ma_tls_session_cache_deinit(void)
{
  if (!ma_hashtbl_inited(&tls_session_cache))
    return;
  ma_hashtbl_free(&tls_session_cache);
  pthread_mutex_destroy(&LOCK_tls_session_cache);
}

static void ma_tls_key_int(MA_HASH_CTX *ctx, uint32 value)
{
  ma_hash_input(ctx, (const uchar *)&value, sizeof(value));
}

/* A NULL string must not hash equal to an empty one: ssl_ca=NULL means
   "use the default verify paths", ssl_ca="" does not */
static void ma_tls_key_str(MA_HASH_CTX *ctx, const char *str)
{
  size_t len= str ? strlen(str) : 0xFFFFFFFF;
  ma_tls_key_int(ctx, (uint32)len);
  if (str)
    ma_hash_input(ctx, (const uchar *)str, len);
}

/*
  Build the cache key of a connection.

  A resumed handshake exchanges and verifies no certificate whatsoever, so
  everything that decides which certificate is acceptable, and as whom we
  present ourselves, has to be part of the key.
*/
static my_bool ma_tls_session_key(MYSQL *mysql, MA_TLS_RECEIVED_SESSIONS *rs)
{
  struct st_mysql_options_extension *ext= mysql->options.extension;
  MA_HASH_CTX *ctx;

  if (!(ctx= ma_hash_new(MA_HASH_SHA256)))
    return 1;

  ma_tls_key_str(ctx, mysql->host);
  ma_tls_key_int(ctx, mysql->port);
  ma_tls_key_str(ctx, mysql->unix_socket);
  ma_tls_key_int(ctx, mysql->options.protocol);
  ma_tls_key_str(ctx, mysql->options.ssl_ca);
  ma_tls_key_str(ctx, mysql->options.ssl_capath);
  ma_tls_key_str(ctx, mysql->options.ssl_cert);
  ma_tls_key_str(ctx, mysql->options.ssl_key);
  ma_tls_key_str(ctx, mysql->options.ssl_cipher);
  ma_tls_key_str(ctx, ext->ssl_crl);
  ma_tls_key_str(ctx, ext->ssl_crlpath);
  ma_tls_key_str(ctx, ext->tls_version);
  ma_tls_key_str(ctx, ext->tls_fp);
  ma_tls_key_str(ctx, ext->tls_fp_list);
  ma_tls_key_int(ctx, ext->tls_cipher_strength);
  ma_tls_key_int(ctx, ext->tls_allow_invalid_server_cert);
  ma_hash_input(ctx, (const uchar *)&ext->tls_verification_callback,
                     sizeof(ext->tls_verification_callback));

  ma_hash_result(ctx, rs->key);
  ma_hash_free(ctx);
  return 0;
}

static MA_TLS_RECEIVED_SESSIONS *ma_tls_received_sessions_new(MYSQL *mysql)
{
  MA_TLS_RECEIVED_SESSIONS *rs;

  if (!ma_hashtbl_inited(&tls_session_cache))
    return NULL;

  if (!(rs= (MA_TLS_RECEIVED_SESSIONS *)
            calloc(1, sizeof(MA_TLS_RECEIVED_SESSIONS))))
    return NULL;

  if (ma_tls_session_key(mysql, rs))
  {
    free(rs);
    return NULL;
  }
  return rs;
}

static void ma_tls_received_sessions_free(MARIADB_TLS *ctls)
{
  MA_TLS_RECEIVED_SESSIONS *rs= ctls->received_sessions;
  unsigned int i;

  /* Sessions still here were not cached, so they belong to a handshake
     that was not accepted */
  for (i= 0; i < rs->session_count; i++)
    ma_tls_session_delete(rs->session[i]);

  free(rs);
  ctls->received_sessions= NULL;
}

SSL_SESSION *ma_tls_session_cache_get(MARIADB_TLS *ctls)
{
  MA_TLS_RECEIVED_SESSIONS *rs= ctls->received_sessions;
  MA_TLS_SESSION *entry;
  SSL_SESSION *session= NULL;
  time_t now;

  assert(rs->session_count == 0);
  now= time(NULL);
  pthread_mutex_lock(&LOCK_tls_session_cache);

  while (!session && (entry= ma_hashtbl_search(&tls_session_cache, rs->key,
                                               MA_SHA256_HASH_SIZE)))
  {
    if (entry->not_after > now)
    {
      session= entry->session;
      entry->session= NULL;
    }
    ma_hashtbl_delete(&tls_session_cache, (uchar *)entry);
  }
  pthread_mutex_unlock(&LOCK_tls_session_cache);
  return session;
}

/*
  Drop every session with a given key. Used when a handshake on
  one of the sessions fails. Drop all others - they aren't any good either.
*/
static void ma_tls_session_cache_purge(MA_TLS_RECEIVED_SESSIONS *rs)
{
  MA_TLS_SESSION *entry;

  if (!ma_hashtbl_inited(&tls_session_cache))
    return;

  pthread_mutex_lock(&LOCK_tls_session_cache);
  while ((entry= ma_hashtbl_search(&tls_session_cache, rs->key,
                                   MA_SHA256_HASH_SIZE)))
    ma_hashtbl_delete(&tls_session_cache, (uchar *)entry);
  pthread_mutex_unlock(&LOCK_tls_session_cache);
}

static void ma_tls_session_cache_put(MA_TLS_SESSION *entry)
{
  if (!ma_hashtbl_inited(&tls_session_cache))
  {
    ma_tls_session_delete(entry);
    return;
  }

  pthread_mutex_lock(&LOCK_tls_session_cache);

  /* see the comment above MA_TLS_SESSION_CACHE_MAX */
  if (tls_session_cache.records >= MA_TLS_SESSION_CACHE_MAX)
  {
    ma_hashtbl_free(&tls_session_cache);
    ma_tls_session_cache_create();
  }

  if (ma_hashtbl_insert(&tls_session_cache, (uchar *)entry))
  {
    pthread_mutex_unlock(&LOCK_tls_session_cache);
    ma_tls_session_delete(entry);
    return;
  }
  pthread_mutex_unlock(&LOCK_tls_session_cache);
}

int ma_tls_session_received(MARIADB_TLS *ctls, SSL_SESSION *session,
                            time_t not_after)
{
  MA_TLS_RECEIVED_SESSIONS *rs= ctls->received_sessions;
  MA_TLS_SESSION *entry;

  if (rs->session_count == MA_TLS_MAX_RECEIVED_SESSIONS)
    return 1;

  if (!(entry= (MA_TLS_SESSION *)malloc(sizeof(MA_TLS_SESSION))))
    return 1;

  entry->session= session;
  entry->not_after= not_after;
  memcpy(entry->key, rs->key, MA_SHA256_HASH_SIZE);

  rs->session[rs->session_count++]= entry;

  if (rs->authenticated)
    ma_pvio_cache_tls_session(ctls->pvio->mysql);
  return 0;
}

void ma_pvio_cache_tls_session(MYSQL *mysql)
{
  MARIADB_TLS *ctls= mysql->net.pvio->ctls;
  MA_TLS_RECEIVED_SESSIONS *rs= ctls->received_sessions;
  unsigned int i;

  rs->authenticated= 1;
  for (i= 0; i < rs->session_count; i++)
    ma_tls_session_cache_put(rs->session[i]);
  rs->session_count= 0;
}


MARIADB_TLS *ma_pvio_tls_init(MYSQL *mysql)
{
  MARIADB_TLS *ctls= NULL;

  if (!ma_tls_initialized)
    ma_tls_start(mysql->net.last_error, MYSQL_ERRMSG_SIZE);

  if (!(ctls= (MARIADB_TLS *)calloc(1, sizeof(MARIADB_TLS))))
  {
    return NULL;
  }

  /* register error routine and methods */
  ctls->pvio= mysql->net.pvio;
  if (!(ctls->received_sessions= ma_tls_received_sessions_new(mysql)))
  {
    free(ctls);
    return NULL;
  }

  if (!(ctls->ssl= ma_tls_init(mysql, ctls)))
  {
    ma_tls_received_sessions_free(ctls);
    free(ctls);
    return NULL;
  }
  return ctls;
}

my_bool ma_pvio_tls_connect(MARIADB_TLS *ctls)
{
  my_bool rc;

  if ((rc= ma_tls_connect(ctls)))
  {
    ma_tls_session_cache_purge(ctls->received_sessions);
    ma_tls_close(ctls);
    ma_tls_received_sessions_free(ctls);
  }
  return rc;
}

ssize_t ma_pvio_tls_read(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{
  return ma_tls_read(ctls, buffer, length);
}

ssize_t ma_pvio_tls_write(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{
  return ma_tls_write(ctls, buffer, length);
}

my_bool ma_pvio_tls_close(MARIADB_TLS *ctls)
{
  my_bool rc= ma_tls_close(ctls);
  ma_tls_received_sessions_free(ctls);
  return rc;
}

int ma_pvio_tls_verify_server_cert(MARIADB_TLS *ctls, unsigned int flags)
{
  MYSQL *mysql;
  int rc;

  if (!ctls || !ctls->pvio || !ctls->pvio->mysql)
    return 0;

  mysql= ctls->pvio->mysql;

  /* Skip peer certificate verification */
  if (mysql->options.extension->tls_allow_invalid_server_cert &&
      (!mysql->options.extension->tls_fp &&
       !mysql->options.extension->tls_fp_list &&
       !mysql->options.extension->ssl_crl &&
       !mysql->options.extension->ssl_crlpath &&
       !mysql->options.ssl_ca &&
       !mysql->options.ssl_capath))
  {
    /* Since OpenSSL implementation sets status during TLS handshake
       we need to clear verification status */
    mysql->net.tls_verify_status= 0;
    return 0;
  }

  if (flags & MARIADB_TLS_VERIFY_FINGERPRINT)
  {
    if (ma_pvio_tls_check_fp(ctls, mysql->options.extension->tls_fp, mysql->options.extension->tls_fp_list))
    {
      mysql->net.tls_verify_status|= MARIADB_TLS_VERIFY_FINGERPRINT;
      mysql->extension->tls_validation= mysql->net.tls_verify_status;
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Fingerprint validation of peer certificate failed");
      return 1;
    }
#ifdef HAVE_OPENSSL
    /* verification already happened via callback */
    if (!(mysql->net.tls_verify_status & flags))
    {
      mysql->extension->tls_validation= mysql->net.tls_verify_status;
      mysql->net.tls_verify_status= MARIADB_TLS_VERIFY_OK;
      return 0;
    }
#endif
  }
  rc= ma_tls_verify_server_cert(ctls, flags);

  /* Set error messages */
  if (!mysql->net.last_errno)
  {
    if (mysql->net.tls_verify_status & MARIADB_TLS_VERIFY_PERIOD)
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Certificate not yet valid or expired");
    else if (mysql->net.tls_verify_status & MARIADB_TLS_VERIFY_FINGERPRINT)
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Fingerprint validation of peer certificate failed");
    else if (mysql->net.tls_verify_status & MARIADB_TLS_VERIFY_REVOKED)
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Certificate revoked");
    else if (mysql->net.tls_verify_status & MARIADB_TLS_VERIFY_HOST)
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Hostname verification failed");
    else if (mysql->net.tls_verify_status & MARIADB_TLS_VERIFY_UNKNOWN)
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Peer certificate verification failed");
    else if (mysql->net.tls_verify_status & MARIADB_TLS_VERIFY_TRUST)
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Peer certificate is not trusted");
  }
  /* Save original validation */
  mysql->extension->tls_validation= mysql->net.tls_verify_status;
  mysql->net.tls_verify_status&= flags;
  return rc;
}

const char *ma_pvio_tls_cipher(MARIADB_TLS *ctls)
{
  return ma_tls_get_cipher(ctls);
}

void ma_pvio_tls_end()
{
  ma_tls_session_cache_deinit();
  ma_tls_end();
}

int ma_pvio_tls_get_protocol_version_id(MARIADB_TLS *ctls)
{
  return ma_tls_get_protocol_version(ctls);
}

const char *ma_pvio_tls_get_protocol_version(MARIADB_TLS *ctls)
{
  int version;

  version= ma_tls_get_protocol_version(ctls);
  if (version < 0 || version > PROTOCOL_MAX)
    return tls_protocol_version[PROTOCOL_UNKNOWN];
  return tls_protocol_version[version];
}

static signed char ma_hex2int(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  return -1;
}

#ifndef EVP_MAX_MD_SIZE
#define EVP_MAX_MD_SIZE 64
#endif

static my_bool ma_pvio_tls_compare_fp(MARIADB_TLS *ctls,
                                     const char *cert_fp,
                                     unsigned int cert_fp_len)
{
  char fp[EVP_MAX_MD_SIZE];
  unsigned int fp_len= EVP_MAX_MD_SIZE;
  unsigned int hash_type;

  char *p, *c;
  uint hash_len;

  /* check length without colons */
  if (strchr(cert_fp, ':'))
    hash_len= (uint)((strlen(cert_fp) + 1) / 3) * 2;
  else
    hash_len= (uint)strlen(cert_fp);

  /* check hash size */
  switch (hash_len) {
#ifndef DISABLE_WEAK_HASH
  case MA_SHA1_HASH_SIZE * 2:
    hash_type = MA_HASH_SHA1;
    break;
#endif
  case MA_SHA224_HASH_SIZE * 2:
    hash_type = MA_HASH_SHA224;
    break;
  case MA_SHA256_HASH_SIZE * 2:
    hash_type = MA_HASH_SHA256;
    break;
  case MA_SHA384_HASH_SIZE * 2:
    hash_type = MA_HASH_SHA384;
    break;
  case MA_SHA512_HASH_SIZE * 2:
    hash_type = MA_HASH_SHA512;
    break;
  default:
    {
      MYSQL* mysql = ctls->pvio->mysql;
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
        ER(CR_SSL_CONNECTION_ERROR),
        "Unknown or invalid fingerprint hash size detected");
      return 1;
    }
  }

  if (!ma_tls_get_finger_print(ctls, hash_type, fp, fp_len))
    return 1;

  c = fp;

  for (p = (char*)cert_fp; p < cert_fp + cert_fp_len; c++, p += 2)
  {
    signed char d1, d2;
    if (*p == ':')
      p++;
    if ((d1 = ma_hex2int(*p)) == -1 ||
      (d2 = ma_hex2int(*(p + 1))) == -1 ||
      (char)(d1 * 16 + d2) != *c)
      return 1;
  }
  return 0;
}

my_bool ma_pvio_tls_check_fp(MARIADB_TLS *ctls, const char *fp, const char *fp_list)
{
  my_bool rc=1;
  MYSQL *mysql= ctls->pvio->mysql;

  if (fp)
  {
    rc = ma_pvio_tls_compare_fp(ctls, fp, (uint)strlen(fp));
  }
  else if (fp_list)
  {
    MA_FILE *f;
    char buff[255];

    if (!(f = ma_open(fp_list, "r", mysql)))
      goto end;

    while (ma_gets(buff, sizeof(buff)-1, f))
    {
      /* remove trailing new line character */
      char *pos= strchr(buff, '\r');
      if (!pos)
        pos= strchr(buff, '\n');
      if (pos)
        *pos= '\0';
        
      if (!ma_pvio_tls_compare_fp(ctls, buff, (uint)strlen(buff)))
      {
        /* finger print is valid: close file and exit */
        ma_close(f);
        rc= 0;
        goto end;
      }
    }

    /* No finger print matched - close file and return error */
    ma_close(f);
  }

end:
  if (rc && !mysql->net.last_errno)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                         ER(CR_SSL_CONNECTION_ERROR), 
                         "Fingerprint verification of server certificate failed");
  }
  return rc;
}

void ma_pvio_tls_set_connection(MYSQL *mysql)
{
  ma_tls_set_connection(mysql);
}

unsigned int ma_pvio_tls_get_peer_cert_info(MARIADB_TLS *ctls, unsigned int size)
{
  return ma_tls_get_peer_cert_info(ctls, size);
}
#endif /* HAVE_TLS */
