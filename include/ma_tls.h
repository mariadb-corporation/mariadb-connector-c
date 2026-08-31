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

#ifndef _ma_tls_h_
#define _ma_tls_h_

#include <ma_hash.h>
#include <time.h>

enum enum_pvio_tls_type {
  SSL_TYPE_DEFAULT=0,
#ifdef _WIN32
  SSL_TYPE_SCHANNEL,
#endif
  SSL_TYPE_OPENSSL,
  SSL_TYPE_GNUTLS
};

#define PROTOCOL_SSLV3    0
#define PROTOCOL_TLS_1_0  1
#define PROTOCOL_TLS_1_1  2
#define PROTOCOL_TLS_1_2  3
#define PROTOCOL_TLS_1_3  4
#define PROTOCOL_UNKNOWN  5
#define PROTOCOL_MAX PROTOCOL_TLS_1_3

#define TLS_VERSION_LENGTH 64

#define have_fingerprint(m) \
((m)->options.extension) && \
(((m)->options.extension->tls_fp && (m)->options.extension->tls_fp[0]) ||\
((m)->options.extension->tls_fp_list && (m)->options.extension->tls_fp_list[0]))

extern char tls_library_version[TLS_VERSION_LENGTH];
extern my_bool ma_is_ip_address(const char *s);

/* The backend session object. On OpenSSL builds this is SSL_SESSION; other
   backends define the tag as they need it */
typedef struct ssl_session_st SSL_SESSION;

/* Sessions received on a connection, until they are added to the cache. */
typedef struct st_ma_tls_received_sessions MA_TLS_RECEIVED_SESSIONS;

typedef struct st_ma_pvio_tls {
  MA_TLS_RECEIVED_SESSIONS *received_sessions;
  MARIADB_PVIO *pvio;
  void *ssl;
  MARIADB_X509_INFO cert_info;
  const uchar *early_data; /* TLS 1.3 early data */
  size_t early_data_len;
} MARIADB_TLS;

/* Function prototypes */

/* ma_tls_start
   initializes the ssl library
   Parameter:
     errmsg      pointer to error message buffer
     errmsg_len  length of error message buffer
   Returns:
     0           success
     1           if an error occurred
   Notes:
     On success the global variable ma_tls_initialized will be set to 1
*/
int ma_tls_start(char *errmsg, size_t errmsg_len);

/* ma_tls_end
   unloads/deinitializes ssl library and unsets global variable
   ma_tls_initialized
*/
void ma_tls_end(void);

/* ma_tls_init
   creates a new SSL structure for a SSL connection and loads
   client certificates

   Parameters:
     MYSQL        a mysql structure
     MARIADB_TLS  MariaDB SSL container, with received_sessions already
                  set up
   Returns:
     void *       a pointer to internal SSL structure
*/
void * ma_tls_init(MYSQL *mysql, MARIADB_TLS *ctls);

/* ma_tls_session_free
   releases one backend session object received on a connection or taken
   from the session cache
*/
void ma_tls_session_free(SSL_SESSION *session);

/* ma_tls_connect
   performs SSL handshake
   Parameters:
     MARIADB_TLS   MariaDB SSL container
   Returns:
     0             success
     1             error
*/
my_bool ma_tls_connect(MARIADB_TLS *ctls);

/* ma_tls_read
   reads up to length bytes from socket
   Parameters:
     ctls         MariaDB SSL container
     buffer       read buffer
     length       buffer length
   Returns:
     0-n          bytes read
     -1           if an error occurred
*/
ssize_t ma_tls_read(MARIADB_TLS *ctls, const uchar* buffer, size_t length);

/* ma_tls_write
   write buffer to socket
   Parameters:
     ctls         MariaDB SSL container
     buffer       write buffer
     length       buffer length
   Returns:
     0-n          bytes written
     -1           if an error occurred
*/
ssize_t ma_tls_write(MARIADB_TLS *ctls, const uchar* buffer, size_t length);

/* ma_tls_close
   closes SSL connection and frees SSL structure which was previously
   created by ma_tls_init call
   Parameters:
     MARIADB_TLS  MariaDB SSL container
   Returns:
     0            success
     1            error
*/
my_bool ma_tls_close(MARIADB_TLS *ctls);

/* ma_tls_verify_server_cert
   validation check of server certificate
   Parameter:
     MARIADB_TLS  MariaDB SSL container
     flags        verification flags
   Returns:
     0            success
     1            error
*/
int ma_tls_verify_server_cert(MARIADB_TLS *ctls, unsigned int flags);

/* ma_tls_get_cipher
   returns cipher for current ssl connection
   Parameter:
     MARIADB_TLS  MariaDB SSL container
   Returns: 
     cipher in use or
     NULL on error
*/
const char *ma_tls_get_cipher(MARIADB_TLS *ssl);

/* ma_tls_get_finger_print
   returns SHA1 finger print of server certificate
   Parameter:
     MARIADB_TLS  MariaDB SSL container
     hash_type    hash_type as defined in ma_hash.h
     fp           buffer for fingerprint
     fp_len       buffer length

   Returns:
     actual size of finger print
*/
unsigned int ma_tls_get_finger_print(MARIADB_TLS *ctls, uint hash_type, char *fp, unsigned int fp_len);

/* ma_tls_get_protocol_version 
   returns protocol version number in use
   Parameter:
     MARIADB_TLS    MariaDB SSL container
   Returns:
     protocol number
*/
int ma_tls_get_protocol_version(MARIADB_TLS *ctls);
const char *ma_pvio_tls_get_protocol_version(MARIADB_TLS *ctls);
int ma_pvio_tls_get_protocol_version_id(MARIADB_TLS *ctls);
unsigned int ma_tls_get_peer_cert_info(MARIADB_TLS *ctls, unsigned int size);
void ma_tls_set_connection(MYSQL *mysql);

/* Function prototypes */
MARIADB_TLS *ma_pvio_tls_init(MYSQL *mysql);
my_bool ma_pvio_tls_connect(MARIADB_TLS *ctls);
ssize_t ma_pvio_tls_read(MARIADB_TLS *ctls, const uchar *buffer, size_t length);
ssize_t ma_pvio_tls_write(MARIADB_TLS *ctls, const uchar *buffer, size_t length);
my_bool ma_pvio_tls_close(MARIADB_TLS *ctls);
int ma_pvio_tls_verify_server_cert(MARIADB_TLS *ctls, unsigned int flags);
const char *ma_pvio_tls_cipher(MARIADB_TLS *ctls);
my_bool ma_pvio_tls_check_fp(MARIADB_TLS *ctls, const char *fp, const char *fp_list);
my_bool ma_pvio_start_ssl(MARIADB_PVIO *pvio, const uchar *early_data,
                          size_t early_data_len);
void ma_pvio_tls_set_connection(MYSQL *mysql);
void ma_pvio_tls_end();
unsigned int ma_pvio_tls_get_peer_cert_info(MARIADB_TLS *ctls, unsigned int size);

/* The session to offer on this connection, or NULL when nothing suitable is
   cached - see ma_session_cache.h. Called by the backend from
   ma_tls_connect(). The reference is handed over to the caller. */
SSL_SESSION *ma_tls_session_cache_get(MARIADB_TLS *ctls);

/* Saves a session received in the handshake in the ctls. Session
   is valid until not_after. Returns 0 if the session was accepted. */
int ma_tls_session_received(MARIADB_TLS *ctls, SSL_SESSION *session,
                            time_t not_after);

/* Cache sessions received in the handshake. Called after the connection
   authenticated, sessions for failed connections are never cached. */
void ma_pvio_cache_tls_session(MYSQL *mysql);

/* Whether the early data was sent and accepted. When it was not -
   the caller must send the packet again the ordinary way. */
my_bool ma_tls_early_data_accepted(MARIADB_TLS *ctls);

#endif /* _ma_tls_h_ */
