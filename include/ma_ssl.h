#ifndef _ma_ssl_h_
#define _ma_ssl_h_

enum enum_pvio_ssl_type {
  SSL_TYPE_DEFAULT=0,
#ifdef _WIN32
  SSL_TYPE_SCHANNEL,
#endif
  SSL_TYPE_OPENSSL,
  SSL_TYPE_GNUTLS
};

typedef struct st_ma_pvio_ssl {
  void *data;
  MARIADB_PVIO *pvio;
  void *ssl;
} MARIADB_SSL;

struct st_ssl_version {
  unsigned int iversion;
  char *cversion;
};

/* Function prototypes */

/* ma_ssl_start
   initializes the ssl library
   Parameter:
     errmsg      pointer to error message buffer
     errmsg_len  length of error message buffer
   Returns:
     0           success
     1           if an error occured
   Notes:
     On success the global variable ma_ssl_initialized will be set to 1
*/
int ma_ssl_start(char *errmsg, size_t errmsg_len);

/* ma_ssl_end
   unloads/deinitializes ssl library and unsets global variable
   ma_ssl_initialized
*/
void ma_ssl_end(void);

/* ma_ssl_init
   creates a new SSL structure for a SSL connection and loads
   client certificates

   Parameters:
     MYSQL        a mysql structure
   Returns:
     void *       a pointer to internal SSL structure
*/
void * ma_ssl_init(MYSQL *mysql);

/* ma_ssl_connect
   performs SSL handshake
   Parameters:
     MARIADB_SSL   MariaDB SSL container
   Returns:
     0             success
     1             error
*/
my_bool ma_ssl_connect(MARIADB_SSL *cssl);

/* ma_ssl_read
   reads up to length bytes from socket
   Parameters:
     cssl         MariaDB SSL container
     buffer       read buffer
     length       buffer length
   Returns:
     0-n          bytes read
     -1           if an error occured
*/
size_t ma_ssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length);

/* ma_ssl_write
   write buffer to socket
   Parameters:
     cssl         MariaDB SSL container
     buffer       write buffer
     length       buffer length
   Returns:
     0-n          bytes written
     -1           if an error occured
*/
size_t ma_ssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length);

/* ma_ssl_close
   closes SSL connection and frees SSL structure which was previously
   created by ma_ssl_init call
   Parameters:
     MARIADB_SSL  MariaDB SSL container
   Returns:
     0            success
     1            error
*/
my_bool ma_ssl_close(MARIADB_SSL *cssl);

/* ma_ssl_verify_server_cert
   validation check of server certificate
   Parameter:
     MARIADB_SSL  MariaDB SSL container
   Returns:
     ß            success
     1            error
*/
int ma_ssl_verify_server_cert(MARIADB_SSL *cssl);

/* ma_ssl_get_cipher
   returns cipher for current ssl connection
   Parameter:
     MARIADB_SSL  MariaDB SSL container
   Returns: 
     cipher in use or
     NULL on error
*/
const char *ma_ssl_get_cipher(MARIADB_SSL *ssl);

/* ma_ssl_get_finger_print
   returns SHA1 finger print of server certificate
   Parameter:
     MARIADB_SSL  MariaDB SSL container
     fp           buffer for fingerprint
     fp_len       buffer length
   Returns:
     actual size of finger print
*/
unsigned int ma_ssl_get_finger_print(MARIADB_SSL *cssl, unsigned char *fp, unsigned int fp_len);

/* ma_ssl_get_protocol_version 
   returns protocol version in use
   Parameter:
     MARIADB_SSL    MariaDB SSL container
     version        pointer to ssl version info
   Returns:
     0              success
     1              error
*/
my_bool ma_ssl_get_protocol_version(MARIADB_SSL *cssl, struct st_ssl_version *version);

/* Function prototypes */
MARIADB_SSL *ma_pvio_ssl_init(MYSQL *mysql);
my_bool ma_pvio_ssl_connect(MARIADB_SSL *cssl);
size_t ma_pvio_ssl_read(MARIADB_SSL *cssl, const uchar *buffer, size_t length);
size_t ma_pvio_ssl_write(MARIADB_SSL *cssl, const uchar *buffer, size_t length);
my_bool ma_pvio_ssl_close(MARIADB_SSL *cssl);
int ma_pvio_ssl_verify_server_cert(MARIADB_SSL *cssl);
const char *ma_pvio_ssl_cipher(MARIADB_SSL *cssl);
my_bool ma_pvio_ssl_check_fp(MARIADB_SSL *cssl, const char *fp, const char *fp_list);
my_bool ma_pvio_start_ssl(MARIADB_PVIO *pvio);
my_bool ma_pvio_ssl_get_protocol_version(MARIADB_SSL *cssl, struct st_ssl_version *version);
void ma_pvio_ssl_end();

#endif /* _ma_ssl_h_ */
