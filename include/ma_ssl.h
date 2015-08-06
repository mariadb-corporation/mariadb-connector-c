#ifndef _ma_ssl_h_
#define _ma_ssl_h_

struct st_ma_cio_ssl_methods;
typedef struct st_ma_cio_ssl_methods CIO_SSL_METHODS;
extern int ssl_default_plugin;

enum enum_cio_ssl_type {
  SSL_TYPE_DEFAULT=0,
#ifdef _WIN32
  SSL_TYPE_SCHANNEL,
#endif
  SSL_TYPE_OPENSSL,
  SSL_TYPE_GNUTLS
};

typedef struct st_ma_cio_ssl {
  void *data;
  enum enum_cio_ssl_type type;
  MARIADB_CIO *cio;
  CIO_SSL_METHODS *methods;
  void *ssl;
} MARIADB_SSL;

struct st_ma_cio_ssl_methods
{
  void *(*init)(MARIADB_SSL *cssl, MYSQL *mysql);
  my_bool (*connect)(MARIADB_SSL *cssl);
  size_t (*read)(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
  size_t (*write)(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
  my_bool (*close)(MARIADB_SSL *cssl);
  int (*verify_server_cert)(MARIADB_SSL *ssl);
  const char *(*cipher)(MARIADB_SSL *ssl);
  my_bool (*check_fp)(MARIADB_SSL *cssl, const char *fp);
};

/* Function prototypes */
MARIADB_SSL *ma_cio_ssl_init(MYSQL *mysql);
my_bool ma_cio_ssl_connect(MARIADB_SSL *cssl);
size_t ma_cio_ssl_read(MARIADB_SSL *cssl, const uchar *buffer, size_t length);
size_t ma_cio_ssl_write(MARIADB_SSL *cssl, const uchar *buffer, size_t length);
my_bool ma_cio_ssl_close(MARIADB_SSL *cssl);
int ma_cio_ssl_verify_server_cert(MARIADB_SSL *cssl);
const char *ma_cio_ssl_cipher(MARIADB_SSL *cssl);
my_bool ma_cio_ssl_check_fp(MARIADB_SSL *cssl, const char *fp, size_t length);

#endif /* _ma_ssl_h_ */
