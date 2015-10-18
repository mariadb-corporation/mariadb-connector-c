#ifndef _ma_cio_h_
#define _ma_cio_h_
#define cio_defined

#ifdef HAVE_SSL
#include <ma_ssl.h>
#endif

#define CIO_SET_ERROR if (cio->set_error) \
                        cio->set_error

#define CIO_READ_AHEAD_CACHE_SIZE 16384
#define CIO_READ_AHEAD_CACHE_MIN_SIZE 2048
#define CIO_EINTR_TRIES 2

struct st_ma_cio_methods;
typedef struct st_ma_cio_methods CIO_METHODS;

#ifndef ssl_defined
#define ssl_defined
struct st_ma_cio_ssl;
typedef struct st_ma_cio_ssl MARIADB_SSL;
#endif

enum enum_cio_timeout {
  CIO_CONNECT_TIMEOUT= 0,
  CIO_READ_TIMEOUT,
  CIO_WRITE_TIMEOUT 
};

enum enum_cio_io_event
{
  VIO_IO_EVENT_READ,
  VIO_IO_EVENT_WRITE,
  VIO_IO_EVENT_CONNECT
};

enum enum_cio_type {
  CIO_TYPE_UNIXSOCKET= 0,
  CIO_TYPE_SOCKET,
  CIO_TYPE_NAMEDPIPE
};

enum enum_cio_operation {
  CIO_READ= 0,
  CIO_WRITE=1
};

struct st_cio_callback;

typedef struct st_cio_callback {
  void (*callback)(MYSQL *mysql, uchar *buffer, size_t size);
  struct st_cio_callback *next;
} CIO_CALLBACK;

struct st_ma_cio {
  void *data;
  /* read ahead cache */
  uchar *cache;
  uchar *cache_pos;
  size_t cache_size;
  enum enum_cio_type type;
  int timeout[3];
  int ssl_type;  /* todo: change to enum (ssl plugins) */
  MARIADB_SSL *cssl;
  MYSQL *mysql;
  struct mysql_async_context *async_context; /* For non-blocking API */
  CIO_METHODS *methods;
  FILE *fp;
  void (*set_error)(MYSQL *mysql, unsigned int error_nr, const char *sqlstate, const char *format, ...);
  void (*callback)(MARIADB_CIO *cio, my_bool is_read, const char *buffer, size_t length);
};

typedef struct st_ma_cio_cinfo
{
  const char *host;
  const char *unix_socket;
  int port;
  enum enum_cio_type type;
  MYSQL *mysql;
} MA_CIO_CINFO;

struct st_ma_cio_methods
{
  my_bool (*set_timeout)(MARIADB_CIO *cio, enum enum_cio_timeout type, int timeout);
  int (*get_timeout)(MARIADB_CIO *cio, enum enum_cio_timeout type);
  size_t (*read)(MARIADB_CIO *cio, const uchar *buffer, size_t length);
  size_t (*async_read)(MARIADB_CIO *cio, const uchar *buffer, size_t length);
  size_t (*write)(MARIADB_CIO *cio, const uchar *buffer, size_t length);
  size_t (*async_write)(MARIADB_CIO *cio, const uchar *buffer, size_t length);
  int (*wait_io_or_timeout)(MARIADB_CIO *cio, my_bool is_read, int timeout);
  my_bool (*blocking)(MARIADB_CIO *cio, my_bool value, my_bool *old_value);
  my_bool (*connect)(MARIADB_CIO *cio, MA_CIO_CINFO *cinfo);
  my_bool (*close)(MARIADB_CIO *cio);
  int (*fast_send)(MARIADB_CIO *cio);
  int (*keepalive)(MARIADB_CIO *cio);
  my_bool (*get_handle)(MARIADB_CIO *cio, void *handle);
  my_bool (*is_blocking)(MARIADB_CIO *cio);
  my_bool (*is_alive)(MARIADB_CIO *cio);
};

/* Function prototypes */
MARIADB_CIO *ma_cio_init(MA_CIO_CINFO *cinfo);
void ma_cio_close(MARIADB_CIO *cio);
size_t ma_cio_cache_read(MARIADB_CIO *cio, uchar *buffer, size_t length);
size_t ma_cio_read(MARIADB_CIO *cio, const uchar *buffer, size_t length);
size_t ma_cio_write(MARIADB_CIO *cio, const uchar *buffer, size_t length);
int ma_cio_get_timeout(MARIADB_CIO *cio, enum enum_cio_timeout type);
my_bool ma_cio_set_timeout(MARIADB_CIO *cio, enum enum_cio_timeout type, int timeout);
int ma_cio_fast_send(MARIADB_CIO *cio);
int ma_cio_keepalive(MARIADB_CIO *cio);
my_socket ma_cio_get_socket(MARIADB_CIO *cio);
my_bool ma_cio_is_blocking(MARIADB_CIO *cio);
my_bool ma_cio_blocking(MARIADB_CIO *cio, my_bool block, my_bool *previous_mode);
my_bool ma_cio_is_blocking(MARIADB_CIO *cio);
int ma_cio_wait_io_or_timeout(MARIADB_CIO *cio, my_bool is_read, int timeout);
my_bool ma_cio_connect(MARIADB_CIO *cio, MA_CIO_CINFO *cinfo);
my_bool ma_cio_is_alive(MARIADB_CIO *cio);

#endif /* _ma_cio_h_ */
