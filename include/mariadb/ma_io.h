#ifndef _ma_io_h_
#define _ma_io_h_

#include <curl/curl.h>

enum enum_file_type {
  MA_FILE_NONE=0,
  MA_FILE_LOCAL=1,
  MA_FILE_REMOTE=2
};

typedef struct 
{
  enum enum_file_type type;
  void *ptr;
} MA_FILE;

struct st_rio_methods {
  MA_FILE *(*open)(const char *url, const char *mode);
  int (*close)(MA_FILE *ptr);
  int (*feof)(MA_FILE *file);
  size_t (*read)(void *ptr, size_t size, size_t nmemb, MA_FILE *file);
  char * (*gets)(char *ptr, size_t size, MA_FILE *file);
};

/* function prototypes */
MA_FILE *ma_open(const char *location, const char *mode, MYSQL *mysql);
int ma_close(MA_FILE *file);
int ma_feof(MA_FILE *file);
size_t ma_read(void *ptr, size_t size, size_t nmemb, MA_FILE *file);
char *ma_gets(char *ptr, size_t size, MA_FILE *file);

#endif
