/*
   Copyright (C) 2015 MariaDB Corporation AB
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA 
*/

#include <my_global.h>
#include <my_sys.h>
#include <mysys_err.h>
#include <errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <stdio.h>
#include <string.h>

struct st_mysql_client_plugin_REMOTEIO *rio_plugin= NULL;

/* {{{ ma_open */
MA_FILE *ma_open(const char *location, const char *mode, MYSQL *mysql)
{
  int CodePage= -1;
  FILE *fp= NULL;
  MA_FILE *ma_file= NULL;

  if (!location || !location[0])
    return NULL;

  if (strstr(location, "://"))
    goto remote;

#ifdef _WIN32
  if (mysql && mysql->charset)
    CodePage= madb_get_windows_cp(mysql->charset);
#endif
  if (CodePage == -1)
    if (!(fp= fopen(location, mode)))
    {
#ifdef WIN32
      my_errno= GetLastError();
#else
      my_errno= errno;
#endif
      return NULL;
    }
#ifdef WIN32
  /* See CONC-44: we need to support non ascii filenames too, so we convert
     current character set to wchar_t and try to open the file via _wsopen */
  else
  {
    wchar_t *filename= NULL;
    int len;

    len= MultiByteToWideChar(CodePage, 0, location, (int)strlen(location), NULL, 0)M;
    if (!len)
      return NULL;
    if (!(w_filename= (wchar_t *)my_malloc((len + 1) * sizeof(wchar_t), MYF(MY_ZEROFILL))))
    {
      my_set_error(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
      return NULL;
    }
    len= MultiByteToWideChar(CodePage, 0, location, (int)strlen(location), w_filename, (int)Length);
    if (!len)
    {
      /* todo: error handling */
      my_free(w_filename);
      return NULL;
    }
    fp= _wfopen(w_filename, mode);
    my_errno= GetLastError();
    my_free(w_filename);
  }
#endif
  if (fp)
  {
    ma_file= (MA_FILE *)my_malloc(sizeof(MA_FILE), MYF(0));
    if (!ma_file)
    {
      my_set_error(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
      return NULL;
    }
    ma_file->type= MA_FILE_LOCAL;
    ma_file->ptr= (void *)fp;
  }
  return ma_file;
remote:
  /* check if plugin for remote io is available and try
   * to open location */
  {
    MYSQL mysql;
    if (rio_plugin ||(rio_plugin= (struct st_mysql_client_plugin_REMOTEIO *)
                      mysql_client_find_plugin(&mysql, NULL, MYSQL_CLIENT_REMOTEIO_PLUGIN)))
      return rio_plugin->methods->open(location, mode);
    return NULL;
  }
}
/* }}} */

/* {{{ ma_close */
int ma_close(MA_FILE *file)
{
  int rc;
  if (!file)
    return -1;

  switch (file->type) {
  case MA_FILE_LOCAL:
    rc= fclose((FILE *)file->ptr);
    my_free(file);
    break;
  case MA_FILE_REMOTE:
    rc= rio_plugin->methods->close(file);
    break;
  default:
    return -1;
  }
  return rc;
}
/* }}} */

/* {{{ ma_feof */
int ma_feof(MA_FILE *file)
{
  if (!file)
    return -1;

  switch (file->type) {
  case MA_FILE_LOCAL:
    return feof((FILE *)file->ptr);
    break;
  case MA_FILE_REMOTE:
    return rio_plugin->methods->feof(file);
    break;
  default:
    return -1;
  }
}
/* }}} */

/* {{{ ma_read */
size_t ma_read(void *ptr, size_t size, size_t nmemb, MA_FILE *file)
{
  size_t s= 0;
  if (!file)
    return -1;

  switch (file->type) {
  case MA_FILE_LOCAL:
    s= fread(ptr, size, nmemb, (FILE *)file->ptr);
    return s;
    break;
  case MA_FILE_REMOTE:
    return rio_plugin->methods->read(ptr, size, nmemb, file);
    break;
  default:
    return -1;
  }
}
/* }}} */

/* {{{ ma_gets */
char *ma_gets(char *ptr, size_t size, MA_FILE *file)
{
  if (!file)
    return NULL;

  switch (file->type) {
  case MA_FILE_LOCAL:
    return fgets(ptr, size, (FILE *)file->ptr);
    break;
  case MA_FILE_REMOTE:
    return rio_plugin->methods->gets(ptr, size, file);
    break;
  default:
    return NULL;
  }
}
/* }}} */


