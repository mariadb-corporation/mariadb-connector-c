/************************************************************************************
    Copyright (C) 2000, 2011 MySQL AB & MySQL Finland AB & TCX DataKonsult AB,
                 Monty Program AB
   
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

   Part of this code includes code from the PHP project which
   is freely available from http://www.php.net
*************************************************************************************/
/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2011 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Georg Richter <georg@mysql.com>                             |
  |          Andrey Hristov <andrey@mysql.com>                           |
  |          Ulf Wendel <uwendel@mysql.com>                              |
  +----------------------------------------------------------------------+
*/

#include "my_global.h"
#include <my_sys.h>
#include <mysys_err.h>
#include <m_string.h>
#include "errmsg.h"
#include "mysql.h"
#include <string.h>
#ifdef _WIN32
#include <share.h>
#endif

typedef struct st_mysql_infile_info
{
  int        fd;
  int        error_no;
  char       error_msg[MYSQL_ERRMSG_SIZE + 1];
  const char *filename;
} MYSQL_INFILE_INFO;

/* {{{ mysql_local_infile_init */
static
int mysql_local_infile_init(void **ptr, const char *filename, void *userdata)
{
  MYSQL_INFILE_INFO *info;
  int CodePage= -1;
#ifdef _WIN32
  MYSQL *mysql= (MYSQL *)userdata;
  wchar_t *w_filename= NULL;
  int Length;
#endif
  DBUG_ENTER("mysql_local_infile_init");

  info = (MYSQL_INFILE_INFO *)my_malloc(sizeof(MYSQL_INFILE_INFO), MYF(MY_ZEROFILL));
  if (!info) {
    DBUG_RETURN(1);
  }

  *ptr = info;

  info->filename = filename;

#ifdef _WIN32
  if (mysql)
    CodePage= madb_get_windows_cp(mysql->charset->csname);
#endif
  if (CodePage == -1)
  {
#ifdef _WIN32
    info->fd= sopen(info->filename, _O_RDONLY | _O_BINARY, _SH_DENYNO , _S_IREAD | _S_IWRITE);
#else
    info->fd = open(info->filename, O_RDONLY | O_BINARY, my_umask);
#endif
    my_errno= errno;
  }
#ifdef _WIN32
  else
  {
    if ((Length= MultiByteToWideChar(CodePage, 0, info->filename, (int)strlen(info->filename), NULL, 0)))
    {
      if (!(w_filename= (wchar_t *)my_malloc((Length + 1) * sizeof(wchar_t), MYF(MY_ZEROFILL))))
      {
        info->error_no= CR_OUT_OF_MEMORY;
        my_snprintf((char *)info->error_msg, sizeof(info->error_msg), 
                     ER(CR_OUT_OF_MEMORY));
        DBUG_RETURN(1);
      }
      Length= MultiByteToWideChar(CodePage, 0, info->filename, (int)strlen(info->filename), w_filename, (int)Length);
    }
    if (Length == 0)
    {
      my_free(w_filename);
      info->error_no= CR_UNKNOWN_ERROR;
      my_snprintf((char *)info->error_msg, sizeof(info->error_msg), 
                  "Character conversion error: %d", GetLastError());
      DBUG_RETURN(1);
    }
    info->fd= _wsopen(w_filename, _O_RDONLY | _O_BINARY, _SH_DENYNO , _S_IREAD | _S_IWRITE);
    my_errno= errno;
    my_free(w_filename);
  }
#endif

  if (info->fd < 0)
  {
    info->error_no = my_errno;
    my_snprintf((char *)info->error_msg, sizeof(info->error_msg), 
                EE(EE_FILENOTFOUND), filename, info->error_no);
    DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
}
/* }}} */


/* {{{ mysql_local_infile_read */
static
int mysql_local_infile_read(void *ptr, char * buf, unsigned int buf_len)
{
  MYSQL_INFILE_INFO *info = (MYSQL_INFILE_INFO *)ptr;
  int count;

  DBUG_ENTER("mysql_local_infile_read");

  count= read(info->fd, (void *)buf, (size_t)buf_len);

  if (count < 0)
  {
    strcpy(info->error_msg, "Error reading file");
    info->error_no = EE_READ;
  }
  DBUG_RETURN(count);
}
/* }}} */


/* {{{ mysql_local_infile_error */
static
int mysql_local_infile_error(void *ptr, char *error_buf, unsigned int error_buf_len)
{
  MYSQL_INFILE_INFO *info = (MYSQL_INFILE_INFO *)ptr;

  DBUG_ENTER("mysql_local_infile_error");

  if (info) {
    strncpy(error_buf, info->error_msg, error_buf_len);
    DBUG_RETURN(info->error_no);
  }

  strncpy(error_buf, "Unknown error", error_buf_len);
  DBUG_RETURN(CR_UNKNOWN_ERROR);
}
/* }}} */


/* {{{ mysql_local_infile_end */
static
void mysql_local_infile_end(void *ptr)
{
  MYSQL_INFILE_INFO *info = (MYSQL_INFILE_INFO *)ptr;

  DBUG_ENTER("mysql_local_infile_end");

  if (info)
  {
    if (info->fd >= 0)
      close(info->fd);
    my_free(ptr);
  }		
  DBUG_VOID_RETURN;
}
/* }}} */


/* {{{ mysql_local_infile_default */
void mysql_set_local_infile_default(MYSQL *conn)
{
  DBUG_ENTER("mysql_local_infile_default");
  conn->options.local_infile_init = mysql_local_infile_init;
  conn->options.local_infile_read = mysql_local_infile_read;
  conn->options.local_infile_error = mysql_local_infile_error;
  conn->options.local_infile_end = mysql_local_infile_end;
  DBUG_VOID_RETURN;
}
/* }}} */

/* {{{ mysql_set_local_infile_handler */
void STDCALL mysql_set_local_infile_handler(MYSQL *conn,
        int (*local_infile_init)(void **, const char *, void *),
        int (*local_infile_read)(void *, char *, uint),
        void (*local_infile_end)(void *),
        int (*local_infile_error)(void *, char *, uint),
        void *userdata)
{
  DBUG_ENTER("mysql_set_local_infile_handler");
  conn->options.local_infile_init=  local_infile_init;
  conn->options.local_infile_read=  local_infile_read;
  conn->options.local_infile_end=   local_infile_end;
  conn->options.local_infile_error= local_infile_error;
  conn->options.local_infile_userdata = userdata;
  DBUG_VOID_RETURN;
}
/* }}} */

/* {{{ mysql_handle_local_infile */
my_bool mysql_handle_local_infile(MYSQL *conn, const char *filename)
{
  unsigned int buflen= 4096;
  int bufread;
  unsigned char *buf= NULL;
  void *info= NULL;
  my_bool result= 1;

  DBUG_ENTER("mysql_handle_local_infile");

  /* check if all callback functions exist */
  if (!conn->options.local_infile_init || !conn->options.local_infile_end ||
      !conn->options.local_infile_read || !conn->options.local_infile_error)
  {
    conn->options.local_infile_userdata= conn;
    mysql_set_local_infile_default(conn);
  }

  if (!(conn->options.client_flag & CLIENT_LOCAL_FILES)) {
    my_set_error(conn, CR_UNKNOWN_ERROR, SQLSTATE_UNKNOWN, "Load data local infile forbidden");
    /* write empty packet to server */
    my_net_write(&conn->net, "", 0);
    net_flush(&conn->net);
    goto infile_error;
  }

  /* allocate buffer for reading data */
  buf = (uchar *)my_malloc(buflen, MYF(0));

  /* init handler: allocate read buffer and open file */
  if (conn->options.local_infile_init(&info, filename,
                                      conn->options.local_infile_userdata))
  {
    char tmp_buf[MYSQL_ERRMSG_SIZE];
    int tmp_errno;

    tmp_errno= conn->options.local_infile_error(info, tmp_buf, sizeof(tmp_buf));
    my_set_error(conn, tmp_errno, SQLSTATE_UNKNOWN, tmp_buf);
    my_net_write(&conn->net, "", 0);
    net_flush(&conn->net);
    goto infile_error;
  }

  /* read data */
  while ((bufread= conn->options.local_infile_read(info, (char *)buf, buflen)) > 0)
  {
    if (my_net_write(&conn->net, (char *)buf, bufread))
    {
      my_set_error(conn, CR_SERVER_LOST, SQLSTATE_UNKNOWN, NULL);
      goto infile_error;
    }
  }

  /* send empty packet for eof */
  if (my_net_write(&conn->net, "", 0) || net_flush(&conn->net))
  {
    my_set_error(conn, CR_SERVER_LOST, SQLSTATE_UNKNOWN, NULL);
    goto infile_error;
  }

  /* error during read occured */
  if (bufread < 0)
  {
    char tmp_buf[MYSQL_ERRMSG_SIZE];
    int tmp_errno= conn->options.local_infile_error(info, tmp_buf, sizeof(tmp_buf));
    my_set_error(conn, tmp_errno, SQLSTATE_UNKNOWN, tmp_buf);
    goto infile_error;
  }

  result = 0;

infile_error:
  conn->options.local_infile_end(info);
  my_free(buf);
  DBUG_RETURN(result);
}
/* }}} */

