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

  DBUG_ENTER("mysql_local_infile_init");

  info = (MYSQL_INFILE_INFO *)my_malloc(sizeof(MYSQL_INFILE_INFO), MYF(MY_ZEROFILL));
  if (!info) {
    DBUG_RETURN(1);
  }

  *ptr = info;

  info->filename = filename;
  info->fd = my_open(info->filename, O_RDONLY, MYF(0));

  if (info->fd < 0)
  {
    my_snprintf((char *)info->error_msg, sizeof(info->error_msg), 
                "Can't open file '%-.64s'.", filename);
    info->error_no = EE_FILENOTFOUND;
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

  count= my_read(info->fd, buf, buf_len, MYF(0));

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
    if (info->fd)
    {
      my_close(info->fd, MYF(0));
      info->fd= 0;
    }
    my_free(ptr, MYF(0));
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
  unsigned int bufread;
  unsigned char *buf= NULL;
  void *info= NULL;
  my_bool result= 1;

  DBUG_ENTER("mysql_handle_local_infile");

  if (!(conn->options.client_flag & CLIENT_LOCAL_FILES)) {
    my_set_error(conn, CR_UNKNOWN_ERROR, SQLSTATE_UNKNOWN, "Load data local infile forbidden");
    /* write empty packet to server */
    my_net_write(&conn->net, "", 0);
    net_flush(&conn->net);
    goto infile_error;
  }

  /* check if all callback functions exist */
  if (!conn->options.local_infile_init || !conn->options.local_infile_end ||
      !conn->options.local_infile_read || !conn->options.local_infile_error)
    mysql_set_local_infile_default(conn);

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
  my_free((char *)buf, MYF(0));
  DBUG_RETURN(result);
}
/* }}} */
