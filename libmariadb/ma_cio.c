/************************************************************************************
    Copyright (C) 2015 MariaDB Corporation AB,
   
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

/* MariaDB Communication IO (CIO) interface

   CIO is the interface for client server communication and replaces former vio
   component of the client library.

   CIO support various protcols like sockets, pipes and shared memory, which are 
   implemented as plugins and can be extended therfore easily.

   Interface function description:

   ma_cio_init          allocates a new CIO object which will be used
                        for the current connection

   ma_cio_close         frees all resources of previously allocated CIO object
                        and closes open connections

   ma_cio_read          reads data from server

   ma_cio_write         sends data to server

   ma_cio_set_timeout   sets timeout for connection, read and write

   ma_cio_register_callback
                        register callback functions for read and write
 */

#include <my_global.h>
#include <my_sys.h>
#include <mysql.h>
#include <errmsg.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_common.h>
#include <ma_cio.h>
#include <mysql_async.h>
#include <my_context.h>

extern pthread_mutex_t THR_LOCK_lock;

/* callback functions for read/write */
LIST *cio_callback= NULL;

/* {{{ MARIADB_CIO *ma_cio_init */
MARIADB_CIO *ma_cio_init(MA_CIO_CINFO *cinfo)
{
  /* check connection type and load the required plugin.
   * Currently we support the following cio types:
   *   cio_socket
   *   cio_namedpipe
   */
  char *cio_plugins[] = {"cio_socket", "cio_npipe"};
  int type;
  MARIADB_CIO_PLUGIN *cio_plugin;
  MARIADB_CIO *cio= NULL;

  switch (cinfo->type)
  {
    case CIO_TYPE_UNIXSOCKET:
    case CIO_TYPE_SOCKET:
      type= 0;
      break;
#ifdef _WIN32
    case CIO_TYPE_NAMEDPIPE:
      type= 1;
      break;
#endif
    default:
      return NULL;
  }

  if (!(cio_plugin= (MARIADB_CIO_PLUGIN *)
                 mysql_client_find_plugin(cinfo->mysql,
                                          cio_plugins[type], 
                                          MYSQL_CLIENT_CIO_PLUGIN)))
  {
    /* error handling */
    return NULL;
  }


  if (!(cio= (MARIADB_CIO *)my_malloc(sizeof(MARIADB_CIO), 
                                      MYF(MY_WME | MY_ZEROFILL))))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
    return NULL;
  }

  /* register error routine and methods */
  cio->methods= cio_plugin->methods;
  cio->set_error= my_set_error;

  /* set tineouts */
  if (cio->methods->set_timeout)
  {
    cio->methods->set_timeout(cio, CIO_CONNECT_TIMEOUT, cinfo->mysql->options.connect_timeout);
    cio->methods->set_timeout(cio, CIO_READ_TIMEOUT, cinfo->mysql->options.read_timeout);
    cio->methods->set_timeout(cio, CIO_WRITE_TIMEOUT, cinfo->mysql->options.write_timeout);
  }

  if (!(cio->cache= my_malloc(CIO_READ_AHEAD_CACHE_SIZE, MYF(MY_ZEROFILL))))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
    return NULL;
  }
  cio->cache_size= 0;
  cio->cache_pos= cio->cache;

  return cio;
}
/* }}} */

/* {{{ my_bool ma_cio_is_alive */
my_bool ma_cio_is_alive(MARIADB_CIO *cio)
{
  if (cio->methods->is_alive)
    return cio->methods->is_alive(cio);
}
/* }}} */

/* {{{ int ma_cio_fast_send */
int ma_cio_fast_send(MARIADB_CIO *cio)
{
  if (!cio || !cio->methods->fast_send)
    return 1;
  return cio->methods->fast_send(cio);
}
/* }}} */

/* {{{ int ma_cio_keepalive */
int ma_cio_keepalive(MARIADB_CIO *cio)
{
  if (!cio || !cio->methods->keepalive)
    return 1;
  return cio->methods->keepalive(cio);
}
/* }}} */

/* {{{ my_bool ma_cio_set_timeout */
my_bool ma_cio_set_timeout(MARIADB_CIO *cio, 
                           enum enum_cio_timeout type,
                           int timeout)
{
  if (!cio)
    return 1;

  if (cio->methods->set_timeout)
    return cio->methods->set_timeout(cio, type, timeout);
  return 1;
}
/* }}} */

/* {{{ size_t ma_cio_read_async */
static size_t ma_cio_read_async(MARIADB_CIO *cio, const uchar *buffer, size_t length)
{
  ssize_t res;
  struct mysql_async_context *b= cio->async_context;
  int timeout= cio->timeout[CIO_READ_TIMEOUT];

  for (;;)
  {
    /* todo: async */
    if (cio->methods->async_read)
      res= cio->methods->async_read(cio, buffer, length);
    if (res >= 0 /* || IS_BLOCKING_ERROR()*/)
      return res;
    b->events_to_wait_for= MYSQL_WAIT_READ;
    if (timeout >= 0)
    {
      b->events_to_wait_for|= MYSQL_WAIT_TIMEOUT;
      b->timeout_value= timeout;
    }
    if (b->suspend_resume_hook)
      (*b->suspend_resume_hook)(TRUE, b->suspend_resume_hook_user_data);
    my_context_yield(&b->async_context);
    if (b->suspend_resume_hook)
      (*b->suspend_resume_hook)(FALSE, b->suspend_resume_hook_user_data);
    if (b->events_occured & MYSQL_WAIT_TIMEOUT)
      return -1;
  }
}
/* }}} */

/* {{{ size_t ma_cio_read */
size_t ma_cio_read(MARIADB_CIO *cio, const uchar *buffer, size_t length)
{
  size_t r= -1;
  if (!cio)
    return -1;


  if (cio && cio->async_context && cio->async_context->active)
  {
    goto end;
    r= ma_cio_read_async(cio, buffer, length);
  }
  else
  {
    if (cio->async_context)
    {
      /*
        If switching from non-blocking to blocking API usage, set the socket
        back to blocking mode.
      */
      my_bool old_mode;
      ma_cio_blocking(cio, TRUE, &old_mode);
    }
  }

  /* secure connection */
#ifdef HAVE_SSL
  if (cio->cssl)
    r= ma_cio_ssl_read(cio->cssl, buffer, length);
  else
#endif
  if (cio->methods->read)
    r= cio->methods->read(cio, buffer, length);
end:
  if (cio_callback)
  {
    void (*callback)(int mode, MYSQL *mysql, const uchar *buffer, size_t length);
    LIST *p= cio_callback;
    while (p)
    {
      callback= p->data;
      callback(0, cio->mysql, buffer, r);
      p= p->next;
    }
  }
  return r;
}
/* }}} */

/* {{{  size_t ma_cio_cache_read */
size_t ma_cio_cache_read(MARIADB_CIO *cio, uchar *buffer, size_t length)
{
  size_t r;

  if (!cio)
    return -1;

  if (!cio->cache)
    return ma_cio_read(cio, buffer, length);

  if (cio->cache + cio->cache_size > cio->cache_pos)
  {
    r= MIN(length, cio->cache + cio->cache_size - cio->cache_pos);
    memcpy(buffer, cio->cache_pos, r);
    cio->cache_pos+= r;
  }
  else if (length >= CIO_READ_AHEAD_CACHE_MIN_SIZE)
  {
    r= ma_cio_read(cio, buffer, length); 
  }
  else
  {
    r= ma_cio_read(cio, cio->cache, CIO_READ_AHEAD_CACHE_SIZE);
    if ((ssize_t)r > 0)
    {
      if (length < r)
      {
        cio->cache_size= r;
        cio->cache_pos= cio->cache + length;
        r= length;
      }
      memcpy(buffer, cio->cache, r);
    }
  } 
  return r;
}
/* }}} */

/* {{{ size_t ma_cio_write */
size_t ma_cio_write(MARIADB_CIO *cio, const uchar *buffer, size_t length)
{
  size_t r;

  if (!cio)
   return -1;

  if (cio_callback)
  {
    void (*callback)(int mode, MYSQL *mysql, const uchar *buffer, size_t length);
    LIST *p= cio_callback;
    while (p)
    {
      callback= p->data;
      callback(1, cio->mysql, buffer, length);
      p= p->next;
    }
  }

  /* secure connection */
#ifdef HAVE_SSL
  if (cio->cssl)
    r= ma_cio_ssl_write(cio->cssl, buffer, length);
  else
#endif
  if (cio->methods->write)
    r= cio->methods->write(cio, buffer, length);
  if (cio->callback)
    cio->callback(cio, 0, buffer, r);
  return r;
}
/* }}} */

/* {{{ void ma_cio_close */
void ma_cio_close(MARIADB_CIO *cio)
{
  /* free internal structures and close connection */
#ifdef HAVE_SSL
  if (cio && cio->cssl)
  {
    ma_cio_ssl_close(cio->cssl);
    my_free((gptr)cio->cssl);
  }
#endif
  if (cio && cio->methods->close)
    cio->methods->close(cio);

  if (cio->cache)
    my_free((gptr)cio->cache);

  if (cio->fp)
    my_fclose(cio->fp, MYF(0));

  my_free((gptr)cio);
}
/* }}} */

/* {{{ my_bool ma_cio_get_handle */
my_bool ma_cio_get_handle(MARIADB_CIO *cio, void *handle)
{
  if (cio && cio->methods->get_handle)
    return cio->methods->get_handle(cio, handle);
  return 1;
}
/* }}} */

/* {{{ ma_cio_wait_io_or_timeout */
int ma_cio_wait_io_or_timeout(MARIADB_CIO *cio, my_bool is_read, int timeout)
{
  if (cio && cio->async_context && cio->async_context->active)
    return my_io_wait_async(cio->async_context, 
                            (is_read) ? VIO_IO_EVENT_READ : VIO_IO_EVENT_WRITE,
                             timeout);


  if (cio && cio->methods->wait_io_or_timeout)
    return cio->methods->wait_io_or_timeout(cio, is_read, timeout);
  return 1;
}
/* }}} */

/* {{{ my_bool ma_cio_connect */
my_bool ma_cio_connect(MARIADB_CIO *cio,  MA_CIO_CINFO *cinfo)
{
  if (cio && cio->methods->connect)
    return cio->methods->connect(cio, cinfo);
  return 1;
}
/* }}} */

/* {{{ my_bool ma_cio_blocking */
my_bool ma_cio_blocking(MARIADB_CIO *cio, my_bool block, my_bool *previous_mode)
{
  if (cio && cio->methods->blocking)
    return cio->methods->blocking(cio, block, previous_mode);
  return 1;
}
/* }}} */

/* {{{ my_bool ma_cio_is_blocking */ 
my_bool ma_cio_is_blocking(MARIADB_CIO *cio) 
{
  if (cio && cio->methods->is_blocking)
    return cio->methods->is_blocking(cio);
  return 1;
}
/* }}} */

#ifdef HAVE_SSL
/* {{{ my_bool ma_cio_start_ssl */
my_bool ma_cio_start_ssl(MARIADB_CIO *cio)
{
  if (!cio || !cio->mysql)
    return 1;
  CLEAR_CLIENT_ERROR(cio->mysql);
  if (!(cio->cssl= ma_cio_ssl_init(cio->mysql)))
  {
    return 1;
  }
  if (ma_cio_ssl_connect(cio->cssl))
  {
    my_free((gptr)cio->cssl);
    cio->cssl= NULL;
    return 1;
  }
  if ((cio->mysql->options.ssl_ca || cio->mysql->options.ssl_capath) &&
        (cio->mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT) &&
         ma_cio_ssl_verify_server_cert(cio->cssl))
    return 1;

  if (cio->mysql->options.extension &&
      (cio->mysql->options.extension->ssl_fp || cio->mysql->options.extension->ssl_fp_list))
  {

    if (ma_cio_ssl_check_fp(cio->cssl, 
          cio->mysql->options.extension->ssl_fp,
          cio->mysql->options.extension->ssl_fp_list))
      return 1;
  }

  return 0;
}
/* }}} */
#endif

/* {{{ ma_cio_register_callback */
int ma_cio_register_callback(my_bool register_callback,
                             void (*callback_function)(int mode, MYSQL *mysql, const uchar *buffer, size_t length))
{
  LIST *list;

  if (!callback_function)
    return 1;

  /* plugin will unregister in it's deinit function */
  if (register_callback)
  {
    list= (LIST *)malloc(sizeof(LIST));

    list->data= (void *)callback_function;
    cio_callback= list_add(cio_callback, list);
  }
  else /* unregister callback function */
  {  
    LIST *p= cio_callback;
    while (p)
    {
      if (p->data == callback_function)
      {
        list_delete(cio_callback, p);
        break;
      }
      p= p->next;
    }
  }
  return 0;
}
/* }}} */
