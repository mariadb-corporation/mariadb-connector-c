/************************************************************************************
  Copyright (C) 2014 MariaDB Corporation AB

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

#ifdef HAVE_SSL

#include <my_global.h>
#include <my_sys.h>
#include <ma_common.h>
//#include <ma_secure.h>
#include <errmsg.h>
#include <ma_cio.h>
#include <ma_ssl.h>
#include <mysql/client_plugin.h>

/*
#include <mysql_async.h>
#include <my_context.h>
*/

/* Errors should be handled via cio callback function */

MARIADB_SSL *ma_cio_ssl_init(MYSQL *mysql)
{
  MARIADB_CIO_PLUGIN *cio_plugin;
  MARIADB_SSL *cssl= NULL;

  if (!(cssl= (MARIADB_SSL *)my_malloc(sizeof(MARIADB_CIO), 
                                      MYF(MY_WME | MY_ZEROFILL))))
  {
    return NULL;
  }

  /* register error routine and methods */
  cssl->methods= cio_plugin->ssl_methods;
  cssl->cio= mysql->net.cio;

  if (!(cssl->ssl= cssl->methods->init(cssl, mysql)))
  {
    my_free((gptr)cssl);
    cssl= NULL;
  }
  return cssl;
}

my_bool ma_cio_ssl_check_fp(MARIADB_SSL *cssl, const char *fp, size_t length)
{
  if (cssl && cssl->methods->check_fp)
    return cssl->methods->check_fp(cssl, fp);
  return 0;
}

my_bool ma_cio_ssl_connect(MARIADB_SSL *cssl)
{
  if (cssl && cssl->methods->connect)
    return cssl->methods->connect(cssl);
  return 1;
}

size_t ma_cio_ssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  if (cssl && cssl->methods->read)
    return cssl->methods->read(cssl, buffer, length);
  return -1;
}

size_t ma_cio_ssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  if (cssl && cssl->methods->write)
    return cssl->methods->write(cssl, buffer, length);
  return -1;
}

my_bool ma_cio_ssl_close(MARIADB_SSL *cssl)
{
  if (cssl && cssl->methods->close)
    return cssl->methods->close(cssl);
  return 1;
}

int ma_cio_ssl_verify_server_cert(MARIADB_SSL *cssl)
{
  if (cssl && cssl->methods->verify_server_cert)
    return cssl->methods->verify_server_cert(cssl);
  return 0;
}

const char *ma_cio_ssl_cipher(MARIADB_SSL *cssl)
{
  if (!cssl && !cssl->methods->cipher)
    return NULL;
  return cssl->methods->cipher(cssl);
}
#endif /* HAVE_SSL */
