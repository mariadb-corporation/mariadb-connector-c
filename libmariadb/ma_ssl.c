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
#include <string.h>
//#include <ma_secure.h>
#include <errmsg.h>
#include <ma_pvio.h>
#include <ma_ssl.h>
#include <mysql/client_plugin.h>

/*
#include <mysql_async.h>
#include <my_context.h>
*/

/* Errors should be handled via pvio callback function */
my_bool ma_ssl_initialized= FALSE;
unsigned int mariadb_deinitialize_ssl= 1;

MARIADB_SSL *ma_pvio_ssl_init(MYSQL *mysql)
{
  MARIADB_SSL *cssl= NULL;

  if (!ma_ssl_initialized)
    ma_ssl_start(mysql->net.last_error, MYSQL_ERRMSG_SIZE);

  if (!(cssl= (MARIADB_SSL *)my_malloc(sizeof(MARIADB_SSL), 
                                      MYF(MY_WME | MY_ZEROFILL))))
  {
    return NULL;
  }

  /* register error routine and methods */
  cssl->pvio= mysql->net.pvio;
  if (!(cssl->ssl= ma_ssl_init(mysql)))
  {
    my_free(cssl);
    cssl= NULL;
  }
  return cssl;
}

my_bool ma_pvio_ssl_connect(MARIADB_SSL *cssl)
{
  return ma_ssl_connect(cssl);
}

size_t ma_pvio_ssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  return ma_ssl_read(cssl, buffer, length);
}

size_t ma_pvio_ssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  return ma_ssl_write(cssl, buffer, length);
}

my_bool ma_pvio_ssl_close(MARIADB_SSL *cssl)
{
  return ma_ssl_close(cssl);
}

int ma_pvio_ssl_verify_server_cert(MARIADB_SSL *cssl)
{
  return ma_ssl_verify_server_cert(cssl);
}

const char *ma_pvio_ssl_cipher(MARIADB_SSL *cssl)
{
  return ma_ssl_get_cipher(cssl);
}

static my_bool ma_pvio_ssl_compare_fp(char *fp1, unsigned int fp1_len,
                                   char *fp2, unsigned int fp2_len)
{
  char hexstr[64];

  fp1_len= (unsigned int)mysql_hex_string(hexstr, fp1, fp1_len);
#ifdef WIN32
  if (strnicmp(hexstr, fp2, fp1_len) != 0)
#else
  if (strncasecmp(hexstr, fp2, fp1_len) != 0)
#endif
   return 1;
  return 0;
}

my_bool ma_pvio_ssl_check_fp(MARIADB_SSL *cssl, const char *fp, const char *fp_list)
{
  unsigned int cert_fp_len= 64;
  unsigned char cert_fp[64];
  MYSQL *mysql;
  my_bool rc=1;

  if ((cert_fp_len= ma_ssl_get_finger_print(cssl, cert_fp, cert_fp_len)) < 1)
    goto end;
  if (fp)
    rc= ma_pvio_ssl_compare_fp(cert_fp, cert_fp_len, fp, strlen(fp));
  else if (fp_list)
  {
    FILE *fp;
    char buff[255];

    if (!(fp = fopen(fp_list, "r")))
    {
/*      
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                          ER(CR_SSL_CONNECTION_ERROR), 
                          "Can't open finger print list");
                          */
      goto end;
    }

    while (fgets(buff, sizeof(buff)-1, fp))
    {
      /* remove trailing new line character */
      char *pos= strchr(buff, '\r');
      if (!pos)
        pos= strchr(buff, '\n');
      if (pos)
        *pos= '\0';
        
      if (!ma_pvio_ssl_compare_fp(cert_fp, cert_fp_len, buff, strlen(buff)))
      {
        /* finger print is valid: close file and exit */
        fclose(fp);
        rc= 0;
        goto end;
      }
    }

    /* No finger print matched - close file and return error */
    fclose(fp);
  }


end:
  return rc;
}
#endif /* HAVE_SSL */
