/************************************************************************************
  Copyright (C) 2018 MariaDB Corporation AB

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

/* MariaDB Connection plugin for connecting via DSN connection string */

#include <ma_global.h>
#include <ma_sys.h>
#include <errmsg.h>
#include <ma_common.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_string.h>


/* function prototypes */
MYSQL *dsn_connect(MYSQL *mysql, const char *host, const char *user,
                   const char *passwd, const char *db, unsigned int port,
                   const char *unix_socket, unsigned long clientflag);

#ifndef PLUGIN_DYNAMIC
MARIADB_CONNECTION_PLUGIN dsn_client_plugin =
#else
MARIADB_CONNECTION_PLUGIN _mysql_client_plugin_declaration_ =
#endif
{
  MARIADB_CLIENT_CONNECTION_PLUGIN,
  MARIADB_CLIENT_CONNECTION_PLUGIN_INTERFACE_VERSION,
  "dsn",
  "Georg Richter",
  "MariaDB connection plugin for connecting via DSN",
  {1, 0, 0},
  "LGPL",
  NULL,
  NULL,
  NULL,
  NULL,
  dsn_connect,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
};

static struct st_mariadb_api *mariadb_api= NULL;

/* {{{ MYSQL *dsn_connect */
MYSQL *dsn_connect(MYSQL *mysql, 
                  const char *host,
                  const char *user __attribute__((unused)),
                  const char *passwd __attribute__((unused)),
                  const char *db __attribute__((unused)),
                  unsigned int port __attribute__((unused)),
                  const char *unix_socket __attribute__((unused)),
                  unsigned long client_flag __attribute__((unused)))
{
  char *dsn, *key, *value, *p;

  if (!mariadb_api &&
       !(mariadb_api= mysql->methods->api))
    return NULL;

  if (!host || !host[0])
    return NULL;

  dsn= strdup(host);

  while ((key= strtok_r(dsn, ";", &dsn)))
  {
    if ((p= strchr(key, '=')))
    {
      *p= 0;
      value= ++p;
      /* In case an unknown key was specified, we don't return
         an error (like we don't when reading my.cnf) */
      mariadb_api->mysql_optionsv(mysql, MARIADB_OPT_DSN, key, value);
    }
  }
  return mariadb_api->mysql_real_connect(mysql, NULL, NULL, NULL, NULL, 0, NULL, 0);
}
/* }}} */
