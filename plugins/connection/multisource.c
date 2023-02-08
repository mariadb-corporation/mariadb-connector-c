/************************************************************************************
    Copyright (C) 2015-2023 MariaDB Corporation AB
   
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

/* MariaDB Connection plugin for load balancing  */

#include <ma_global.h>
#include <ma_sys.h>
#include <errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_string.h>
#include <ma_common.h>

#ifndef WIN32
#include <sys/time.h>
#endif

/* function prototypes */
MYSQL *multisource_connect(MYSQL *mysql, const char *host, const char *user, const char *passwd,
        const char *db, unsigned int port, const char *unix_socket, unsigned long clientflag);
void multisource_close(MYSQL *mysql);
int multisource_set_connection(MYSQL *mysql,enum enum_server_command command, const char *arg,
                      size_t length, my_bool skipp_check, void *opt_arg);

static struct st_mariadb_api *libmariadb_api= NULL;

#ifndef PLUGIN_DYNAMIC
MARIADB_CONNECTION_PLUGIN multisource_client_plugin =
#else
MARIADB_CONNECTION_PLUGIN _mysql_client_plugin_declaration_ =
#endif
{
  MARIADB_CLIENT_CONNECTION_PLUGIN,
  MARIADB_CLIENT_CONNECTION_PLUGIN_INTERFACE_VERSION,
  "multisource",
  "Jonah H. Harris",
  "MariaDB connection plugin for multi-source load balancing",
  {1, 0, 0},
  "LGPL",
  NULL,
  NULL,
  NULL,
  NULL,
  multisource_connect,
  multisource_close,
  NULL,
  multisource_set_connection,
  NULL,
  NULL,
};

typedef struct st_conn_multisource {
  MARIADB_PVIO *pvio;
  char *url;
  char *host;
  unsigned int port;
} REPL_DATA;

/* parse url
 * Url has the following format:
 * host[:port],host[:port],host[:port],..,hostn[:port]
 */
my_bool multisource_parse_url(const char *url, REPL_DATA *data)
{
  const char delim[2] = { ',', '\0' };
  size_t counter = 0;
  char *brk;
  char *token;
  char *p;
#ifndef WIN32
  struct timeval tp;
  gettimeofday(&tp,NULL);
  srand(tp.tv_usec / 1000 + tp.tv_sec * 1000);
#else
  srand(GetTickCount());
#endif

  if (!url || url[0] == 0)
    return 1;

  data->host = NULL;
  data->port = 0;

  if (!data->url)
    data->url= strdup(url);

  token = data->url;
  while (*token) {
    brk = strpbrk(token, delim);
    ++counter;
    if (NULL == brk) {
      break;
    } else {
      token = ++brk;
    }
  }

  if (!counter)
    return 0;

  counter = ((size_t) rand() % counter);

  token = data->url;
  brk = NULL;
  for (size_t ii = 0; ii <= counter; ++ii) {
    brk = strpbrk(token, delim);
    if (ii < counter) {
      token = ++brk;
    }
  }

  data->host = token;

  if (brk != NULL)
    data->host[(brk - token)] = '\0';

  /* check ports */
  /* We need to be aware of IPv6 addresses: According to RFC3986 sect. 3.2.2
     hostnames have to be enclosed in square brackets if a port is given */
  if (data->host[0]== '[' && strchr(data->host, ':') && (p= strchr(data->host,']')))
  {
    /* ignore first square bracket */
    memmove(data->host, data->host+1, strlen(data->host) - 1);
    p= strchr(data->host,']');
    *p= 0;
    p++;
  }
  else
    p= data->host;
  if (p && (p= strchr(p, ':')))
  {
    *p= '\0';
    p++;
    data->port= atoi(p);
  }

  return 0;
}

MYSQL *multisource_connect(MYSQL *mysql, const char *host, const char *user, const char *passwd,
        const char *db, unsigned int port, const char *unix_socket, unsigned long clientflag)
{
  REPL_DATA *data= NULL;
  MA_CONNECTION_HANDLER *hdlr= mysql->extension->conn_hdlr;

  if (!libmariadb_api)
    libmariadb_api= mysql->methods->api;

  if ((data= (REPL_DATA *)hdlr->data))
  {
    data->pvio->methods->close(data->pvio);
    data->pvio= 0;
    multisource_close(mysql);
  }

  if (!(data= calloc(1, sizeof(REPL_DATA))))
  {
    mysql->methods->set_error(mysql, CR_OUT_OF_MEMORY, "HY000", 0);
    return NULL;
  }
  memset(&data->pvio, 0, sizeof(data->pvio));

  if (multisource_parse_url(host, data))
    goto error;

  /* try to connect to master */
  if (!(libmariadb_api->mysql_real_connect(mysql, data->host, user, passwd, db, 
        data->port ? data->port : port, unix_socket, clientflag)))
    goto error;

  data->pvio= mysql->net.pvio;
  hdlr->data= data;

  return mysql;
error:
  if (data)
  {
    if (data->url)
      free(data->url);
    free(data);
  }
  return NULL;
}

void multisource_close(MYSQL *mysql)
{
  MA_CONNECTION_HANDLER *hdlr= mysql->extension->conn_hdlr;
  REPL_DATA *data= (REPL_DATA *)hdlr->data;

  /* free and close connection */
  free(data->url);
  free(data);
  mysql->extension->conn_hdlr->data= NULL;
}

int multisource_set_connection(MYSQL *mysql,enum enum_server_command command, const char *arg,
                     size_t length, 
                     my_bool skipp_check __attribute__((unused)), 
                     void *opt_arg __attribute__((unused)))
{
  /* Nothing to do, but this callback is required and can't return -1 */
  return 0;
}

