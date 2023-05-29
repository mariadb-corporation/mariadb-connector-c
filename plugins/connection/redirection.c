/************************************************************************************
	Copyright (C) 2020 MariaDB Corporation AB

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
/* MariaDB Connection plugin for redirection. */
#include <ma_global.h>
#include <ma_sys.h>
#include <errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_string.h>
#include <ma_common.h>
#include "redirection_utility.h"
#ifndef WIN32
#include <sys/time.h>
#endif
/* redirection function declaration */
int redirection_init(char* errbuf, size_t buf_size, int argc, va_list argv);
MYSQL* redirection_connect(
	MYSQL* mysql,
	const char* host,
	const char* user,
	const char* passwd,
	const char* db,
	unsigned int port,
	const char* unix_socket,
	unsigned long clientflag);
void redirection_close(MYSQL* mysql);
int redirection_set_connection(
	MYSQL* mysql,
	enum enum_server_command command,
	const char* arg,
	size_t length,
	my_bool skipp_check,
	void* opt_arg);

#ifndef PLUGIN_DYNAMIC
MARIADB_CONNECTION_PLUGIN redirection_client_plugin =
#else
MARIADB_CONNECTION_PLUGIN _mysql_client_plugin_declaration_ =
#endif
{
  MARIADB_CLIENT_CONNECTION_PLUGIN,
  MARIADB_CLIENT_CONNECTION_PLUGIN_INTERFACE_VERSION,
  "redirection",
  "Shihao Chen",
  "MariaDB connection plugin for redirection",
  {1, 0, 0},
  "LGPL",
  NULL,
  redirection_init,
  NULL,
  NULL,
  redirection_connect,
  redirection_close,
  NULL,
  redirection_set_connection,
  NULL,
  NULL
};

int redirection_init(char* errbuf, size_t buf_size, int argc, va_list argv) {
	return init_redirection_cache();
}

MYSQL* redirection_connect(MYSQL* mysql, const char* host, const char* user, const char* passwd,
	const char* db, unsigned int port, const char* unix_socket, unsigned long clientflag)
{
	struct st_mariadb_api* libmariadb_api = mysql->methods->api;
	if (libmariadb_api == NULL)
	{
		return NULL;
	}

	if (check_redirect(mysql, host, user, passwd, db, port, unix_socket, clientflag)) {
		return mysql;
	}

	return redirect(mysql, host, user, passwd, db, port, unix_socket, clientflag);
}

void redirection_close(MYSQL* mysql)
{
	if (mysql != NULL)
	{
		mysql->extension->conn_hdlr->data = NULL;
	}
}

int redirection_set_connection(
	MYSQL* mysql,
	enum enum_server_command command,
	const char* arg,
	size_t length,
	my_bool skipp_check,
	void* opt_arg)
{
	return 0;
}