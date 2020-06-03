/************************************************************************************
	Copyright (C) 2020 MariaDB Corporation AB,

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

#include <ma_global.h>
#include <ma_sys.h>
#include <mysql.h>
#include <errmsg.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_common.h>
#include <mariadb_ctype.h>
#include "ma_server_error.h"
#include <ma_pthread.h>
#include "redirection_utility.h"

/* Note that key, host and user and malloced together with Redirection_Entry */
struct Redirection_Entry
{
	char* key;
	char* host;
	char* user;
	unsigned int port;
	struct Redirection_Entry* next;
	struct Redirection_Entry* prev;
};

/* Note that host and user are malloced together with Redirection_info */
struct Redirection_Info
{
	char* host;
	char* user;
	unsigned int port;
};

#define MAX_CACHED_REDIRECTION_ENTRYS 4
#define MAX_REDIRECTION_KEY_LENGTH 512
#define MAX_REDIRECTION_INFO_LENGTH 512
static unsigned int redirection_cache_num = 0;
static struct Redirection_Entry redirection_cache_root = { 0 };
static struct Redirection_Entry* redirection_cache_rear = NULL;

static pthread_mutex_t redirect_lock;

#define redirect_mutex redirect_lock

#define mutex_lock(x) pthread_mutex_lock(&x);

#define mutex_unlock(x) pthread_mutex_unlock(&x)

#define mutex_destroy(x) pthread_mutex_destroy(&x)

int init_redirection_cache()
{
	pthread_mutex_init(&redirect_mutex, NULL);

	redirection_cache_root.next = NULL;
	redirection_cache_rear = &redirection_cache_root;
	redirection_cache_num = 0;

	return 0;
}

void add_redirection_entry(char* key, char* host, char* user, unsigned int port);

void delete_redirection_entry(char* key);

my_bool get_redirection_info(char* key, struct Redirection_Info** info, my_bool copy_on_found);

struct Redirection_Info* parse_redirection_info(MYSQL* mysql);

MYSQL* check_redirect(MYSQL* mysql, const char* host,
	const char* user, const char* passwd,
	const char* db, uint port,
	const char* unix_socket,
	ulong client_flag)
{
	enable_redirect redirection_mode;
	mysql->methods->api->mysql_get_option(mysql, MARIADB_OPT_USE_REDIRECTION, &redirection_mode);

	if (redirection_mode != REDIRECTION_OFF)
	{
		const char redirect_key[MAX_REDIRECTION_KEY_LENGTH] = { 0 };
		struct Redirection_Info* info = NULL;

		if (!port)
			port = MARIADB_PORT;

		snprintf(redirect_key, MAX_REDIRECTION_KEY_LENGTH, "%s_%s_%u", host, user, port);

		my_bool copy_on_found = 1;
		if (get_redirection_info(redirect_key, &info, copy_on_found))
		{
			MYSQL* ret_mysql = mysql->methods->api->mysql_real_connect(mysql,
				info->host,
				info->user,
				passwd,
				db,
				info->port,
				unix_socket,
				client_flag | CLIENT_REMEMBER_OPTIONS);

			free(info);

			if (ret_mysql)
			{
				return ret_mysql;
			}
			else
			{
				/* redirection_entry is incorrect or has expired, delete entry before going back to normal workflow */
				delete_redirection_entry(redirect_key);
			}
		}
	}

	return NULL;
}

MYSQL* redirect(MYSQL* mysql, const char* host,
	const char* user, const char* passwd,
	const char* db, uint port,
	const char* unix_socket,
	ulong client_flag)
{
	enable_redirect redirection_mode;
	mysql->methods->api->mysql_get_option(mysql, MARIADB_OPT_USE_REDIRECTION, &redirection_mode);
	
	if (redirection_mode == REDIRECTION_OFF)
		return mysql->methods->db_connect(mysql, host, user, passwd, db, port, unix_socket, client_flag);

	/* create a temp connection to gateway to retrieve redirection info */
	MYSQL tmp_mysql;
	my_bool use_ssl = 1;
	if (mysql->options.use_ssl == 0)
		use_ssl = 0;
	mysql->methods->api->mysql_init(&tmp_mysql);
	mysql->methods->api->mysql_options(&tmp_mysql, MYSQL_OPT_SSL_ENFORCE, &use_ssl);
	MYSQL* ret_mysql = mysql->methods->db_connect(&tmp_mysql, host, user, passwd,
		db, port, unix_socket, client_flag);

	if (!ret_mysql) {
		mysql->methods->set_error(mysql, tmp_mysql.net.last_errno,
			tmp_mysql.net.sqlstate,
			tmp_mysql.net.last_error);
		mysql->methods->api->mysql_close(&tmp_mysql);
		return NULL;
	}

	/* redirection info is present in tmp_mysql.info if redirection enabled on both ends */
	struct Redirection_Info* info = NULL;
	info = parse_redirection_info(&tmp_mysql);
	mysql->methods->api->mysql_close(&tmp_mysql);

	if (!info)
	{
		if (redirection_mode == REDIRECTION_ON)
		{
			mysql->methods->set_error(mysql, ER_PARSE_ERROR, "HY000",
				"redirection set to ON on client side but parse_redirection_info failed. Redirection info: %s",
				mysql->info);
			return NULL;
		}
		else
		{
			/* enable_redirect = PREFERRED, fallback to normal connection workflow */
			return mysql->methods->db_connect(mysql, host, user, passwd, db, port, unix_socket, client_flag);
		}
	}

	/* No need to redirect if we are talking directly to the server */
	if (!strcmp(info->host, host) &&
		!strcmp(info->user, user) &&
		info->port == port)
	{
		free(info);
		return mysql->methods->db_connect(mysql, host, user, passwd, db, port, unix_socket, client_flag);
	}

	/* the "real" connection */
	if (!mysql->methods->db_connect(mysql, info->host, info->user, passwd,
		db, info->port, unix_socket, client_flag))
	{
		free(info);
		if (redirection_mode == REDIRECTION_ON)
		{
			mysql->methods->set_error(mysql, ER_BAD_HOST_ERROR, "HY000",
				"redirection set to ON on client side but parse_redirection_info failed. Redirection info: %s",
				mysql->info);
			return NULL;
		}
		else
		{
			/* enable_redirect = PREFERRED, fallback to normal connection workflow */
			return mysql->methods->db_connect(mysql, host, user, passwd, db, port, unix_socket, client_flag);
		}
		return NULL;
	}

	/* real_connect succeeded */
	free(info);

	const char redirect_key[MAX_REDIRECTION_KEY_LENGTH] = { 0 };
	snprintf(redirect_key, MAX_REDIRECTION_KEY_LENGTH, "%s_%s_%u", host, user, port);
	add_redirection_entry(redirect_key, mysql->host, mysql->user, mysql->port);

	return mysql;
}

struct Redirection_Info* parse_redirection_info(MYSQL* mysql)
{
	struct Redirection_Info* info = NULL;
	if (!mysql->info || !mysql->info[0])
	{
		return NULL;
	}
	
	/*
		redirection info format:
		Location: mysql://[redirectedHostName]:redirectedPort/?user=redirectedUser&ttl=%d\n
	*/
	const char* msg_header = "Location: mysql://[";
	int msg_header_len = strlen(msg_header);

	char* info_str = strstr(mysql->info, msg_header);
	char* cur_pos = info_str + msg_header_len;
	char* end = info_str + strlen(info_str);

	char* host_begin = cur_pos, * host_end = NULL,
		* port_begin = NULL, * port_end = NULL,
		* user_begin = NULL, * user_end = NULL,
		* ttl_begin = NULL, * ttl_end = NULL;

	host_end = strchr(cur_pos, ']');
	if (host_end == NULL) return NULL;

	cur_pos = host_end + 1;
	if (cur_pos == end || *cur_pos != ':' || ++cur_pos == end) return NULL;

	port_begin = cur_pos;
	port_end = strchr(cur_pos, '/');
	if (port_end == NULL) return NULL;

	cur_pos = port_end + 1;
	if (cur_pos == end || *cur_pos != '?' || ++cur_pos == end) return NULL;

	int user_delimiter_len = strlen("user=");
	if (end - cur_pos <= user_delimiter_len || strncmp(cur_pos, "user=", user_delimiter_len) != 0) return NULL;

	user_begin = cur_pos + user_delimiter_len;
	user_end = strchr(cur_pos, '&');
	if (user_end == NULL) return NULL;

	cur_pos = user_end + 1;
	if (cur_pos == end) return NULL;

	int ttl_delimiter_len = strlen("ttl=");
	if (end - cur_pos <= ttl_delimiter_len || strncmp(cur_pos, "ttl=", ttl_delimiter_len) != 0) return NULL;

	ttl_begin = cur_pos + ttl_delimiter_len;
	ttl_end = strchr(cur_pos, '\n');
	if (ttl_end == NULL) return NULL;

	int host_len = host_end - host_begin;
	int port_len = port_end - port_begin;
	int user_len = user_end - user_begin;
	int ttl_len = ttl_end - ttl_begin;
	int redirection_info_length = ttl_end - info_str;

	/* server side protocol rules that redirection_info_length should not exceed 512 bytes */
	if (host_len <= 0 || port_len <= 0 || user_len <= 0 || ttl_len <= 0 || redirection_info_length > MAX_REDIRECTION_INFO_LENGTH) {
		return NULL;
	}

	char* host_str = NULL;
	char* user_str = NULL;

	/* 
		free(info) will free all pointers alloced by this ma_multi_malloc
		do not include port_str here because port_str is a temp var, whereas port is the real member
		of redirection info, so port_str should not get out of this function's scope
	*/
	if (!ma_multi_malloc(0,
		&info, sizeof(struct Redirection_Info),
		&host_str, (size_t)host_len + 1,
		&user_str, (size_t)user_len + 1,
		NULL))
		return NULL;

	char* port_str = (char*)malloc((size_t)port_len + 1);

	ma_strmake(host_str, host_begin, host_len);
	ma_strmake(user_str, user_begin, user_len);
	ma_strmake(port_str, port_begin, port_len);
	info->host = host_str;
	info->user = user_str;

	if (!(info->port = strtoul(port_str, NULL, 0)))
	{
		free(info);
		free(port_str);
		return NULL;
	}

	free(port_str);
	return info;
}

my_bool get_redirection_info(char* key, struct Redirection_Info** info, my_bool copy_on_found)
{
	struct Redirection_Entry* ret_entry = NULL;
	struct Redirection_Entry* cur_entry = NULL;

	mutex_lock(redirect_mutex);
	cur_entry = redirection_cache_root.next;
	while (cur_entry)
	{
		if (cur_entry->key)
		{
			if (!strcmp(cur_entry->key, key))
			{
				ret_entry = cur_entry;
				break;
			}
			cur_entry = cur_entry->next;
		}
		else break;
	}

	if (ret_entry)
	{
		/* after find the cache, move it to list header */
		if (redirection_cache_root.next != ret_entry)
		{
			if (redirection_cache_rear == ret_entry)
			{
				redirection_cache_rear = ret_entry->prev;
			}

			ret_entry->prev->next = ret_entry->next;

			if (ret_entry->next)
			{
				ret_entry->next->prev = ret_entry->prev;
			}

			ret_entry->next = redirection_cache_root.next;
			ret_entry->prev = &redirection_cache_root;

			redirection_cache_root.next = ret_entry;
		}

		if (copy_on_found)
		{
			size_t host_len = strlen(ret_entry->host);
			size_t user_len = strlen(ret_entry->user);

			char* host_str;
			char* user_str;

			if (!ma_multi_malloc(0,
				info, sizeof(struct Redirection_Info),
				&host_str, host_len + 1,
				&user_str, user_len + 1,
				NULL))
			{
				mutex_unlock(redirect_mutex);
				return 0;
			}

			ma_strmake(host_str, ret_entry->host, strlen(ret_entry->host));
			ma_strmake(user_str, ret_entry->user, strlen(ret_entry->user));
			(*info)->host = host_str;
			(*info)->user = user_str;
			(*info)->port = ret_entry->port;
		}
	}

	my_bool retval = (ret_entry != NULL);
	mutex_unlock(redirect_mutex);

	return retval;
}

void add_redirection_entry(char* key, char* host, char* user, unsigned int port)
{
	struct Redirection_Entry* new_entry = NULL;
	struct Redirection_Entry* popingEntry = NULL;
	char* _key;
	char* _host;
	char* _user;
	size_t key_len = 0;
	size_t host_len = 0;
	size_t user_len = 0;

	if (key == NULL || host == NULL || user == NULL)
	{
		return;
	}

	my_bool copy_on_found = 0;
	if (get_redirection_info(key, NULL, copy_on_found))
	{
		return;
	}

	key_len = strlen(key);
	host_len = strlen(host);
	user_len = strlen(user);

	if (!ma_multi_malloc(0,
		&new_entry, sizeof(struct Redirection_Entry),
		&_key, key_len + 1,
		&_host, host_len + 1,
		&_user, user_len + 1,
		NULL))
	{
		return;
	}

	new_entry->key = _key;
	new_entry->host = _host;
	new_entry->user = _user;
	new_entry->next = NULL;
	new_entry->prev = NULL;

	strcpy(new_entry->key, key);
	strcpy(new_entry->host, host);
	strcpy(new_entry->user, user);
	new_entry->port = port;

	mutex_lock(redirect_mutex);

	if (NULL == redirection_cache_root.next)
	{
		redirection_cache_root.next = new_entry;
		new_entry->prev = &redirection_cache_root;
		redirection_cache_rear = new_entry;
	}
	else
	{
		new_entry->next = redirection_cache_root.next;
		new_entry->prev = &redirection_cache_root;

		redirection_cache_root.next->prev = new_entry;
		redirection_cache_root.next = new_entry;
	}

	redirection_cache_num++;

	if (redirection_cache_num > MAX_CACHED_REDIRECTION_ENTRYS)
	{
		popingEntry = redirection_cache_rear;
		redirection_cache_rear = redirection_cache_rear->prev;
		redirection_cache_rear->next = NULL;

		redirection_cache_num--;
	}

	mutex_unlock(redirect_mutex);

	if (popingEntry)
		free(popingEntry);

	return;
}

void delete_redirection_entry(char* key)
{
	struct Redirection_Entry* del_entry = NULL;
	struct Redirection_Entry* cur_entry = NULL;

	mutex_lock(redirect_mutex);
	cur_entry = redirection_cache_root.next;
	while (cur_entry)
	{
		if (cur_entry->key)
		{
			if (!strcmp(cur_entry->key, key))
			{
				del_entry = cur_entry;
				break;
			}
			cur_entry = cur_entry->next;
		}
		else break;
	}

	if (del_entry)
	{
		if (redirection_cache_rear == del_entry)
		{
			redirection_cache_rear = del_entry->prev;
		}
		del_entry->prev->next = del_entry->next;

		if (del_entry->next)
		{
			del_entry->next->prev = del_entry->prev;
		}

		redirection_cache_num--;
	}

	mutex_unlock(redirect_mutex);

	if (del_entry)
		free(del_entry);
}

#ifdef PLUGIN_DYNAMIC
void* ma_multi_malloc(myf myFlags, ...)
{
	va_list args;
	char** ptr, * start, * res;
	size_t tot_length, length;

	va_start(args, myFlags);
	tot_length = 0;
	while ((ptr = va_arg(args, char**)))
	{
		length = va_arg(args, size_t);
		tot_length += ALIGN_SIZE(length);
	}
	va_end(args);

	if (!(start = (char*)malloc(tot_length)))
		return 0;

	va_start(args, myFlags);
	res = start;
	while ((ptr = va_arg(args, char**)))
	{
		*ptr = res;
		length = va_arg(args, size_t);
		res += ALIGN_SIZE(length);
	}
	va_end(args);
	return start;
}

char* ma_strmake(register char* dst, register const char* src, size_t length)
{
	while (length--)
		if (!(*dst++ = *src++))
			return dst - 1;
	*dst = 0;
	return dst;
}
#endif