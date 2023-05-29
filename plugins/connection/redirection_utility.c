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
#include <time.h>

/* Note that key, host and user and malloced together with Redirection_Entry */
struct Redirection_Entry
{
	char* key;
	char* host;
	char* user;
	unsigned int port;
	time_t last_used;
};

/* Note that host and user are malloced together with Redirection_info */
struct Redirection_Info
{
	char* host;
	char* user;
	unsigned int port;
};

#define MAX_CACHED_REDIRECTION_ENTRIES 4
#define MAX_REDIRECTION_KEY_LENGTH 512
#define MAX_REDIRECTION_INFO_LENGTH 512

static struct Redirection_Entry** redirection_cache = NULL;

static pthread_mutex_t redirect_lock;

#define redirect_mutex redirect_lock

#define mutex_lock(x) pthread_mutex_lock(&x);

#define mutex_unlock(x) pthread_mutex_unlock(&x)

#define mutex_destroy(x) pthread_mutex_destroy(&x)

my_bool check_redirection_entry(char* key);

void add_redirection_entry(char* key, char* host, char* user, unsigned int port);

void delete_redirection_entry(char* key);

struct Redirection_Entry* allocate_redirection_entry(char* key, char* host, char* user, unsigned int port);

struct Redirection_Info* get_redirection_info(char* key);

struct Redirection_Info* allocate_redirection_info(char* host, size_t host_len, char* user, size_t user_len, unsigned int port);

struct Redirection_Info* parse_redirection_info(MYSQL* mysql);

int init_redirection_cache()
{
	pthread_mutex_init(&redirect_mutex, NULL);

	redirection_cache = (struct Redirection_Entry**)malloc(sizeof(struct Redirection_Entry*) * MAX_CACHED_REDIRECTION_ENTRIES);
	memset(redirection_cache, 0, sizeof(struct Redirection_Entry*) * MAX_CACHED_REDIRECTION_ENTRIES);

	return 0;
}

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

		if (!port)
			port = MARIADB_PORT;

		snprintf(redirect_key, MAX_REDIRECTION_KEY_LENGTH, "%s_%s_%u", host, user, port);

		struct Redirection_Info* info = get_redirection_info(redirect_key);
		if (info)
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

	// convert port to integer before allocating redirection info
	char* port_str = (char*)malloc((size_t)port_len + 1);
	ma_strmake(port_str, port_begin, port_len);
	unsigned int port = strtoul(port_str, NULL, 0);
	free(port_str);
	if (!port)
		return NULL;

	struct Redirection_Info* info = allocate_redirection_info(host_begin, host_len, user_begin, user_len, port);
	return info;
}

struct Redirection_Info* get_redirection_info(char* key) {
	struct Redirection_Entry* ret_entry = NULL;
	mutex_lock(redirect_mutex);
	for (int i = 0; i < MAX_CACHED_REDIRECTION_ENTRIES; ++i) {
		if (redirection_cache[i] && redirection_cache[i]->key && !strcmp(redirection_cache[i]->key, key))
			redirection_cache[i]->last_used = time(NULL);
		ret_entry = redirection_cache[i];
		break;
	}

	if (!ret_entry) {
		mutex_unlock(redirect_mutex);
		return NULL;
	}

	struct Redirection_Info* info = allocate_redirection_info(ret_entry->host, strlen(ret_entry->host),
		ret_entry->user, strlen(ret_entry->user), ret_entry->port);
	mutex_unlock(redirect_mutex);
	return info;
}

struct Redirection_Info* allocate_redirection_info(char* host, size_t host_len, char* user, size_t user_len, unsigned int port) {
	struct Redirection_Info* info = NULL;

	char* host_str;
	char* user_str;

	if (!ma_multi_malloc(0,
		&info, sizeof(struct Redirection_Info),
		&host_str, host_len + 1,
		&user_str, user_len + 1,
		NULL))
	{
		return NULL;
	}

	ma_strmake(host_str, host, host_len);
	ma_strmake(user_str, user, user_len);
	(info)->host = host_str;
	(info)->user = user_str;
	(info)->port = port;

	return info;
}

my_bool check_redirection_entry(char* key) {
	my_bool found = 0;
	mutex_lock(redirect_mutex);

	for (int i = 0; i < MAX_CACHED_REDIRECTION_ENTRIES; ++i) {
		if (redirection_cache[i] && redirection_cache[i]->key && !strcmp(redirection_cache[i]->key, key)) {
			redirection_cache[i]->last_used = time(NULL);
			found = 1;
			break;
		}
	}

	mutex_unlock(redirect_mutex);
	return found;
}

void add_redirection_entry(char* key, char* host, char* user, unsigned int port) 
{

	if (key == NULL || host == NULL || user == NULL)
	{
		return;
	}

	if (check_redirection_entry(key))
	{
		return;
	}

	struct Redirection_Entry* new_entry = allocate_redirection_entry(key, host, user, port);
	if (!new_entry) {
		return;
	}

	time_t least_recent_use_time = new_entry->last_used;
	int poping_index = -1;
	struct Redirection_Entry* poping_entry = NULL;
	mutex_lock(redirect_mutex);
	for (int i = 0; i < MAX_CACHED_REDIRECTION_ENTRIES; ++i) {
		if (redirection_cache[i] == NULL) {
			redirection_cache[i] = new_entry;
			mutex_unlock(redirect_mutex);
			return;
		}

		if (redirection_cache[i]->last_used < least_recent_use_time) {
			poping_index = i;
			least_recent_use_time = redirection_cache[i]->last_used;
		}
	}

	if (poping_index != -1) {
		poping_entry = redirection_cache[poping_index];
		redirection_cache[poping_index] = new_entry;
	}

	mutex_unlock(redirect_mutex);
	if (poping_entry) {
		free(poping_entry);
	}
}

void delete_redirection_entry(char* key) {
	struct Redirection_Entry* del_entry = NULL;
	mutex_lock(redirect_mutex);

	for (int i = 0; i < MAX_CACHED_REDIRECTION_ENTRIES; ++i) {
		if (redirection_cache[i] && redirection_cache[i]->key && !strcmp(redirection_cache[i]->key, key)) {
			del_entry = redirection_cache[i];
			redirection_cache[i] = NULL;
			break;
		}
	}

	mutex_unlock(redirect_mutex);
	if (del_entry)
		free(del_entry);
}

struct Redirection_Entry* allocate_redirection_entry(char* key, char* host, char* user, unsigned int port) {
	struct Redirection_Entry* entry = NULL;
	char* key_str;
	char* host_str;
	char* user_str;
	size_t key_len = strlen(key);
	size_t host_len = strlen(host);
	size_t user_len = strlen(user);

	if (!ma_multi_malloc(0,
		&entry, sizeof(struct Redirection_Entry),
		&key_str, key_len + 1,
		&host_str, host_len + 1,
		&user_str, user_len + 1,
		NULL))
	{
		return NULL;
	}

	ma_strmake(key_str, key, key_len);
	ma_strmake(host_str, host, host_len);
	ma_strmake(user_str, user, user_len);
	(entry)->key = key_str;
	(entry)->host = host_str;
	(entry)->user = user_str;
	(entry)->port = port;
	(entry)->last_used = time(NULL);

	return entry;
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