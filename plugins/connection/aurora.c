/************************************************************************************
  Copyright (C) 2015 MariaDB Corporation AB

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

/* MariaDB Connection plugin for Aurora failover  */

#include <my_global.h>
#include <my_sys.h>
#include <errmsg.h>
#include <ma_common.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <m_string.h>

#ifndef WIN32
#include <sys/time.h>
#endif

/* function prototypes */
int aurora_init(char *errormsg, size_t errormsg_size,
    int unused  __attribute__((unused)), 
    va_list unused1 __attribute__((unused)));

MYSQL *aurora_connect(MYSQL *mysql, const char *host, const char *user, const char *passwd,
    const char *db, unsigned int port, const char *unix_socket, unsigned long clientflag);
void aurora_close(MYSQL *mysql);
int aurora_command(MYSQL *mysql,enum enum_server_command command, const char *arg,
    size_t length, my_bool skipp_check, void *opt_arg);
int aurora_set_options(MYSQL *msql, enum mysql_option option, void *arg);
my_bool aurora_reconnect(MYSQL *mysql);

#define AURORA_MAX_INSTANCES 16

#define AURORA_UNKNOWN -1
#define AURORA_PRIMARY 0
#define AURORA_REPLICA 1
#define AURORA_UNAVAILABLE 2

#define ENABLE_AURORA(mysql)\
  (mysql)->net.conn_hdlr->active= 1;
#define DISABLE_AURORA(mysql)\
  (mysql)->net.conn_hdlr->active= 0;

#ifndef HAVE_REPLICATION_DYNAMIC
MARIADB_CONNECTION_PLUGIN connection_aurora_plugin =
#else
MARIADB_CONNECTION_PLUGIN _mysql_client_plugin_declaration_ =
#endif
{
  MARIADB_CLIENT_CONNECTION_PLUGIN,
  MARIADB_CLIENT_CONNECTION_PLUGIN_INTERFACE_VERSION,
  "aurora",
  "Georg Richter",
  "MariaDB connection plugin for Aurora failover",
  {1, 0, 0},
  "LGPL",
  aurora_init,
  NULL,
  aurora_connect,
  aurora_close,
  aurora_set_options,
  aurora_command,
  aurora_reconnect
};

struct st_mariadb_api *mariadb_api= NULL;

typedef struct st_aurora_instance {
  char *host;
  int  port;
  time_t blacklisted;
  int type;
} AURORA_INSTANCE;

typedef struct st_conn_aurora {
  MARIADB_PVIO *pvio[2];
  MYSQL *mysql[2];
  my_bool active[2];
  char *url;
  unsigned int num_instances;
  AURORA_INSTANCE instance[AURORA_MAX_INSTANCES];
  char *username, *password, *database;
  unsigned int port;
  unsigned long client_flag;
  unsigned int last_instance_type; /* Primary or Replica */
  char primary_id[100];
} AURORA;

#define AURORA_BLACKLIST_TIMEOUT 150

#define AURORA_IS_BLACKLISTED(a, i) \
  ((time(NULL) - (a)->instance[(i)].blacklisted) < AURORA_BLACKLIST_TIMEOUT)

/* {{{ my_bool aurora_swutch_connection */
my_bool aurora_switch_connection(MYSQL *mysql, AURORA *aurora, int type)
{
  switch (type)
  {
    case AURORA_REPLICA:
      if (aurora->mysql[AURORA_REPLICA])
      {
        mysql->net.pvio= aurora->pvio[AURORA_REPLICA];
        aurora->pvio[AURORA_REPLICA]->mysql= mysql;
        mysql->thread_id= aurora->mysql[AURORA_REPLICA]->thread_id;
        aurora->last_instance_type= AURORA_REPLICA;
      }
      break;
    case AURORA_PRIMARY:
      if (aurora->mysql[AURORA_PRIMARY])
      {
        if (aurora->mysql[AURORA_REPLICA])
          aurora->mysql[AURORA_REPLICA]->net.pvio->mysql= aurora->mysql[AURORA_REPLICA];
        mysql->net.pvio= aurora->pvio[AURORA_PRIMARY];
        mysql->thread_id= aurora->mysql[AURORA_PRIMARY]->thread_id;
        aurora->last_instance_type= AURORA_PRIMARY;
      }
      break;
    default:
      return 1;
  }
  return 0;
}
/* }}} */

/* {{{ int aurora_init
 *
 *     plugin initialization function
 */
int aurora_init(char *errormsg, size_t errormsg_size,
    int unused  __attribute__((unused)), 
    va_list unused1 __attribute__((unused)))
{
  /* random generator initialization */
#ifndef WIN32
  struct timeval tp;
  gettimeofday(&tp,NULL);
  srand(tp.tv_usec / 1000 + tp.tv_sec * 1000);
#else
  srand(GetTickCount());
#endif
  return 0;
}
/* }}} */

/* {{{ void aurora_close_memory */
void aurora_close_memory(AURORA *aurora)
{
  free(aurora->url);
  free(aurora->username);
  free(aurora->password);
  free(aurora->database);
  free(aurora);
}
/* }}} */

/* {{{ my_bool aurora_parse_url 
 * 
 *    parse url
 *   Url has the following format:
 *   instance1:port, instance2:port, .., instanceN:port
 *
 */
my_bool aurora_parse_url(const char *url, AURORA *aurora)
{
  char *p, *c;
  unsigned int i;

  if (!url || url[0] == 0)
    return 1;

  bzero(aurora->instance, (AURORA_MAX_INSTANCES + 1) * sizeof(char *));
  bzero(&aurora->port, (AURORA_MAX_INSTANCES + 1) * sizeof(int));

  if (aurora->url)
    free(aurora->url);

  aurora->url= strdup(url);
  c= aurora->url;

  /* get instances */ 
  while((c))
  {
    if (p= strchr(c, ','))
    {
      *p= '\0';
      p++;
    }
    if (*c)
    {
      aurora->instance[aurora->num_instances].host= c;
      aurora->num_instances++;
    }
    c= p;
  }

  if (!aurora->num_instances)
    return 0;

  /* check ports */
  for (i=0; i < aurora->num_instances && aurora->instance[i].host; i++)
  { 
    aurora->instance[i].type= AURORA_UNKNOWN;

    /* We need to be aware of IPv6 addresses: According to RFC3986 sect. 3.2.2
       hostnames have to be enclosed in square brackets if a port is given */
    if (aurora->instance[i].host[0]== '[' && 
        strchr(aurora->instance[i].host, ':') && 
        (p= strchr(aurora->instance[i].host,']')))
    {
      /* ignore first square bracket */
      memmove(aurora->instance[i].host, 
          aurora->instance[i].host+1, 
          strlen(aurora->instance[i].host) - 1);
      p= strchr(aurora->instance[i].host,']');
      *p= 0;
      p++;
    }
    else
      p= aurora->instance[i].host;
    if (p && (p= strchr(p, ':')))
    {
      *p= '\0';
      p++;
      aurora->instance[i].port= atoi(p);
    }
  }
  return 0;
}
/* }}} */

/* {{{ int aurora_get_instance_type 
 *
 *  RETURNS:
 *
 *    AURORA_PRIMARY
 *    AURORA_REPLICA
 *    -1 on error
 */
int aurora_get_instance_type(MYSQL *mysql)
{
  int rc;
  char *query= "select variable_value from information_schema.global_variables where variable_name='INNODB_READ_ONLY' AND variable_value='OFF'";

  if (!mariadb_api->mysql_query(mysql, query))
  {
    MYSQL_RES *res= mysql_store_result(mysql);
    rc= mysql_num_rows(res) ? AURORA_PRIMARY : AURORA_REPLICA;
    mysql_free_result(res);
    return rc;
  }
  return -1;
}
/* }}} */

/* {{{ my_bool aurora_get_primary_id 
 *
 *   try to find primary instance from slave by retrieving
 *   primary_id information_schema.replica_host_status information
 *
 *   If the function succeeds, primary_id will be copied into
 *   aurora->primary_id
 *
 *   Returns:
 *     1 on success
 *     0 if an error occured or primary_id couldn't be 
 *       found
 */
my_bool aurora_get_primary_id(MYSQL *mysql, AURORA *aurora)
{
  my_bool rc= 0;

  if (!mariadb_api->mysql_query(mysql, "select server_id from information_schema.replica_host_status "
        "where session_id = 'MASTER_SESSION_ID'"))
  {
    MYSQL_RES *res;
    MYSQL_ROW row;

    if ((res= mysql_store_result(mysql)))
    {
      if ((row= mysql_fetch_row(res)))
      {
        if (row[0])
        {
          strcpy(aurora->primary_id, row[0]);
          rc= 1;
        }
      }
      mysql_free_result(res);
    }
  }
  return rc;
}
/* }}} */

/* {{{ unsigned int aurora_get_valid_instances 
 *
 *     returns the number of instances which are
 *     not blacklisted or don't have a type assigned.
 */
static unsigned int aurora_get_valid_instances(AURORA *aurora, AURORA_INSTANCE **instances)
{
  unsigned int i, valid_instances= 0;

  memset(instances, 0, sizeof(AURORA_INSTANCE *) * AURORA_MAX_INSTANCES);

  for (i=0; i < aurora->num_instances; i++)
  {
    if (aurora->instance[i].type != AURORA_UNAVAILABLE)
    {
      if (aurora->instance[i].type == AURORA_PRIMARY && aurora->active[AURORA_PRIMARY])
        continue;
      instances[valid_instances]= &aurora->instance[i];
      valid_instances++;
    }
  }
  return valid_instances;
}
/* }}} */

/* {{{ void aurora_refresh_blacklist() */
void aurora_refresh_blacklist(AURORA *aurora)
{
  unsigned int i;
  for (i=0; i < aurora->num_instances; i++)
  {
    if (aurora->instance[i].blacklisted &&
        !(AURORA_IS_BLACKLISTED(aurora, i)))
    {
      aurora->instance[i].blacklisted= 0;
      aurora->instance[i].type= AURORA_UNKNOWN;
    }
  }
}
/* }}} */

/* {{{ MYSQL *aurora_connect_instance() */
MYSQL *aurora_connect_instance(AURORA *aurora, AURORA_INSTANCE *instance, MYSQL *mysql)
{
  if (!mysql->methods->db_connect(mysql,
        instance->host,
        aurora->username,
        aurora->password,
        aurora->database,
        instance->port ? instance->port : aurora->port,
        NULL,
        aurora->client_flag))
  {
    /* connection not available */
    instance->blacklisted= time(NULL);
    instance->type= AURORA_UNAVAILABLE;
    return NULL;
  }

  /* check if we are slave or master */
  switch (aurora_get_instance_type(mysql))
  {
    case AURORA_PRIMARY:
      instance->type= AURORA_PRIMARY;
      return mysql;
      break;
    case AURORA_REPLICA:
      instance->type= AURORA_REPLICA;
      break;
    default:
      instance->type= AURORA_UNAVAILABLE;
      instance->blacklisted= time(NULL);
      return NULL;
  }
  if (!aurora->primary_id[0])
    aurora_get_primary_id(mysql, aurora);
  return mysql;
}
/* }}} */

/* {{{ void aurora_copy_mysql() */
void aurora_copy_mysql(MYSQL *from, MYSQL *to)
{
  LIST *li_stmt= to->stmts;

  for (;li_stmt;li_stmt= li_stmt->next)
  {
    MYSQL_STMT *stmt= (MYSQL_STMT *)li_stmt->data;

    if (stmt->state != MYSQL_STMT_INITTED)
    {
      stmt->state= MYSQL_STMT_INITTED;
      SET_CLIENT_STMT_ERROR(stmt, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    }
  }

  from->free_me= to->free_me;
  from->reconnect= to->reconnect;
  from->net.conn_hdlr= to->net.conn_hdlr;
  from->stmts= to->stmts;
  to->stmts= NULL;

  memset(&to->options, 0, sizeof(to->options));
  to->free_me= 0;
  to->net.conn_hdlr= 0;
  mariadb_api->mysql_close(to);
  *to= *from;
  to->net.pvio= from->net.pvio;
  to->net.pvio->mysql= to;
  from->net.pvio= NULL;
}
/* }}} */

/* {{{ my_bool aurora_find_replica() */
my_bool aurora_find_replica(AURORA *aurora)
{
  int valid_instances;
  my_bool replica_found= 0;
  AURORA_INSTANCE *instance[AURORA_MAX_INSTANCES];
  MYSQL mysql;
//  struct st_dynamic_array *init_command= aurora->mysql[AURORA_PRIMARY]->options.init_command;

  if (aurora->num_instances < 2)
    return 0;

  mariadb_api->mysql_init(&mysql);
  mysql.options= aurora->mysql[AURORA_PRIMARY]->options;

  /* don't execute init_command on slave */
  mysql.net.conn_hdlr= aurora->mysql[AURORA_PRIMARY]->net.conn_hdlr;

  valid_instances= aurora_get_valid_instances(aurora, instance);

  while (valid_instances && !replica_found)
  {
    int random_pick= rand() % valid_instances;
    if ((aurora_connect_instance(aurora, instance[random_pick], &mysql)))
    {
      switch (instance[random_pick]->type) {
        case AURORA_REPLICA:
          if (!aurora->mysql[AURORA_REPLICA])
          {
            aurora->mysql[AURORA_REPLICA]= mysql_init(NULL);
          }
          aurora_copy_mysql(&mysql, aurora->mysql[AURORA_REPLICA]);
          aurora->active[AURORA_REPLICA]= 1;
          return 1;
          break;
        case AURORA_PRIMARY:
          aurora_copy_mysql(&mysql, aurora->mysql[AURORA_PRIMARY]);
          aurora->pvio[AURORA_PRIMARY]= aurora->mysql[AURORA_PRIMARY]->net.pvio;
          aurora->active[AURORA_PRIMARY]= 1;
          continue;
          break;
        default:
          mysql_close(&mysql);
          return 0;
          break;
      }
    }
    valid_instances= aurora_get_valid_instances(aurora, instance);
  }
  return 0;
}
/* }}} */

/* {{{ AURORA_INSTANCE aurora_get_primary_id_instance() */
AURORA_INSTANCE *aurora_get_primary_id_instance(AURORA *aurora)
{
  unsigned int i;

  if (!aurora->primary_id[0])
    return 0;

  for (i=0; i < aurora->num_instances; i++)
  {
    if (!strncmp(aurora->instance[i].host, aurora->primary_id, strlen(aurora->primary_id)))
      return &aurora->instance[i];
  }
  return NULL;
}
/* }}} */

/* {{{ my_bool aurora_find_primary() */
my_bool aurora_find_primary(AURORA *aurora)
{
  unsigned int i;
  AURORA_INSTANCE *instance= NULL;
  MYSQL mysql;
  my_bool check_primary= 1;

  if (!aurora->num_instances)
    return 0;

  mariadb_api->mysql_init(&mysql);
  mysql.options= aurora->mysql[AURORA_PRIMARY]->options;
  mysql.net.conn_hdlr= aurora->mysql[AURORA_PRIMARY]->net.conn_hdlr;

  for (i=0; i < aurora->num_instances; i++)
  {
    if (check_primary && aurora->primary_id[0])
    {
      if ((instance= aurora_get_primary_id_instance(aurora)) &&
          aurora_connect_instance(aurora, instance, &mysql) &&
          instance->type == AURORA_PRIMARY)
      {
        aurora_copy_mysql(&mysql, aurora->mysql[AURORA_PRIMARY]);
        aurora->active[AURORA_PRIMARY]= 1;
        return 1;
      }
      /* primary id connect failed, don't try again */
      aurora->primary_id[0]= 0;
      check_primary= 0;
    }
    if (aurora->instance[i].type != AURORA_UNAVAILABLE)
    {
      if (aurora_connect_instance(aurora, &aurora->instance[i], &mysql)
          && aurora->instance[i].type == AURORA_PRIMARY)
      {
        aurora_copy_mysql(&mysql, aurora->mysql[AURORA_PRIMARY]);
        aurora->active[AURORA_PRIMARY]= 1;
        return 1;
      }
    }
  }
  return 0;
}
/* }}} */

/* {{{ void aurora_close_replica() */
void aurora_close_replica(MYSQL *mysql, AURORA *aurora)
{
  if (aurora->mysql[AURORA_REPLICA])
  {
    aurora->mysql[AURORA_REPLICA]->net.pvio->mysql= aurora->mysql[AURORA_REPLICA];
    aurora->mysql[AURORA_REPLICA]->net.conn_hdlr= 0;
    mariadb_api->mysql_close(aurora->mysql[AURORA_REPLICA]);
    aurora->pvio[AURORA_REPLICA]= 0;
    aurora->mysql[AURORA_REPLICA]= NULL;
  }
}
/* }}} */

/* {{{ MYSQL *aurora_connect */
MYSQL *aurora_connect(MYSQL *mysql, const char *host, const char *user, const char *passwd,
    const char *db, unsigned int port, const char *unix_socket, unsigned long client_flag)
{
  AURORA *aurora= NULL;
  MA_CONNECTION_HANDLER *hdlr= mysql->net.conn_hdlr;
  my_bool is_reconnect= 0;

  if (!mariadb_api)
    mariadb_api= mysql->methods->api;

  if ((aurora= (AURORA *)hdlr->data))
  {
    aurora_refresh_blacklist(aurora);
    if (aurora->mysql[aurora->last_instance_type]->net.pvio)
    {
      SET_CLIENT_ERROR(mysql, CR_ALREADY_CONNECTED, SQLSTATE_UNKNOWN, 0);
      return NULL;
    }
    is_reconnect= 1;
  }
  else
  {
    if (!(aurora= (AURORA *)my_malloc(sizeof(AURORA), MYF(MY_ZEROFILL))))
    {
      mysql->methods->set_error(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
      return NULL;
    }

    mysql->net.conn_hdlr->data= (void *)aurora;

    aurora->mysql[AURORA_PRIMARY]= mysql;

    if (aurora_parse_url(host, aurora))
    {
      goto error;
    }

    if (user)
      aurora->username= strdup(user);
    if (passwd)
      aurora->password= strdup(passwd);
    if (db)
      aurora->database= strdup(db);
    aurora->port= port;
    aurora->client_flag= client_flag;
    aurora->pvio[AURORA_PRIMARY]= aurora->pvio[AURORA_REPLICA]= NULL;
    hdlr->data= aurora;
  }


  /* In case of reconnect, close broken connection first */
  if (is_reconnect)
  {
    DISABLE_AURORA(mysql);
    switch (aurora->last_instance_type) {
      case AURORA_REPLICA:
        aurora_close_replica(mysql, aurora);
        aurora->pvio[AURORA_REPLICA]= NULL;
        break;
      case AURORA_PRIMARY:
        /* pvio will be closed in mysql_reconnect() */
        aurora->pvio[AURORA_PRIMARY]= NULL;
        aurora->primary_id[0]= 0;
        break;
    }
    aurora->active[aurora->last_instance_type]= 0;
  }

  if (!aurora->active[AURORA_REPLICA])
  {
    if (aurora_find_replica(aurora))
    {
      aurora->pvio[AURORA_REPLICA]= aurora->mysql[AURORA_REPLICA]->net.pvio;
      aurora->mysql[AURORA_REPLICA]->net.conn_hdlr= mysql->net.conn_hdlr;
    }
    else
      aurora->pvio[AURORA_REPLICA]= NULL;
  }

  if (!aurora->active[AURORA_PRIMARY])
  {
    if (aurora_find_primary(aurora))
    {
      aurora->active[AURORA_PRIMARY]= 1;
      aurora->pvio[AURORA_PRIMARY]= aurora->mysql[AURORA_PRIMARY]->net.pvio;
    }
  }

  aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);
  ENABLE_AURORA(mysql);
  return mysql;
error:
  aurora_close_memory(aurora);
  return NULL;
}
/* }}} */

/* {{{ my_bool aurora_reconnect */
my_bool aurora_reconnect(MYSQL *mysql)
{
  AURORA *aurora;
  MA_CONNECTION_HANDLER *hdlr= mysql->net.conn_hdlr;
  my_bool rc= 1;

  aurora= (AURORA *)hdlr->data;

  DISABLE_AURORA(mysql);
  switch (aurora->last_instance_type)
  {
    case AURORA_REPLICA:
      if (!(rc= mariadb_api->mysql_reconnect(aurora->mysql[aurora->last_instance_type])))
        aurora_switch_connection(mysql, aurora, AURORA_REPLICA);
    break;
    case AURORA_PRIMARY:
      if (!(rc= mysql_reconnect(aurora->mysql[aurora->last_instance_type])))
        aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);
      break;
    default:
      /* todo: error message */
      break;
  }
  ENABLE_AURORA(mysql);
  return rc; 
}
/* }}} */

/* {{{  void aurora_close */
void aurora_close(MYSQL *mysql)
{
  MA_CONNECTION_HANDLER *hdlr= mysql->net.conn_hdlr;
  AURORA *aurora= (AURORA *)hdlr->data;

  aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);

  /* if the connection is not active yet, just return */
  if (!aurora->active[1])
    return;

  if (aurora->mysql[AURORA_REPLICA])
  {
    /* we got options from primary, so don't free it twice */
    memset(&aurora->mysql[AURORA_REPLICA]->options, 0, sizeof(mysql->options));
    /* connection handler wull be freed in mariadb_api->mysql_close() */
    aurora->mysql[AURORA_REPLICA]->net.conn_hdlr= 0;

    mysql_close(aurora->mysql[AURORA_REPLICA]);
  }

  if (aurora->mysql[AURORA_PRIMARY])
  {
    /* connection handler wull be freed in mysql_close() */
    aurora->mysql[AURORA_PRIMARY]->net.conn_hdlr= 0;

    aurora->mysql[AURORA_PRIMARY]->net.pvio= aurora->pvio[AURORA_PRIMARY];

    mysql_close(aurora->mysql[AURORA_PRIMARY]);
  }



/*
  if (aurora->mysql[AURORA_PRIMARY])
  {
    aurora->mysql[AURORA_PRIMARY]->net.pvio= aurora->pvio[AURORA_PRIMARY];
    aurora->mysql[AURORA_PRIMARY]->net.conn_hdlr= 0;
    mysql_close(aurora->mysql[AURORA_PRIMARY]);
  }
*/
  /* free masrwe information  */
  aurora_close_memory(aurora);
}
/* }}} */

/* {{{ my_bool is_replica_command */
my_bool is_replica_command(const char *buffer, size_t buffer_len)
{
  const char *buffer_end= buffer + buffer_len;

  for (; buffer < buffer_end; ++buffer)
  {
    char c;
    if (isalpha(c=*buffer))
    {
      if (tolower(c) == 's')
        return 1;
      return 0;
    }
  }
  return 0;
}
/* }}} */

/* {{{ my_bool is_replica_stmt */
my_bool is_replica_stmt(MYSQL *mysql, const char *buffer)
{
  unsigned long stmt_id= uint4korr(buffer);
  LIST *stmt_list= mysql->stmts;

  for (; stmt_list; stmt_list= stmt_list->next)
  {
    MYSQL_STMT *stmt= (MYSQL_STMT *)stmt_list->data;
    if (stmt->stmt_id == stmt_id)
      return 1;
  }
  return 0;
}
/* }}} */

/* {{{ int aurora_command */
int aurora_command(MYSQL *mysql,enum enum_server_command command, const char *arg,
    size_t length, my_bool skipp_check, void *opt_arg)
{
  AURORA *aurora= (AURORA *)mysql->net.conn_hdlr->data;

  /* if we don't have slave or slave became unavailable root traffic to master */
  if (!aurora->mysql[AURORA_REPLICA] || !OPT_HAS_EXT_VAL(mysql, read_only))
  {
    if (command != COM_INIT_DB)
    {
      aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);
      return 0;
    }
  }

  switch(command) {
    case COM_INIT_DB:
      /* we need to change default database on primary and replica */
      if (aurora->mysql[AURORA_REPLICA] && aurora->last_instance_type != AURORA_REPLICA)
      {
        aurora_switch_connection(mysql, aurora, AURORA_REPLICA);
        DISABLE_AURORA(mysql);
        mariadb_api->mysql_select_db(aurora->mysql[AURORA_REPLICA], arg);
        ENABLE_AURORA(mysql);
        aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);
      }
      break;
    case COM_QUERY:
    case COM_STMT_PREPARE:
      if (aurora->mysql[AURORA_REPLICA] && aurora->last_instance_type != AURORA_REPLICA)
        aurora_switch_connection(mysql, aurora, AURORA_REPLICA);
      break;
    case COM_STMT_EXECUTE:
    case COM_STMT_FETCH:
      if (aurora->pvio[AURORA_REPLICA]->mysql->stmts && is_replica_stmt(aurora->pvio[AURORA_REPLICA]->mysql, arg))
      {
        if (aurora->last_instance_type != AURORA_REPLICA)
          aurora_switch_connection(mysql, aurora, AURORA_REPLICA);
      }
      else
      {
        if (aurora->last_instance_type != AURORA_PRIMARY)
          aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);
      }  

    default:
      aurora_switch_connection(mysql, aurora, AURORA_PRIMARY);
      break; 
  }
  return 0;
}
/* }}} */

/* {{{ int aurora_set_options() */
int aurora_set_options(MYSQL *mysql, enum mysql_option option, void *arg)
{
  switch(option) {
    default:
      return -1;
  }
}
/* }}} */
