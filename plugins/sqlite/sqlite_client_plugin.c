/************************************************************************************
  Copyright (C) 2012 Monty Program AB

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
#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>
#include <errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <mysql.h>
#include <mysql_com.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <errmsg.h>
#include <string.h>

#define CLEAR_ERROR(a) my_set_error((a), 0, "", "");

enum enum_s3_status {S3_OK= 0, S3_RESULT_WAIT, S3_RESULT_FETCH, S3_FETCH_DONE};

typedef struct st_mariadb_sqlite
{
  enum enum_s3_status status;
  sqlite3 *db;
  sqlite3_stmt *stmt;
  ulong last_stmt_id;
  MYSQL_ROW row;
} MARIADB_SQLT;

unsigned long s3_connection_id= 0;

void s3_close(MYSQL *mysql);

/**
    opens a sqlite connection, the parameter db (database name)
    must be specified. If db doesn't exist, it will be created.

    @param MYSQL        mysql handle
    @param host         unused
    @param user         unused
    @param passwd       unused
    @param db           database name (must be specified)
    @param port         unused
    @param unix_socket  unused
    @param client_flag  unused (todo, support open flag)

    @retval             Pointer to a MYSQL connection handle
                        or NULL if error 
**/ 
MYSQL *s3_connect(MYSQL *mysql,const char *host, const char *user,
		   const char *passwd, const char *db,
       uint port, const char *unix_socket,unsigned long client_flag)
{
  MARIADB_SQLT *dbhdl;
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  int rc;
  size_t len;

  DBUG_ASSERT(s3_driver != NULL);

  if (!db)
    return 0;

  /* make sure that we don't leak in case s3_close was not called */
  if (s3_driver->name)
    s3_close(mysql);

  if (!(s3_driver->buffer= my_malloc(sizeof(MARIADB_SQLT), MYF(MY_ZEROFILL))))
  {
    my_set_error(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    return 0;
  }
  dbhdl= (MARIADB_SQLT*)s3_driver->buffer;

  if ((rc= sqlite3_open(db, (sqlite3 **)&dbhdl->db)))
  {
    my_set_error(mysql, sqlite3_errcode(dbhdl->db), SQLSTATE_UNKNOWN, sqlite3_errmsg(dbhdl->db));
    sqlite3_close(dbhdl->db);
    return 0;
  }

  /* connection settings */
  len= strlen(SQLITE_VERSION) + strlen(sqlite3_sourceid()) + 10;
  if (mysql->server_version= (char *)my_malloc(len, MYF(0)))
  {
    my_snprintf(mysql->server_version, len, "%s Sqlite %s", SQLITE_VERSION, sqlite3_sourceid());
  }
  mysql->db= my_strdup(db,MYF(MY_WME));

  sqlite3_mutex_enter(sqlite3_db_mutex(dbhdl->db));
  mysql->thread_id= ++s3_connection_id;
  sqlite3_mutex_leave(sqlite3_db_mutex(dbhdl->db));

  return mysql;
}

void s3_skip_result(MYSQL *mysql)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;

  sqlite3_finalize(db->stmt);
  db->stmt= NULL;
}
/**
    read field information and map information to
    MYSQL_FIELD

    @param MYSQL        connection handle

    @retval             Array of MYSQL_FIELD or NULL on 
                        error
**/
MYSQL_FIELD *s3_get_fields(MYSQL *mysql, sqlite3_stmt *stmt)
{
  MYSQL_FIELD *field;
  int i, column_count;
 
  if (!stmt ||
      !(column_count = sqlite3_column_count(stmt)))
    return NULL;

  field= (MYSQL_FIELD*) alloc_root(&mysql->field_alloc,sizeof(MYSQL_FIELD)* column_count);
  memset(field, 0, sizeof(MYSQL_FIELD) * column_count);
  
  for (i=0; i < column_count; i++)
  {
    /* map column types */
    switch(sqlite3_column_type(stmt, i)) {
    case SQLITE_NULL:
      field[i].type= MYSQL_TYPE_NULL;
      field[i].length= 0;
      field[i].charsetnr= 63; /* binary */
      break;
    case SQLITE_BLOB:
      field[i].type= MYSQL_TYPE_BLOB;
      field[i].length= sqlite3_column_bytes(stmt, i);
      field[i].charsetnr= 63; /* binary */
      break;
    case SQLITE_INTEGER:
      field[i].type= MYSQL_TYPE_LONG;
      field[i].length= 11;
      field[i].charsetnr= 63; /* binary */
      break;
    case SQLITE_TEXT:
      field[i].type= MYSQL_TYPE_VAR_STRING;
      field[i].length= sqlite3_column_bytes(stmt, i);
      field[i].charsetnr= 33; /* utf8 */
      break;
    case SQLITE_FLOAT:
      field[i].type= MYSQL_TYPE_DOUBLE;
      field[i].length= 22;
      field[i].charsetnr= 63; /* binary */
      break;
    }
    /* we will update max_length in store/use result */
    field[i].max_length= 0;
    field[i].table= (char *)sqlite3_column_table_name(stmt, i);
    field[i].name= (char *)sqlite3_column_name(stmt, i);
    field[i].org_name= (char *)sqlite3_column_origin_name(stmt, i);
    field[i].db= (char *)sqlite3_column_database_name(stmt, i);
  }
  return field;
}

/**
    return next row from a previous sqlite3_prepare
    call.

    @param MYSQL    connection handle
    @param length   total length of row
**/
MYSQL_ROW s3_get_row(MYSQL *mysql, size_t *length)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;
  int rc= SQLITE_ROW;

  *length= 0;

  if (!mysql->field_count || db->status == S3_FETCH_DONE)
    return NULL;

  if (db->status == S3_RESULT_WAIT) {
    db->row= (MYSQL_ROW)my_malloc(mysql->field_count * sizeof(char *), MYF(0));
    db->status= S3_RESULT_FETCH;
  }
  else
    rc= sqlite3_step(db->stmt);

  if (rc == SQLITE_ROW)
  {
    int i;

    for (i=0; i < mysql->field_count; i++)
    {
      if ((db->row[i]= (char *)sqlite3_column_text(db->stmt, i)))
      {
        size_t slen= strlen(db->row[i]);  
        *length += slen + 1;
        if (mysql->fields)
          if (slen > mysql->fields[i].max_length)
            mysql->fields[i].max_length= slen;
      }
    }
    return db->row;
  }
  /* nothing to fetch or error */
  db->status= S3_FETCH_DONE;
  return NULL;  
}

/**
    frees up memory and close db->stmt.

    @param MYSQL    connection handle

    @retval void
**/
void db_query_end(MYSQL *mysql)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;

  if (!db || !db->db)
    return;

  if (db->stmt)
  {
    sqlite3_finalize(db->stmt);
    db->stmt= NULL;
  }
  if (db->row)
  {
    my_free((gptr)db->row, MYF(0));
    db->row= NULL;
  }
  db->status= S3_OK;
}

/**
   read one row. This function is used for unbuffered
   result sets and will be called from mysql_fetch_row()

   @param mysql   connection handle
   @param fields  number of fields
   @param row     row
   @param lengths total length of row

   @return int    0 on success, != 0 on error
**/
int s3_read_one_row(MYSQL *mysql, uint fields, 
                    MYSQL_ROW row, ulong *lengths)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;
  uint field;
  size_t length;
  MYSQL_ROW s3row;

  if (!mysql->field_count || 
      (db->status != S3_RESULT_WAIT && db->status != S3_RESULT_FETCH) ||
      !db->stmt)
   return -1;

  if ((s3row= s3_get_row(mysql, &length)))
  {
    for (field=0 ; field < fields ; field++)
    {
      if (s3row[field] == NULL)
        *lengths++=0;
      else
      {
        row[field] = (char*) s3row[field];
        *lengths++=strlen(row[field]);
      }
    }
    return 0;
  }
  /* all rows fetched */
  sqlite3_finalize(db->stmt);
  db->stmt= NULL;
  return -1;
}

/**
    read all rows. This function will be called from 
    mysql_store_result()

    @param mysql        connection handle
    @param mysql_fields array of field descriptors
    @param fields       number of fields

    @return MYSQL_DATA  MYSQL_DATA array or NULL on error
**/
MYSQL_DATA *s3_read_all_rows(MYSQL *mysql, MYSQL_FIELD *mysql_fields,
                             uint fields)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;
  MYSQL_DATA *result;
  MYSQL_ROW row;
  MYSQL_ROWS **prev_ptr, *cur;
  uint field;
  size_t length;
  char *to;

  if (!mysql->field_count || db->status != S3_RESULT_WAIT || !db->stmt)
    return NULL;

  if (!(result=(MYSQL_DATA*) my_malloc(sizeof(MYSQL_DATA),
				       MYF(MY_ZEROFILL))))
  {
    my_set_error(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    return NULL;
  }
  init_alloc_root(&result->alloc, 8192, 0);	/* Assume rowlength < 8192 */
  result->alloc.min_malloc=sizeof(MYSQL_ROWS);
  prev_ptr= &result->data;
  result->rows=0;
  result->fields= fields;

  while ((row= s3_get_row(mysql, &length)))
  {
    result->rows++;
    if (!(cur= (MYSQL_ROWS*) alloc_root(&result->alloc,
          sizeof(MYSQL_ROWS))) ||
        !(cur->data= ((MYSQL_ROW)
 	        alloc_root(&result->alloc,
          (fields+1)*sizeof(char *)+length))))
    {
      free_rows(result);
      my_set_error(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
      return 0;
    }
    *prev_ptr=cur;
    prev_ptr= &cur->next;
    to= (char*) (cur->data+fields+1);
    for (field=0 ; field < fields ; field++)
    {
      if (row[field] == NULL)
      {						/* null field */
        cur->data[field] = 0;
      }
      else
      {
        size_t len= strlen(row[field]);
        cur->data[field] = to;
        memcpy(to,(char*) row[field], len); to[len]=0;
        to+=len+1;
      }
    }
    cur->data[field]=to;			/* End of last field */
  }
  *prev_ptr=0;					/* last pointer is null */
  sqlite3_finalize(db->stmt);
  db->stmt= NULL;
  return result;
}

/**
   db_query()

   Executes a SQL query. Will be called from mysql_real_query

   @param mysql    connection handle
   @param query    SQL statement
   @param length   length of statement

   @return int     0 on success, !=0 on error
**/
int s3_query(MYSQL *mysql, const char *query, size_t length)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;
  int rc;
  
  CLEAR_ERROR(mysql);

  rc= sqlite3_prepare_v2(db->db, query, (int)length, &db->stmt, NULL);
  if (rc != SQLITE_OK)
  {
    my_set_error(mysql, sqlite3_errcode(db->db), SQLSTATE_UNKNOWN, sqlite3_errmsg(db->db));
    return 1;
  }
  
  /* since mariadb client library has different calls and logic
     for queries and prepared statements, we need to check for 
     parameter markers */
  if (sqlite3_bind_parameter_count(db->stmt) > 0)
  {
    my_set_error(mysql, CR_UNKNOWN_ERROR, SQLSTATE_UNKNOWN, 
        "SQL statement contains parameter markers");
    db_query_end(mysql);
    return 1;
  } 


  return 0;
}

/**
    s3_close()

    terminates connection and frees previously allocated
    memory. Will be called from mysql_close().

    @param mysql  connection handle

    @return void
**/
void s3_close(MYSQL *mysql)
{
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;

  if (!db)
    return;
  /* cleanup */
  if (db->db)
  {
    db_query_end(mysql);
    sqlite3_close_v2(db->db);
  }
  my_free((gptr)s3_driver->buffer, MYF(0));
  s3_driver->buffer= NULL;
}

/********************************************************************
                      !!  Experimental  !!

                   Prepared statement (PS) support

                      !!  Experimental  !!

Todo: 
- Error handling: clear errors, handle stmt_execute return codes
- bind_result not implemented yet

**********************************************************************/

/**
    s3_stmt_prepare()

    Prepares a statement for execution

    @param MYSQL_STMT  a stmt handle
    @param stmt_str    statement SQL string
    @param length      length of statement string

    @return            0 on success, non-zero on error
 
**/
int s3_stmt_prepare(MYSQL_STMT *stmt, const char *stmt_str, ulong length)
{
  MARIADB_DB_DRIVER *s3_driver= stmt->mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;
  int rc;
  sqlite3_stmt *s3_stmt;

  rc= sqlite3_prepare_v2(db->db, (char *)stmt_str, (int)length, &s3_stmt, NULL);
  if (rc != SQLITE_OK)
  {
    SET_CLIENT_STMT_ERROR(stmt, sqlite3_errcode(db->db), SQLSTATE_UNKNOWN, sqlite3_errmsg(db->db));
    return 1;
  }

  stmt->ext_stmt= s3_stmt;
  stmt->state= MYSQL_STMT_PREPARED;

  return 0;
}

my_bool s3_read_prepare_response(MYSQL_STMT *stmt)
{
  MARIADB_DB_DRIVER *s3_driver= stmt->mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;
  sqlite3_stmt *s3_stmt= stmt->ext_stmt;

  /* set statement id */
  sqlite3_mutex_enter(sqlite3_db_mutex(db->db));
  stmt->stmt_id= ++db->last_stmt_id;
  sqlite3_mutex_leave(sqlite3_db_mutex(db->db));

  stmt->param_count= sqlite3_bind_parameter_count(s3_stmt);
  stmt->field_count= sqlite3_column_count(s3_stmt);

  return 0;
}

/**
    bind parameters to a prepared statement.
    This function has to be called before
    db_stmt_execute since sqlite doesn't support
    binding of addresses, so we need to rebind
    values for every statement execution.

    @paran NYSQL_STMT
    @param MYSQL_BIND

    @return bool
**/
my_bool s3_set_bind_params(MYSQL_STMT *stmt, MYSQL_BIND *bind)
{
  int i;

  for (i=0; i < stmt->param_count; i++)
  {
    switch(bind[i].buffer_type) {
    case MYSQL_TYPE_NULL:
      sqlite3_bind_null(stmt->ext_stmt, i + 1);
      break;
    case MYSQL_TYPE_TINY:
      sqlite3_bind_int(stmt->ext_stmt, i + 1, *(uchar *)stmt->params[i].buffer);
      break;
    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_YEAR:
      sqlite3_bind_int(stmt->ext_stmt, i + 1, *(short *)stmt->params[i].buffer);
      break;
    case MYSQL_TYPE_DOUBLE:
      sqlite3_bind_double(stmt->ext_stmt, i + 1, *(double *)stmt->params[i].buffer);
      break;
    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_INT24:
      sqlite3_bind_int(stmt->ext_stmt, i + 1, *(int32 *)stmt->params[i].buffer);
      break;
    case MYSQL_TYPE_LONGLONG:
      sqlite3_bind_int64(stmt->ext_stmt, i + 1, *(my_ulonglong *)stmt->params[i].buffer);
      break;
    case MYSQL_TYPE_TINY_BLOB:
    case MYSQL_TYPE_MEDIUM_BLOB:
    case MYSQL_TYPE_LONG_BLOB:
    case MYSQL_TYPE_BLOB:
      sqlite3_bind_blob(stmt->ext_stmt, i + 1, stmt->params[i].buffer, 
                         stmt->params[i].buffer_length, NULL);
      break;
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_STRING:
      sqlite3_bind_text(stmt->ext_stmt, i + 1, (char *)stmt->params[i].buffer, 
                         stmt->params[i].buffer_length, NULL);
      break;
    default:
      SET_CLIENT_STMT_ERROR(stmt, CR_UNSUPPORTED_PARAM_TYPE, SQLSTATE_UNKNOWN, 0);
      return 1;
      break;
    }
  }
  return 0;
}

/**
    check if the field type of bind variable is compatible.

    @param type   buffer type
    @retval int   1 if type is compatible, 0 if not
**/
my_bool s3_supported_buffer_type(enum enum_field_types type)
{
  switch(type) {
    case MYSQL_TYPE_NULL:
    case MYSQL_TYPE_TINY:
    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_YEAR:
    case MYSQL_TYPE_DOUBLE:
    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_INT24:
    case MYSQL_TYPE_LONGLONG:
    case MYSQL_TYPE_TINY_BLOB:
    case MYSQL_TYPE_MEDIUM_BLOB:
    case MYSQL_TYPE_LONG_BLOB:
    case MYSQL_TYPE_BLOB:
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_STRING:
      return 1;
      break;
    default:
      return 0;
  }
}
 
int s3_stmt_execute(MYSQL_STMT *stmt)
{
  int rc;
  MARIADB_DB_DRIVER *s3_driver= stmt->mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;

  /* Opposed to MariaDB sqlite doesn't support binding of variables/addresses, so
   * we need to reassign values before executing the statement */
  if (stmt->param_count)
  {
    sqlite3_reset(stmt->ext_stmt);
    if (s3_set_bind_params(stmt, stmt->params))
      return 1;
  }

  rc= sqlite3_step(stmt->ext_stmt);

  switch(rc) {
  case SQLITE_ROW:
    stmt->mysql->field_count= sqlite3_column_count(stmt->ext_stmt);
    stmt->mysql->fields= s3_get_fields(stmt->mysql, stmt->ext_stmt);
    stmt->upsert_status.affected_rows= 0;
    rc= 0;
    break;
  case SQLITE_DONE: /* no rows returned */
    stmt->upsert_status.affected_rows= sqlite3_changes(db->db);
    stmt->upsert_status.last_insert_id= sqlite3_last_insert_rowid(db->db);
    rc= 0;
    break;
  case SQLITE_ERROR:
    SET_CLIENT_STMT_ERROR(stmt, sqlite3_errcode(db->db), SQLSTATE_UNKNOWN, sqlite3_errmsg(db->db));
    rc= 1;
    break;
  default:
    rc= 0;
  }
  return rc;
}

int s3_stmt_fetch(MYSQL_STMT *stmt, unsigned char **row)
{
  int rc= 0;

  if (stmt->state != MYSQL_STMT_WAITING_USE_OR_STORE)
  {
    rc= sqlite3_step(stmt->ext_stmt);

    if (rc == SQLITE_DONE)
    {
      stmt->state= MYSQL_STMT_FETCH_DONE;
      stmt->mysql->status= MYSQL_STATUS_READY;
      /* to fetch data again, stmt must be executed again */
      return MYSQL_NO_DATA;
    }
  }
  return (rc != SQLITE_ROW) ? rc : 0;
}

int s3_stmt_fetch_to_bind(MYSQL_STMT *stmt, unsigned char *row)
{
  int i;
  longlong lval;
  double dval;
  char *buf;
  size_t s;

  for (i=0; i < stmt->field_count; i++)
  {
    switch (stmt->bind[i].buffer_type) {
    case MYSQL_TYPE_NULL:
      *stmt->bind[i].is_null= 1;
    case MYSQL_TYPE_TINY:
      lval= sqlite3_column_int64(stmt->ext_stmt, i);
      if (stmt->bind[i].is_unsigned) 
        *(uchar *)stmt->bind[i].buffer= (uchar)lval;
      else
        *(char *)stmt->bind[i].buffer= (char)lval;
      break; 
    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_YEAR:
      lval= sqlite3_column_int64(stmt->ext_stmt, i);
      if (stmt->bind[i].is_unsigned) 
        *(ushort *)stmt->bind[i].buffer= (ushort)lval;
      else
        *(short *)stmt->bind[i].buffer= (short)lval;
      break; 
    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_INT24:
      lval= sqlite3_column_int64(stmt->ext_stmt, i);
      if (stmt->bind[i].is_unsigned) 
        *(ulong *)stmt->bind[i].buffer= (ulong)lval;
      else
        *(long *)stmt->bind[i].buffer= (long)lval;
      break; 
    case MYSQL_TYPE_LONGLONG:
      lval= sqlite3_column_int64(stmt->ext_stmt, i);
      break; 
    case MYSQL_TYPE_DOUBLE:
      dval= sqlite3_column_double(stmt->ext_stmt, i);
      *(double *)stmt->bind[i].buffer= dval;
      break;
    case MYSQL_TYPE_TINY_BLOB:
    case MYSQL_TYPE_MEDIUM_BLOB:
    case MYSQL_TYPE_LONG_BLOB:
    case MYSQL_TYPE_BLOB:
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_STRING:
      buf= (char *)sqlite3_column_text(stmt->ext_stmt, i);
      if ((s= MIN(stmt->bind[i].buffer_length, sqlite3_column_bytes(stmt->ext_stmt, i))))
        memcpy(stmt->bind[i].buffer, buf, s);
      ((char *)stmt->bind[i].buffer)[s]= 0;
      break;
    }
  }
  return 0;
}

my_bool s3_stmt_close(MYSQL_STMT *stmt)
{
  int rc= sqlite3_finalize(stmt->ext_stmt);
  return (rc == SQLITE_OK) ? 0 : 1;
}

int
s3_db_command(MYSQL *mysql,enum enum_server_command command, const char *arg,
	       size_t length, my_bool skipp_check, void *opt_arg)
{
  int rc= 1;

  switch (command) {
  case MYSQL_COM_QUERY:
    rc= s3_query(mysql, arg, length);
    break;
  case MYSQL_COM_STMT_PREPARE:
    {
      MYSQL_STMT *stmt= (MYSQL_STMT *)opt_arg;
      rc= s3_stmt_prepare(stmt, arg, length);
    }
    break;
  case MYSQL_COM_STMT_EXECUTE:
    {
      MYSQL_STMT *stmt= (MYSQL_STMT *)opt_arg;
      rc= s3_stmt_execute(stmt);
    }
    break;
  case MYSQL_COM_STMT_CLOSE:
    {
      MYSQL_STMT *stmt= (MYSQL_STMT *)opt_arg;
      s3_stmt_close(stmt);
    }
    break;
  case MYSQL_COM_STMT_RESET:
    {
      MYSQL_STMT *stmt= (MYSQL_STMT *)opt_arg;
      sqlite3_reset(stmt->ext_stmt);
    }
    break;
  default:
    if (!opt_arg)
      my_set_error(mysql, CR_PLUGIN_FUNCTION_NOT_SUPPORTED, SQLSTATE_UNKNOWN, 0);
    else
      SET_CLIENT_STMT_ERROR((MYSQL_STMT *)opt_arg, CR_PLUGIN_FUNCTION_NOT_SUPPORTED, SQLSTATE_UNKNOWN, 0);
    break;
  }
  return rc;
}

int s3_read_query_result(MYSQL *mysql)
{
  int rc;
  MARIADB_DB_DRIVER *s3_driver= mysql->options.extension->db_driver;
  MARIADB_SQLT *db= (MARIADB_SQLT *)s3_driver->buffer;

  mysql->field_count= sqlite3_column_count(db->stmt);
  rc= sqlite3_step(db->stmt);

  switch(rc) {
  case SQLITE_ERROR:
  case SQLITE_MISUSE:
  case SQLITE_BUSY:
    my_set_error(mysql, sqlite3_errcode(db->db), SQLSTATE_UNKNOWN, sqlite3_errmsg(db->db));
    sqlite3_finalize(db->stmt);
    db->stmt= NULL;
    rc= 1;
    break;
      
  case SQLITE_ROW:
    db->status= S3_RESULT_WAIT;
    mysql->status = MYSQL_STATUS_GET_RESULT;
    mysql->fields= s3_get_fields(mysql, db->stmt);
    mysql->affected_rows= 0;
    rc= 0;
    break;
  case SQLITE_DONE: /* no rows returned */
    mysql->affected_rows= sqlite3_changes(db->db);
    mysql->insert_id= sqlite3_last_insert_rowid(db->db);
    mysql->status=MYSQL_STATUS_READY;
    if (!mysql->field_count)
    {
      sqlite3_finalize(db->stmt);
      db->stmt= NULL;
    }
    rc= 0;
    break;
  }
  return rc;
}

my_bool s3_get_param_metadata(MYSQL_STMT *stmt)
{
  return 0;
}

my_bool s3_get_result_metadata(MYSQL_STMT *stmt)
{
  if (!(stmt->fields= s3_get_fields(stmt->mysql, stmt->ext_stmt)))
    return 1;
  return 0;
}

int s3_read_all_stmt_rows(MYSQL_STMT *stmt)
{
  SET_CLIENT_STMT_ERROR(stmt, CR_PLUGIN_FUNCTION_NOT_SUPPORTED, SQLSTATE_UNKNOWN, 0);
  return 1;
}

void s3_stmt_flush_unbuffered(MYSQL_STMT *stmt)
{
  sqlite3_reset(stmt->ext_stmt);
}

int s3_read_stmt_result(MYSQL *mysql)
{
  /* nothing to do */
  return 0;
}


typedef struct st_mariadb_client_plugin_DB dbapi_plugin_t;

struct st_mysql_methods s3_methods = {
  s3_connect,
  s3_close,
  s3_db_command,
  s3_skip_result,
  s3_read_query_result,
  s3_read_all_rows,
  s3_read_one_row,
  s3_supported_buffer_type,
  s3_read_prepare_response, 
  s3_read_stmt_result,
  s3_get_result_metadata,
  s3_get_param_metadata,
  s3_read_all_stmt_rows,
  s3_stmt_fetch,
  s3_stmt_fetch_to_bind
};

dbapi_plugin_t sqlite3_plugin=
{
  MYSQL_CLIENT_DB_PLUGIN,
  MYSQL_CLIENT_DB_PLUGIN_INTERFACE_VERSION,
  "sqlite",
  "Georg Richter",
  "Sqlite3 plugin for MariaDB client library",
  {1, 0, 0},
  NULL,
  NULL,
  &s3_methods
};
