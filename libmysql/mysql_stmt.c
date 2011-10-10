/****************************************************************************
   Copyright (C) 2011 Monty Program AB
   
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
*****************************************************************************/

/* The implementation for preoared statements was ported from PHP's mysqlnd
   extension, written by Andrey Hristov, Georg Richter and Ulf Wendel */

#ifdef __WIN__
#include <winsock.h>
#include <odbcinst.h>
#endif
#include "my_global.h"
#include <my_sys.h>
#include <mysys_err.h>
#include <m_string.h>
#include <m_ctype.h>
#include "mysql.h"
#include "mysql_priv.h"
#include "mysql_version.h"
#include "mysqld_error.h"
#include "errmsg.h"
#include <violite.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>

static my_bool is_not_null= 0;
static my_bool is_null= 1;

const char * const mysql_stmt_not_prepared = "Statement not prepared";


my_bool is_supported_buffer_type(enum enum_field_types type)
{
  switch (type) {
    case MYSQL_TYPE_TINY:
    case MYSQL_TYPE_NULL:
    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_YEAR:
    case MYSQL_TYPE_INT24:
    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_LONGLONG:
    case MYSQL_TYPE_FLOAT:
    case MYSQL_TYPE_DOUBLE:
    case MYSQL_TYPE_TIME:
    case MYSQL_TYPE_DATE:
    case MYSQL_TYPE_DATETIME:
    case MYSQL_TYPE_TIMESTAMP:
    case MYSQL_TYPE_TINY_BLOB:
    case MYSQL_TYPE_MEDIUM_BLOB:
    case MYSQL_TYPE_LONG_BLOB:
    case MYSQL_TYPE_BLOB:
    case MYSQL_TYPE_BIT:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_STRING:
    case MYSQL_TYPE_DECIMAL:
    case MYSQL_TYPE_NEWDECIMAL:
    case MYSQL_TYPE_NEWDATE:
      return 1;
    break;
  default:
    return 0;
    break;

  }
}

static int stmt_unbuffered_eof(MYSQL_STMT *stmt, uchar **row)
{
  return MYSQL_NO_DATA;
}

static int stmt_unbuffered_fetch(MYSQL_STMT *stmt, uchar **row)
{
  ulong pkt_len;

  DBUG_ENTER("stmt_unbuffered_fetch");

  pkt_len= net_safe_read(stmt->conn);
  DBUG_PRINT("info",("packet_length= %ld",pkt_len));

  if (pkt_len == packet_error)
  {
    stmt->fetch_row_func= stmt_unbuffered_eof;
    DBUG_RETURN(MYSQL_NO_DATA);
  }

  if (stmt->conn->net.read_pos[0] == 254)
  {
    *row = NULL;
    stmt->fetch_row_func= stmt_unbuffered_eof;
    DBUG_RETURN(MYSQL_NO_DATA);
  }
  else
    *row = stmt->conn->net.read_pos;
  return 0;
}



static int stmt_buffered_fetch(MYSQL_STMT *stmt, uchar **row)
{
  if (!stmt->result_cursor)
  {
    *row= NULL;
    stmt->state= MYSQL_STMT_FETCH_DONE;
    return MYSQL_NO_DATA;
  }
  stmt->state= MYSQL_STMT_USER_FETCHING;
  *row= (uchar *)stmt->result_cursor->data;
  
  stmt->result_cursor= stmt->result_cursor->next;
  return 0;
}

static int stmt_read_all_rows(MYSQL_STMT *stmt)
{
  MYSQL_DATA *result= &stmt->result;
  MYSQL_ROWS *current, **pprevious;
  ulong packet_len;
  unsigned char *p;

  DBUG_ENTER("stmt_read_all_rows");

  pprevious= &result->data;

  while ((packet_len = net_safe_read(stmt->conn)) != packet_error)
  {
    p= stmt->conn->net.read_pos;
    if (packet_len > 7 || p[0] != 254)
    {
      /* allocate space for rows */
      if (!(current= (MYSQL_ROWS *)alloc_root(&result->alloc, sizeof(MYSQL_ROWS) + packet_len)))
      {
        SET_CLIENT_STMT_ERROR(stmt->error_info, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
        DBUG_RETURN(1);
      }
      current->data= (MYSQL_ROW)(current + 1);
      *pprevious= current;
      pprevious= &current->next;

      /* copy binary row, we will encode it during mysql_stmt_fetch */
      memcpy((char *)current->data, (char *)p, packet_len);

      if (stmt->update_max_length)
      {
        uchar *null_ptr, bit_offset= 4;
        uchar *cp= p;
        int i;

        cp++; /* skip first byte */
        null_ptr= cp;
        cp+= (stmt->field_count + 9) / 8;

        for (i=0; i < stmt->field_count; i++)
        {
          if (!(*null_ptr & bit_offset))
          {
            switch(mysql_ps_fetch_functions[stmt->fields[i].type].max_len) {
            case -1:
            {
              size_t len= net_field_length(&cp);
              if (len > stmt->fields[i].max_length)
                stmt->fields[i].max_length= len;
            }
            break;
            default:
               if (!stmt->fields[i].max_length)
                 stmt->fields[i].max_length= mysql_ps_fetch_functions[stmt->fields[i].type].max_len;
              break;
            }
          }
          if (!((bit_offset <<=1) & 255))
          {
            bit_offset= 1; /* To next byte */
            null_ptr++;
          }
        }
      }


      current->length= packet_len;
      result->rows++; 
    } else  /* end of stream */
    {
      *pprevious= 0;
      /* sace status info */
      p++;
      stmt->upsert_status.warning_count= stmt->conn->warning_count= uint2korr(p);
      p+=2;
      stmt->conn->server_status= uint2korr(p);
      stmt->result_cursor= result->data; 
      DBUG_RETURN(0);
    }
  }
  stmt->result_cursor= 0;
  SET_CLIENT_STMT_ERROR(stmt->error_info, stmt->conn->net.last_errno, stmt->conn->net.sqlstate,
                        stmt->conn->net.last_error); 
  DBUG_RETURN(1);
}

static int stmt_cursor_fetch(MYSQL_STMT *stmt, uchar **row)
{
  uchar buf[STMT_ID_LENGTH + 4];
  MYSQL_DATA *result= &stmt->result;

  DBUG_ENTER("stmt_cursor_fetch");

  if (stmt->state < MYSQL_STMT_USE_OR_STORE_CALLED)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  /* do we have some prefetched rows available ? */
  if (stmt->result_cursor)
    DBUG_RETURN(stmt_buffered_fetch(stmt, row));

  int4store(buf, stmt->stmt_id);
  int4store(buf + STMT_ID_LENGTH, stmt->prefetch_rows);

  if (simple_command(stmt->conn, MYSQL_COM_STMT_FETCH, (char *)buf, sizeof(buf), 1))
    DBUG_RETURN(1);

  /* free previously allocated buffer */
  free_root(&result->alloc, MYF(MY_KEEP_PREALLOC));
  result->data= 0;
  result->rows= 0; 

  if (stmt_read_all_rows(stmt))
    DBUG_RETURN(1);

  DBUG_RETURN(stmt_buffered_fetch(stmt, row));
}

static void stmt_flush_unbuffered(MYSQL_STMT *stmt)
{
  ulong packet_len;
  while ((packet_len = net_safe_read(stmt->conn)) != packet_error)
    if (packet_len < 8 || stmt->conn->net.read_pos[0] == 254)
      return;
}

static int stmt_fetch_to_bind(MYSQL_STMT *stmt, unsigned char *row)
{
  int i;
  size_t truncations= 0;
  unsigned char *null_ptr, bit_offset= 4;

  DBUG_ENTER("stmt_fetch-to_bind");

  if (!stmt->bind_result_done)  /* nothing to do */
    return 0; 

  row++; /* skip status byte */
  null_ptr= row;
  row+= (stmt->field_count + 9) / 8;

  for (i=0; i < stmt->field_count; i++)
  {
    /* save row position for fetching values in pieces */
    if (*null_ptr & bit_offset)
    {
      *stmt->result_bind[i].is_null= 1;
      stmt->result_bind[i].row_ptr= NULL;
    } else
    { 
      if (!stmt->result_bind[i].length)
        stmt->result_bind[i].length= &stmt->result_bind[i].length_value;
      if (!stmt->result_bind[i].is_null)
        stmt->result_bind[i].is_null= &stmt->result_bind[i].is_null_value;
      *stmt->result_bind[i].is_null= 0;
      stmt->result_bind[i].row_ptr= row;
      mysql_ps_fetch_functions[stmt->fields[i].type].func(&stmt->result_bind[i], &stmt->fields[i], &row);
      truncations+= *stmt->result_bind[i].error;
    }

    if (!((bit_offset <<=1) & 255)) {
      bit_offset= 1; /* To next byte */
      null_ptr++;
    }
  }
  return (truncations) ? MYSQL_DATA_TRUNCATED : 0;
}

MYSQL_RES *_mysql_stmt_use_result(MYSQL_STMT *stmt)
{
  MYSQL *mysql= stmt->conn;

  DBUG_ENTER("mysql_stmt_use_result");

  if (!stmt->field_count ||
     (!stmt->cursor_exists && mysql->status != MYSQL_STATUS_GET_RESULT) ||
     (stmt->cursor_exists && mysql->status != MYSQL_STATUS_READY) ||
     (stmt->state != MYSQL_STMT_WAITING_USE_OR_STORE))
  {
    SET_CLIENT_ERROR(mysql, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(NULL);
  }

  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);

  stmt->state = MYSQL_STMT_USE_OR_STORE_CALLED;
  if (!stmt->cursor_exists)
    stmt->fetch_row_func= stmt_unbuffered_fetch; //mysql_stmt_fetch_unbuffered_row;
  else
    stmt->fetch_row_func= stmt_cursor_fetch;

  DBUG_RETURN(NULL);
}

unsigned char *mysql_net_store_length(unsigned char *packet, my_ulonglong length)
{
  if (length < (my_ulonglong) L64(251)) {
    *packet = (unsigned char) length;
    return packet + 1;
  }

  if (length < (my_ulonglong) L64(65536)) {
    *packet++ = 252;
    int2store(packet,(uint) length);
    return packet + 2;
  }

  if (length < (my_ulonglong) L64(16777216)) {
    *packet++ = 253;
    int3store(packet,(ulong) length);
    return packet + 3;
  }
  *packet++ = 254;
  int8store(packet, length);
  return packet + 8;
}

int store_param(MYSQL_STMT *stmt, int column, unsigned char **p)
{
      switch (stmt->param_bind[column].buffer_type) {
        case MYSQL_TYPE_TINY:
          int1store(*p, *(uchar *)stmt->param_bind[column].buffer);
          (*p) += 1;
          break;
        case MYSQL_TYPE_SHORT:
        case MYSQL_TYPE_YEAR:
          int2store(*p, *(short *)stmt->param_bind[column].buffer);
          (*p) += 2;
          break;
        case MYSQL_TYPE_FLOAT:
          float4store(*p, *(float *)stmt->param_bind[column].buffer);
          (*p) += 4;
          break;
        case MYSQL_TYPE_DOUBLE:
          float8store(*p, *(double *)stmt->param_bind[column].buffer);
          (*p) += 8;
          break;
        case MYSQL_TYPE_LONGLONG:
          int8store(*p, *(my_ulonglong *)stmt->param_bind[column].buffer);
          (*p) += 8;
          break;
        case MYSQL_TYPE_LONG:
        case MYSQL_TYPE_INT24:
          int4store(*p, *(int32 *)stmt->param_bind[column].buffer);
          (*p) += 4;
          break;
        case MYSQL_TYPE_TIME:
        {
           /* binary encoding:
              Offset     Length  Field
              0          1       Length
              1          1       negative
              2-5        4       day
              6          1       hour
              7          1       ninute
              8          1       second;
              9-13       4       second_part
            */
           MYSQL_TIME *t= (MYSQL_TIME *)stmt->param_bind[column].buffer;
           char t_buffer[14];
           uint len= *stmt->param_bind[column].length;

           t_buffer[0]= len;
           t_buffer[1]= t->neg ? 1 : 0;
           int4store(t_buffer + 2, t->day);
           t_buffer[6]= (uchar) t->hour; 
           t_buffer[7]= (uchar) t->minute; 
           t_buffer[8]= (uchar) t->second; 
           int4store(t_buffer + 9, t->second_part);
           memcpy(*p, t_buffer, len);
           len++;
           (*p)+= len;
         }
         break;
         case MYSQL_TYPE_DATE:
         case MYSQL_TYPE_TIMESTAMP:
         case MYSQL_TYPE_DATETIME:
          {
            /* binary format for date, timestamp and datetime
              Offset     Length  Field
              0          1       Length
              1-2        2       Year
              3          1       Month
              4          1       Day
              5          1       Hour
              6          1       minute
              7          1       second
              8-11       4       secondpart
            */ 
            MYSQL_TIME *t= (MYSQL_TIME *)stmt->param_bind[column].buffer;
            char t_buffer[12];
            uint len= *stmt->param_bind[column].length;

            t_buffer[0]= len;
            int2store(t_buffer + 1, t->year);
            t_buffer[3]= (char) t->month;
            t_buffer[4]= (char) t->day;
            t_buffer[5]= (char) t->hour;
            t_buffer[6]= (char) t->minute;
            t_buffer[7]= (char) t->second;
            int4store(t_buffer + 8, t->second_part);
            memcpy(*p, t_buffer, len);
            len++;
            (*p)+= len;
          }
        break;
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_STRING:
        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_NEWDECIMAL:
          {
            ulong len= (ulong)*stmt->param_bind[column].length;
            /* to is after p. The latter hasn't been moved */
            uchar *to = mysql_net_store_length(*p, len);
            if (len)
              memcpy(to, stmt->param_bind[column].buffer, len);
            (*p) = to + len;
          }

          break;
        default:
                                        /* unsupported parameter type */
          SET_CLIENT_STMT_ERROR(stmt->error_info, CR_UNSUPPORTED_PARAM_TYPE, SQLSTATE_UNKNOWN, "");
          return 1;
      }
   return 0;
}

/* {{{ mysqlnd_stmt_execute_generate_request */
unsigned char* mysql_stmt_execute_generate_request(MYSQL_STMT *stmt, size_t *request_len)
{
  /* execute packet has the following format:
     Offset   Length      Description
     -----------------------------------------
     0             4      Statement id
     4             1      Flags (cursor type)
     5             4      Iteration count
     -----------------------------------------
     if (stmt->param_count):
     6  (paramcount+7)/8  null bitmap
    ------------------------------------------
     if (stmt->send_types_to_server):
         param_count*2    parameter types
    ------------------------------------------
                   n      data from bind_buffer
  */

  size_t length= 9000;
  size_t free_bytes= 0;
  size_t data_size= 0;
  int i;
  
  uchar *start= NULL, *p;

  if (!(start= p= (uchar *)my_malloc(length, MYF(MY_WME | MY_ZEROFILL))))
    goto mem_error;

  int4store(p, stmt->stmt_id);
  p += STMT_ID_LENGTH;

  /* flags is 4 bytes, we store just 1 */
  int1store(p, (unsigned char) stmt->flags);
  p++;

  int1store(p, 1); /* and send 1 for iteration count */
  p+= 4;


  if (stmt->param_count)
  {
    size_t null_byte_offset,
           null_count= (stmt->param_count + 7) / 8;

    null_byte_offset = p - start;
    memset(p, 0, null_count);
    p += null_count;


    int1store(p, stmt->send_types_to_server); 
    p++;

    free_bytes= length - (p - start);

    /* Store type information:
       2 bytes per type
    */
    if (stmt->send_types_to_server)
    {
      if (free_bytes < stmt->param_count * 2 + 20)
      {
        uchar *buf;
        ulonglong offset= p - start;
        length= offset + stmt->param_count * 2 + 20;
        if (!(buf= (uchar *)my_malloc(length, MYF(MY_WME | MY_ZEROFILL))))
          goto mem_error;
        memcpy(buf, start, offset);
        my_free((gptr)start, MYF(0));
        start= buf;
        p= start + offset;
      }
      for (i = 0; i < stmt->param_count; i++)
      {
        /* this differs from mysqlnd, c api supports unsinged !! */
        uint buffer_type= stmt->param_bind[i].buffer_type | (stmt->param_bind[i].is_unsigned ? 32768 : 0);
        int2store(p, buffer_type); 
        p+= 2;
      }
    }
    /* calculate data size */
    for (i = 0; i < stmt->param_count; i++) {
      if (stmt->param_bind[i].buffer && !stmt->param_bind[i].is_null)
        stmt->param_bind[i].is_null = &is_not_null;
      if (!stmt->param_bind[i].length)
        stmt->param_bind[i].length= &stmt->param_bind[i].length_value;
      if (!*stmt->param_bind[i].is_null)
      {
        switch (stmt->param_bind[i].buffer_type) {
        case MYSQL_TYPE_NULL:
          stmt->param_bind[i].is_null = &is_null;
          break;
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_STRING:
        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_NEWDECIMAL:
        case MYSQL_TYPE_GEOMETRY:
        case MYSQL_TYPE_NEWDATE:
        case MYSQL_TYPE_ENUM:
        case MYSQL_TYPE_BIT:
        case MYSQL_TYPE_SET:
          data_size+= 5; /* max 8 bytes for size */
          data_size+= *stmt->param_bind[i].length;     
          break;
        default:
          data_size+= mysql_ps_fetch_functions[stmt->param_bind[i].buffer_type].pack_len;
          break;
        }
      }
    }

    /* store data */
    free_bytes= length - (p - start);
    if (free_bytes < data_size + 20)
    {
      uchar *buf;
      ulonglong offset= p - start;
      length= offset + data_size + 20;
      if (!(buf= (uchar *)my_malloc(length, MYF(MY_WME | MY_ZEROFILL))))
        goto mem_error;
      memcpy(buf, start, offset);
      my_free((gptr)start, MYF(0));
      start= buf;
      p= start + offset;
    }
    for (i = 0; i < stmt->param_count; i++) 
    {
      if (stmt->param_bind[i].long_data_used) {
        stmt->param_bind[i].long_data_used= 0;
      }
      else {
        if (!stmt->param_bind[i].buffer || *stmt->param_bind[i].is_null || stmt->param_bind[i].buffer_type == MYSQL_TYPE_NULL) {
          (start + null_byte_offset)[i/8] |= (unsigned char) (1 << (i & 7));
        } else {
          store_param(stmt, i, &p);
        }
      }
    }
  }
  stmt->send_types_to_server= 0;
  *request_len = (p - start);
  return start;


mem_error:
  SET_CLIENT_STMT_ERROR(stmt->error_info, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
  my_free((gptr)start, MYF(ALLOW_ZERO_PTR));
  *request_len= 0;
  return NULL;
}
/* }}} */

/*!
 *******************************************************************************

  \fn        my_ulonglong mysql_stmt_affected_rows
  \brief     returns the number of affected rows from last mysql_stmt_execute 
             call

  \param[in]  stmt The statement handle
 *******************************************************************************
*/
my_ulonglong mysql_stmt_affected_rows(MYSQL_STMT *stmt)
{
  return stmt->upsert_status.affected_rows;
}

my_bool mysql_stmt_attr_get(MYSQL_STMT *stmt, enum enum_stmt_attr_type attr_type, void *value)
{
  DBUG_ENTER("mysql_stmt_attr_get");

  switch (attr_type) {
    case STMT_ATTR_UPDATE_MAX_LENGTH:
      *(my_bool *)value= stmt->update_max_length;
      break;
    case STMT_ATTR_CURSOR_TYPE:
      *(unsigned long *)value= stmt->flags;
      break;
    case STMT_ATTR_PREFETCH_ROWS:
      *(unsigned long *)value= stmt->prefetch_rows;
      break;
    default:
      DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
}

my_bool mysql_stmt_attr_set(MYSQL_STMT *stmt, enum enum_stmt_attr_type attr_type, const void *value)
{
  DBUG_ENTER("mysql_stmt_attr_get");

  switch (attr_type) {
    case STMT_ATTR_UPDATE_MAX_LENGTH:
      stmt->update_max_length= *(my_bool *)value;
      break;
    case STMT_ATTR_CURSOR_TYPE: {
      if (*(ulong *)value > (unsigned long) CURSOR_TYPE_READ_ONLY)
      {
        SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NOT_IMPLEMENTED, SQLSTATE_UNKNOWN, "Not implemented");
        DBUG_RETURN(1);
      }
      stmt->flags = *(ulong *)value;
      break;
    }
    case STMT_ATTR_PREFETCH_ROWS: {
      if (*(ulong *)value == 0)
        *(long *)value= MYSQL_DEFAULT_PREFETCH_ROWS;
      else
        stmt->prefetch_rows= *(long *)value;
      break;
    }
    default:
      SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NOT_IMPLEMENTED, SQLSTATE_UNKNOWN, "Not implemented");
      DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
}

my_bool mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bind)
{
  DBUG_ENTER("mysql_stmt_bind_param");

  if (stmt->state < MYSQL_STMT_PREPARED) {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NO_PREPARE_STMT, SQLSTATE_UNKNOWN, mysql_stmt_not_prepared);
    DBUG_RETURN(1);
  }

  if (stmt->param_count && bind)
  {
    int i;

    memcpy(stmt->param_bind, bind, sizeof(MYSQL_BIND) * stmt->param_count);
    stmt->send_types_to_server= 1;

    for (i=0; i < stmt->param_count; i++)
    {
      if (!stmt->param_bind[i].is_null)
        stmt->param_bind[i].is_null= &is_not_null;

      if (!stmt->param_bind[i].length)
        stmt->param_bind[i].length= &stmt->param_bind[i].buffer_length;

      switch(stmt->param_bind[i].buffer_type) {
        case MYSQL_TYPE_NULL:
          stmt->param_bind[i].is_null= &is_null;
          break;
       case MYSQL_TYPE_TINY:
          stmt->param_bind[i].buffer_length= 1;
          break; 
       case MYSQL_TYPE_SHORT:
       case MYSQL_TYPE_YEAR:
          stmt->param_bind[i].buffer_length= 2;
          break; 
       case MYSQL_TYPE_LONG:
       case MYSQL_TYPE_FLOAT:
          stmt->param_bind[i].buffer_length= 4;
          break; 
       case MYSQL_TYPE_LONGLONG:
       case MYSQL_TYPE_DOUBLE:
          stmt->param_bind[i].buffer_length= 8;
          break;
       case MYSQL_TYPE_DATETIME:
       case MYSQL_TYPE_TIMESTAMP:
          stmt->param_bind[i].buffer_length= 12;
          break;
       case MYSQL_TYPE_TIME:
          stmt->param_bind[i].buffer_length= 13;
          break;
       case MYSQL_TYPE_DATE:
          stmt->param_bind[i].buffer_length= 5;
          break;
       case MYSQL_TYPE_STRING:
       case MYSQL_TYPE_VAR_STRING:
       case MYSQL_TYPE_BLOB:
       case MYSQL_TYPE_TINY_BLOB:
       case MYSQL_TYPE_MEDIUM_BLOB:
       case MYSQL_TYPE_LONG_BLOB:
       case MYSQL_TYPE_DECIMAL:
       case MYSQL_TYPE_NEWDECIMAL:
          break;
       default:
          SET_CLIENT_STMT_ERROR(stmt->error_info, CR_UNSUPPORTED_PARAM_TYPE, SQLSTATE_UNKNOWN, 0);
          DBUG_RETURN(1);
          break;
      }
    }
  }
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);
  DBUG_RETURN(0);
}

my_bool mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bind)
{
  int i;
  DBUG_ENTER("mysql_stmt_bind_result");

  if (stmt->state < MYSQL_STMT_PREPARED)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NO_PREPARE_STMT, SQLSTATE_UNKNOWN, mysql_stmt_not_prepared);
    DBUG_RETURN(1);
  }

  if (!stmt->field_count)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NO_STMT_METADATA, SQLSTATE_UNKNOWN, "todo: metadata error");
    DBUG_RETURN(1); 
  }

  if (!bind)
    DBUG_RETURN(1);

  memcpy(stmt->result_bind, bind, sizeof(MYSQL_BIND) * stmt->field_count);

  for (i=0; i < stmt->field_count; i++)
  {
    if (!is_supported_buffer_type(bind[i].buffer_type))
    {
      SET_CLIENT_STMT_ERROR(stmt->error_info, CR_UNSUPPORTED_PARAM_TYPE, SQLSTATE_UNKNOWN, "");
      DBUG_RETURN(1);
    }

    if (!stmt->result_bind[i].is_null)
      stmt->result_bind[i].is_null= &stmt->result_bind[i].is_null_value;
    if (!stmt->result_bind[i].length)
      stmt->result_bind[i].length= &stmt->result_bind[i].length_value;
    if (!stmt->result_bind[i].error)
      stmt->result_bind[i].error= &stmt->result_bind[i].error_value;

    /* set length values for numeric types */
    switch(bind[i].buffer_type) {
    case MYSQL_TYPE_NULL:
      *stmt->result_bind[i].length= stmt->result_bind[i].length_value= 0;
      break;
    case MYSQL_TYPE_TINY:
      *stmt->result_bind[i].length= stmt->result_bind[i].length_value= 1;
      break;
    case MYSQL_TYPE_SHORT:
    case MYSQL_TYPE_YEAR:
      *stmt->result_bind[i].length= stmt->result_bind[i].length_value= 2;
      break;
    case MYSQL_TYPE_INT24:
    case MYSQL_TYPE_LONG:
    case MYSQL_TYPE_FLOAT:
      *stmt->result_bind[i].length= stmt->result_bind[i].length_value= 4;
      break;
    case MYSQL_TYPE_LONGLONG:
    case MYSQL_TYPE_DOUBLE:
      *stmt->result_bind[i].length= stmt->result_bind[i].length_value= 8;
      break;
    case MYSQL_TYPE_TIME:
    case MYSQL_TYPE_DATE:
    case MYSQL_TYPE_DATETIME:
    case MYSQL_TYPE_TIMESTAMP:
      *stmt->result_bind[i].length= stmt->result_bind[i].length_value= sizeof(MYSQL_TIME);
      break;
    default:
      break;
    }
  }
  stmt->bind_result_done= 1;
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);

  DBUG_RETURN(0);
}

my_bool net_stmt_close(MYSQL_STMT *stmt, my_bool remove)
{
  char stmt_id[STMT_ID_LENGTH];
  /* clear memory */
  free_root(&stmt->result.alloc, MYF(00)); /* allocated in mysql_stmt_store_result */
  free_root(&stmt->mem_root,MYF(0));

  if (stmt->conn)
  {
    CLEAR_CLIENT_ERROR(stmt->conn);

    /* remove from stmt list */
    if (remove)
      stmt->conn->stmts= list_delete(stmt->conn->stmts, &stmt->list);

    /* check if all data are fetched */
    if (stmt->conn->status != MYSQL_STATUS_READY)
    {
       stmt_flush_unbuffered(stmt);
       stmt->conn->status= MYSQL_STATUS_READY;
    }
    if (stmt->state > MYSQL_STMT_INITTED)
    {
      int4store(stmt_id, stmt->stmt_id);
      if (simple_command(stmt->conn,MYSQL_COM_STMT_CLOSE, stmt_id, sizeof(stmt_id), 1))
      {
        SET_CLIENT_STMT_ERROR(stmt->error_info, stmt->conn->net.last_errno, stmt->conn->net.sqlstate,
                              stmt->conn->net.last_error); 
        return 1;
      }
    }
  }
  return 0;
}

my_bool mysql_stmt_close(MYSQL_STMT *stmt)
{
  DBUG_ENTER("mysql_stmt_close");

  net_stmt_close(stmt, 1);
  
  my_free((char *)stmt, MYF(MY_WME));
  DBUG_RETURN(0);
}

void mysql_stmt_data_seek(MYSQL_STMT *stmt, my_ulonglong offset)
{
  my_ulonglong i= offset;
  DBUG_ENTER("mysql_stmt_data_seel");

  if (offset >= stmt->result.rows)
    DBUG_VOID_RETURN;

  stmt->result_cursor= stmt->result.data;

  while(i-- && stmt->result_cursor)
    stmt->result_cursor= stmt->result_cursor->next;

  DBUG_VOID_RETURN;
}

unsigned int mysql_stmt_errno(MYSQL_STMT *stmt)
{
  return stmt->error_info.error_no; 
}

const char *mysql_stmt_error(MYSQL_STMT *stmt)
{
  return (const char *)stmt->error_info.error;
}

int mysql_stmt_fetch(MYSQL_STMT *stmt)
{
  unsigned char *row;
  int rc;

  DBUG_ENTER("mysql_stmt_fetch");

  if (stmt->state == MYSQL_STMT_EXECUTED)
    return 1;

  if (stmt->state < MYSQL_STMT_WAITING_USE_OR_STORE || !stmt->field_count)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  } else if (stmt->state== MYSQL_STMT_WAITING_USE_OR_STORE)
  {
    stmt->default_rset_handler(stmt);
  }

  if (stmt->state == MYSQL_STMT_FETCH_DONE)
  {
    DBUG_RETURN(MYSQL_NO_DATA);
  }

  if ((rc= stmt->fetch_row_func(stmt, &row)))
  {
    stmt->state= MYSQL_STMT_FETCH_DONE;
    stmt->conn->status= MYSQL_STATUS_READY;
    /* to fetch data again, stmt must be executed again */
    DBUG_RETURN(MYSQL_NO_DATA);
  }

  if ((rc= stmt_fetch_to_bind(stmt, row)))
    DBUG_RETURN(rc);
    
  stmt->state= MYSQL_STMT_USER_FETCHING;
  CLEAR_CLIENT_ERROR(stmt->conn);
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);
  DBUG_RETURN(0);
}

int mysql_stmt_fetch_column(MYSQL_STMT *stmt, MYSQL_BIND *bind, unsigned int column, unsigned long offset)
{
  DBUG_ENTER("mysql_stmt_fetch");

  if (stmt->state < MYSQL_STMT_USER_FETCHING || column >= stmt->field_count || 
    stmt->state == MYSQL_STMT_FETCH_DONE)  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NO_DATA, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  if (!stmt->result_bind[column].row_ptr)
  {
    /* we set row_ptr only for columns which contain data, so this must be a NULL column */
    if (bind[0].is_null)
      *bind[0].is_null= 1;
  }
  else
  {
    unsigned char *save_ptr;
    if (bind[0].length)
      *bind[0].length= stmt->result_bind[column].length_value;
    else
      *bind[0].length= *stmt->result_bind[column].length;
    if (bind[0].is_null)
      *bind[0].is_null= 0;
    else
       bind[0].is_null= &bind[0].is_null_value;
    if (!bind[0].error)
      bind[0].error= &bind[0].error_value;
    *bind[0].error= 0;
    bind[0].offset= offset;
    save_ptr= stmt->result_bind[column].row_ptr;
    mysql_ps_fetch_functions[stmt->fields[column].type].func(&bind[0], &stmt->fields[column], &stmt->result_bind[column].row_ptr);
    stmt->result_bind[column].row_ptr= save_ptr;
  }
  DBUG_RETURN(0);
}

unsigned int mysql_stmt_field_count(MYSQL_STMT *stmt)
{
  return stmt->field_count;
}

my_bool mysql_stmt_free_result(MYSQL_STMT *stmt)
{
  return mysql_stmt_reset(stmt);
}

MYSQL_STMT * STDCALL mysql_stmt_init(MYSQL *mysql)
{
  
  MYSQL_STMT *stmt = (MYSQL_STMT *)my_malloc(sizeof(MYSQL_STMT), MYF(MY_WME | MY_ZEROFILL));
  DBUG_ENTER("mysql_stmt_init");

  if (!stmt)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(NULL);
  }

 /* fill mysql's stmt list */
  stmt->list.data= stmt;
  stmt->conn= mysql;
  mysql->stmts= list_add(mysql->stmts, &stmt->list);

  
  /* clear flags */
  strcpy(stmt->error_info.sqlstate, "00000");

  stmt->state= MYSQL_STMT_INITTED;

  /* set default */
  stmt->prefetch_rows= 1;

  DBUG_RETURN(stmt);
}

my_bool stmt_read_prepare_response(MYSQL_STMT *stmt)
{
  ulong packet_length;
  uchar *p;

  DBUG_ENTER("read_prepare_response");

  if ((packet_length= net_safe_read(stmt->conn)) == packet_error)
    DBUG_RETURN(1);

  DBUG_PRINT("info",("packet_length= %ld",packet_length));

  p= (uchar *)stmt->conn->net.read_pos;

  if (0xFF == p[0])  /* Error occured */
  {
    DBUG_RETURN(1);
  }

  p++;
  stmt->stmt_id= uint4korr(p);
  p+= 4;
  stmt->field_count= uint2korr(p);
  p+= 2;
  stmt->param_count= uint2korr(p);

  /* filler */
  p++;
  stmt->upsert_status.warning_count= uint2korr(p);
  
  DBUG_RETURN(0);
}

my_bool stmt_get_param_metadata(MYSQL_STMT *stmt)
{
  MYSQL_DATA *result;

  DBUG_ENTER("stmt_get_param_metadata");

  if (!(result= read_rows(stmt->conn, (MYSQL_FIELD *)0, 7)))
    DBUG_RETURN(1);
  
  free_rows(result);
  DBUG_RETURN(0);
}

my_bool stmt_read_result_metadata(MYSQL_STMT *stmt)
{
  MYSQL_DATA *result;
  DBUG_ENTER("stmt_read_result_metadata");

  if (!(result= read_rows(stmt->conn, (MYSQL_FIELD *)0, 7)))
    DBUG_RETURN(1);
  if (!(stmt->fields= unpack_fields(result,&stmt->mem_root,
            stmt->field_count, 0,
            stmt->conn->server_capabilities)))
    DBUG_RETURN(1); 
  DBUG_RETURN(0);
}

int STDCALL mysql_stmt_prepare(MYSQL_STMT *stmt, const char *query, unsigned long length)
{
  int rc= 1;
  DBUG_ENTER("mysql_stmt_prepare");

  if (!stmt->conn)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  /* clear flags */
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);
  CLEAR_CLIENT_ERROR(stmt->conn);
  stmt->upsert_status.affected_rows= stmt->conn->affected_rows= (my_ulonglong) ~0;
  
  /* check if we have to clear results */
  if (stmt->state > MYSQL_STMT_INITTED)
  {
    /* We need to semi-close the prepared statement:
       reset stmt and free all buffers and close the statement
       on server side. Statment handle will get a new stmt_id */
    char stmt_id[STMT_ID_LENGTH];

    mysql_stmt_reset(stmt);

    free_root(&stmt->mem_root, MYF(MY_KEEP_PREALLOC));
    stmt->param_count= 0;
    stmt->field_count= 0;

    int4store(stmt_id, stmt->stmt_id);
    if (simple_command(stmt->conn, MYSQL_COM_STMT_CLOSE, stmt_id, sizeof(stmt_id), 1))
      goto fail;
  }

  if (simple_command(stmt->conn,MYSQL_COM_STMT_PREPARE, query, length, 1))
    goto fail;

  if  (stmt_read_prepare_response(stmt))
    goto fail;
  
  /* metadata not supported yet */
  if (stmt->param_count && stmt_get_param_metadata(stmt))
  {
    goto fail;
  }

  if (stmt->field_count && stmt_read_result_metadata(stmt))
  {
    goto fail;
  }

  /* allocated bind buffer for parameters */
  if (stmt->param_count)
  {
    if (!(stmt->param_bind= (MYSQL_BIND *)alloc_root(&stmt->mem_root, stmt->param_count * sizeof(MYSQL_BIND))))
    {
      SET_CLIENT_STMT_ERROR(stmt->error_info, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
      goto fail; 
    }
  }
  /* allocated bind buffer for result */
  if (stmt->field_count)
  {
    if (!(stmt->result_bind= (MYSQL_BIND *)alloc_root(&stmt->mem_root, stmt->field_count * sizeof(MYSQL_BIND))))
    {
      SET_CLIENT_STMT_ERROR(stmt->error_info, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
      goto fail; 
    }
  }
  stmt->state = MYSQL_STMT_PREPARED;
  DBUG_RETURN(0);

fail:
  stmt->state= MYSQL_STMT_INITTED;
  SET_CLIENT_STMT_ERROR(stmt->error_info, stmt->conn->net.last_errno, stmt->conn->net.sqlstate,
                        stmt->conn->net.last_error); 
  DBUG_RETURN(rc);
}

int STDCALL mysql_stmt_store_result(MYSQL_STMT *stmt)
{
  DBUG_ENTER("mysql_stmt_store_result");

  /* test_pure_coverage requires checking of error_no */
  if (stmt->error_info.error_no)
    DBUG_RETURN(1);

  if (!stmt->conn)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  if (!stmt->field_count)
    DBUG_RETURN(0);

  if (stmt->state < MYSQL_STMT_EXECUTED)
  {
    SET_CLIENT_ERROR(stmt->conn, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  /* if stmt is a cursor, we need to tell server to send all rows */
  if (stmt->cursor_exists && stmt->conn->status == MYSQL_STATUS_READY)
  {
    char buff[STMT_ID_LENGTH + 4];
    int4store(buff, stmt->stmt_id);
    int4store(buff + STMT_ID_LENGTH, (int)~0);

    if (simple_command(stmt->conn, MYSQL_COM_STMT_FETCH, buff, sizeof(buff), 1))
      DBUG_RETURN(1);
    /* todo: cursor */
  }
  else if (stmt->conn->status != MYSQL_STATUS_GET_RESULT)
  {
    SET_CLIENT_ERROR(stmt->conn, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  if (stmt_read_all_rows(stmt))
  {
    /* error during read - reset stmt->data */
    free_root(&stmt->result.alloc, 0);
    stmt->result.data= NULL;
    stmt->result.rows= 0;
    stmt->conn->status= MYSQL_STATUS_READY;
    DBUG_RETURN(1);
  }
  stmt->result_cursor= stmt->result.data;
  stmt->fetch_row_func= stmt_buffered_fetch;
  stmt->conn->status= MYSQL_STATUS_READY; 
  stmt->state= MYSQL_STMT_USE_OR_STORE_CALLED;

  /* set affected rows: see bug 2247 */
  stmt->upsert_status.affected_rows= stmt->result.rows;
  stmt->conn->affected_rows= stmt->result.rows;

  DBUG_RETURN(0);
}

int STDCALL mysql_stmt_execute(MYSQL_STMT *stmt)
{
  char *request;
  int ret;
  size_t request_len= 0;
  

  DBUG_ENTER("mysql_stmt_execute");

  if (!stmt->conn)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  if (stmt->state < MYSQL_STMT_PREPARED)
  {
    SET_CLIENT_ERROR(stmt->conn, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_COMMANDS_OUT_OF_SYNC, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  if (stmt->param_count && !stmt->param_bind)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_PARAMS_NOT_BOUND, SQLSTATE_UNKNOWN,
                            "No data supplied for parameters in prepared statement");
    DBUG_RETURN(1);
  }

  if (stmt->state == MYSQL_STMT_WAITING_USE_OR_STORE)
  {
    stmt->default_rset_handler = _mysql_stmt_use_result;
    stmt->default_rset_handler(stmt);
  }
  if (stmt->state > MYSQL_STMT_WAITING_USE_OR_STORE && stmt->state < MYSQL_STMT_FETCH_DONE && !stmt->result.data)
  {
      stmt_flush_unbuffered(stmt);
      stmt->state= MYSQL_STMT_PREPARED;
      stmt->conn->status= MYSQL_STATUS_READY;
  }

  /* clear data, in case mysql_stmt_store_result was called */
  if (stmt->result.data)
  {
    free_root(&stmt->result.alloc, MYF(MY_KEEP_PREALLOC));
    stmt->result_cursor= stmt->result.data= 0;
    stmt->result.rows= 0;
  }

  request= (char *)mysql_stmt_execute_generate_request(stmt, &request_len);
  DBUG_PRINT("info",("request_len=%ld", request_len));

  ret= test(simple_command(stmt->conn, MYSQL_COM_STMT_EXECUTE, request, request_len, 1) || 
            mysql_read_query_result(stmt->conn));

  if (request)
    my_free(request, MYF(0));

  /* update affected rows, also if an error occured */
  stmt->upsert_status.affected_rows= stmt->conn->affected_rows;

  if (ret)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, stmt->conn->net.last_errno, stmt->conn->net.sqlstate,
                          stmt->conn->net.last_error); 
    DBUG_RETURN(1);
  }
  stmt->upsert_status.last_insert_id= stmt->conn->insert_id;
  stmt->upsert_status.server_status= stmt->conn->server_status;
  stmt->upsert_status.warning_count= stmt->conn->warning_count;

  CLEAR_CLIENT_ERROR(stmt->conn);
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);
 
  stmt->execute_count++;
  stmt->send_types_to_server= 0;

  stmt->state= MYSQL_STMT_EXECUTED;

  if (stmt->conn->field_count)
  {
    if (!stmt->field_count) /* fix for ps_bug: test_misc */
    {
      uint i;
      if (!(stmt->fields= (MYSQL_FIELD *)alloc_root(&stmt->mem_root,
                                                   sizeof(MYSQL_FIELD) * stmt->conn->field_count)))
      {
        /*todo: set error */
        DBUG_RETURN(1);
      }
      stmt->field_count= stmt->conn->field_count;
      
      for (i=0; i < stmt->field_count; i++)
      {
        stmt->fields[i].db= strdup_root(&stmt->mem_root, stmt->conn->fields[i].db);
        stmt->fields[i].table= strdup_root(&stmt->mem_root, stmt->conn->fields[i].table);
        stmt->fields[i].org_table= strdup_root(&stmt->mem_root, stmt->conn->fields[i].org_table);
        stmt->fields[i].name= strdup_root(&stmt->mem_root, stmt->conn->fields[i].name);
        stmt->fields[i].org_name= strdup_root(&stmt->mem_root, stmt->conn->fields[i].org_name);
        stmt->fields[i].def= stmt->conn->fields[i].def ? strdup_root(&stmt->mem_root, stmt->conn->fields[i].def) : NULL;
      }
    }

    if (stmt->upsert_status.server_status & SERVER_STATUS_CURSOR_EXISTS)
    {
      stmt->cursor_exists = TRUE;
      stmt->conn->status = MYSQL_STATUS_READY;

      /* Only cursor read */
      stmt->default_rset_handler = _mysql_stmt_use_result;

    } else if (stmt->flags & CURSOR_TYPE_READ_ONLY)
    {
      /*
      We have asked for CURSOR but got no cursor, because the condition
      above is not fulfilled. Then...
      This is a single-row result set, a result set with no rows, EXPLAIN,
      SHOW VARIABLES, or some other command which either a) bypasses the
      cursors framework in the server and writes rows directly to the
      network or b) is more efficient if all (few) result set rows are
      precached on client and server's resources are freed.
      */

      /* preferred is buffered read */
      mysql_stmt_store_result(stmt);
    } else
    {
      /* preferred is unbuffered read */
      stmt->default_rset_handler = _mysql_stmt_use_result;
    }
    stmt->state= MYSQL_STMT_WAITING_USE_OR_STORE;
    /* in certain cases parameter types can change: For example see bug
       4026 (SELECT ?), so we need to update field information */
    if (stmt->conn->field_count == stmt->field_count)
    {
      uint i;
      for (i=0; i < stmt->field_count; i++)
      {
        stmt->fields[i].type= stmt->conn->fields[i].type;
        stmt->fields[i].length= stmt->conn->fields[i].length;
        stmt->fields[i].flags= stmt->conn->fields[i].flags;
        stmt->fields[i].decimals= stmt->conn->fields[i].decimals;
        stmt->fields[i].charsetnr= stmt->conn->fields[i].charsetnr;
      }
    } else
    {
      /* table was altered, see test_wl4166_2  */
      SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NEW_STMT_METADATA, SQLSTATE_UNKNOWN, 0);
      DBUG_RETURN(1);
    }
  }
  DBUG_RETURN(0);
}

my_bool STDCALL mysql_stmt_reset(MYSQL_STMT *stmt)
{
  unsigned char cmd_buf[STMT_ID_LENGTH];
  my_bool ret= 1;

  DBUG_ENTER("mysql_stmt_reset");

  if (!stmt->conn)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  CLEAR_CLIENT_ERROR(stmt->conn);
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);


  if (stmt->stmt_id)
  {
    if (stmt->state == MYSQL_STMT_WAITING_USE_OR_STORE)
    {
      stmt->default_rset_handler(stmt);
      stmt->state = MYSQL_STMT_USER_FETCHING;
    }

    if (stmt->conn->status!= MYSQL_STATUS_READY && stmt->field_count)
    {
      stmt_flush_unbuffered(stmt);
      stmt->conn->status= MYSQL_STATUS_READY;
    } 

    /* reset statement on server side */
    if (stmt->conn->status == MYSQL_STATUS_READY)
    {
       int4store(cmd_buf, stmt->stmt_id);
       if ((ret= simple_command(stmt->conn,MYSQL_COM_STMT_RESET, (char *)cmd_buf, sizeof(cmd_buf), 0)))
         SET_CLIENT_STMT_ERROR(stmt->error_info, stmt->conn->net.last_errno, stmt->conn->net.sqlstate,
                          stmt->conn->net.last_error);
       
    }
    if (stmt->param_bind) {
      ulonglong i;
      for (i=0; i < stmt->param_count; i++)
        if (stmt->param_bind[i].long_data_used)
          stmt->param_bind[i].long_data_used= 0;
    }
    stmt->state= MYSQL_STMT_PREPARED;
    stmt->upsert_status.affected_rows= stmt->conn->affected_rows;
    stmt->upsert_status.last_insert_id= stmt->conn->insert_id;
    stmt->upsert_status.server_status= stmt->conn->server_status;
    stmt->upsert_status.warning_count= stmt->conn->warning_count;
    stmt->conn->status= MYSQL_STATUS_READY;
  }

  DBUG_RETURN(ret);
}

MYSQL_RES * STDCALL mysql_stmt_result_metadata(MYSQL_STMT *stmt)
{
  MYSQL_RES *res;

  DBUG_ENTER("mysql_stmt_result_metadata");

  if (!stmt->field_count)
    DBUG_RETURN(NULL);

  /* aloocate result set structutr and copy stmt information */
  if (!(res= (MYSQL_RES *)my_malloc(sizeof(MYSQL_RES), MYF(MY_WME | MY_ZEROFILL))))
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(NULL);
  }

  res->eof= 1;
  res->fields= stmt->fields;
  res->field_count= stmt->field_count;  
  DBUG_RETURN(res);}

const char * STDCALL mysql_stmt_sqlstate(MYSQL_STMT *stmt)
{
  return stmt->error_info.sqlstate;
}

MYSQL_ROW_OFFSET STDCALL mysql_stmt_row_tell(MYSQL_STMT *stmt)
{
  DBUG_ENTER("mysql_stmt_row_tell");
  DBUG_RETURN(stmt->result_cursor);
}

unsigned long STDCALL mysql_stmt_param_count(MYSQL_STMT *stmt)
{
  return stmt->param_count;
}

MYSQL_ROW_OFFSET STDCALL mysql_stmt_row_seek(MYSQL_STMT *stmt, MYSQL_ROW_OFFSET new_row)
{
  MYSQL_ROW_OFFSET old_row; /* for returning old position */
  DBUG_ENTER("mysql_stmt_row_seek");

  old_row= stmt->result_cursor;
  stmt->result_cursor= new_row;

  DBUG_RETURN(old_row);
}

my_bool STDCALL mysql_stmt_send_long_data(MYSQL_STMT *stmt, uint param_number,
                                          const char *data, ulong length)
{
  DBUG_ENTER("mysql_stmt_send_long_data");
  
  CLEAR_CLIENT_ERROR(stmt->conn);
  CLEAR_CLIENT_STMT_ERROR(stmt->error_info);
 
  if (stmt->state < MYSQL_STMT_PREPARED || !stmt->param_bind)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_NO_PREPARE_STMT, SQLSTATE_UNKNOWN, mysql_stmt_not_prepared);
    DBUG_RETURN(1);
  }

  if (param_number >= stmt->param_count)
  {
    SET_CLIENT_STMT_ERROR(stmt->error_info, CR_INVALID_PARAMETER_NO, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  if (stmt->conn->status== MYSQL_STATUS_READY && (length || !stmt->param_bind[param_number].long_data_used))
  {
    int ret;
    size_t packet_len;
    uchar *cmd_buff= (uchar *)my_malloc(packet_len= STMT_ID_LENGTH + 2 + length, MYF(MY_WME | MY_ZEROFILL));
    int4store(cmd_buff, stmt->stmt_id);
    int2store(cmd_buff + STMT_ID_LENGTH, param_number);
    memcpy(cmd_buff + STMT_ID_LENGTH + 2, data, length);
    stmt->param_bind[param_number].long_data_used= 1;
    ret= simple_command(stmt->conn,MYSQL_COM_STMT_SEND_LONG_DATA, (char *)cmd_buff, packet_len, 1);
    my_free((gptr)cmd_buff, MYF(MY_WME));
    DBUG_RETURN(ret); 
  } 
  DBUG_RETURN(1);
}
