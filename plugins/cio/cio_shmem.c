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
/* MariaDB Communication IO (CIO) plugin for named pipe communication */

#ifdef _WIN32

#include <my_global.h>
#include <my_sys.h>
#include <errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <m_string.h>

#ifdef HAVE_SHMEM_DYNAMIC
#define my_malloc(A, B) malloc((A))
#undef my_free
#define my_free(A,B) free(((A)))
#endif

#define SHM_DEFAULT_NAME "MYSQL"
#define CIO_SHM_BUFFER_SIZE 16000 + 4

my_bool cio_shm_set_timeout(MARIADB_CIO *cio, enum enum_cio_timeout type, int timeout);
int cio_shm_get_timeout(MARIADB_CIO *cio, enum enum_cio_timeout type);
size_t cio_shm_read(MARIADB_CIO *cio, const uchar *buffer, size_t length);
size_t cio_shm_write(MARIADB_CIO *cio, uchar *buffer, size_t length);
int cio_shm_wait_io_or_timeout(MARIADB_CIO *cio, my_bool is_read, int timeout);
my_bool cio_shm_blocking(MARIADB_CIO *cio, my_bool value, my_bool *old_value);
my_bool cio_shm_connect(MARIADB_CIO *cio, MA_CIO_CINFO *cinfo);
my_bool cio_shm_close(MARIADB_CIO *cio);


struct st_ma_cio_methods cio_shm_methods= {
  cio_shm_set_timeout,
  cio_shm_get_timeout,
  cio_shm_read,
  NULL,
  cio_shm_write,
  NULL,
  cio_shm_wait_io_or_timeout,
  cio_shm_blocking,
  cio_shm_connect,
  cio_shm_close,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

#ifndef HAVE_SHMEM_DYNAMIC
MARIADB_CIO_PLUGIN cio_shmem_plugin=
#else
MARIADB_CIO_PLUGIN _mysql_client_plugin_declaration_=
#endif
{
  MARIADB_CLIENT_CIO_PLUGIN,
  MARIADB_CLIENT_CIO_PLUGIN_INTERFACE_VERSION,
  "cio_shmem",
  "Georg Richter",
  "MariaDB communication IO plugin for Windows shared memory communication",
  {1, 0, 0},
  "LGPPL",
  NULL,
  NULL,
  &cio_shm_methods,
  NULL,
  NULL
};

enum enum_shm_events
{
  CIO_SHM_SERVER_WROTE= 0,
  CIO_SHM_SERVER_READ,
  CIO_SHM_CLIENT_WROTE,
  CIO_SHM_CLIENT_READ,
  CIO_SHM_CONNECTION_CLOSED
};

typedef struct {
  HANDLE event[5];
  HANDLE file_map;
  LPVOID *map;
  char *read_pos;
  size_t buffer_size;
} CIO_SHM;

char *StrEvent[]= {"SERVER_WROTE", "SERVER_READ", "CLIENT_WROTE", "CLIENT_READ", "CONNECTION_CLOSED"};

struct st_cio_shm {
  char *shm_name;
};

my_bool cio_shm_set_timeout(MARIADB_CIO *cio, enum enum_cio_timeout type, int timeout)
{
  if (!cio)
    return 1;
  cio->timeout[type]= (timeout > 0) ? timeout * 1000 : INFINITE;
  return 0;
}

int cio_shm_get_timeout(MARIADB_CIO *cio, enum enum_cio_timeout type)
{
  if (!cio)
    return -1;
  return cio->timeout[type] / 1000;
}

size_t cio_shm_read(MARIADB_CIO *cio, const uchar *buffer, size_t length)
{
  CIO_SHM *cio_shm= (CIO_SHM *)cio->data;
  size_t copy_size= length;
  HANDLE events[2];
  
  if (!cio_shm)
    return -1;

  /* we need to wait for write and close events */
  if (!cio_shm->buffer_size)
  {
    events[0]= cio_shm->event[CIO_SHM_CONNECTION_CLOSED];
    events[1]= cio_shm->event[CIO_SHM_SERVER_WROTE];

    switch(WaitForMultipleObjects(2, events, 0, cio->timeout[CIO_READ_TIMEOUT]))
    {
    case WAIT_OBJECT_0: /* server closed connection */
      SetLastError(ERROR_GRACEFUL_DISCONNECT);
      return -1;
    case WAIT_OBJECT_0 +1: /* server_wrote event */
      break;
    case WAIT_TIMEOUT:
      SetLastError(ETIMEDOUT);
    default:
      return -1;
    }
    /* server sent data */
    cio_shm->read_pos= cio_shm->map;
    cio_shm->buffer_size= uint4korr(cio_shm->read_pos);
    cio_shm->read_pos+= 4;
  }

  if (cio_shm->buffer_size < copy_size)
    copy_size= cio_shm->buffer_size;
  
  if (copy_size)
  {
    memcpy(buffer, cio_shm->read_pos, cio_shm->buffer_size);
    cio_shm->read_pos+= copy_size;
    cio_shm->buffer_size-= copy_size;
  }

  /* we need to read again */
  if (!cio_shm->buffer_size)
    if (!SetEvent(cio_shm->event[CIO_SHM_CLIENT_READ]))
      return -1;

  return copy_size;
}

size_t cio_shm_write(MARIADB_CIO *cio,  uchar *buffer, size_t length)
{
  HANDLE events[2];
  CIO_SHM *cio_shm= (CIO_SHM *)cio->data;
  size_t bytes_to_write= length;
  uchar *buffer_pos= buffer;
  
  if (!cio_shm)
    return -1;

  events[0]= cio_shm->event[CIO_SHM_CONNECTION_CLOSED];
  events[1]= cio_shm->event[CIO_SHM_SERVER_READ];

  while (bytes_to_write)
  {
    size_t pkt_length;
    switch (WaitForMultipleObjects(2, events, 0, cio->timeout[CIO_WRITE_TIMEOUT])) {
    case WAIT_OBJECT_0: /* connection closed */
      SetLastError(ERROR_GRACEFUL_DISCONNECT);
      return -1;
    case WAIT_OBJECT_0 + 1: /* server_read */
      break;
    case WAIT_TIMEOUT:
      SetLastError(ETIMEDOUT);
    default:
      return -1;
    }
    pkt_length= MIN(CIO_SHM_BUFFER_SIZE, length);
    int4store(cio_shm->map, pkt_length);
    memcpy((uchar *)cio_shm->map + 4, buffer_pos, length);
    buffer_pos+= length;
    bytes_to_write-= length;

    if (!SetEvent(cio_shm->event[CIO_SHM_CLIENT_WROTE]))
      return -1;
  }
  return length;
}


int cio_shm_wait_io_or_timeout(MARIADB_CIO *cio, my_bool is_read, int timeout)
{
}

my_bool cio_shm_blocking(MARIADB_CIO *cio, my_bool block, my_bool *previous_mode)
{
  /* not supported */
  return 0;
}

int cio_shm_keepalive(MARIADB_CIO *cio)
{
  /* not supported */
  return 0;
}

int cio_shm_fast_send(MARIADB_CIO *cio)
{
  /* not supported */
  return 0;
}

my_bool cio_shm_connect(MARIADB_CIO *cio, MA_CIO_CINFO *cinfo)
{
  char *base_memory_name;
  char *prefixes[]= {"", "Global\\", NULL};
  char *shm_name, *shm_suffix, *shm_prefix;
  uchar i= 0;
  int len;
  DWORD cid;
  char connection_id[28];
  char *connection_id_str;
  DWORD dwDesiredAccess= EVENT_MODIFY_STATE | SYNCHRONIZE;
  HANDLE hdlConnectRequest= NULL,
         hdlConnectRequestAnswer= NULL,
         file_map= NULL;
  LPVOID map= NULL;
  CIO_SHM *cio_shm= (CIO_SHM*)LocalAlloc(LMEM_ZEROINIT, sizeof(CIO_SHM));       

  if (!cio_shm)
  {
    CIO_SET_ERROR(cinfo->mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0, "");
    return 0;
  }

  /* MariaDB server constructs the event name as follows:
     "Global\\base_memory_name" or
     "\\base_memory_name"
   */
 

  base_memory_name= (cinfo->mysql->options.shared_memory_base_name) ?
                     cinfo->mysql->options.shared_memory_base_name : SHM_DEFAULT_NAME;
  

  if (!(shm_name= LocalAlloc(LMEM_ZEROINIT, strlen(base_memory_name) + 40)))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0, "");
    goto error;
  }

  /* iterate through prefixes */
  while (prefixes[i])
  {
    len= sprintf(shm_name, "%s%s_", prefixes[i], base_memory_name);
    shm_suffix= shm_name + len;
    strcpy(shm_suffix, "CONNECT_REQUEST");
    if ((hdlConnectRequest= OpenEvent(dwDesiredAccess, 0, shm_name)))
    {
      /* save prefix to prevent further loop */
      shm_prefix= prefixes[i];
      break;
    }
    i++;
  }
  if (!hdlConnectRequest)
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Opening CONNECT_REQUEST event failed", GetLastError());
    goto error;
  }

  strcpy(shm_suffix, "CONNECT_ANSWER");
  if (!(hdlConnectRequestAnswer= OpenEvent(dwDesiredAccess, 0, shm_name)))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Opening CONNECT_ANSWER event failed", GetLastError());
    goto error;
  }
  
  /* get connection id, so we can build the filename used for connection */
  strcpy(shm_suffix, "CONNECT_DATA");
  if (!(file_map= OpenFileMapping(FILE_MAP_WRITE, 0, shm_name)))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "OpenFileMapping failed", GetLastError());
    goto error;
  }

  /* try to get first 4 bytes, which represents connection_id */
  if (!(map= MapViewOfFile(file_map, FILE_MAP_WRITE, 0, 0, sizeof(cid))))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Reading connection_id failed", GetLastError());
    goto error;
  }

  /* notify server */
  if (!SetEvent(hdlConnectRequest))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Failed sending connection request", GetLastError());
    goto error;
  }

  /* Wait for server answer */
  switch(WaitForSingleObject(hdlConnectRequestAnswer, cio->timeout[CIO_CONNECT_TIMEOUT])) {
  case WAIT_ABANDONED:
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Mutex was not released in time", GetLastError());
    goto error;
    break;
  case WAIT_FAILED:
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Operation wait failed", GetLastError());
    goto error;
    break;
  case WAIT_TIMEOUT:
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Operation timed out", GetLastError());
    goto error;
    break;
  case WAIT_OBJECT_0:
    break;
  default:
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Wait for server failed", GetLastError());
    break;
  }

  cid= uint4korr(map);

  len= sprintf(shm_name, "%s%s_%d_", shm_prefix, base_memory_name, cid);
  shm_suffix= shm_name + len;
  
  strcpy(shm_suffix, "DATA");
  cio_shm->file_map= OpenFileMapping(FILE_MAP_WRITE, 0, shm_name);
  if (cio_shm->file_map == NULL)
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "OpenFileMapping failed", GetLastError());
    goto error;
  }
  if (!(cio_shm->map= MapViewOfFile(cio_shm->file_map, FILE_MAP_WRITE, 0, 0, CIO_SHM_BUFFER_SIZE)))
  {
    CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "MapViewOfFile failed", GetLastError());
    goto error;
  }

  for (i=0; i < 5; i++)
  {
    strcpy(shm_suffix, StrEvent[i]);
    if (!(cio_shm->event[i]= OpenEvent(dwDesiredAccess, 0, shm_name)))
    {
      CIO_SET_ERROR(cinfo->mysql, CR_SHARED_MEMORY_CONNECT_ERROR, unknown_sqlstate, 0, "Couldn't create event", GetLastError());
      goto error;
    }
  }
  /* we will first read from server */
  SetEvent(cio_shm->event[CIO_SHM_SERVER_READ]);

error:
  if (hdlConnectRequest)
    CloseHandle(hdlConnectRequest);
  if (hdlConnectRequestAnswer)
    CloseHandle(hdlConnectRequestAnswer);
  if (shm_name)
    LocalFree(shm_name);
  if (map)
    UnmapViewOfFile(map);
  if (file_map)
    CloseHandle(file_map);
  if (cio_shm)
  {
    /* check if all events are set */
    if (cio_shm->event[4])
    {
      cio->data= (void *)cio_shm;
      cio->mysql= cinfo->mysql;
      cio->type= cinfo->type;
      cio_shm->read_pos= cio_shm->map;
      cio->mysql->net.cio= cio;
      return 0;
    }
    for (i=0;i < 5; i++)
      if (cio_shm->event[i])
        CloseHandle(cio_shm->event[i]);
    if (cio_shm->map)
      UnmapViewOfFile(cio_shm->map);
    if (cio_shm->file_map)
      CloseHandle(cio_shm->file_map);
    LocalFree(cio_shm);
  }
  return 1;

}

my_bool cio_shm_close(MARIADB_CIO *cio)
{
  CIO_SHM *cio_shm= (CIO_SHM *)cio->data;
  int i;

  if (!cio_shm)
    return 1;

  /* notify server */
  SetEvent(cio_shm->event[CIO_SHM_CONNECTION_CLOSED]);

  UnmapViewOfFile(cio_shm->map);
  CloseHandle(cio_shm->file_map);

  for (i=0; i < 5; i++)
    CloseHandle(cio_shm->event[i]);

  LocalFree(cio_shm);
  cio->data= NULL;
  return 0;
}

my_socket cio_shm_get_socket(MARIADB_CIO *cio)
{
} 

my_bool cio_shm_is_blocking(MARIADB_CIO *cio)
{
  return 1;
}

#endif

