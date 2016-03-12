/************************************************************************************
    Copyright (C) 2015 Georg Richter and MariaDB Corporation AB
   
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

/* MariaDB virtual IO plugin for Windows named pipe communication */

#ifdef _WIN32

#include <ma_global.h>
#include <ma_sys.h>
#include <ma_errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_string.h>

/* Function prototypes */
my_bool pvio_npipe_set_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type, int timeout);
int pvio_npipe_get_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type);
size_t pvio_npipe_read(MARIADB_PVIO *pvio, uchar *buffer, size_t length);
size_t pvio_npipe_async_read(MARIADB_PVIO *pvio, uchar *buffer, size_t length);
size_t pvio_npipe_write(MARIADB_PVIO *pvio, const uchar *buffer, size_t length);
size_t pvio_npipe_async_write(MARIADB_PVIO *pvio, const uchar *buffer, size_t length);
int pvio_npipe_wait_io_or_timeout(MARIADB_PVIO *pvio, my_bool is_read, int timeout);
my_bool pvio_npipe_blocking(MARIADB_PVIO *pvio, my_bool value, my_bool *old_value);
my_bool pvio_npipe_connect(MARIADB_PVIO *pvio, MA_PVIO_CINFO *cinfo);
my_bool pvio_npipe_close(MARIADB_PVIO *pvio);
int pvio_npipe_fast_send(MARIADB_PVIO *pvio);
int pvio_npipe_keepalive(MARIADB_PVIO *pvio);
my_bool pvio_npipe_get_handle(MARIADB_PVIO *pvio, void *handle);
my_bool pvio_npipe_is_blocking(MARIADB_PVIO *pvio);

struct st_ma_pvio_methods pvio_npipe_methods= {
  pvio_npipe_set_timeout,
  pvio_npipe_get_timeout,
  pvio_npipe_read,
  NULL,
  pvio_npipe_write,
  NULL,
  pvio_npipe_wait_io_or_timeout,
  pvio_npipe_blocking,
  pvio_npipe_connect,
  pvio_npipe_close,
  pvio_npipe_fast_send,
  pvio_npipe_keepalive,
  pvio_npipe_get_handle,
  pvio_npipe_is_blocking
};

#ifndef HAVE_NPIPE_DYNAMIC
MARIADB_PVIO_PLUGIN pvio_npipe_plugin =
#else
MARIADB_PVIO_PLUGIN _mysql_client_plugin_declaration_ =
#endif
{
  MARIADB_CLIENT_PVIO_PLUGIN,
  MARIADB_CLIENT_PVIO_PLUGIN_INTERFACE_VERSION,
  "pvio_npipe",
  "Georg Richter",
  "MariaDB virtual IO plugin for named pipe connection",
  {1, 0, 0},
  "LGPL",
  NULL,
  NULL,
  NULL,
  NULL,
  &pvio_npipe_methods
};

struct st_pvio_npipe {
  HANDLE pipe;
  OVERLAPPED overlapped;
  size_t rw_size;
  MYSQL *mysql;
};

my_bool pvio_npipe_set_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type, int timeout)
{
  if (!pvio)
    return 1;
  pvio->timeout[type]= (timeout > 0) ? timeout * 1000 : -1;
  return 0;
}

int pvio_npipe_get_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type)
{
  if (!pvio)
    return -1;
  return pvio->timeout[type] / 1000;
}

size_t pvio_npipe_read(MARIADB_PVIO *pvio, uchar *buffer, size_t length)
{
  DWORD dwRead= 0;
  size_t r= -1;
  struct st_pvio_npipe *cpipe= NULL;

  if (!pvio || !pvio->data)
    return -1;

  cpipe= (struct st_pvio_npipe *)pvio->data;

  if (ReadFile(cpipe->pipe, (LPVOID)buffer, (DWORD)length, &dwRead, &cpipe->overlapped))
  {
    r= (size_t)dwRead;
    goto end;
  }
  if (GetLastError() == ERROR_IO_PENDING)
  {
    if (!pvio_npipe_wait_io_or_timeout(pvio, 1, 0))
      r= cpipe->rw_size;
  }
end:  
  return r;
}

size_t pvio_npipe_write(MARIADB_PVIO *pvio, const uchar *buffer, size_t length)
{
  DWORD dwWrite= 0;
  size_t r= -1;
  struct st_pvio_npipe *cpipe= NULL;

  if (!pvio || !pvio->data)
    return -1;

  cpipe= (struct st_pvio_npipe *)pvio->data;

  if (WriteFile(cpipe->pipe, buffer, (DWORD)length, &dwWrite, &cpipe->overlapped))
  {
    r= (size_t)dwWrite;
    goto end;
  }
  if (GetLastError() == ERROR_IO_PENDING)
  {
    if (!pvio_npipe_wait_io_or_timeout(pvio, 0, 0))
      r= cpipe->rw_size;
  }
end:  
  return r;
}

int pvio_npipe_wait_io_or_timeout(MARIADB_PVIO *pvio, my_bool is_read, int timeout)
{
  int r= -1;
  DWORD status;
  int save_error;
  struct st_pvio_npipe *cpipe= NULL;

  cpipe= (struct st_pvio_npipe *)pvio->data;

  if (!timeout)
    timeout= (is_read) ? pvio->timeout[PVIO_READ_TIMEOUT] : pvio->timeout[PVIO_WRITE_TIMEOUT];
  if (!timeout)
    timeout= INFINITE;

  status= WaitForSingleObject(cpipe->overlapped.hEvent, timeout);
  if (status == WAIT_OBJECT_0)
  {
    if (GetOverlappedResult(cpipe->pipe, &cpipe->overlapped, (LPDWORD)&cpipe->rw_size, FALSE))
      return 0;
  }  
  /* For other status codes (WAIT_ABANDONED, WAIT_TIMEOUT and WAIT_FAILED)
     we return error */
  save_error= GetLastError();
  CancelIo(cpipe->pipe);
  SetLastError(save_error);
  return -1;
}

my_bool pvio_npipe_blocking(MARIADB_PVIO *pvio, my_bool block, my_bool *previous_mode)
{
  /* not supported */
  DWORD flags= 0;
  struct st_pvio_npipe *cpipe= NULL;

  cpipe= (struct st_pvio_npipe *)pvio->data;

  if (previous_mode)
  {
    if (!GetNamedPipeHandleState(cpipe->pipe, &flags, NULL, NULL, NULL, NULL, 0))
      return 1;
    *previous_mode= flags & PIPE_NOWAIT ? 0 : 1;
  }

  flags= block ? PIPE_WAIT : PIPE_NOWAIT;
  if (!SetNamedPipeHandleState(cpipe->pipe, &flags, NULL, NULL))
    return 1;
  return 0;
}

int pvio_npipe_keepalive(MARIADB_PVIO *pvio)
{
  /* keep alive is used for TCP/IP connections only */
  return 0;
}

int pvio_npipe_fast_send(MARIADB_PVIO *pvio)
{
  /* not supported */
  return 0;
}
my_bool pvio_npipe_connect(MARIADB_PVIO *pvio, MA_PVIO_CINFO *cinfo)
{
  struct st_pvio_npipe *cpipe= NULL;

  if (!pvio || !cinfo)
    return 1;

  /* if connect timeout is set, we will overwrite read/write timeout */
  if (pvio->timeout[PVIO_CONNECT_TIMEOUT])
  {
    pvio->timeout[PVIO_READ_TIMEOUT]= pvio->timeout[PVIO_WRITE_TIMEOUT]= pvio->timeout[PVIO_CONNECT_TIMEOUT];
  }

  if (!(cpipe= (struct st_pvio_npipe *)LocalAlloc(LMEM_ZEROINIT, sizeof(struct st_pvio_npipe))))
  {
    PVIO_SET_ERROR(cinfo->mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0, "");
    return 1;
  }
  memset(cpipe, 0, sizeof(struct st_pvio_npipe));
  pvio->data= (void *)cpipe;
  cpipe->pipe= INVALID_HANDLE_VALUE;
  pvio->mysql= cinfo->mysql;
  pvio->type= cinfo->type;

  if (cinfo->type == PVIO_TYPE_NAMEDPIPE)
  {
    my_bool has_timedout= 0;
    char szPipeName[MAX_PATH];
    DWORD dwMode;

    if ( ! cinfo->unix_socket || (cinfo->unix_socket)[0] == 0x00)
      cinfo->unix_socket = MARIADB_NAMEDPIPE;
    if (!cinfo->host || !strcmp(cinfo->host,LOCAL_HOST))
      cinfo->host=LOCAL_HOST_NAMEDPIPE;

    szPipeName[MAX_PATH - 1]= 0;
    snprintf(szPipeName, MAX_PATH - 1, "\\\\%s\\pipe\\%s", cinfo->host, cinfo->unix_socket);

    while (1)
    {
      if ((cpipe->pipe = CreateFile(szPipeName,
                                    GENERIC_READ |
                                    GENERIC_WRITE,
                                    0,               /* no sharing */
                                    NULL,            /* default security attributes */
                                    OPEN_EXISTING,
                                    FILE_FLAG_OVERLAPPED,
                                    NULL)) != INVALID_HANDLE_VALUE)
        break;

      if (GetLastError() != ERROR_PIPE_BUSY)
      {
        pvio->set_error(pvio->mysql, CR_NAMEDPIPEOPEN_ERROR, SQLSTATE_UNKNOWN, 0,
                       cinfo->host, cinfo->unix_socket, GetLastError());
        goto end;
      }

      if (has_timedout || !WaitNamedPipe(szPipeName, pvio->timeout[PVIO_CONNECT_TIMEOUT]))
      {
        pvio->set_error(pvio->mysql, CR_NAMEDPIPEWAIT_ERROR, SQLSTATE_UNKNOWN, 0,
                       cinfo->host, cinfo->unix_socket, GetLastError());
        goto end;
      }
      has_timedout= 1;
    }

    dwMode = PIPE_READMODE_BYTE | PIPE_WAIT;
    if (!SetNamedPipeHandleState(cpipe->pipe, &dwMode, NULL, NULL))
    {
      pvio->set_error(pvio->mysql, CR_NAMEDPIPESETSTATE_ERROR, SQLSTATE_UNKNOWN, 0,
                     cinfo->host, cinfo->unix_socket, (ulong) GetLastError());
      goto end;
    }

    /* Register event handler for overlapped IO */
    if (!(cpipe->overlapped.hEvent= CreateEvent(NULL, FALSE, FALSE, NULL)))
    {
      pvio->set_error(pvio->mysql, CR_EVENT_CREATE_FAILED, SQLSTATE_UNKNOWN, 0,
                     GetLastError());
      goto end;
    }
    return 0;
  }
end:
  if (cpipe)
  {
    if (cpipe->pipe != INVALID_HANDLE_VALUE)
      CloseHandle(cpipe->pipe);
    LocalFree(cpipe);
    pvio->data= NULL;
  }
  return 1;
}

my_bool pvio_npipe_close(MARIADB_PVIO *pvio)
{
  struct st_pvio_npipe *cpipe= NULL;
  int r= 0;

  if (!pvio)
    return 1;

  if (pvio->data)
  {
    cpipe= (struct st_pvio_npipe *)pvio->data;
    CloseHandle(cpipe->overlapped.hEvent);
    if (cpipe->pipe != INVALID_HANDLE_VALUE)
    {
      CloseHandle(cpipe->pipe);
      cpipe->pipe= INVALID_HANDLE_VALUE;
    }
    LocalFree(pvio->data);
    pvio->data= NULL;
  }
  return r;
}

my_bool pvio_npipe_get_handle(MARIADB_PVIO *pvio, void *handle)
{
  if (pvio && pvio->data)
  {
    *(HANDLE *)handle= ((struct st_pvio_npipe *)pvio->data)->pipe;
    return 0;
  }
  return 1;
} 

my_bool pvio_npipe_is_blocking(MARIADB_PVIO *pvio)
{
  DWORD flags= 0;
  struct st_pvio_npipe *cpipe= NULL;

  cpipe= (struct st_pvio_npipe *)pvio->data;

  if (!GetNamedPipeHandleState(cpipe->pipe, &flags, NULL, NULL, NULL, NULL, 0))
    return 1;
  return (flags & PIPE_NOWAIT) ? 0 : 1;
}

#endif
