/* Copyright (C) 2000 MySQL AB & MySQL Finland AB & TCX DataKonsult AB
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA */

/*
  Note that we can't have assertion on file descriptors;  The reason for
  this is that during mysql shutdown, another thread can close a file
  we are working on.  In this case we should just return read errors from
  the file descriptior.
*/

#ifndef HAVE_VIO /* is Vio suppored by the Vio lib ? */

#include <my_global.h>
#include <errno.h>
#include <assert.h>
#include <violite.h>
#include <my_sys.h>
#include <my_net.h>
#include <m_string.h>
#ifdef HAVE_POLL
#include <sys/poll.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_OPENSSL
#include <ma_secure.h>
#endif

#ifdef _WIN32
#define socklen_t int
#pragma comment (lib, "ws2_32")
#endif

#if !defined(_WIN32) && !defined(HAVE_BROKEN_NETINET_INCLUDES)  
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if !defined(alpha_linux_port)
#include <netinet/tcp.h>
#endif
#endif

#if defined(__EMX__) || defined(OS2)
#define ioctlsocket ioctl
#endif /* defined(__EMX__) */

#if defined(MSDOS) || defined(_WIN32)
#define O_NONBLOCK 1    /* For emulation of fcntl() */
#endif
#ifndef EWOULDBLOCK
#define SOCKET_EWOULDBLOCK SOCKET_EAGAIN
#endif

#include <mysql_async.h>
#include <my_context.h>

#ifdef _WIN32
#define ma_get_error() WSAGetLastError()
#else
#define ma_get_error() errno
#endif

typedef void *vio_ptr;
typedef char *vio_cstring;

/*
 * Helper to fill most of the Vio* with defaults.
 */

void vio_reset(Vio* vio, enum enum_vio_type type,
               my_socket sd, HANDLE hPipe,
               my_bool localhost)
{
  uchar *save_cache= vio->cache;
  int save_timeouts[2]= {vio->read_timeout, vio->write_timeout};
  bzero((char*) vio, sizeof(*vio));
  vio->type= type;
  vio->sd= sd;
  vio->hPipe= hPipe;
  vio->localhost= localhost;
  /* do not clear cache */
  vio->cache= vio->cache_pos= save_cache;
  vio->cache_size= 0;
  vio->read_timeout= save_timeouts[0];
  vio->write_timeout= save_timeouts[1];
}

void vio_timeout(Vio *vio, int type, uint timeval)
{
#ifdef _WIN32
  uint timeout= timeval; /* milli secs */
#else
  struct timeval timeout;
  timeout.tv_sec= timeval / 1000;
  timeout.tv_usec= (timeval % 1000) * 1000;
#endif

  if (setsockopt(vio->sd, SOL_SOCKET, type,
#ifdef _WIN32
                (const char *)&timeout,
#else
                (const void *)&timeout,
#endif
                sizeof(timeout)))
  {
    DBUG_PRINT("error", ("setsockopt failed. Errno: %d", errno));
  }
}

void vio_read_timeout(Vio *vio, uint timeout)
{
  vio->read_timeout= (timeout >= 0) ? timeout * 1000 : -1;
  vio_timeout(vio, SO_RCVTIMEO, vio->read_timeout);
}

void vio_write_timeout(Vio *vio, uint timeout)
{
  vio->write_timeout= (timeout >= 0) ? timeout * 1000 : -1;
  vio_timeout(vio, SO_SNDTIMEO, vio->write_timeout);
}

/* Open the socket or TCP/IP connection and read the fnctl() status */

Vio *vio_new(my_socket sd, enum enum_vio_type type, my_bool localhost)
{
  Vio *vio;
  DBUG_ENTER("vio_new");
  DBUG_PRINT("enter", ("sd=%d", sd));
  if ((vio = (Vio*) my_malloc(sizeof(*vio),MYF(MY_WME))))
  {
    vio_reset(vio, type, sd, 0, localhost);
    sprintf(vio->desc,
            (vio->type == VIO_TYPE_SOCKET ? "socket (%d)" : "TCP/IP (%d)"),
             vio->sd);
#if !defined(__WIN32) && !defined(__EMX__) && !defined(OS2)
#if !defined(NO_FCNTL_NONBLOCK)
    vio->fcntl_mode = fcntl(sd, F_GETFL);
#elif defined(HAVE_SYS_IOCTL_H) /* hpux */
    /* Non blocking sockets doesn't work good on HPUX 11.0 */
    (void) ioctl(sd,FIOSNBIO,0);
#endif
#else /* !defined(_WIN32) && !defined(__EMX__) */
    {
      /* set to blocking mode by default */
      ulong arg=0, r;
      r = ioctlsocket(vio->sd,FIONBIO,(void*) &arg/*, sizeof(arg)*/);
    }
#endif
  }
  if (!(vio->cache= my_malloc(VIO_CACHE_SIZE, MYF(MY_ZEROFILL))))
  {
    my_free(vio);
    vio= NULL;
  }
  vio->cache_size= 0;
  vio->cache_pos= vio->cache;
  DBUG_RETURN(vio);
}


#ifdef _WIN32

Vio *vio_new_win32pipe(HANDLE hPipe)
{
  Vio *vio;
  DBUG_ENTER("vio_new_handle");
  if ((vio = (Vio*) my_malloc(sizeof(Vio),MYF(MY_ZEROFILL))))
  {
    vio_reset(vio, VIO_TYPE_NAMEDPIPE, 0, hPipe, TRUE);
    strmov(vio->desc, "named pipe");
  }
  DBUG_RETURN(vio);
}

#endif

void vio_delete(Vio * vio)
{
  /* It must be safe to delete null pointers. */
  /* This matches the semantics of C++'s delete operator. */
  if (vio)
  {
    if (vio->type != VIO_CLOSED)
      vio_close(vio);
    my_free(vio->cache);
    my_free(vio);
  }
}

int vio_errno(Vio *vio __attribute__((unused)))
{
  return socket_errno; /* On Win32 this mapped to WSAGetLastError() */
}

int vio_wait_or_timeout(Vio *vio, my_bool is_read, int timeout)
{
  int rc;
#ifndef _WIN32
  struct pollfd p_fd;
#else
  struct timeval tv= {0,0};
  fd_set fds, exc_fds;
#endif

  /* we don't support it via named pipes yet.
   * maybe this could be handled via PeekNamedPipe somehow !? */
  if (vio->type == VIO_TYPE_NAMEDPIPE)
    return 1;

  /*
    Note that if zero timeout, then we will not block, so we do not need to
    yield to calling application in the async case.
  */
  if (timeout != 0 && vio->async_context && vio->async_context->active)
  {
    rc= my_io_wait_async(vio->async_context,
                         (is_read) ? VIO_IO_EVENT_READ : VIO_IO_EVENT_WRITE,
                         timeout);
    return(rc);
  }
  else
  {
#ifndef _WIN32
    p_fd.fd= vio->sd;
    p_fd.events= (is_read) ? POLLIN : POLLOUT;

    do {
      rc= poll(&p_fd, 1, timeout);
    } while (rc == -1 || errno == EINTR);

    if (rc == 0)
      errno= ETIMEDOUT;
#else
    FD_ZERO(&fds);
    FD_ZERO(&exc_fds);

    FD_SET(vio->sd, &fds);
    FD_SET(vio->sd, &exc_fds);

    if (timeout >= 0)
    {
      tv.tv_sec= timeout / 1000;
      tv.tv_usec= (timeout % 1000) * 1000;
    }

    rc= select(0, (is_read) ? &fds : NULL,
                  (is_read) ? NULL : &fds,
                  &exc_fds, 
                  (timeout >= 0) ? &tv : NULL);
    if (rc == SOCKET_ERROR)
      errno= WSAGetLastError();
    if (rc == 0)
      errno= ETIMEDOUT;
#endif
  }
  return rc;
}


size_t vio_real_read(Vio *vio, gptr buf, size_t size)
{
  size_t r;

  switch(vio->type) {
#ifdef HAVE_OPENSSL
  case VIO_TYPE_SSL:
    return my_ssl_read(vio, (char *)buf, size);
    break;
#endif
#ifdef _WIN32
  case VIO_TYPE_NAMEDPIPE:
    {
      DWORD length= 0;
      if (!ReadFile(vio->hPipe, buf, (DWORD)size, &length, NULL))
        return -1;
      return length;
    }
    break;
#endif
  default:
    if (vio->async_context && vio->async_context->active)
      r= my_recv_async(vio->async_context,
                       vio->sd,
                       buf, size, vio->read_timeout);
    else
    {
      if (vio->async_context)
      {
        /*
          If switching from non-blocking to blocking API usage, set the socket
          back to blocking mode.
        */
        my_bool old_mode;
        vio_blocking(vio, TRUE, &old_mode);
      }
#ifndef _WIN32
      do {
        r= read(vio->sd, buf, size);
      } while (r == -1 && errno == EINTR);

      while (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)
                      && vio->read_timeout > 0)
      {
        if (vio_wait_or_timeout(vio, TRUE, vio->write_timeout) < 1)
          return 0;
        do {
          r= read(vio->sd, buf, size);
        } while (r == -1 && errno == EINTR);
      }
#else
      {
        WSABUF wsaData;
        DWORD dwBytes = 0;
        DWORD flags = 0;

        wsaData.len= size;
        wsaData.buf= buf;

        if (WSARecv(vio->sd, &wsaData, 1, &dwBytes, &flags, NULL, NULL) == SOCKET_ERROR)
        {
          errno= WSAGetLastError();
          return 0;
        }
        r= (size_t)dwBytes;
      }
#endif
    }
    break;
  }
  return r;
}


size_t vio_read(Vio * vio, gptr buf, size_t size)
{
  size_t r;
  DBUG_ENTER("vio_read");
  DBUG_PRINT("enter", ("sd=%d  size=%d", vio->sd, size));

  if (!vio->cache)
    DBUG_RETURN(vio_real_read(vio, buf, size));

  if (vio->cache + vio->cache_size > vio->cache_pos)
  {
    r= MIN(size, (size_t)(vio->cache + vio->cache_size - vio->cache_pos));
    memcpy(buf, vio->cache_pos, r);
    vio->cache_pos+= r;
  }
  else if (size >= VIO_CACHE_MIN_SIZE)
  {
    r= vio_real_read(vio, buf, size); 
  }
  else
  {
    r= vio_real_read(vio, vio->cache, VIO_CACHE_SIZE);
    if (r > 0)
    {
      if (size < r)
      {
        vio->cache_size= r; /* might be < VIO_CACHE_SIZE */
        vio->cache_pos= vio->cache + size;
        r= size;
      }
      memcpy(buf, vio->cache, r);
    }
  } 

#ifndef DBUG_OFF
  if ((size_t)r == -1)
  {
    DBUG_PRINT("vio_error", ("Got error %d during read",socket_errno));
  }
#endif /* DBUG_OFF */
  DBUG_PRINT("exit", ("%u", (uint)r));
  DBUG_RETURN(r);
}

/*
 Return data from the beginning of the receive queue without removing 
 that data from the queue. A subsequent receive call will return the same data.
*/
my_bool vio_read_peek(Vio *vio, size_t *bytes)
{
#ifdef _WIN32
  if (ioctlsocket(vio->sd, FIONREAD, (unsigned long*)bytes))
    return TRUE;
#else
  char buffer[1024];
  ssize_t length;

  vio_blocking(vio, 0, 0);
  length= recv(vio->sd, &buffer, sizeof(buffer), MSG_PEEK);
  if (length < 0)
    return TRUE;
  *bytes= length; 
#endif 
  return FALSE;
}


size_t vio_write(Vio * vio, const gptr buf, size_t size)
{
  size_t r;
  DBUG_ENTER("vio_write");
  DBUG_PRINT("enter", ("sd=%d  size=%d", vio->sd, size));
#ifdef HAVE_OPENSSL
  if (vio->type == VIO_TYPE_SSL)
  {
    r= my_ssl_write(vio, (uchar *)buf, size);
    DBUG_RETURN(r); 
  }
#endif
#ifdef _WIN32
  if ( vio->type == VIO_TYPE_NAMEDPIPE)
  {
    DWORD length;
    if (!WriteFile(vio->hPipe, (char*) buf, (DWORD)size, &length, NULL))
      DBUG_RETURN(-1);
    DBUG_RETURN(length);
  }
#endif
  if (vio->async_context && vio->async_context->active)
    r= my_send_async(vio->async_context, vio->sd, buf, size,
                     vio->write_timeout);
  else
  {
    if (vio->async_context)
    {
      /*
        If switching from non-blocking to blocking API usage, set the socket
        back to blocking mode.
      */
      my_bool old_mode;
      vio_blocking(vio, TRUE, &old_mode);
    }
#ifndef _WIN32
    do {
      r= send(vio->sd, buf, size, vio->write_timeout ? MSG_DONTWAIT : MSG_WAITALL);
    } while (r == -1 && errno == EINTR);

    while (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
           vio->write_timeout > 0)
    {
      if (vio_wait_or_timeout(vio, FALSE, vio->write_timeout) < 1)
        return 0;
      do {
        r= send(vio->sd, buf, size, vio->write_timeout ? MSG_DONTWAIT : MSG_WAITALL);
      } while (r == -1 && errno == EINTR);
    }
#else
    {
      WSABUF wsaData;
      DWORD dwBytes = 0;

      wsaData.len= size;
      wsaData.buf= (char *)buf;

      if (WSASend(vio->sd, &wsaData, 1, &dwBytes, 0, NULL, NULL) == SOCKET_ERROR)
      {
        errno= WSAGetLastError();
        DBUG_RETURN(0);
      }
      r= (size_t)dwBytes;
    }
#endif
  }
#ifndef DBUG_OFF
  if ((size_t)r == -1)
  {
    DBUG_PRINT("vio_error", ("Got error on write: %d",socket_errno));
  }
#endif /* DBUG_OFF */
  DBUG_PRINT("exit", ("%u", (uint)r));
  DBUG_RETURN(r);
}


int vio_blocking(Vio *vio, my_bool block, my_bool *previous_mode)
{
  int *sd_flags= &vio->fcntl_mode;
  int save_flags= vio->fcntl_mode;
  my_bool tmp;
  my_socket sock= vio->sd;

  if (vio->type == VIO_TYPE_NAMEDPIPE)
    return 0;

  if (!previous_mode)
    previous_mode= &tmp;

#ifdef _WIN32
  *previous_mode= (*sd_flags & O_NONBLOCK) != 0;
  *sd_flags = (block) ? *sd_flags & ~O_NONBLOCK : *sd_flags | O_NONBLOCK;
  {
    ulong arg= 1 - block;
    if (ioctlsocket(sock, FIONBIO, (void *)&arg))
    {
      vio->fcntl_mode= save_flags;
      return(WSAGetLastError());
    }
  }
#else
#if defined(O_NONBLOCK)
  *previous_mode= (*sd_flags & O_NONBLOCK) != 0;
  *sd_flags = (block) ? *sd_flags & ~O_NONBLOCK : *sd_flags | O_NONBLOCK;
#elif defined(O_NDELAY)
  *previous_mode= (*sd_flags & O_NODELAY) != 0;
  *sd_flags = (block) ? *sd_flags & ~O_NODELAY : *sd_flags | O_NODELAY;
#elif defined(FNDELAY)
  *previous_mode= (*sd_flags & O_FNDELAY) != 0;
  *sd_flags = (block) ? *sd_flags & ~O_FNDELAY : *sd_flags | O_FNDELAY;
#else
#error socket blocking is not supported on this platform
#endif
  if (fcntl(sock, F_SETFL, *sd_flags) == -1)
  {
    vio->fcntl_mode= save_flags;
    return errno;
  }
#endif
  return 0;
}

my_bool
vio_is_blocking(Vio * vio)
{
  my_bool r;
  DBUG_ENTER("vio_is_blocking");
  r = !(vio->fcntl_mode & O_NONBLOCK);
  DBUG_PRINT("exit", ("%d", (int) r));
  DBUG_RETURN(r);
}


int vio_fastsend(Vio * vio __attribute__((unused)))
{
  int r=0;
  DBUG_ENTER("vio_fastsend");

  {
#ifdef IPTOS_THROUGHPUT
    int tos = IPTOS_THROUGHPUT;
    if (!setsockopt(vio->sd, IPPROTO_IP, IP_TOS, (void *) &tos, sizeof(tos)))
#endif /* IPTOS_THROUGHPUT */
    {
      int nodelay = 1;
      if (setsockopt(vio->sd, IPPROTO_TCP, TCP_NODELAY, (void *) &nodelay,
                     sizeof(nodelay))) {
        DBUG_PRINT("warning",
                   ("Couldn't set socket option for fast send"));
        r= -1;
      }
    }
  }
  DBUG_PRINT("exit", ("%d", r));
  DBUG_RETURN(r);
}

int vio_keepalive(Vio* vio, my_bool set_keep_alive)
{
  int r=0;
  uint opt = 0;
  DBUG_ENTER("vio_keepalive");
  DBUG_PRINT("enter", ("sd=%d  set_keep_alive=%d", vio->sd, (int)
              set_keep_alive));
  if (vio->type != VIO_TYPE_NAMEDPIPE)
  {
    if (set_keep_alive)
      opt = 1;
    r = setsockopt(vio->sd, SOL_SOCKET, SO_KEEPALIVE, (char *) &opt,
                   sizeof(opt));
  }
  DBUG_RETURN(r);
}


my_bool
vio_should_retry(Vio * vio __attribute__((unused)))
{
  int en = socket_errno;
  return en == SOCKET_EAGAIN || en == SOCKET_EINTR || en == SOCKET_EWOULDBLOCK;
}


int vio_close(Vio * vio)
{
  int r;
  DBUG_ENTER("vio_close");
#ifdef HAVE_OPENSSL
  if (vio->type == VIO_TYPE_SSL)
  {
    r = my_ssl_close(vio);
  }
#endif
#ifdef _WIN32
  if (vio->type == VIO_TYPE_NAMEDPIPE)
  {
    r=CloseHandle(vio->hPipe);
  }
  else if (vio->type != VIO_CLOSED)
#endif /* _WIN32 */
  {
    r=0;
    if (shutdown(vio->sd,2))
      r= -1;
    if (closesocket(vio->sd))
      r= -1;
  }
  if (r)
  {
    DBUG_PRINT("vio_error", ("close() failed, error: %d",socket_errno));
    /* FIXME: error handling (not critical for MySQL) */
  }
  vio->type= VIO_CLOSED;
  vio->sd=   -1;
  DBUG_RETURN(r);
}


const char *vio_description(Vio * vio)
{
  return vio->desc;
}

enum enum_vio_type vio_type(Vio* vio)
{
  return vio->type;
}

my_socket vio_fd(Vio* vio)
{
  return vio->sd;
}


my_bool vio_peer_addr(Vio * vio, char *buf)
{
  DBUG_ENTER("vio_peer_addr");
  DBUG_PRINT("enter", ("sd=%d", vio->sd));
  if (vio->localhost)
  {
    strmov(buf,"127.0.0.1");
  }
  else
  {
    socklen_t addrLen = sizeof(struct sockaddr);
    if (getpeername(vio->sd, (struct sockaddr *) (& (vio->remote)),
        &addrLen) != 0)
    {
      DBUG_PRINT("exit", ("getpeername, error: %d", socket_errno));
      DBUG_RETURN(1);
    }
    my_inet_ntoa(vio->remote.sin_addr,buf);
  }
  DBUG_PRINT("exit", ("addr=%s", buf));
  DBUG_RETURN(0);
}


void vio_in_addr(Vio *vio, struct in_addr *in)
{
  DBUG_ENTER("vio_in_addr");
  if (vio->localhost)
    bzero((char*) in, sizeof(*in)); /* This should never be executed */
  else
    *in=vio->remote.sin_addr;
  DBUG_VOID_RETURN;
}


/* Return 0 if there is data to be read */
/*
my_bool vio_poll_read(Vio *vio,uint timeout)
{
#ifndef HAVE_POLL
  return 0;
#else
  struct pollfd fds;
  int res;
  DBUG_ENTER("vio_poll");
  fds.fd=vio->sd;
  fds.events=POLLIN;
  fds.revents=0;
  if ((res=poll(&fds,1,(int) timeout*1000)) <= 0)
  {
    DBUG_RETURN(res < 0 ? 0 : 1); 
  }
  DBUG_RETURN(fds.revents & POLLIN ? 0 : 1);
#endif
}
*/

#endif /* HAVE_VIO */
