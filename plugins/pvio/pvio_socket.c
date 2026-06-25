/************************************************************************************
   Copyright (C) 2015,2016 MariaDB Corporation AB,
   
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

/* 
   MariaDB virtual IO plugin for socket communication:

   The plugin handles connections via unix and network sockets. it is enabled by
   default and compiled into Connector/C.
*/

#include <ma_global.h>
#include <ma_sys.h>
#include <errmsg.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <ma_context.h>
#include <mariadb_async.h>
#include <ma_common.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_POLL
#include <poll.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/tcp.h>
#define IS_SOCKET_EINTR(err) ((err) == SOCKET_EINTR)
#else
#include <ws2tcpip.h>
#define O_NONBLOCK 1
#define IS_SOCKET_EINTR(err) 0
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#define DNS_TIMEOUT 30

#ifndef O_NONBLOCK
#if defined(O_NDELAY)
#define O_NONBLOCK O_NODELAY
#elif defined (O_FNDELAY)
#define O_NONBLOCK O_FNDELAY
#else
#error socket blocking is not supported on this platform
#endif
#endif

/* Function prototypes */
my_bool pvio_socket_set_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type, int timeout);
int pvio_socket_get_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type);
ssize_t pvio_socket_read(MARIADB_PVIO *pvio, uchar *buffer, size_t length);
ssize_t pvio_socket_write(MARIADB_PVIO *pvio, const uchar *buffer, size_t length);
int pvio_socket_wait_io_or_timeout(MARIADB_PVIO *pvio, my_bool is_read, int timeout);
my_bool pvio_socket_connect(MARIADB_PVIO *pvio, MA_PVIO_CINFO *cinfo);
my_bool pvio_socket_close(MARIADB_PVIO *pvio);
int pvio_socket_fast_send(MARIADB_PVIO *pvio);
int pvio_socket_keepalive(MARIADB_PVIO *pvio);
my_bool pvio_socket_get_handle(MARIADB_PVIO *pvio, void *handle);
my_bool pvio_socket_is_alive(MARIADB_PVIO *pvio);
my_bool pvio_socket_has_data(MARIADB_PVIO *pvio, ssize_t *data_len);
int pvio_socket_shutdown(MARIADB_PVIO *pvio);

static int pvio_socket_init(char *unused1, 
                           size_t unused2, 
                           int unused3, 
                           va_list);
static int pvio_socket_end(void);
static ssize_t ma_send(my_socket socket, const uchar *buffer, size_t length, int flags);
static ssize_t ma_recv(my_socket socket, uchar *buffer, size_t length, int flags);

struct st_ma_pvio_methods pvio_socket_methods= {
  pvio_socket_set_timeout,
  pvio_socket_get_timeout,
  pvio_socket_read,
  pvio_socket_write,
  pvio_socket_wait_io_or_timeout,
  pvio_socket_connect,
  pvio_socket_close,
  pvio_socket_fast_send,
  pvio_socket_keepalive,
  pvio_socket_get_handle,
  pvio_socket_is_alive,
  pvio_socket_has_data,
  pvio_socket_shutdown
};

#ifndef PLUGIN_DYNAMIC
MARIADB_PVIO_PLUGIN pvio_socket_client_plugin=
#else
MARIADB_CLIENT_PLUGIN_EXPORT MARIADB_PVIO_PLUGIN
    _mysql_client_plugin_declaration_=
#endif
{
  MARIADB_CLIENT_PVIO_PLUGIN,
  MARIADB_CLIENT_PVIO_PLUGIN_INTERFACE_VERSION,
  "pvio_socket",
  "Georg Richter",
  "MariaDB virtual IO plugin for socket communication",
  {1, 0, 0},
  "LGPL",
  NULL,
  &pvio_socket_init,
  &pvio_socket_end,
  NULL,
  &pvio_socket_methods
};

struct st_pvio_socket {
  my_socket socket;
  MYSQL *mysql;
};

/*
  Create a socket that is non-blocking from the start.  The socket is used in
  non-blocking mode throughout its whole lifetime; timeouts for the synchronous
  API are layered on top via poll()/select() in
  pvio_socket_wait_io_or_timeout().  Returns INVALID_SOCKET on failure.
*/
static my_socket new_nonblocking_socket(int domain, int type, int protocol)
{
  my_socket fd= socket(domain, type, protocol);
  if (fd == INVALID_SOCKET)
    return INVALID_SOCKET;
#ifdef _WIN32
  {
    ulong arg= 1;
    if (ioctlsocket(fd, FIONBIO, &arg))
      goto error;
  }
#else
  {
    int flags= fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
      goto error;
  }
#endif
  return fd;
error:
  closesocket(fd);
  return INVALID_SOCKET;
}

static my_bool pvio_socket_initialized= FALSE;

static int pvio_socket_init(char *errmsg __attribute__((unused)),
                           size_t errmsg_length __attribute__((unused)), 
                           int unused __attribute__((unused)), 
                           va_list va __attribute__((unused)))
{
  pvio_socket_initialized= TRUE;
  return 0;
}

static int pvio_socket_end(void)
{
  if (!pvio_socket_initialized)
    return 1;
  return 0;
}

/* {{{ pvio_socket_set_timeout */
/*
   set timeout value

   SYNOPSIS
     pvio_socket_set_timeout
     pvio            PVIO
     type           timeout type (connect, read, write)
     timeout        timeout in seconds

   DESCRIPTION
     Sets timeout values for connection-, read or write time out.
     PVIO internally stores all timeout values in milliseconds, but
     accepts and returns all time values in seconds (like api does).

     Timeouts are not applied to the socket itself (e.g. via SO_RCVTIMEO/
     SO_SNDTIMEO): the socket is always non-blocking and the stored value
     is used by pvio_socket_wait_io_or_timeout() to drive poll()/select().

   RETURNS
     0              Success
     1              Error
*/
my_bool pvio_socket_set_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type, int timeout)
{
  if (!pvio)
    return 1;
  pvio->timeout[type]= (timeout > 0) ? timeout * 1000 : -1;
  return 0;
}
/* }}} */

/* {{{ pvio_socket_get_timeout */
/*
   get timeout value

   SYNOPSIS
     pvio_socket_get_timeout
     pvio            PVIO
     type           timeout type (connect, read, write)

   DESCRIPTION
     Returns timeout values for connection-, read or write time out.
     PVIO internally stores all timeout values in milliseconds, but 
     accepts and returns all time values in seconds (like api does).

   RETURNS
      0...n         time out value
     -1             error
*/
int pvio_socket_get_timeout(MARIADB_PVIO *pvio, enum enum_pvio_timeout type)
{
  if (!pvio)
    return -1;
  return pvio->timeout[type] / 1000;
}
/* }}} */

/* {{{ pvio_socket_read */
/*
   read from socket

   SYNOPSIS
   pvio_socket_read()
     pvio             PVIO
     buffer          read buffer
     length          buffer length

   DESCRIPTION
     reads up to length bytes into specified buffer. In the event of an
     error erno is set to indicate it.

   RETURNS
      1..n           number of bytes read
      0              peer has performed shutdown
     -1              on error
                     
*/   
ssize_t pvio_socket_read(MARIADB_PVIO *pvio, uchar *buffer, size_t length)
{
  ssize_t r;
  int timeout;
  struct st_pvio_socket *csock;

  if (!pvio || !pvio->data)
    return -1;

  csock= (struct st_pvio_socket *)pvio->data;
  timeout= pvio->timeout[PVIO_READ_TIMEOUT];

  /* The socket is non-blocking. In synchronous mode ma_pvio_wait_io_or_timeout()
     blocks the calling thread via poll()/select(); in asynchronous mode it
     suspends the fiber (my_context_yield()). Either way the same loop serves
     both, so there is no separate async read path. */
  while ((r= ma_recv(csock->socket, buffer, length, 0)) == -1)
  {
    if (!ma_socket_wouldblock(socket_errno) || timeout == 0)
      return r;
    if (ma_pvio_wait_io_or_timeout(pvio, TRUE, timeout) < 1)
      return -1;
  }
  return r;
}
/* }}} */

/* send() flags: ask the kernel to suppress SIGPIPE where the flag exists.
   On platforms without it ma_send() falls back to blocking the signal. */
#ifdef MSG_NOSIGNAL
#define MA_SEND_FLAGS MSG_NOSIGNAL
#else
#define MA_SEND_FLAGS 0
#endif

static ssize_t ma_send(my_socket socket, const uchar *buffer, size_t length, int flags)
{
  ssize_t r;
#if !defined(MSG_NOSIGNAL) && !defined(SO_NOSIGPIPE) && !defined(_WIN32)
  struct sigaction act, oldact;
  act.sa_handler= SIG_IGN;
  sigaction(SIGPIPE, &act, &oldact);
#endif
  do {
    r = send(socket, (const char *)buffer, IF_WIN((int)length,length), flags);
  }
  while (r == -1 && IS_SOCKET_EINTR(socket_errno));
#if !defined(MSG_NOSIGNAL) && !defined(SO_NOSIGPIPE) && !defined(_WIN32)
  sigaction(SIGPIPE, &oldact, NULL);
#endif
  return r;
}

static ssize_t ma_recv(my_socket socket, uchar *buffer, size_t length, int flags)
{
  ssize_t r;
  do {
   r = recv(socket, (char*) buffer, IF_WIN((int)length, length), flags);
  }
  while (r == -1 && IS_SOCKET_EINTR(socket_errno));
  return r;
}

/* {{{ pvio_socket_write */
/*
   write to socket

   SYNOPSIS
   pvio_socket_write()
     pvio             PVIO
     buffer          read buffer
     length          buffer length

   DESCRIPTION
     writes up to length bytes to socket. In the event of an
     error erno is set to indicate it.

   RETURNS
      1..n           number of bytes read
      0              peer has performed shutdown
     -1              on error
                     
*/
ssize_t pvio_socket_write(MARIADB_PVIO *pvio, const uchar *buffer, size_t length)
{
  ssize_t r;
  int timeout;
  struct st_pvio_socket *csock;

  if (!pvio || !pvio->data)
    return -1;

  csock= (struct st_pvio_socket *)pvio->data;
  timeout= pvio->timeout[PVIO_WRITE_TIMEOUT];

  /* See pvio_socket_read(): ma_pvio_wait_io_or_timeout() either blocks the
     thread (sync) or suspends the fiber (async). */
  while ((r= ma_send(csock->socket, buffer, length, MA_SEND_FLAGS)) == -1)
  {
    if (!ma_socket_wouldblock(socket_errno) || timeout == 0)
      return r;
    if (ma_pvio_wait_io_or_timeout(pvio, FALSE, timeout) < 1)
      return -1;
  }
  return r;
}
/* }}} */

int pvio_socket_wait_io_or_timeout(MARIADB_PVIO *pvio, my_bool is_read, int timeout)
{
  int rc;
  struct st_pvio_socket *csock= NULL;

#ifndef _WIN32
  struct pollfd p_fd;
#else
  struct timeval tv= {0,0};
  fd_set fds, exc_fds;
#endif

  if (!pvio || !pvio->data)
    return 0;

  if (pvio->mysql->options.extension && 
      pvio->mysql->options.extension->io_wait != NULL) {
    my_socket handle;
    if (pvio_socket_get_handle(pvio, &handle))
      return 0;
    return pvio->mysql->options.extension->io_wait(handle, is_read, timeout);
  }

  csock= (struct st_pvio_socket *)pvio->data;
  {
#ifndef _WIN32
    struct timespec start;
    int remaining;

    memset(&p_fd, 0, sizeof(p_fd));
    p_fd.fd= csock->socket;
    p_fd.events= (is_read) ? POLLIN : POLLOUT;

    if (!timeout)
      timeout= -1;

    remaining= timeout;

    if (timeout > 0)
      clock_gettime(CLOCK_MONOTONIC, &start);

    for (;;) {
      rc= poll(&p_fd, 1, remaining);

      if (rc != -1 || errno != EINTR)
        break;

      if (timeout > 0)
      {
        struct timespec now;
        long long elapsed_ms;

        clock_gettime(CLOCK_MONOTONIC, &now);

        /* Calculate elapsed time utilizing a long long to safely avoid int wrapping */
        elapsed_ms= (now.tv_sec - start.tv_sec) * 1000LL + 
                    (now.tv_nsec - start.tv_nsec) / 1000000LL;

        remaining= timeout - (int)elapsed_ms;

        if (remaining <= 0)
        {
          rc= 0; /* Budget exhausted, force a timeout return */
          break;
        }
      }
    }

    if (rc == 0)
      errno= ETIMEDOUT;

#else
    FD_ZERO(&fds);
    FD_ZERO(&exc_fds);

    FD_SET(csock->socket, &fds);
    FD_SET(csock->socket, &exc_fds);

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
    {
      errno= WSAGetLastError();
    }
    else if (rc == 0)
    {
      rc= SOCKET_ERROR;
      WSASetLastError(WSAETIMEDOUT);
      errno= ETIMEDOUT;
    }
    else if (FD_ISSET(csock->socket, &exc_fds))
    {
      int err;
      int len = sizeof(int);
      if (getsockopt(csock->socket, SOL_SOCKET, SO_ERROR, (char *)&err, &len) != SOCKET_ERROR)
      {
        WSASetLastError(err);
        errno= err;
      }
      rc= SOCKET_ERROR;
    }
   
#endif
  }
  return rc;
}

static int pvio_socket_internal_connect(MARIADB_PVIO *pvio,
                                       const struct sockaddr *name, 
                                       size_t namelen)
{
  int rc= 0;
  struct st_pvio_socket *csock= NULL;
  int timeout;
#ifndef _WIN32
  unsigned int wait_conn= 1;
  time_t start_t= time(NULL);
#endif

  if (!pvio || !pvio->data)
    return 1;

  csock= (struct st_pvio_socket *)pvio->data;
  timeout= pvio->timeout[PVIO_CONNECT_TIMEOUT];

#ifndef _WIN32
  do {
    int save_errno;
    rc= connect(csock->socket, (struct sockaddr*) name, (int)namelen);

    if (time(NULL) - start_t > (time_t)timeout/1000)
      break;

    /* CONC-612: Since usleep may fail and will set errno (On MacOSX usleep
      always sets errno=ETIMEDOUT), we need to save and restore errno */
    save_errno= errno;
    usleep(wait_conn);
    errno= save_errno;

    wait_conn= wait_conn >= 1000000 ? 1000000 : wait_conn * 2;

  } while (rc == -1 && (errno == EINTR || errno == EAGAIN));
  /* in case a timeout values was set we need to check error values
     EINPROGRESS */
  if (timeout != 0 && rc == -1 && errno == EINPROGRESS)
  {
    rc= pvio_socket_wait_io_or_timeout(pvio, FALSE, timeout);
    if (rc < 1)
      return -1;
    {
      int error;
      socklen_t error_len= sizeof(error);
      if ((rc = getsockopt(csock->socket, SOL_SOCKET, SO_ERROR, 
                           (char *)&error, &error_len)) < 0)
        return errno;
      else if (error) 
        return error;
    }
  }
#ifdef __APPLE__
  if (csock->socket)
  {
    int val= 1;
    setsockopt(csock->socket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&val, sizeof(int));
  }
#endif
#else
  rc= connect(csock->socket, (struct sockaddr*) name, (int)namelen);
  if (rc == SOCKET_ERROR)
  {
    if (WSAGetLastError() == WSAEWOULDBLOCK)
    {
      if (pvio_socket_wait_io_or_timeout(pvio, FALSE, timeout) < 0)
        return -1;
      rc= 0;
    }
  }
#endif
  return rc;
}

int pvio_socket_keepalive(MARIADB_PVIO *pvio)
{
  int opt= 1;
  struct st_pvio_socket *csock= NULL;

  if (!pvio || !pvio->data)
    return 1;

  csock= (struct st_pvio_socket *)pvio->data;

  return setsockopt(csock->socket, SOL_SOCKET, SO_KEEPALIVE,
#ifndef _WIN32
               (const void *)&opt, sizeof(opt));
#else
               (char *)&opt, (int)sizeof(opt));
#endif
}

int pvio_socket_fast_send(MARIADB_PVIO *pvio)
{
  int r= 0;
  struct st_pvio_socket *csock= NULL;

  if (!pvio || !pvio->data)
    return 1;

  csock= (struct st_pvio_socket *)pvio->data;

/* Setting IP_TOS is not recommended on Windows. See 
   http://msdn.microsoft.com/en-us/library/windows/desktop/ms738586(v=vs.85).aspx
*/
#if !defined(_WIN32) && defined(IPTOS_THROUGHPUT)
  {
    int tos = IPTOS_THROUGHPUT;
    r= setsockopt(csock->socket, IPPROTO_IP, IP_TOS,
	                         (const void *)&tos, sizeof(tos));
  }
#endif /* !_WIN32 && IPTOS_THROUGHPUT */
  if (!r)
  {
    int opt = 1;
    /* turn off nagle algorithm */
    r= setsockopt(csock->socket, IPPROTO_TCP, TCP_NODELAY,
#ifdef _WIN32
                  (const char *)&opt, (int)sizeof(opt));
#else
                  (const void *)&opt, sizeof(opt));
#endif
  }
  return r;
}

static int
pvio_socket_connect_async(MARIADB_PVIO *pvio,
                          const struct sockaddr *name, uint namelen)
{
  MYSQL *mysql= pvio->mysql;
  mysql->options.extension->async_context->pvio= pvio;
  return my_connect_async(pvio, name, namelen, pvio->timeout[PVIO_CONNECT_TIMEOUT]);
}

static int
pvio_socket_connect_sync_or_async(MARIADB_PVIO *pvio,
                          const struct sockaddr *name, uint namelen)
{
  MYSQL *mysql= pvio->mysql;
  if (mysql->options.extension && mysql->options.extension->async_context &&
      mysql->options.extension->async_context->active)
  {
    /* even if we are not connected yet, application needs to check socket
     * via mysql_get_socket api call, so we need to assign pvio */
    return pvio_socket_connect_async(pvio, name, namelen);
  }

  return pvio_socket_internal_connect(pvio, name, namelen);
}

my_bool pvio_socket_connect(MARIADB_PVIO *pvio, MA_PVIO_CINFO *cinfo)
{
  struct st_pvio_socket *csock= NULL;
  MYSQL *mysql;

  if (!pvio || !cinfo)
    return 1;

  if (!(csock= (struct st_pvio_socket *)calloc(1, sizeof(struct st_pvio_socket))))
  {
    PVIO_SET_ERROR(cinfo->mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0, "");
    return 1;
  }
  pvio->data= (void *)csock;
  csock->socket= INVALID_SOCKET;
  mysql= pvio->mysql= cinfo->mysql;
  pvio->type= cinfo->type;

  if (cinfo->type == PVIO_TYPE_UNIXSOCKET)
  {
#ifndef _WIN32
#ifdef HAVE_SYS_UN_H
    size_t port_length;
    struct sockaddr_un UNIXaddr;
    if ((csock->socket = new_nonblocking_socket(AF_UNIX,SOCK_STREAM,0)) == INVALID_SOCKET ||
        (port_length=strlen(cinfo->unix_socket)) >= (sizeof(UNIXaddr.sun_path)))
    {
      PVIO_SET_ERROR(cinfo->mysql, CR_SOCKET_CREATE_ERROR, unknown_sqlstate, 0, errno);
      goto error;
    }
    memset((char*) &UNIXaddr, 0, sizeof(UNIXaddr));
    UNIXaddr.sun_family = AF_UNIX;
#if defined(__linux__)
    /* Abstract socket */
    if (cinfo->unix_socket[0] == '@')
    {
      strncpy(UNIXaddr.sun_path + 1, cinfo->unix_socket + 1, 106);
      port_length+= offsetof(struct sockaddr_un, sun_path);
    }
    else
#endif
    {
      size_t sun_path_size = sizeof(UNIXaddr.sun_path);
      strncpy(UNIXaddr.sun_path, cinfo->unix_socket, sun_path_size - 1);
      if (sun_path_size == strlen(UNIXaddr.sun_path) + 1 && UNIXaddr.sun_path[sun_path_size - 1] != '\0')
      {
        /* Making the string null-terminated */
        UNIXaddr.sun_path[sun_path_size - 1] = '\0';
      }
      port_length= sizeof(UNIXaddr);
    }
    if (pvio_socket_connect_sync_or_async(pvio, (struct sockaddr *) &UNIXaddr, port_length))
    {
      PVIO_SET_ERROR(cinfo->mysql, CR_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                    ER(CR_CONNECTION_ERROR), cinfo->unix_socket, socket_errno);
      goto error;
    }
#else
/* todo: error, not supported */
#endif
#endif
  } else if (cinfo->type == PVIO_TYPE_SOCKET)
  {
    struct addrinfo hints, *save_res= 0, *bind_res= 0, *res= 0, *bres= 0;
    char server_port[NI_MAXSERV];
    int gai_rc;
    int rc= 0;
    time_t start_t= time(NULL);
#ifdef _WIN32
    DWORD wait_gai;
#else
    unsigned int wait_gai;
#endif

    memset(&server_port, 0, NI_MAXSERV);
    snprintf(server_port, NI_MAXSERV, "%d", cinfo->port);

    /* set hints for getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_protocol= IPPROTO_TCP; /* TCP connections only */
    hints.ai_family= AF_UNSPEC;     /* includes: IPv4, IPv6 or hostname */
    hints.ai_socktype= SOCK_STREAM;

    /* if client has multiple interfaces, we will bind socket to given
     * bind_address */
    if (cinfo->mysql->options.bind_address)
    {
      wait_gai= 1;
      while ((gai_rc= getaddrinfo(cinfo->mysql->options.bind_address, 0,
                          &hints, &bind_res)) == EAI_AGAIN)
      {
        unsigned int timeout= mysql->options.connect_timeout ?
                              mysql->options.connect_timeout : DNS_TIMEOUT;
        if (time(NULL) - start_t > (time_t)timeout)
          break;
#ifndef _WIN32
        usleep(wait_gai);
#else
        Sleep(wait_gai);
#endif
        wait_gai*= 2;
      }
      if (gai_rc != 0 || !bind_res)
      {
        PVIO_SET_ERROR(cinfo->mysql, CR_BIND_ADDR_FAILED, SQLSTATE_UNKNOWN, 
                     CER(CR_BIND_ADDR_FAILED), cinfo->mysql->options.bind_address, gai_rc);
        goto error;
      }
    }
    /* Get the address information for the server using getaddrinfo() */
    wait_gai= 1;
    while ((gai_rc= getaddrinfo(cinfo->host, server_port,
                                &hints, &res)) == EAI_AGAIN)
    {
      unsigned int timeout= mysql->options.connect_timeout ?
                            mysql->options.connect_timeout : DNS_TIMEOUT;
      if (time(NULL) - start_t > (time_t)timeout)
        break;
#ifndef _WIN32
      usleep(wait_gai);
#else
      Sleep(wait_gai);
#endif
      wait_gai*= 2;
    }
    if (gai_rc != 0 || !res)
    {
      PVIO_SET_ERROR(cinfo->mysql, CR_UNKNOWN_HOST, SQLSTATE_UNKNOWN, 
                   ER(CR_UNKNOWN_HOST), cinfo->host, gai_rc);
      if (bind_res)
        freeaddrinfo(bind_res);
      goto error;
    }

    /* res is a linked list of addresses for the given hostname. We loop until
       we are able to connect to one address or all connect attempts failed */
    for (save_res= res; save_res; save_res= save_res->ai_next)
    {
      /* CONC-364: Avoid leak of open sockets */
      if (csock->socket != INVALID_SOCKET)
        closesocket(csock->socket);
      csock->socket= new_nonblocking_socket(save_res->ai_family, save_res->ai_socktype,
                                        save_res->ai_protocol);
      if (csock->socket == INVALID_SOCKET)
        /* Errors will be handled after loop finished */
        continue;

      if (bind_res)
      {
        for (bres= bind_res; bres; bres= bres->ai_next)
        {
          if (!(rc= bind(csock->socket, bres->ai_addr, (int)bres->ai_addrlen)))
            break;
        }
        if (rc)
        {
          closesocket(csock->socket);
          csock->socket= INVALID_SOCKET;
          continue;
        }
      }

      if (mysql->options.extension && mysql->options.extension->async_context &&
          mysql->options.extension->async_context->active)
      {
        mysql->options.extension->async_context->pending_gai_res = res;
        rc= pvio_socket_connect_async(pvio, save_res->ai_addr, (uint)save_res->ai_addrlen);
        mysql->options.extension->async_context->pending_gai_res = NULL;
      }
      else
      {
        rc= pvio_socket_connect_sync_or_async(pvio, save_res->ai_addr, (uint)save_res->ai_addrlen);
      }

      if (!rc)
        break; /* success! (socket was set non-blocking before connect) */
    }
 
    freeaddrinfo(res);
    if (bind_res)
      freeaddrinfo(bind_res);

    if (csock->socket == INVALID_SOCKET)
    {
      PVIO_SET_ERROR(cinfo->mysql, CR_IPSOCK_ERROR, SQLSTATE_UNKNOWN, ER(CR_IPSOCK_ERROR),
                         socket_errno);
      goto error;
    }

    /* last call to connect 2 failed */
    if (rc)
    {
      PVIO_SET_ERROR(cinfo->mysql, CR_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                     ER(CR_CONN_HOST_ERROR), cinfo->host,
#ifdef _WIN32
                     errno);
#else
                     socket_errno);
#endif
      goto error;
    }
  }
  /* The socket stays non-blocking: read/write timeouts are enforced via
     poll()/select() in pvio_socket_wait_io_or_timeout(), not setsockopt. */
  return 0;
error:
  /* close socket: MDEV-10891 */
  if (csock->socket != INVALID_SOCKET)
  {
    closesocket(csock->socket);
    csock->socket= INVALID_SOCKET;
  }
  if (pvio->data)
  {
    free((gptr)pvio->data);
    pvio->data= NULL;
  }
  return 1;
}

/* {{{ my_bool pvio_socket_close() */
my_bool pvio_socket_close(MARIADB_PVIO *pvio)
{
  struct st_pvio_socket *csock= NULL;
  int r= 0;

  if (!pvio)
    return 1;

  if (pvio->data)
  {
    csock= (struct st_pvio_socket *)pvio->data;
    if (csock && csock->socket != INVALID_SOCKET)
    {
      r= closesocket(csock->socket);
      csock->socket= INVALID_SOCKET;
    }
    free((gptr)pvio->data);
    pvio->data= NULL;
  }
  return r;
}
/* }}} */

/* {{{ my_socket pvio_socket_get_handle */
my_bool pvio_socket_get_handle(MARIADB_PVIO *pvio, void *handle)
{
  if (pvio && pvio->data && handle)
  {
    *(my_socket *)handle= ((struct st_pvio_socket *)pvio->data)->socket;
    return 0;
  }
  return 1;
}
/* }}} */

/* {{{ my_bool pvio_socket_is_alive(MARIADB_PVIO *pvio) */
my_bool pvio_socket_is_alive(MARIADB_PVIO *pvio)
{
  struct st_pvio_socket *csock= NULL;
 #ifndef _WIN32
  struct pollfd poll_fd;
#else
  FD_SET sfds;
  struct timeval tv= {0,0};
#endif
  int res;

  if (!pvio || !pvio->data)
    return 0;

  csock= (struct st_pvio_socket *)pvio->data;
#ifndef _WIN32
  memset(&poll_fd, 0, sizeof(struct pollfd));
  poll_fd.events= POLLPRI | POLLIN;
  poll_fd.fd= csock->socket;

  res= poll(&poll_fd, 1, 0);
  if (res <= 0) /* timeout or error */
    return TRUE;
  if (!(poll_fd.revents & (POLLIN | POLLPRI)))
    return TRUE;
  return FALSE;
#else
  /* We can't use the WSAPoll function, it's broken :-(
     (see Windows 8 Bugs 309411 - WSAPoll does not report failed connections)
     Instead we need to use select function:
     If TIMEVAL is initialized to {0, 0}, select will return immediately; 
     this is used to poll the state of the selected sockets.
  */
  FD_ZERO(&sfds);
  FD_SET(csock->socket, &sfds);

  res= select((int)csock->socket + 1, &sfds, NULL, NULL, &tv);
  if (res > 0 && FD_ISSET(csock->socket, &sfds))
    return FALSE;
  return TRUE;
#endif
}
/* }}} */

/* {{{ my_boool pvio_socket_has_data */
my_bool pvio_socket_has_data(MARIADB_PVIO *pvio, ssize_t *data_len)
{
  struct st_pvio_socket *csock= NULL;
  char tmp_buf;
  ssize_t len;

  if (!pvio || !pvio->data)
    return 0;

  csock= (struct st_pvio_socket *)pvio->data;
  /* MSG_PEEK: Peeks at the incoming data. The data is copied into the buffer,
      but is not removed from the input queue. The socket is always
      non-blocking, so the peek never blocks.
  */
  len= recv(csock->socket, &tmp_buf, sizeof(tmp_buf), MSG_PEEK);
  if (len < 0)
    return 1;
  *data_len= len;
  return 0;
}
/* }}} */

int pvio_socket_shutdown(MARIADB_PVIO *pvio)
{
  if (pvio && pvio->data)
  {
    my_socket s = ((struct st_pvio_socket *)pvio->data)->socket;
#ifdef _WIN32
    shutdown(s, SD_BOTH);
    CancelIoEx((HANDLE)s, NULL);
#else
    shutdown(s, SHUT_RDWR);
#endif
  }
  return -1;
}

