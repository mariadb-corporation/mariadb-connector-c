/*
  +----------------------------------------------------------------------+
  | PHP Version 6                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Andrey Hristov <andrey@php.net>                             |
  +----------------------------------------------------------------------+
*/
#if defined(__WIN__) || defined(_WIN32) || defined(_WIN64)
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
#include "mysql_io.h"
#include <stdlib.h>

#ifndef _WIN32
#ifdef HAVE_SIGNAL
#include <signal.h>
#endif
#endif

#define MYSQL_SOCK_CHUNK_SIZE	8192

#ifdef _WIN32
/* socklen_t */
#include <ws2tcpip.h>
#if HAVE_WSPIAPI_H
#include <wspiapi.h> /* getaddrinfo */
# endif
#define SOCK_ERR INVALID_SOCKET
#define SOCK_CONN_ERR SOCKET_ERROR
#define SOCK_RECV_ERR SOCKET_ERROR
#define mysql_socket_errno() WSAGetLastError()
#else /* else */
#undef closesocket
#define closesocket close
#define SOCK_ERR -1
#define SOCK_CONN_ERR -1
#define SOCK_RECV_ERR -1
#define mysql_socket_errno() errno
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h> /* inet_ntoa */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_AF_UNIX
#include <sys/un.h>
#endif
#endif /* _WIN32 */


#ifdef _WIN32
void mysql_io_win_init(void)
{
	WSADATA wsaData;   // if this doesn't work
	//WSAData wsaData; // then try this instead

	if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed.\n");
	}
}
#endif

int mysql_set_sock_blocking(int socketd, int block)
{
	int ret = 0;
	int flags;
	int myflag = 0;

#ifdef _WIN32
	/* with ioctlsocket, a non-zero sets nonblocking, a zero sets blocking */
	flags = !block;
	if (ioctlsocket(socketd, FIONBIO, &flags) == SOCKET_ERROR) {
		char *error_string;
		
		error_string = php_socket_strerror(WSAGetLastError(), NULL, 0);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_string);
		efree(error_string);
		ret = FAILURE;
	}
#else
	flags = fcntl(socketd, F_GETFL);
#ifdef O_NONBLOCK
	myflag = O_NONBLOCK; /* POSIX version */
#elif defined(O_NDELAY)
	myflag = O_NDELAY;   /* old non-POSIX version */
#endif
	if (!block) {
		flags |= myflag;
	} else {
		flags &= ~myflag;
	}
	fcntl(socketd, F_SETFL, flags);
#endif
	return ret;
}

/* {{{ mysql_resolve_host */
static int mysql_resolve_host(const char *host, struct sockaddr **sa)
#ifdef _WIN32
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s;
	DBUG_ENTER("mysql_resolve_host");
	if (host == NULL) {
		DBUG_INF("Can't resolve");
		DBUG_RETURN(0);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	s = getaddrinfo(host, NULL, &hints, &result);
	if (s != 0) {
		DBUG_INF_FMT("Can't resolve [%s] error=%d", host, s);
		DBUG_RETURN(0);
	}

	/* getaddrinfo() returns a list of address structures */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		*sa = my_malloc(rp->ai_addrlen, MYF(0));
		memcpy(*sa, rp->ai_addr, rp->ai_addrlen);
		break;
	}

	if (rp == NULL) {               /* No address succeeded */
		DBUG_INF("Can't resolve");
		DBUG_RETURN(0);
	}

	freeaddrinfo(result);           /* No longer needed */

	DBUG_INF("Success");
	DBUG_RETURN(1);
}
/* }}} */
#else
{
	struct hostent *host_info;
	struct in_addr in;
	DBUG_ENTER("mysql_resolve_host");
	if (host == NULL) {
		DBUG_RETURN(0);
	}
	if (!inet_aton(host, &in)) {
		host_info = gethostbyname(host);
		if (host_info == NULL) {
			//mysql_print_error(E_WARNING, "connect() failed: gethostbyname failed");
			DBUG_RETURN(0);
		}
		in = *((struct in_addr *) host_info->h_addr);
	}

	*sa = my_malloc(sizeof(struct sockaddr_in), MYF(0));
	(*sa)->sa_family = AF_INET;
	((struct sockaddr_in *)*sa)->sin_addr = in;

	DBUG_RETURN(1);
}
#endif
/* }}} */


/* {{{ mysql_parse_host_n_port */
static
char *mysql_parse_host_n_port(const char *host_n_port, size_t host_n_port_len, int *port)
{
	const char *colon;
	char *host = NULL;
	DBUG_ENTER("mysql_parse_host_n_port");

	if (host_n_port_len) {
		colon = memchr(host_n_port, ':', host_n_port_len - 1);
	} else {
		colon = NULL;
	}
	if (colon) {
		*port = atoi(colon + 1);
		host = my_strndup(host_n_port, colon - host_n_port, MYF(0));
	} else {
		//mysql_print_error(E_WARNING, "Connect failed. Failed to parse string \"%s\"", host_n_port);
	}
	DBUG_RETURN(host);
}
/* }}} */


/* {{{ mysql_tcp_connect */
static MYSQL_SOCKET
mysql_tcp_connect(const char *host_n_port, size_t host_n_port_len)
{
	int port;
	MYSQL_SOCKET sock;
	struct sockaddr *sa = NULL;
	char *host = mysql_parse_host_n_port(host_n_port, host_n_port_len, &port);
	DBUG_ENTER("mysql_tcp_connect");
	
	if (host == NULL || mysql_resolve_host(host, &sa) == 0 || sa == NULL) {
		/* could not resolve address(es) */
		sock = SOCK_ERR;
	} else {
		if (SOCK_ERR != (sock = socket(sa->sa_family, SOCK_STREAM, 0)) ) {
			((struct sockaddr_in *)sa)->sin_family = sa->sa_family;
			((struct sockaddr_in *)sa)->sin_port = htons(port);

			if (connect(sock, sa, sizeof(struct sockaddr_in)) == SOCK_CONN_ERR) {
				closesocket(sock);
				sock = SOCK_ERR;
			}
		}
	}
	my_free((gptr)sa, MYF(0));
	my_free(host, MYF(0));
	DBUG_RETURN(sock);
}
/* }}} */


#ifdef HAVE_AF_UNIX
/* {{{ mysql_unix_connect */
static MYSQL_SOCKET
mysql_unix_connect(MYSQL_SOCKET *sock, const char *name, size_t namelen)
{
	struct sockaddr_un unix_addr;
	DBUG_ENTER("mysql_unix_connect");
	memset(&unix_addr, 0, sizeof(unix_addr));
	
	if (SOCK_ERR == (*sock = socket(PF_UNIX, SOCK_STREAM, 0))) {
		//mysql_print_error(E_WARNING, "connect() failed: Failed to create unix socket");
		DBUG_RETURN(SOCK_ERR);
	}

	unix_addr.sun_family = AF_UNIX;

	if (namelen >= sizeof(unix_addr.sun_path)) {
		namelen = sizeof(unix_addr.sun_path) - 1;
	}
	memcpy(unix_addr.sun_path, name, namelen);
	DBUG_RETURN(connect(*sock, (const struct sockaddr *)&unix_addr, (socklen_t)sizeof(unix_addr)));
}
/* }}} */
#endif


/* {{{ mysql_io_open */
MYSQL_STREAM *
mysql_io_open(const char *name, size_t namelen)
{
	MYSQL_STREAM *stream = NULL;
	DBUG_ENTER("mysql_io_open");

	if ((stream = (MYSQL_STREAM*) my_malloc(sizeof(MYSQL_STREAM), MYF(MY_WME | MY_ZEROFILL))) == NULL)	{
		DBUG_RETURN(NULL);
	}

	stream->chunk_size = MYSQL_SOCK_CHUNK_SIZE;
	stream->socket = SOCK_ERR;

	if (!strncmp("tcp://", name, sizeof("tcp://")-1)) {
		stream->socket_type = MYSQL_SOCKET_TCP;
		name += sizeof("tcp://")-1;
		namelen -= sizeof("tcp://")-1;
		stream->socket = mysql_tcp_connect(name, namelen);
		if (stream->socket == SOCK_ERR) {
			mysql_io_close(stream);
			stream = NULL;
		}
#ifdef HAVE_AF_UNIX
	} else if (!strncmp("unix://", name, sizeof("unix://")-1)) {
		stream->socket_type = MYSQL_SOCKET_UNIX;
		name += sizeof("unix://")-1;
		namelen -= sizeof("unix://")-1;
		if (SOCK_ERR == mysql_unix_connect(&stream->socket, name, namelen)) {
			mysql_io_close(stream);
			stream = NULL;
		}
#endif
	}

	DBUG_RETURN(stream);
}
/* }}} */


/* {{{ mysql_io_read */
size_t mysql_io_read(MYSQL_STREAM *stream, char *buf, size_t size)
{
	size_t total_read = 0;
	int just_read = 0;
	DBUG_ENTER("mysql_io_read");

	if (stream->socket == SOCK_ERR) {
		DBUG_RETURN(0);
	}

	while (size > 0) {
#if defined(HAVE_SIGNAL) && !defined(WIN32) 
		void (*handler) (int);
		handler = signal(SIGPIPE, SIG_IGN);
#endif
		just_read = recv(stream->socket, buf, size, 0);
                if (just_read < 0)
#if defined(HAVE_SIGNAL) && !defined(WIN32) 
		signal(SIGPIPE, handler);
#endif
		if (just_read == 0 || just_read == SOCK_ERR) {
			break;
		}

		total_read += just_read;
		buf += just_read;
		size -= just_read;
	}

	DBUG_RETURN(total_read);
}
/* }}} */


/* {{{ mysql_io_write */
size_t mysql_io_write(MYSQL_STREAM *stream, const char *buf, size_t count)
{
	size_t didwrite = 0, towrite;
	int bytes_sent;
	DBUG_ENTER("mysql_io_write");

	if (buf == NULL || count == 0) {
		DBUG_RETURN(0);
	}
 
	while (count > 0) {
		towrite = (count > stream->chunk_size) ? stream->chunk_size :count;
		bytes_sent = 0;

		if (stream->socket != SOCK_ERR){
#ifndef _WIN32
			void (*handler) (int);
			handler = signal(SIGPIPE, SIG_IGN);
#endif
			if ((bytes_sent = send(stream->socket, buf, towrite, 0)) <= 0) {
				//mysql_print_error(E_NOTICE, "send of %ld bytes failed with errno=%ld", (long) count, (long) mysql_socket_errno());
				bytes_sent = 0;
			}
#ifndef _WIN32
			signal(SIGPIPE, handler);
#endif
		}
		if (bytes_sent == 0) {
			break;
		}

		buf += bytes_sent;
		count -= bytes_sent;
		didwrite += bytes_sent;
	}
	DBUG_RETURN(didwrite);
}
/* }}} */


/* {{{ mysql_io_close */
void mysql_io_close(MYSQL_STREAM *stream)
{
	DBUG_ENTER("mysql_io_close");
	if (stream->socket != SOCK_ERR) {
		closesocket(stream->socket);
		stream->socket = SOCK_ERR;
	}

	if (stream->readbuf) {
		my_free(stream->readbuf, MYF(0));
		stream->readbuf = NULL;
	}
	my_free(stream, MYF(0));
	DBUG_VOID_RETURN;
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
