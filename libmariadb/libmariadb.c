/************************************************************************************
    Copyright (C) 2000, 2012 MySQL AB & MySQL Finland AB & TCX DataKonsult AB,
                 Monty Program AB
   
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

#include <my_global.h>

#include <my_sys.h>
#include <mysys_err.h>
#include <m_string.h>
#include <m_ctype.h>
#include <ma_common.h>
#include "my_context.h"
#include "mysql.h"
#include "mysql_version.h"
#include "mysqld_error.h"
#include <mariadb/ma_io.h>
#include "errmsg.h"
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#if !defined(MSDOS) && !defined(_WIN32)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_SELECT_H
#  include <select.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif
#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#endif
#if defined(THREAD) && !defined(_WIN32)
#include <my_pthread.h> /* because of signal() */
#endif
#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
#include <sha1.h>
#include <violite.h>
#ifdef HAVE_OPENSSL
#include <ma_secure.h>
#endif
#ifndef _WIN32
#include <poll.h>
#endif
#include <ma_dyncol.h>
#include <mysql_async.h>

#define ASYNC_CONTEXT_DEFAULT_STACK_SIZE (4096*15)

#undef max_allowed_packet
#undef net_buffer_length
extern ulong max_allowed_packet; /* net.c */
extern ulong net_buffer_length;  /* net.c */
static MYSQL_PARAMETERS mariadb_internal_parameters=
{&max_allowed_packet, &net_buffer_length, 0};

static my_bool mysql_client_init=0;
static void mysql_close_options(MYSQL *mysql);
extern my_bool  my_init_done;
extern my_bool  mysql_ps_subsystem_initialized;
extern my_bool mysql_handle_local_infile(MYSQL *mysql, const char *filename);
extern const CHARSET_INFO * mysql_find_charset_nr(uint charsetnr);
extern const CHARSET_INFO * mysql_find_charset_name(const char * const name);
extern int run_plugin_auth(MYSQL *mysql, char *data, uint data_len,
                           const char *data_plugin, const char *db);

/* prepare statement methods from my_stmt.c */
extern my_bool mthd_supported_buffer_type(enum enum_field_types type);
extern my_bool mthd_stmt_read_prepare_response(MYSQL_STMT *stmt);
extern my_bool mthd_stmt_get_param_metadata(MYSQL_STMT *stmt);
extern my_bool mthd_stmt_get_result_metadata(MYSQL_STMT *stmt);
extern int mthd_stmt_fetch_row(MYSQL_STMT *stmt, unsigned char **row);
extern int mthd_stmt_fetch_to_bind(MYSQL_STMT *stmt, unsigned char *row);
extern int mthd_stmt_read_all_rows(MYSQL_STMT *stmt);
extern void mthd_stmt_flush_unbuffered(MYSQL_STMT *stmt);
extern unsigned char *mysql_net_store_length(unsigned char *packet, size_t length);

uint mysql_port=0;
my_string mysql_unix_port=0;

#ifdef _WIN32
#define CONNECT_TIMEOUT 20
#else
#define CONNECT_TIMEOUT 0
#endif

struct st_mysql_methods MARIADB_DEFAULT_METHODS;

#if defined(MSDOS) || defined(_WIN32)
// socket_errno is defined in my_global.h for all platforms
#define perror(A)
#else
#include <errno.h>
#define SOCKET_ERROR -1
#endif /* _WIN32 */

#include <mysql/client_plugin.h>

#define native_password_plugin_name "mysql_native_password"

static void end_server(MYSQL *mysql);
static void mysql_close_memory(MYSQL *mysql);
void read_user_name(char *name);
static void append_wild(char *to,char *end,const char *wild);
static my_bool mysql_reconnect(MYSQL *mysql);
static sig_handler pipe_sig_handler(int sig);
static int cli_report_progress(MYSQL *mysql, uchar *packet, uint length);

extern int mysql_client_plugin_init();
extern void mysql_client_plugin_deinit();

/*
  Let the user specify that we don't want SIGPIPE;  This doesn't however work
  with threaded applications as we can have multiple read in progress.
*/

#if !defined(_WIN32) && defined(SIGPIPE) && !defined(THREAD)
#define init_sigpipe_variables  sig_return old_signal_handler=(sig_return) 0;
#define set_sigpipe(mysql)     if ((mysql)->client_flag & CLIENT_IGNORE_SIGPIPE) old_signal_handler=signal(SIGPIPE,pipe_sig_handler)
#define reset_sigpipe(mysql) if ((mysql)->client_flag & CLIENT_IGNORE_SIGPIPE) signal(SIGPIPE,old_signal_handler);
#else
#define init_sigpipe_variables
#define set_sigpipe(mysql)
#define reset_sigpipe(mysql)
#endif



/****************************************************************************
* A modified version of connect().  connect2() allows you to specify
* a timeout value, in seconds, that we should wait until we
* derermine we can't connect to a particular host.  If timeout is 0,
* connect2() will behave exactly like connect().
*
* Base version coded by Steve Bernacki, Jr. <steve@navinet.net>
*****************************************************************************/

int socket_block(my_socket s,my_bool blocked)
{
#ifdef _WIN32
  unsigned long socket_blocked= blocked ? 0 : 1;
  return ioctlsocket(s, FIONBIO, &socket_blocked);
#else
  int flags= fcntl(s, F_GETFL, 0);
  if (blocked)
    flags&= ~O_NONBLOCK;
  else 
    flags|= O_NONBLOCK;
  return fcntl(s, F_SETFL, flags);
#endif
}

static int connect2(my_socket s, const struct sockaddr *name, size_t namelen,
		    uint timeout)
{
  int res, s_err;
  socklen_t s_err_size = sizeof(uint);
#ifndef _WIN32
  struct pollfd poll_fd;
#else
  FD_SET sfds, efds;
  struct timeval tv;
#endif

  if (!timeout)
    return connect(s, (struct sockaddr*) name, (int)namelen);

  /* set socket to non blocking */
  if (socket_block(s, 0) == SOCKET_ERROR)
    return -1;

  res= connect(s, (struct sockaddr*) name, (int)namelen);
  if (res == 0)
    return res;

#ifdef _WIN32
  if (GetLastError() != WSAEWOULDBLOCK &&
      GetLastError() != WSAEINPROGRESS)
#else
  if (errno != EINPROGRESS)
#endif
     return -1;
#ifndef _WIN32
  memset(&poll_fd, 0, sizeof(struct pollfd));
  poll_fd.events= POLLOUT | POLLERR;
  poll_fd.fd= s;

  /* connection timeout in milliseconds */
  res= poll(&poll_fd, 1, timeout);

  switch(res)
  {
    /* Error= - 1, timeout = 0 */
    case -1:
      break;
    case 0: 
      errno= ETIMEDOUT;
      break;
  }
#else
  FD_ZERO(&sfds);
  FD_ZERO(&efds);
  FD_SET(s, &sfds);
  FD_SET(s, &efds);

  memset(&tv, 0, sizeof(struct timeval));
  tv.tv_sec= timeout;

  res= select((int)s+1, NULL, &sfds, &efds, &tv);
  if (res < 1)
    return -1;
#endif

  s_err=0;
  if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*) &s_err, &s_err_size) != 0)
    return(-1);

  if (s_err)
  {						/* getsockopt could succeed */
    errno = s_err;
    return(-1);					/* but return an error... */
  }
  return (0);					/* ok */
}

static int
connect_sync_or_async(MYSQL *mysql, NET *net, my_socket fd,
                      const struct sockaddr *name, uint namelen)
{
  int vio_timeout= (mysql->options.connect_timeout >= 0) ? 
                   mysql->options.connect_timeout * 1000 : -1;

  if (mysql->options.extension && mysql->options.extension->async_context &&
      mysql->options.extension->async_context->active)
  {
    my_bool old_mode;
    vio_blocking(net->vio, FALSE, &old_mode);
    return my_connect_async(mysql->options.extension->async_context, fd,
                            name, namelen, vio_timeout);
  }

  return connect2(fd, name, namelen, vio_timeout);
}
/*
** Create a named pipe connection
*/

#ifdef _WIN32

HANDLE create_named_pipe(NET *net, uint connect_timeout, char **arg_host,
			 char **arg_unix_socket)
{
  HANDLE hPipe=INVALID_HANDLE_VALUE;
  char szPipeName [ 257 ];
  DWORD dwMode;
  int i;
  my_bool testing_named_pipes=0;
  char *host= *arg_host, *unix_socket= *arg_unix_socket;

  if ( ! unix_socket || (unix_socket)[0] == 0x00)
    unix_socket = mysql_unix_port;
  if (!host || !strcmp(host,LOCAL_HOST))
    host=LOCAL_HOST_NAMEDPIPE;

  sprintf( szPipeName, "\\\\%s\\pipe\\%s", host, unix_socket);
  DBUG_PRINT("info",("Server name: '%s'.  Named Pipe: %s",
		     host, unix_socket));

  for (i=0 ; i < 100 ; i++)			/* Don't retry forever */
  {
    if ((hPipe = CreateFile(szPipeName,
			    GENERIC_READ | GENERIC_WRITE,
			    0,
			    NULL,
			    OPEN_EXISTING,
			    0,
			    NULL )) != INVALID_HANDLE_VALUE)
      break;
    if (GetLastError() != ERROR_PIPE_BUSY)
    {
      net->last_errno=CR_NAMEDPIPEOPEN_ERROR;
      sprintf(net->last_error,ER(net->last_errno),host, unix_socket,
	      (ulong) GetLastError());
      return INVALID_HANDLE_VALUE;
    }
    /* wait for for an other instance */
    if (! WaitNamedPipe(szPipeName, connect_timeout) )
    {
      net->last_errno=CR_NAMEDPIPEWAIT_ERROR;
      sprintf(net->last_error,ER(net->last_errno),host, unix_socket,
	      (ulong) GetLastError());
      return INVALID_HANDLE_VALUE;
    }
  }
  if (hPipe == INVALID_HANDLE_VALUE)
  {
    net->last_errno=CR_NAMEDPIPEOPEN_ERROR;
    sprintf(net->last_error,ER(net->last_errno),host, unix_socket,
	    (ulong) GetLastError());
    return INVALID_HANDLE_VALUE;
  }
  dwMode = PIPE_READMODE_BYTE | PIPE_WAIT;
  if ( !SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL) )
  {
    CloseHandle( hPipe );
    net->last_errno=CR_NAMEDPIPESETSTATE_ERROR;
    sprintf(net->last_error,ER(net->last_errno),host, unix_socket,
	    (ulong) GetLastError());
    return INVALID_HANDLE_VALUE;
  }
  *arg_host=host ; *arg_unix_socket=unix_socket;	/* connect arg */
  return (hPipe);
}
#endif

/* net_get_error */
void net_get_error(char *buf, size_t buf_len,
       char *error, size_t error_len,
       unsigned int *error_no,
       char *sqlstate)
{
  char *p= buf;
  size_t error_msg_len= 0;

  if (buf_len > 2)
  {
    *error_no= uint2korr(p);
    p+= 2;

    /* since 4.1 sqlstate is following */
    if (*p == '#')
    {
      memcpy(sqlstate, ++p, SQLSTATE_LENGTH);
      p+= SQLSTATE_LENGTH;  
    }
    error_msg_len= buf_len - (p - buf);
    error_msg_len= MIN(error_msg_len, error_len - 1);
    memcpy(error, p, error_msg_len);
  }
  else
  {
    *error_no= CR_UNKNOWN_ERROR;
    memcpy(sqlstate, unknown_sqlstate, SQLSTATE_LENGTH);
  }
}


/*****************************************************************************
** read a packet from server. Give error message if socket was down
** or packet is an error message
*****************************************************************************/

ulong
net_safe_read(MYSQL *mysql)
{
  NET *net= &mysql->net;
  ulong len=0;
  init_sigpipe_variables

restart:
  /* Don't give sigpipe errors if the client doesn't want them */
  set_sigpipe(mysql);
  if (net->vio != 0)
    len=my_net_read(net);
  reset_sigpipe(mysql);

  if (len == packet_error || len == 0)
  {
    end_server(mysql);
    my_set_error(mysql, net->last_errno == ER_NET_PACKET_TOO_LARGE ?
		     CR_NET_PACKET_TOO_LARGE:
		     CR_SERVER_LOST,
         SQLSTATE_UNKNOWN, 0);
    return(packet_error);
  }
  if (net->read_pos[0] == 255)
  {
    if (len > 3)
    {
      char *pos=(char*) net->read_pos+1;
      uint last_errno=uint2korr(pos);
      pos+=2;
      len-=2;

      if (last_errno== 65535 &&
          (mysql->server_capabilities & CLIENT_PROGRESS))
      {
        if (cli_report_progress(mysql, (uchar *)pos, (uint) (len-1)))
        {
          /* Wrong packet */
          my_set_error(mysql, CR_MALFORMED_PACKET, unknown_sqlstate, 0);
          return (packet_error);
        }
        goto restart;
      }
      net->last_errno= last_errno;
      if (pos[0]== '#')
      {
        strmake(net->sqlstate, pos+1, SQLSTATE_LENGTH);
        pos+= SQLSTATE_LENGTH + 1;
      }
      else
      {
        strmov(net->sqlstate, SQLSTATE_UNKNOWN);
      }
      (void) strmake(net->last_error,(char*) pos,
		     min(len,sizeof(net->last_error)-1));
    }
    else
    {
      my_set_error(mysql, CR_UNKNOWN_ERROR, SQLSTATE_UNKNOWN, 0);
    }

    mysql->server_status&= ~SERVER_MORE_RESULTS_EXIST;

    DBUG_PRINT("error",("Got error: %d (%s)", net->last_errno,
			net->last_error));
    return(packet_error);
  }
  return len;
}

/*
  Report progress to the client

  RETURN VALUES
    0  ok
    1  error
*/
static int cli_report_progress(MYSQL *mysql, uchar *packet, uint length)
{
  uint stage, max_stage, proc_length;
  double progress;
  uchar *start= packet;

  if (length < 5)
    return 1;                         /* Wrong packet */

  if (!(mysql->options.extension && mysql->options.extension->report_progress))
    return 0;                         /* No callback, ignore packet */

  packet++;                           /* Ignore number of strings */
  stage= (uint) *packet++;
  max_stage= (uint) *packet++;
  progress= uint3korr(packet)/1000.0;
  packet+= 3;
  proc_length= net_field_length(&packet);
  if (packet + proc_length > start + length)
    return 1;                         /* Wrong packet */
  (*mysql->options.extension->report_progress)(mysql, stage, max_stage,
                                               progress, (char*) packet,
                                               proc_length);
  return 0;
}

/* Get the length of next field. Change parameter to point at fieldstart */
ulong
net_field_length(uchar **packet)
{
  reg1 uchar *pos= *packet;
  if (*pos < 251)
  {
    (*packet)++;
    return (ulong) *pos;
  }
  if (*pos == 251)
  {
    (*packet)++;
    return NULL_LENGTH;
  }
  if (*pos == 252)
  {
    (*packet)+=3;
    return (ulong) uint2korr(pos+1);
  }
  if (*pos == 253)
  {
    (*packet)+=4;
    return (ulong) uint3korr(pos+1);
  }
  (*packet)+=9;					/* Must be 254 when here */
  return (ulong) uint4korr(pos+1);
}

/* Same as above, but returns ulonglong values */

static my_ulonglong
net_field_length_ll(uchar **packet)
{
  reg1 uchar *pos= *packet;
  if (*pos < 251)
  {
    (*packet)++;
    return (my_ulonglong) *pos;
  }
  if (*pos == 251)
  {
    (*packet)++;
    return (my_ulonglong) NULL_LENGTH;
  }
  if (*pos == 252)
  {
    (*packet)+=3;
    return (my_ulonglong) uint2korr(pos+1);
  }
  if (*pos == 253)
  {
    (*packet)+=4;
    return (my_ulonglong) uint3korr(pos+1);
  }
  (*packet)+=9;					/* Must be 254 when here */
#ifdef NO_CLIENT_LONGLONG
  return (my_ulonglong) uint4korr(pos+1);
#else
  return (my_ulonglong) uint8korr(pos+1);
#endif
}


void free_rows(MYSQL_DATA *cur)
{
  if (cur)
  {
    free_root(&cur->alloc,MYF(0));
    my_free(cur);
  }
}


int
mthd_my_send_cmd(MYSQL *mysql,enum enum_server_command command, const char *arg,
	       size_t length, my_bool skipp_check, void *opt_arg)
{
  NET *net= &mysql->net;
  int result= -1;
  init_sigpipe_variables

  DBUG_ENTER("mthd_my_send_command");

  DBUG_PRINT("info", ("server_command: %d  packet_size: %u", command, length));

  /* Don't give sigpipe errors if the client doesn't want them */
  set_sigpipe(mysql);
  if (mysql->net.vio == 0)
  {						/* Do reconnect if possible */
    if (mysql_reconnect(mysql))
    {
      DBUG_PRINT("info", ("reconnect failed"));
      DBUG_RETURN(1);
    }
  }
  if (mysql->status != MYSQL_STATUS_READY ||
      mysql->server_status & SERVER_MORE_RESULTS_EXIST)
  {
    SET_CLIENT_ERROR(mysql, CR_COMMANDS_OUT_OF_SYNC, unknown_sqlstate, 0);
    goto end;
  }

  CLEAR_CLIENT_ERROR(mysql);

  mysql->info=0;
  mysql->affected_rows= ~(my_ulonglong) 0;
  net_clear(net);			/* Clear receive buffer */
  if (!arg)
    arg="";

  if (net_write_command(net,(uchar) command,arg,
			length ? length : (ulong) strlen(arg)))
  {
    DBUG_PRINT("error",("Can't send command to server. Error: %d",socket_errno));
    if (net->last_errno == ER_NET_PACKET_TOO_LARGE)
    {
      my_set_error(mysql, CR_NET_PACKET_TOO_LARGE, SQLSTATE_UNKNOWN, 0);
      goto end;
    }
    end_server(mysql);
    if (mysql_reconnect(mysql))
      goto end;
    if (net_write_command(net,(uchar) command,arg,
			  length ? length : (ulong) strlen(arg)))
    {
      my_set_error(mysql, CR_SERVER_GONE_ERROR, SQLSTATE_UNKNOWN, 0);
      goto end;
    }
  }
  result=0;
  if (!skipp_check) {
    result= ((mysql->packet_length=net_safe_read(mysql)) == packet_error ?
	     1 : 0);
    DBUG_PRINT("info", ("packet_length=%llu", mysql->packet_length));
  }
 end:
  reset_sigpipe(mysql);
  DBUG_RETURN(result);
}

int
simple_command(MYSQL *mysql,enum enum_server_command command, const char *arg,
	       size_t length, my_bool skipp_check, void *opt_arg)
{
  return mysql->methods->db_command(mysql, command, arg, length, skipp_check, opt_arg);
}

static void free_old_query(MYSQL *mysql)
{
  DBUG_ENTER("free_old_query");
  if (mysql->fields)
    free_root(&mysql->field_alloc,MYF(0));
  init_alloc_root(&mysql->field_alloc,8192,0);	/* Assume rowlength < 8192 */
  mysql->fields=0;
  mysql->field_count=0;				/* For API */
  DBUG_VOID_RETURN;
}

#if defined(HAVE_GETPWUID) && defined(NO_GETPWUID_DECL)
struct passwd *getpwuid(uid_t);
char* getlogin(void);
#endif

#if !defined(MSDOS) && ! defined(VMS) && !defined(_WIN32) && !defined(OS2)
void read_user_name(char *name)
{
  DBUG_ENTER("read_user_name");
  if (geteuid() == 0)
    (void) strmov(name,"root");		/* allow use of surun */
  else
  {
#ifdef HAVE_GETPWUID
    struct passwd *skr;
    const char *str;
    if ((str=getlogin()) == NULL)
    {
      if ((skr=getpwuid(geteuid())) != NULL)
	str=skr->pw_name;
      else if (!(str=getenv("USER")) && !(str=getenv("LOGNAME")) &&
	       !(str=getenv("LOGIN")))
	str="UNKNOWN_USER";
    }
    (void) strmake(name,str,USERNAME_LENGTH);
#elif HAVE_CUSERID
    (void) cuserid(name);
#else
    strmov(name,"UNKNOWN_USER");
#endif
  }
  DBUG_VOID_RETURN;
}

#else /* If MSDOS || VMS */

void read_user_name(char *name)
{
  char *str=getenv("USERNAME");		/* ODBC will send user variable */
  strmake(name,str ? str : "ODBC", USERNAME_LENGTH);
}

#endif

#ifdef _WIN32
static my_bool is_NT(void)
{
  char *os=getenv("OS");
  return (os && !strcmp(os, "Windows_NT")) ? 1 : 0;
}
#endif

/*
** Expand wildcard to a sql string
*/

static void
append_wild(char *to, char *end, const char *wild)
{
  end-=5;					/* Some extra */
  if (wild && wild[0])
  {
    to=strmov(to," like '");
    while (*wild && to < end)
    {
      if (*wild == '\\' || *wild == '\'')
	*to++='\\';
      *to++= *wild++;
    }
    if (*wild)					/* Too small buffer */
      *to++='%';				/* Nicer this way */
    to[0]='\'';
    to[1]=0;
  }
}



/**************************************************************************
** Init debugging if MYSQL_DEBUG environment variable is found
**************************************************************************/
void STDCALL mysql_debug_end()
{
#ifndef DBUG_OFF
  DEBUGGER_OFF;
  DBUG_POP();
#endif
}

void STDCALL
mysql_debug(const char *debug __attribute__((unused)))
{
#ifndef DBUG_OFF
  char	*env;
  if (debug)
  {
    DEBUGGER_ON;
    DBUG_PUSH(debug);
  }
  else if ((env = getenv("MYSQL_DEBUG")))
  {
    DEBUGGER_ON;
    DBUG_PUSH(env);
#if !defined(_WINVER) && !defined(WINVER)
    puts("\n-------------------------------------------------------");
    puts("MYSQL_DEBUG found. libmariadb started with the following:");
    puts(env);
    puts("-------------------------------------------------------\n");
#else
    {
      char buff[80];
      strmov(strmov(buff,"libmariadb: "),env);
      MessageBox((HWND) 0,"Debugging variable MYSQL_DEBUG used",buff,MB_OK);
    }
#endif
  }
#endif
}


/**************************************************************************
** Close the server connection if we get a SIGPIPE
   ARGSUSED
**************************************************************************/

static sig_handler
pipe_sig_handler(int sig __attribute__((unused)))
{
  DBUG_PRINT("info",("Hit by signal %d",sig));
#ifdef DONT_REMEMBER_SIGNAL
  (void) signal(SIGPIPE,pipe_sig_handler);
#endif
}


/**************************************************************************
** Shut down connection
**************************************************************************/

static void
end_server(MYSQL *mysql)
{
  DBUG_ENTER("end_server");
  if (mysql->net.vio != 0)
  {
    init_sigpipe_variables
    set_sigpipe(mysql);
    vio_delete(mysql->net.vio);
    reset_sigpipe(mysql);
    mysql->net.vio= 0;    /* Marker */
  }
  net_end(&mysql->net);
  free_old_query(mysql);
  DBUG_VOID_RETURN;
}

void mthd_my_skip_result(MYSQL *mysql)
{
  ulong pkt_len;
  DBUG_ENTER("madb_skip_result");

  do {
    pkt_len= net_safe_read(mysql);
    if (pkt_len == packet_error)
      break;
  } while (pkt_len > 8 || mysql->net.read_pos[0] != 254);
  DBUG_VOID_RETURN;
}

void STDCALL
mysql_free_result(MYSQL_RES *result)
{
  DBUG_ENTER("mysql_free_result");
  DBUG_PRINT("enter",("mysql_res: %lx",result));
  if (result)
  {
    if (result->handle && result->handle->status == MYSQL_STATUS_USE_RESULT)
    {
      result->handle->methods->db_skip_result(result->handle);
      result->handle->status=MYSQL_STATUS_READY;
    }
    free_rows(result->data);
    if (result->fields)
      free_root(&result->field_alloc,MYF(0));
    if (result->row)
      my_free(result->row);
    my_free(result);
  }
  DBUG_VOID_RETURN;
}


/****************************************************************************
** Get options from my.cnf
****************************************************************************/

static const char *default_options[]=
{
  "port","socket","compress","password","pipe", "timeout", "user",
  "init-command", "host", "database", "debug", "return-found-rows",
  "ssl-key" ,"ssl-cert" ,"ssl-ca" ,"ssl-capath",
  "character-sets-dir", "default-character-set", "interactive-timeout",
  "connect-timeout", "local-infile", "disable-local-infile",
  "ssl-cipher", "max-allowed-packet", "protocol", "shared-memory-base-name",
  "multi-results", "multi-statements", "multi-queries", "secure-auth",
  "report-data-truncation", "plugin-dir", "default-auth", "database-type",
  NULL
};

enum option_val
{
  OPT_port=1, OPT_socket, OPT_compress, OPT_password, OPT_pipe,
  OPT_timeout, OPT_user, OPT_init_command, OPT_host, OPT_database,
  OPT_debug, OPT_return_found_rows, OPT_ssl_key, OPT_ssl_cert,
  OPT_ssl_ca, OPT_ssl_capath, OPT_charset_dir, 
  OPT_charset_name, OPT_interactive_timeout,
  OPT_connect_timeout, OPT_local_infile, OPT_disable_local_infile,
  OPT_ssl_cipher, OPT_max_allowed_packet, OPT_protocol, OPT_shared_memory_base_name,
  OPT_multi_results, OPT_multi_statements, OPT_multi_queries, OPT_secure_auth,
  OPT_report_data_truncation, OPT_plugin_dir, OPT_default_auth, OPT_db_type
};

#define CHECK_OPT_EXTENSION_SET(OPTS)\
    if (!(OPTS)->extension)                                     \
      (OPTS)->extension= (struct st_mysql_options_extension *)  \
        my_malloc(sizeof(struct st_mysql_options_extension),    \
                  MYF(MY_WME | MY_ZEROFILL));                   \

#define OPT_SET_EXTENDED_VALUE(OPTS, KEY, VAL, IS_STRING)       \
    CHECK_OPT_EXTENSION_SET(OPTS)                               \
    if (IS_STRING) {                                            \
      my_free((OPTS)->extension->KEY);  \
      (OPTS)->extension->KEY= my_strdup((char *)(VAL), MYF(MY_WME));    \
    } else                                                      \
      (OPTS)->extension->KEY= (VAL);

static TYPELIB option_types={array_elements(default_options)-1,
			     "options",default_options};

const char *protocol_names[]= {"TCP", "SOCKED", "PIPE", "MEMORY", NULL};
static TYPELIB protocol_types= {array_elements(protocol_names)-1,
                                "protocol names", 
                                 protocol_names};

static void options_add_initcommand(struct st_mysql_options *options,
                                     const char *init_cmd)
{
  char *insert= my_strdup(init_cmd, MYF(MY_WME));
  if (!options->init_command)
  {
    options->init_command= (DYNAMIC_ARRAY*)my_malloc(sizeof(DYNAMIC_ARRAY),
						      MYF(MY_WME));
    my_init_dynamic_array(options->init_command, sizeof(char*), 5, 5);
  }

  if (insert_dynamic(options->init_command, (gptr)&insert))
    my_free(insert);
}


static void mysql_read_default_options(struct st_mysql_options *options,
				       const char *filename,const char *group)
{
  int argc;
  char *argv_buff[1],**argv;
  const char *groups[3];
  DBUG_ENTER("mysql_read_default_options");
  DBUG_PRINT("enter",("file: %s  group: %s",filename,group ? group :"NULL"));

  argc=1; argv=argv_buff; argv_buff[0]= (char*) "client";
  groups[0]= (char*) "client"; groups[1]= (char*) group; groups[2]=0;

  load_defaults(filename, groups, &argc, &argv);
  if (argc != 1)				/* If some default option */
  {
    char **option=argv;
    while (*++option)
    {
      /* DBUG_PRINT("info",("option: %s",option[0])); */
      if (option[0][0] == '-' && option[0][1] == '-')
      {
	      char *end=strcend(*option,'=');
	      char *opt_arg=0;
	      if (*end)
	      {
	        opt_arg=end+1;
	        *end=0;				/* Remove '=' */
	      }
	      /* Change all '_' in variable name to '-' */
	      for (end= *option ; *(end= strcend(end,'_')) ; )
	        *end= '-';
	      switch (find_type(*option+2,&option_types,2)) {
      	case OPT_port:
      	  if (opt_arg)
	          options->port=atoi(opt_arg);
      	  break;
      	case OPT_socket:
      	  if (opt_arg)
      	  {
      	    my_free(options->unix_socket);
      	    options->unix_socket=my_strdup(opt_arg,MYF(MY_WME));
      	  }
      	  break;
      	case OPT_compress:
      	  options->compress=1;
      	  break;
      	case OPT_password:
      	  if (opt_arg)
      	  {
      	    my_free(options->password);
      	    options->password=my_strdup(opt_arg,MYF(MY_WME));
      	  }
      	  break;
      	case OPT_pipe:
      	  options->named_pipe=1;	/* Force named pipe */
      	  break;
      	case OPT_connect_timeout:
        case OPT_timeout:
      	  if (opt_arg)
      	    options->connect_timeout=atoi(opt_arg);
      	  break;
      	case OPT_user:
      	  if (opt_arg)
      	  {
      	    my_free(options->user);
      	    options->user=my_strdup(opt_arg,MYF(MY_WME));
      	  }
      	  break;
      	case OPT_init_command:
      	  if (opt_arg)
            options_add_initcommand(options, opt_arg);
      	  break;
      	case OPT_host:
      	  if (opt_arg)
      	  {
      	    my_free(options->host);
      	    options->host=my_strdup(opt_arg,MYF(MY_WME));
      	  }
      	  break;
      	case OPT_database:
      	  if (opt_arg)
      	  {
      	    my_free(options->db);
      	    options->db=my_strdup(opt_arg,MYF(MY_WME));
      	  }
      	  break;
      	case OPT_debug:
      	  mysql_debug(opt_arg ? opt_arg : "d:t:o,/tmp/client.trace");
      	  break;
      	case OPT_return_found_rows:
      	  options->client_flag|=CLIENT_FOUND_ROWS;
      	  break;
      #ifdef HAVE_OPENSSL
      	case OPT_ssl_key:
      	  my_free(options->ssl_key);
          options->ssl_key = my_strdup(opt_arg, MYF(MY_WME));
        break;
      	case OPT_ssl_cert:
      	  my_free(options->ssl_cert);
          options->ssl_cert = my_strdup(opt_arg, MYF(MY_WME));
          break;
      	case OPT_ssl_ca:
      	  my_free(options->ssl_ca);
          options->ssl_ca = my_strdup(opt_arg, MYF(MY_WME));
          break;
      	case OPT_ssl_capath:
          my_free(options->ssl_capath);
          options->ssl_capath = my_strdup(opt_arg, MYF(MY_WME));
          break;
        case OPT_ssl_cipher:
          break;
#else
      	case OPT_ssl_key:
      	case OPT_ssl_cert:
      	case OPT_ssl_ca:
      	case OPT_ssl_capath:
        case OPT_ssl_cipher:
          break;
#endif /* HAVE_OPENSSL */
      	case OPT_charset_dir:
      	  my_free(options->charset_dir);
          options->charset_dir = my_strdup(opt_arg, MYF(MY_WME));
      	  break;
      	case OPT_charset_name:
      	  my_free(options->charset_name);
          options->charset_name = my_strdup(opt_arg, MYF(MY_WME));
      	  break;
      	case OPT_interactive_timeout:
      	  options->client_flag|= CLIENT_INTERACTIVE;
      	  break;
      	case OPT_local_infile:
      	  if (!opt_arg || atoi(opt_arg) != 0)
      	    options->client_flag|= CLIENT_LOCAL_FILES;
      	  else
      	    options->client_flag&= ~CLIENT_LOCAL_FILES;
      	  break;
      	case OPT_disable_local_infile:
      	  options->client_flag&= CLIENT_LOCAL_FILES;
      	  break;
        case OPT_max_allowed_packet:
          if(opt_arg)
            options->max_allowed_packet= atoi(opt_arg);
          break;
        case OPT_protocol:
          options->protocol= find_type(opt_arg, &protocol_types, 0);
#ifndef _WIN32
          if (options->protocol < 0 || options->protocol > 1) 
#else
          if (options->protocol < 0)
#endif
          {
            fprintf(stderr, "Unknown or unsupported protocol %s", opt_arg);
          }
          break;
        case OPT_shared_memory_base_name:
          /* todo */
          break;
        case OPT_multi_results:
          options->client_flag|= CLIENT_MULTI_RESULTS;
          break;
        case OPT_multi_statements:
        case OPT_multi_queries:
          options->client_flag|= CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS;
          break;
        case OPT_report_data_truncation:
          if (opt_arg)
            options->report_data_truncation= atoi(opt_arg);
          else
            options->report_data_truncation= 1;
          break;
        case OPT_secure_auth:
          options->secure_auth= 1;
          break;
        case OPT_plugin_dir:
          {
            char directory[FN_REFLEN];
            if (strlen(opt_arg) >= FN_REFLEN)
              opt_arg[FN_REFLEN]= 0;
            if (!my_realpath(directory, opt_arg, 0))
              OPT_SET_EXTENDED_VALUE(options, plugin_dir, convert_dirname(directory), 1);
          }
          break;
        case OPT_default_auth:
          OPT_SET_EXTENDED_VALUE(options, default_auth, opt_arg, 1);
          break;
        default:
          DBUG_PRINT("warning",("unknown option: %s",option[0]));
        }
      }
    }
  }
  free_defaults(argv);
  DBUG_VOID_RETURN;
}


/***************************************************************************
** Change field rows to field structs
***************************************************************************/

static size_t rset_field_offsets[]= {
  OFFSET(MYSQL_FIELD, catalog),
  OFFSET(MYSQL_FIELD, catalog_length),
  OFFSET(MYSQL_FIELD, db),
  OFFSET(MYSQL_FIELD, db_length),
  OFFSET(MYSQL_FIELD, table),
  OFFSET(MYSQL_FIELD, table_length),
  OFFSET(MYSQL_FIELD, org_table),
  OFFSET(MYSQL_FIELD, org_table_length),
  OFFSET(MYSQL_FIELD, name),
  OFFSET(MYSQL_FIELD, name_length),
  OFFSET(MYSQL_FIELD, org_name),
  OFFSET(MYSQL_FIELD, org_name_length)
};

MYSQL_FIELD *
unpack_fields(MYSQL_DATA *data,MEM_ROOT *alloc,uint fields,
	      my_bool default_value, my_bool long_flag_protocol)
{
  MYSQL_ROWS	*row;
  MYSQL_FIELD	*field,*result;
  char    *p;
  unsigned int i, field_count= sizeof(rset_field_offsets)/sizeof(size_t)/2;

  DBUG_ENTER("unpack_fields");
  field=result=(MYSQL_FIELD*) alloc_root(alloc,sizeof(MYSQL_FIELD)*fields);
  if (!result)
    DBUG_RETURN(0);

  for (row=data->data; row ; row = row->next,field++)
  {
    for (i=0; i < field_count; i++)
    {
      switch(row->data[i][0]) {
      case 0:
       *(char **)(((char *)field) + rset_field_offsets[i*2])= strdup_root(alloc, "");
       *(unsigned int *)(((char *)field) + rset_field_offsets[i*2+1])= 0;
       break;
     default:
       *(char **)(((char *)field) + rset_field_offsets[i*2])= 
         strdup_root(alloc, (char *)row->data[i]);
       *(unsigned int *)(((char *)field) + rset_field_offsets[i*2+1])=
         (uint)(row->data[i+1] - row->data[i] - 1);
       break;
      }
    }

    p= (char *)row->data[6];
    /* filler */
    field->charsetnr= uint2korr(p);
    p+= 2;
    field->length= (uint) uint4korr(p);
    p+= 4;
    field->type=   (enum enum_field_types)uint1korr(p);
    p++;
    field->flags= uint2korr(p);
    p+= 2;
    field->decimals= (uint) p[0];
    p++;

    /* filler */
    p+= 2;

    if (INTERNAL_NUM_FIELD(field))
      field->flags|= NUM_FLAG;

    if (default_value && row->data[7])
    {
      field->def=strdup_root(alloc,(char*) row->data[7]);
    }
    else
      field->def=0;
    field->max_length= 0;
  }
  free_rows(data);				/* Free old data */
  DBUG_RETURN(result);
}


/* Read all rows (fields or data) from server */

MYSQL_DATA *mthd_my_read_rows(MYSQL *mysql,MYSQL_FIELD *mysql_fields,
			     uint fields)
{
  uint	field;
  ulong pkt_len;
  ulong len;
  uchar *cp;
  char	*to, *end_to;
  MYSQL_DATA *result;
  MYSQL_ROWS **prev_ptr,*cur;
  NET *net = &mysql->net;
  DBUG_ENTER("madb_read_rows");

  if ((pkt_len= net_safe_read(mysql)) == packet_error)
    DBUG_RETURN(0);
  if (!(result=(MYSQL_DATA*) my_malloc(sizeof(MYSQL_DATA),
				       MYF(MY_WME | MY_ZEROFILL))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
    DBUG_RETURN(0);
  }
  init_alloc_root(&result->alloc,8192,0);	/* Assume rowlength < 8192 */
  result->alloc.min_malloc=sizeof(MYSQL_ROWS);
  prev_ptr= &result->data;
  result->rows=0;
  result->fields=fields;

  while (*(cp=net->read_pos) != 254 || pkt_len >= 8)
  {
    result->rows++;
    if (!(cur= (MYSQL_ROWS*) alloc_root(&result->alloc,
					    sizeof(MYSQL_ROWS))) ||
	      !(cur->data= ((MYSQL_ROW)
		      alloc_root(&result->alloc,
				     (fields+1)*sizeof(char *)+fields+pkt_len))))
    {
      free_rows(result);
      SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
      DBUG_RETURN(0);
    }
    *prev_ptr=cur;
    prev_ptr= &cur->next;
    to= (char*) (cur->data+fields+1);
    end_to=to+fields+pkt_len-1;
    for (field=0 ; field < fields ; field++)
    {
      if ((len=(ulong) net_field_length(&cp)) == NULL_LENGTH)
      {						/* null field */
        cur->data[field] = 0;
      }
      else
      {
        cur->data[field] = to;
        if (len > (ulong) (end_to - to))
        {
          free_rows(result);
          SET_CLIENT_ERROR(mysql, CR_UNKNOWN_ERROR, unknown_sqlstate, 0);
          DBUG_RETURN(0);
        }
        memcpy(to,(char*) cp,len); to[len]=0;
        to+=len+1;
        cp+=len;
        if (mysql_fields)
        {
          if (mysql_fields[field].max_length < len)
            mysql_fields[field].max_length=len;
         }
      }
    }
    cur->data[field]=to;			/* End of last field */
    if ((pkt_len=net_safe_read(mysql)) == packet_error)
    {
      free_rows(result);
      DBUG_RETURN(0);
    }
  }
  *prev_ptr=0;					/* last pointer is null */
  /* save status */
  if (pkt_len > 1)
  {
    cp++;
    mysql->warning_count= uint2korr(cp);
    cp+= 2;
    mysql->server_status= uint2korr(cp);
  }
  DBUG_PRINT("exit",("Got %d rows",result->rows));
  DBUG_RETURN(result);
}


/*
** Read one row. Uses packet buffer as storage for fields.
** When next packet is read, the previous field values are destroyed
*/


int mthd_my_read_one_row(MYSQL *mysql,uint fields,MYSQL_ROW row, ulong *lengths)
{
  uint field;
  ulong pkt_len,len;
  uchar *pos,*prev_pos, *end_pos;

  if ((pkt_len=(uint) net_safe_read(mysql)) == packet_error)
    return -1;
  
  if (pkt_len <= 8 && mysql->net.read_pos[0] == 254)
  {
    mysql->warning_count= uint2korr(mysql->net.read_pos + 1);
    mysql->server_status= uint2korr(mysql->net.read_pos + 3);
    return 1;				/* End of data */
  }
  prev_pos= 0;				/* allowed to write at packet[-1] */
  pos=mysql->net.read_pos;
  end_pos=pos+pkt_len;
  for (field=0 ; field < fields ; field++)
  {
    if ((len=(ulong) net_field_length(&pos)) == NULL_LENGTH)
    {						/* null field */
      row[field] = 0;
      *lengths++=0;
    }
    else
    {
      if (len > (ulong) (end_pos - pos))
      {
  mysql->net.last_errno=CR_UNKNOWN_ERROR;
  strmov(mysql->net.last_error,ER(mysql->net.last_errno));
  return -1;
      }
      row[field] = (char*) pos;
      pos+=len;
      *lengths++=len;
    }
    if (prev_pos)
      *prev_pos=0;				/* Terminate prev field */
    prev_pos=pos;
  }
  row[field]=(char*) prev_pos+1;		/* End of last field */
  *prev_pos=0;					/* Terminate last field */
  return 0;
}

/****************************************************************************
** Init MySQL structure or allocate one
****************************************************************************/

MYSQL * STDCALL
mysql_init(MYSQL *mysql)
{
  if (mysql_server_init(0, NULL, NULL))
    return NULL;
  if (!mysql)
  {
    if (!(mysql=(MYSQL*) my_malloc(sizeof(*mysql),MYF(MY_WME | MY_ZEROFILL))))
      return 0;
    mysql->free_me=1;
    mysql->net.vio= 0;
  }
  else
    bzero((char*) (mysql),sizeof(*(mysql)));
  mysql->options.connect_timeout=CONNECT_TIMEOUT;
  mysql->charset= default_charset_info;
  strmov(mysql->net.sqlstate, "00000");
  mysql->net.last_error[0]= mysql->net.last_errno= 0;
#if defined(SIGPIPE) && defined(THREAD) && !defined(_WIN32)
  if (!((mysql)->client_flag & CLIENT_IGNORE_SIGPIPE))
    (void) signal(SIGPIPE,pipe_sig_handler);
#endif

/*
  Only enable LOAD DATA INFILE by default if configured with
  --enable-local-infile
*/
#ifdef ENABLED_LOCAL_INFILE
  mysql->options.client_flag|= CLIENT_LOCAL_FILES;
#endif
  mysql->reconnect= 0;
  return mysql;
}



int STDCALL
mysql_ssl_set(MYSQL *mysql, const char *key, const char *cert,
        const char *ca, const char *capath, const char *cipher)
{
  mysql->options.ssl_key = key==0 ? 0 : my_strdup(key,MYF(0));
  mysql->options.ssl_cert = cert==0 ? 0 : my_strdup(cert,MYF(0));
  mysql->options.ssl_ca = ca==0 ? 0 : my_strdup(ca,MYF(0));
  mysql->options.ssl_capath = capath==0 ? 0 : my_strdup(capath,MYF(0));
  mysql->options.ssl_cipher = cipher==0 ? 0 : my_strdup(cipher,MYF(0));
/* todo: add crl stuff */
  return 0;
}

/**************************************************************************
**************************************************************************/

const char * STDCALL
mysql_get_ssl_cipher(MYSQL *mysql)
{
#ifdef HAVE_OPENSSL
  if (mysql->net.vio && mysql->net.vio->ssl)
  {
    return SSL_get_cipher_name(mysql->net.vio->ssl);
  }
#endif
  return(NULL);
}

/**************************************************************************
** Free strings in the SSL structure and clear 'use_ssl' flag.
** NB! Errors are not reported until you do mysql_real_connect.
**************************************************************************/

/**************************************************************************
** Connect to sql server
** If host == 0 then use localhost
**************************************************************************/

MYSQL * STDCALL
mysql_connect(MYSQL *mysql,const char *host,
	      const char *user, const char *passwd)
{
  MYSQL *res;
  mysql=mysql_init(mysql);			/* Make it thread safe */
  {
    DBUG_ENTER("mysql_connect");
    if (!(res=mysql_real_connect(mysql,host,user,passwd,NullS,0,NullS,0)))
    {
      if (mysql->free_me)
	my_free(mysql);
    }
    DBUG_RETURN(res);
  }
}

uchar *ma_send_connect_attr(MYSQL *mysql, uchar *buffer)
{
  if (mysql->server_capabilities & CLIENT_CONNECT_ATTRS)
  {
    buffer= mysql_net_store_length((unsigned char *)buffer, (mysql->options.extension) ?
                             mysql->options.extension->connect_attrs_len : 0);
    if (mysql->options.extension &&
        hash_inited(&mysql->options.extension->connect_attrs))
    {
      uint i;
      for (i=0; i < mysql->options.extension->connect_attrs.records; i++)
      {
        size_t len;
        uchar *p= hash_element(&mysql->options.extension->connect_attrs, i);
        
        len= *(size_t *)p;
        buffer= mysql_net_store_length(buffer, len);
        p+= sizeof(size_t);
        memcpy(buffer, p, len);
        buffer+= len;
        p+= len;
        len= *(size_t *)p;
        buffer= mysql_net_store_length(buffer, len);
        p+= sizeof(size_t);
        memcpy(buffer, p, len);
        buffer+= len;
      }
    }
  }
  return buffer;
}

/** set some default attributes */
static my_bool 
ma_set_connect_attrs(MYSQL *mysql)
{
  char buffer[255];
  int rc= 0;

  rc= mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_DELETE, "_client_name") +
      mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_DELETE, "_client_version") +
      mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_DELETE, "_os") +
#ifdef _WIN32
      mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_DELETE, "_thread") +
#endif
      mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_DELETE, "_pid") +
      mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_DELETE, "_platform");

  rc+= mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_client_name", "libmariadb")
       + mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_client_version", MARIADB_PACKAGE_VERSION)
       + mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_os", MARIADB_SYSTEM_TYPE);

#ifdef _WIN32
  snprintf(buffer, 255, "%lu", (ulong) GetCurrentThreadId());
  rc+= mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_thread", buffer);
  snprintf(buffer, 255, "%lu", (ulong) GetCurrentProcessId());
#else
  snprintf(buffer, 255, "%lu", (ulong) getpid());
#endif
  rc+= mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_pid", buffer);

  rc+= mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_platform", MARIADB_MACHINE_TYPE);
  return(test(rc>0));
}

/*
** Note that the mysql argument must be initialized with mysql_init()
** before calling mysql_real_connect !
*/

MYSQL * STDCALL 
mysql_real_connect(MYSQL *mysql, const char *host, const char *user,
		   const char *passwd, const char *db,
		   uint port, const char *unix_socket,unsigned long client_flag)
{
  if (!mysql->methods)
    mysql->methods= &MARIADB_DEFAULT_METHODS;

  return mysql->methods->db_connect(mysql, host, user, passwd,
                                    db, port, unix_socket, client_flag);
}

MYSQL *mthd_my_real_connect(MYSQL *mysql, const char *host, const char *user,
		   const char *passwd, const char *db,
		   uint port, const char *unix_socket, unsigned long client_flag)
{
  char		buff[NAME_LEN+USERNAME_LENGTH+100];
  char		*end, *end_pkt, *host_info,
                *charset_name= NULL;
  my_socket	sock;
  char    *scramble_data;
  const char *scramble_plugin;
  uint pkt_length, scramble_len, pkt_scramble_len= 0;
  NET	*net= &mysql->net;
#ifdef _WIN32
  HANDLE	hPipe=INVALID_HANDLE_VALUE;
#endif
#ifdef HAVE_SYS_UN_H
  struct	sockaddr_un UNIXaddr;
#endif
  init_sigpipe_variables
  DBUG_ENTER("mysql_real_connect");

  DBUG_PRINT("enter",("host: %s  db: %s  user: %s",
		      host ? host : "(Null)",
		      db ? db : "(Null)",
		      user ? user : "(Null)"));

  ma_set_connect_attrs(mysql);

  if (net->vio)  /* check if we are already connected */
  {
    SET_CLIENT_ERROR(mysql, CR_ALREADY_CONNECTED, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(NULL);
  }
  
  /* Don't give sigpipe errors if the client doesn't want them */
  set_sigpipe(mysql);

  /* use default options */
  if (mysql->options.my_cnf_file || mysql->options.my_cnf_group)
  {
    mysql_read_default_options(&mysql->options,
			       (mysql->options.my_cnf_file ?
				mysql->options.my_cnf_file : "my"),
			       mysql->options.my_cnf_group);
    my_free(mysql->options.my_cnf_file);
    my_free(mysql->options.my_cnf_group);
    mysql->options.my_cnf_file=mysql->options.my_cnf_group=0;
  }

  /* Some empty-string-tests are done because of ODBC */
  if (!host || !host[0])
    host=mysql->options.host;
  if (!user || !user[0])
    user=mysql->options.user;
  if (!passwd)
  {
    passwd=mysql->options.password;
#ifndef DONT_USE_MYSQL_PWD
    if (!passwd)
      passwd=getenv("MYSQL_PWD");  /* get it from environment (haneke) */
#endif
  }
  if (!db || !db[0])
    db=mysql->options.db;
  if (!port)
    port=mysql->options.port;
  if (!unix_socket)
    unix_socket=mysql->options.unix_socket;


  /*  Since 5.0.3 reconnect is not enabled by default!!
  mysql->reconnect=1; */
  mysql->server_status=SERVER_STATUS_AUTOCOMMIT;

  /*
  ** Grab a socket and connect it to the server
  */

#if defined(HAVE_SYS_UN_H)
  if ((!host ||  strcmp(host,LOCAL_HOST) == 0) &&
      mysql->options.protocol != MYSQL_PROTOCOL_TCP &&
      (unix_socket || mysql_unix_port))
  {
    host=LOCAL_HOST;
    if (!unix_socket)
      unix_socket=mysql_unix_port;
    host_info=(char*) ER(CR_LOCALHOST_CONNECTION);
    DBUG_PRINT("info",("Using UNIX sock '%s'",unix_socket));
    if ((sock = socket(AF_UNIX,SOCK_STREAM,0)) == SOCKET_ERROR)
    {
      net->last_errno=CR_SOCKET_CREATE_ERROR;
      sprintf(net->last_error,ER(net->last_errno),socket_errno);
      goto error;
    }
    net->vio = vio_new(sock, VIO_TYPE_SOCKET, TRUE);
    bzero((char*) &UNIXaddr,sizeof(UNIXaddr));
    UNIXaddr.sun_family = AF_UNIX;
    strmov(UNIXaddr.sun_path, unix_socket);
    if (connect_sync_or_async(mysql, net, sock,
                              (struct sockaddr *) &UNIXaddr, sizeof(UNIXaddr)))
    {
      DBUG_PRINT("error",("Got error %d on connect to local server",socket_errno));
      my_set_error(mysql, CR_CONNECTION_ERROR, SQLSTATE_UNKNOWN, ER(CR_CONNECTION_ERROR),
                          unix_socket, socket_errno);
      goto error;
    }
    if (socket_block(sock, 1) == SOCKET_ERROR)
      goto error;
  }
  else
#elif defined(_WIN32)
  {
    if ((unix_socket ||
        (!host && is_NT()) ||
        (host && strcmp(host,LOCAL_HOST_NAMEDPIPE) == 0) ||
        mysql->options.named_pipe ||
        !have_tcpip) &&
        mysql->options.protocol != MYSQL_PROTOCOL_TCP)
    {
      sock=0;
      if ((hPipe=create_named_pipe(net, mysql->options.connect_timeout,
				   (char**) &host, (char**) &unix_socket)) ==
	  INVALID_HANDLE_VALUE)
      {
	DBUG_PRINT("error",
		   ("host: '%s'  socket: '%s'  named_pipe: %d  have_tcpip: %d",
		    host ? host : "<null>",
		    unix_socket ? unix_socket : "<null>",
		    (int) mysql->options.named_pipe,
		    (int) have_tcpip));
	if (mysql->options.named_pipe ||
	    (host && !strcmp(host,LOCAL_HOST_NAMEDPIPE)) ||
	    (unix_socket && !strcmp(unix_socket,MYSQL_NAMEDPIPE)))
	  goto error;		/* User only requested named pipes */
	/* Try also with TCP/IP */
      }
      else
      {
        net->vio=vio_new_win32pipe(hPipe);
        sprintf(host_info=buff, ER(CR_NAMEDPIPE_CONNECTION), host,
                unix_socket);
      }
    }
  }
  if (hPipe == INVALID_HANDLE_VALUE)
#endif
  {
    struct addrinfo hints, *save_res= 0, *res= 0;
    char server_port[NI_MAXSERV];
    int gai_rc;
    int rc;

    unix_socket=0;				/* This is not used */
    if (!port)
      port=mysql_port;
    if (!host)
      host=LOCAL_HOST;
    sprintf(host_info=buff,ER(CR_TCP_CONNECTION),host);
    bzero(&server_port, NI_MAXSERV);

    DBUG_PRINT("info",("Server name: '%s'.  TCP sock: %d", host,port));

    my_snprintf(server_port, NI_MAXSERV, "%d", port);

    /* set hints for getaddrinfo */
    bzero(&hints, sizeof(hints));
    hints.ai_protocol= IPPROTO_TCP; /* TCP connections only */
    hints.ai_family= AF_UNSPEC;     /* includes: IPv4, IPv6 or hostname */
    hints.ai_socktype= SOCK_STREAM;

    /* Get the address information for the server using getaddrinfo() */
    gai_rc= getaddrinfo(host, server_port, &hints, &res);
    if (gai_rc != 0)
    {
      my_set_error(mysql, CR_UNKNOWN_HOST, SQLSTATE_UNKNOWN, 
                   ER(CR_UNKNOWN_HOST), host, gai_rc);
      goto error;
    }

    /* res is a linked list of addresses. If connect to an address fails we will not return
       an error, instead we will try the next address */
    for (save_res= res; save_res; save_res= save_res->ai_next)
    {
      sock= socket(save_res->ai_family, save_res->ai_socktype, 
                   save_res->ai_protocol);
      if (sock == SOCKET_ERROR)
        /* we do error handling after for loop only for last call */
        continue;
      if (!(net->vio= vio_new(sock, VIO_TYPE_TCPIP, FALSE)))
      {
        my_set_error(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
        closesocket(sock);
        freeaddrinfo(res);
        goto error;
      }
      rc= connect_sync_or_async(mysql, net, sock,
                                save_res->ai_addr, save_res->ai_addrlen);
      if (!rc)
      {
        if (mysql->options.extension && mysql->options.extension->async_context &&
             mysql->options.extension->async_context->active)
          break;
        else if (socket_block(sock, 1) == SOCKET_ERROR)
        {
        closesocket(sock);
        continue;
        }
        break; /* success! */
      }
      vio_delete(mysql->net.vio);
      mysql->net.vio= NULL;
    }
 
    freeaddrinfo(res);

    if (sock == SOCKET_ERROR)
    {
      my_set_error(mysql, CR_IPSOCK_ERROR, SQLSTATE_UNKNOWN, ER(CR_IPSOCK_ERROR),
                   socket_errno);
      goto error;
    }

    /* last call to connect 2 failed */
    if (rc)
    {
      my_set_error(mysql, CR_CONN_HOST_ERROR, SQLSTATE_UNKNOWN, ER(CR_CONN_HOST_ERROR),
                          host, socket_errno);
      goto error;
    }
  }

  /* set timeouts */
  net->vio->read_timeout= mysql->options.read_timeout;
  net->vio->write_timeout= mysql->options.write_timeout;

  if (mysql->options.extension && mysql->options.extension->async_context)
    net->vio->async_context= mysql->options.extension->async_context;

  if (!net->vio || my_net_init(net, net->vio))
  {
    vio_delete(net->vio);
    net->vio = 0;
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
    goto error;
  }
  vio_keepalive(net->vio,TRUE);
  strmov(mysql->net.sqlstate, "00000"); 


  /* set read timeout */
  if (mysql->options.read_timeout >= 0)
    vio_read_timeout(net->vio, mysql->options.read_timeout);

  /* set write timeout */
  if (mysql->options.write_timeout >= 0)
    vio_write_timeout(net->vio, mysql->options.read_timeout);
  /* Get version info */
  mysql->protocol_version= PROTOCOL_VERSION;	/* Assume this */
  if (mysql->options.connect_timeout >= 0 &&
      vio_wait_or_timeout(net->vio, FALSE, mysql->options.connect_timeout * 1000) < 1)
  {
    my_set_error(mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                 ER(CR_SERVER_LOST_EXTENDED),
                 "handshake: waiting for inital communication packet",
                 errno);
    goto error;
  }
  if ((pkt_length=net_safe_read(mysql)) == packet_error)
  {
    if (mysql->net.last_errno == CR_SERVER_LOST)
      my_set_error(mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                 ER(CR_SERVER_LOST_EXTENDED),
                 "handshake: reading inital communication packet",
                 errno);

    goto error;
  }
  end= (char *)net->read_pos;
  end_pkt= (char *)net->read_pos + pkt_length;

  /* Check if version of protocoll matches current one */

  mysql->protocol_version= end[0];
  end++;

  /* Check if server sends an error */
  if (mysql->protocol_version == 0XFF)
  {
    net_get_error(end, pkt_length - 1, net->last_error, sizeof(net->last_error),
      &net->last_errno, net->sqlstate);
    /* fix for bug #26426 */
    if (net->last_errno == 1040)
      memcpy(net->sqlstate, "08004", SQLSTATE_LENGTH);
    goto error;
  }

  DBUG_DUMP("packet",net->read_pos,10);
  DBUG_PRINT("info",("mysql protocol version %d, server=%d",
		     PROTOCOL_VERSION, mysql->protocol_version));
  if (mysql->protocol_version <  PROTOCOL_VERSION)
  {
    net->last_errno= CR_VERSION_ERROR;
    sprintf(net->last_error, ER(CR_VERSION_ERROR), mysql->protocol_version,
	    PROTOCOL_VERSION);
    goto error;
  }
  /* Save connection information */
  if (!user) user="";
  if (!passwd) passwd="";

  if (!my_multi_malloc(MYF(0),
		       &mysql->host_info, (uint) strlen(host_info)+1,
		       &mysql->host,      (uint) strlen(host)+1,
		       &mysql->unix_socket,unix_socket ?
		       (uint) strlen(unix_socket)+1 : (uint) 1,
		       &mysql->server_version, (uint) (end - (char*) net->read_pos),
		       NullS) ||
      !(mysql->user=my_strdup(user,MYF(0))) ||
      !(mysql->passwd=my_strdup(passwd,MYF(0))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
    goto error;
  }
  strmov(mysql->host_info,host_info);
  strmov(mysql->host,host);
  if (unix_socket)
    strmov(mysql->unix_socket,unix_socket);
  else
    mysql->unix_socket=0;
  mysql->port=port;
  client_flag|=mysql->options.client_flag;

  if (strncmp(end, "5.5.5-", 6) == 0)
  {
    if (!(mysql->server_version= my_strdup(end + 6, 0)))
    {
      SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
      goto error;
    }
  }
  else
  {
    if (!(mysql->server_version= my_strdup(end, MYF(0))))
    {
      SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
      goto error;
    }
  }
  end+= strlen(end) + 1;

  mysql->thread_id=uint4korr(end);
  end+=4;

  /* This is the first part of scramble packet. In 4.1 and later
     a second package will follow later */
  scramble_data= end;
  scramble_len= SCRAMBLE_LENGTH_323 + 1;
  scramble_plugin= old_password_plugin_name;
  end+= SCRAMBLE_LENGTH_323;

  /* 1st pad */
  end++;

  if (end + 1<= end_pkt)
  {
    mysql->server_capabilities=uint2korr(end);
  }

  /* mysql 5.5 protocol */
  if (end + 18 <= end_pkt)
  {
    mysql->server_language= uint1korr(end + 2);
    mysql->server_status= uint2korr(end + 3);
    mysql->server_capabilities|= uint2korr(end + 5) << 16;
    pkt_scramble_len= uint1korr(end + 7);
  }
  /* pad 2 */
  end+= 18;

  /* second scramble package */
  if (end + SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323 + 1 <= end_pkt)
  {
    memcpy(end - SCRAMBLE_LENGTH_323, scramble_data, SCRAMBLE_LENGTH_323);
    scramble_data= end - SCRAMBLE_LENGTH_323;
    if (mysql->server_capabilities & CLIENT_PLUGIN_AUTH)
    {
      scramble_len= pkt_scramble_len;
      scramble_plugin= scramble_data + scramble_len;
      if (scramble_data + scramble_len > end_pkt)
        scramble_len= (uint)(end_pkt - scramble_data);
    } else
    {
      scramble_len= (uint)(end_pkt - scramble_data);
      scramble_plugin= native_password_plugin_name;
    }
  } else
  {
    mysql->server_capabilities&= ~CLIENT_SECURE_CONNECTION;
    if (mysql->options.secure_auth)
    {
      SET_CLIENT_ERROR(mysql, CR_SECURE_AUTH, unknown_sqlstate, 0);
      goto error;
    }
  }
   

  /* Set character set */
  if (mysql->options.charset_name)
    mysql->charset= mysql_find_charset_name(mysql->options.charset_name);
  else if (mysql->server_language)
    mysql->charset= mysql_find_charset_nr(mysql->server_language);
  else
    mysql->charset=default_charset_info;

  if (!mysql->charset)
  {
    net->last_errno=CR_CANT_READ_CHARSET;
    sprintf(net->last_error,ER(net->last_errno),
      charset_name ? charset_name : "unknown",
      "compiled_in");
    goto error;
  }

  mysql->client_flag= client_flag;

  if (run_plugin_auth(mysql, scramble_data, scramble_len,
                             scramble_plugin, db))
    goto error;

  if (mysql->client_flag & CLIENT_COMPRESS)
    net->compress= 1;

  /* last part: select default db */
  if (db && !mysql->db)
  {
    if (mysql_select_db(mysql, db))
    {
      my_set_error(mysql, CR_SERVER_LOST, unknown_sqlstate,
                          ER(CR_SERVER_LOST_EXTENDED),
                          "Setting intital database",
                          errno);
      goto error;
    }
  }  

  DBUG_PRINT("info",("Server version = '%s'  capabilites: %ld  status: %d  client_flag: %d",
		     mysql->server_version,mysql->server_capabilities,
		     mysql->server_status, client_flag));

  if (mysql->options.init_command)
  {
    char **begin= (char **)mysql->options.init_command->buffer;
    char **end= begin + mysql->options.init_command->elements;

    /* Avoid reconnect in mysql_real_connect */
    my_bool save_reconnect= mysql->reconnect;
    mysql->reconnect= 0;

    for (;begin < end; begin++)
    {  
      if (mysql_real_query(mysql, *begin, (unsigned long)strlen(*begin)))
        goto error;

    /* check if query produced a result set */
      do {
        MYSQL_RES *res;
        if ((res= mysql_use_result(mysql)))
          mysql_free_result(res);
      } while (!mysql_next_result(mysql));
    }
    mysql->reconnect= save_reconnect;
  }

  strmov(mysql->net.sqlstate, "00000");

  DBUG_PRINT("exit",("Mysql handler: %lx",mysql));
  reset_sigpipe(mysql);
  DBUG_RETURN(mysql);

error:
  reset_sigpipe(mysql);
  DBUG_PRINT("error",("message: %u (%s)",net->last_errno,net->last_error));
  {
    /* Free alloced memory */
    end_server(mysql);
    /* only free the allocated memory, user needs to call mysql_close */
    mysql_close_memory(mysql);
    if (!(((ulong) client_flag) & CLIENT_REMEMBER_OPTIONS))
      mysql_close_options(mysql);
  }
  DBUG_RETURN(0);
}


static my_bool mysql_reconnect(MYSQL *mysql)
{
  MYSQL tmp_mysql;
  LIST *li_stmt= mysql->stmts;
  DBUG_ENTER("mysql_reconnect");

  if (!mysql->reconnect ||
      (mysql->server_status & SERVER_STATUS_IN_TRANS) || !mysql->host_info)
  {
   /* Allov reconnect next time */
    mysql->server_status&= ~SERVER_STATUS_IN_TRANS;
    my_set_error(mysql, CR_SERVER_GONE_ERROR, SQLSTATE_UNKNOWN, 0);
    DBUG_RETURN(1);
  }

  mysql_init(&tmp_mysql);
  tmp_mysql.options=mysql->options;

  /* don't reread options from configuration files */
  tmp_mysql.options.my_cnf_group= tmp_mysql.options.my_cnf_file= NULL;

  /* make sure that we reconnect with the same character set */
  if (!tmp_mysql.options.charset_name ||
      strcmp(tmp_mysql.options.charset_name, mysql->charset->csname))
  {
    my_free(tmp_mysql.options.charset_name);
    tmp_mysql.options.charset_name= my_strdup(mysql->charset->csname, MYF(MY_WME));
  }

  tmp_mysql.reconnect= mysql->reconnect;
  if (!mysql_real_connect(&tmp_mysql,mysql->host,mysql->user,mysql->passwd,
			  mysql->db, mysql->port, mysql->unix_socket,
			  mysql->client_flag | CLIENT_REMEMBER_OPTIONS))
  {
    /* don't free options (CONC-118) */
    memset(&tmp_mysql.options, 0, sizeof(struct st_mysql_options));
    my_set_error(mysql, tmp_mysql.net.last_errno, 
                        tmp_mysql.net.sqlstate, 
                        tmp_mysql.net.last_error);
    mysql_close(&tmp_mysql);
    DBUG_RETURN(1);
  }

  /* reset the connection in all active statements 
     todo: check stmt->mysql in mysql_stmt* functions ! */
  for (;li_stmt;li_stmt= li_stmt->next)
  {
    MYSQL_STMT *stmt= (MYSQL_STMT *)li_stmt->data;

    if (stmt->state != MYSQL_STMT_INITTED)
    {
      stmt->state= MYSQL_STMT_INITTED;
      SET_CLIENT_STMT_ERROR(stmt, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    }
  }

  tmp_mysql.free_me= mysql->free_me;
  tmp_mysql.stmts= mysql->stmts;
  mysql->stmts= NULL;

  /* Don't free options, we moved them to tmp_mysql */
  memset(&mysql->options, 0, sizeof(mysql->options));
  mysql->free_me=0;
  mysql->stmts= NULL;
  mysql_close(mysql);
  *mysql=tmp_mysql;
  mysql->reconnect= 1;
  net_clear(&mysql->net);
  mysql->affected_rows= ~(my_ulonglong) 0;
  DBUG_RETURN(0);
}


/**************************************************************************
** Change user and database 
**************************************************************************/

my_bool	STDCALL mysql_change_user(MYSQL *mysql, const char *user, 
				  const char *passwd, const char *db)
{
  const CHARSET_INFO *s_cs= mysql->charset;
  char *s_user= mysql->user, 
       *s_passwd= mysql->passwd, 
       *s_db= mysql->db;
  int rc;
  
  DBUG_ENTER("mysql_change_user");

  if (!user)
    user="";
  if (!passwd)
    passwd="";
  if (!db)
    db="";

  if (mysql->options.charset_name)
    mysql->charset =mysql_find_charset_name(mysql->options.charset_name);
  else if (mysql->server_language)
    mysql->charset=mysql_find_charset_nr(mysql->server_language);
  else
    mysql->charset=default_charset_info;

  mysql->user= (char *)user;
  mysql->passwd= (char *)passwd;
  mysql->db= (char *)db;
  rc= run_plugin_auth(mysql, 0, 0, 0, db);

  if (rc==0)
  {
    LIST *li_stmt= mysql->stmts;
    my_free(s_user);
    my_free(s_passwd);
    my_free(s_db);

    if (!(mysql->user=  my_strdup(user,MYF(MY_WME))) ||
        !(mysql->passwd=my_strdup(passwd,MYF(MY_WME))) ||
        !(mysql->db= db ? my_strdup(db,MYF(MY_WME)) : 0))
    {
      SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
      rc= 1;
    }

    for (;li_stmt;li_stmt= li_stmt->next)
    {
      MYSQL_STMT *stmt= (MYSQL_STMT *)li_stmt->data;
      stmt->mysql= NULL;
      SET_CLIENT_STMT_ERROR(stmt, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    }/* detach stmts */
    mysql->stmts= NULL;
    
  } else
  {
    mysql->user= s_user;
    mysql->passwd= s_passwd;
    mysql->db= s_db;
    mysql->charset= s_cs;
  }
  DBUG_RETURN(rc);
}


/**************************************************************************
** Set current database
**************************************************************************/

int STDCALL
mysql_select_db(MYSQL *mysql, const char *db)
{
  int error;
  DBUG_ENTER("mysql_select_db");
  DBUG_PRINT("enter",("db: '%s'",db));

  if ((error=simple_command(mysql,MYSQL_COM_INIT_DB,db,(uint) strlen(db),0,0)))
    DBUG_RETURN(error);
  my_free(mysql->db);
  mysql->db=my_strdup(db,MYF(MY_WME));
  DBUG_RETURN(0);
}


/*************************************************************************
** Send a QUIT to the server and close the connection
** If handle is alloced by mysql connect free it.
*************************************************************************/

static void mysql_close_options(MYSQL *mysql)
{
  if (mysql->options.init_command)
  {
    char **begin= (char **)mysql->options.init_command->buffer;
    char **end= begin + mysql->options.init_command->elements;

    for (;begin < end; begin++)
      my_free(*begin);
    delete_dynamic(mysql->options.init_command);
    my_free(mysql->options.init_command);
  }
  my_free(mysql->options.user);
  my_free(mysql->options.host);
  my_free(mysql->options.password);
  my_free(mysql->options.unix_socket);
  my_free(mysql->options.db);
  my_free(mysql->options.my_cnf_file);
  my_free(mysql->options.my_cnf_group);
  my_free(mysql->options.charset_dir);
  my_free(mysql->options.charset_name);
  my_free(mysql->options.ssl_key);
  my_free(mysql->options.ssl_cert);
  my_free(mysql->options.ssl_ca);
  my_free(mysql->options.ssl_capath);
  my_free(mysql->options.ssl_cipher);
  if (mysql->options.extension)
  {
    my_free(mysql->options.extension->plugin_dir);
    my_free(mysql->options.extension->default_auth);
    my_free(mysql->options.extension->db_driver);
    my_free(mysql->options.extension->ssl_crl);
    my_free(mysql->options.extension->ssl_crlpath);
    if (mysql->options.extension->async_context){
      my_context_destroy(&mysql->options.extension->async_context->async_context);
      my_free(mysql->options.extension->async_context);
    }
    if(hash_inited(&mysql->options.extension->connect_attrs))
      hash_free(&mysql->options.extension->connect_attrs);
  }
  my_free(mysql->options.extension);
  /* clear all pointer */
  memset(&mysql->options, 0, sizeof(mysql->options));
}

static void mysql_close_memory(MYSQL *mysql)
{
  my_free(mysql->host_info);
  my_free(mysql->user);
  my_free(mysql->passwd);
  my_free(mysql->db);
  my_free(mysql->server_version);
  mysql->host_info= mysql->server_version=mysql->user=mysql->passwd=mysql->db=0;
}



void my_set_error(MYSQL *mysql,
                  unsigned int error_nr,
                  const char *sqlstate,
                  const char *format,
                  ...)
{
  va_list ap;

  DBUG_ENTER("my_set_error");

  mysql->net.last_errno= error_nr;
  strncpy(mysql->net.sqlstate, sqlstate, SQLSTATE_LENGTH);
  va_start(ap, format);
  my_vsnprintf(mysql->net.last_error, MYSQL_ERRMSG_SIZE, 
               format ? format : ER(error_nr), ap);
  DBUG_PRINT("info", ("error(%d) %s", error_nr, mysql->net.last_error));
  va_end(ap);
  DBUG_VOID_RETURN;
}

void mysql_close_slow_part(MYSQL *mysql)
{
  if (mysql->net.vio)
  {
    free_old_query(mysql);
    mysql->status=MYSQL_STATUS_READY; /* Force command */
    mysql->reconnect=0;
    simple_command(mysql,MYSQL_COM_QUIT,NullS,0,1,0);
    end_server(mysql);
  }
}

void STDCALL
mysql_close(MYSQL *mysql)
{
   MYSQL_STMT *stmt;
  DBUG_ENTER("mysql_close");
  if (mysql)					/* Some simple safety */
  {
    LIST *li_stmt= mysql->stmts;

    if (mysql->methods)
      mysql->methods->db_close(mysql);

    /* reset the connection in all active statements 
       todo: check stmt->mysql in mysql_stmt* functions ! */
    for (;li_stmt;li_stmt= li_stmt->next)
    {
      stmt= (MYSQL_STMT *)li_stmt->data;
      stmt->mysql= NULL;
      SET_CLIENT_STMT_ERROR(stmt, CR_SERVER_LOST, SQLSTATE_UNKNOWN, 0);
    }
    mysql_close_memory(mysql);
    mysql_close_options(mysql);
    mysql->host_info=mysql->user=mysql->passwd=mysql->db=0;
   
    /* Clear pointers for better safety */
    bzero((char*) &mysql->options,sizeof(mysql->options));
    mysql->net.vio= 0;
    if (mysql->free_me)
      my_free(mysql);
  }
  DBUG_VOID_RETURN;
}


/**************************************************************************
** Do a query. If query returned rows, free old rows.
** Read data by mysql_store_result or by repeat call of mysql_fetch_row
**************************************************************************/

int STDCALL
mysql_query(MYSQL *mysql, const char *query)
{
  return mysql_real_query(mysql,query, (uint) strlen(query));
}

/*
  Send the query and return so we can do something else.
  Needs to be followed by mysql_read_query_result() when we want to
  finish processing it.
*/  

int STDCALL
mysql_send_query(MYSQL* mysql, const char* query, unsigned long length)
{
  return simple_command(mysql, MYSQL_COM_QUERY, query, length, 1,0);
}

int mthd_my_read_query_result(MYSQL *mysql)
{
  uchar *pos;
  ulong field_count;
  MYSQL_DATA *fields;
  ulong length;
  DBUG_ENTER("mthd_my_read_query_result");

  if (!mysql || (length = net_safe_read(mysql)) == packet_error)
    DBUG_RETURN(1);
  free_old_query(mysql);			/* Free old result */
get_info:
  pos=(uchar*) mysql->net.read_pos;
  if ((field_count= net_field_length(&pos)) == 0)
  {
    mysql->affected_rows= net_field_length_ll(&pos);
    mysql->insert_id=	  net_field_length_ll(&pos);
    mysql->server_status=uint2korr(pos); 
    pos+=2;
    mysql->warning_count=uint2korr(pos); 
    pos+=2;
    if (pos < mysql->net.read_pos+length && net_field_length(&pos))
      mysql->info=(char*) pos;
    DBUG_RETURN(0);
  }
  if (field_count == NULL_LENGTH)		/* LOAD DATA LOCAL INFILE */
  {
    int error=mysql_handle_local_infile(mysql, (char *)pos);

    if ((length=net_safe_read(mysql)) == packet_error || error)
      DBUG_RETURN(-1);
    goto get_info;				/* Get info packet */
  }
  if (!(mysql->server_status & SERVER_STATUS_AUTOCOMMIT))
    mysql->server_status|= SERVER_STATUS_IN_TRANS;

  mysql->extra_info= net_field_length_ll(&pos); /* Maybe number of rec */
  if (!(fields=mysql->methods->db_read_rows(mysql,(MYSQL_FIELD*) 0,8)))
    DBUG_RETURN(-1);
  if (!(mysql->fields=unpack_fields(fields,&mysql->field_alloc,
				    (uint) field_count,1,
				    (my_bool) test(mysql->server_capabilities &
						   CLIENT_LONG_FLAG))))
    DBUG_RETURN(-1);
  mysql->status=MYSQL_STATUS_GET_RESULT;
  mysql->field_count=field_count;
  DBUG_RETURN(0);
}

my_bool STDCALL
mysql_read_query_result(MYSQL *mysql)
{
  return test(mysql->methods->db_read_query_result(mysql)) ? 1 : 0;
}

int STDCALL
mysql_real_query(MYSQL *mysql, const char *query, unsigned long length)
{
  DBUG_ENTER("mysql_real_query");
  DBUG_PRINT("enter",("handle: %lx",mysql));
  DBUG_PRINT("query",("Query = \"%.255s\" length=%u",query, length));

  free_old_query(mysql);

  if (simple_command(mysql,MYSQL_COM_QUERY,query,length,1,0))
    DBUG_RETURN(-1);
  DBUG_RETURN(mysql->methods->db_read_query_result(mysql));
}

/**************************************************************************
** Alloc result struct for buffered results. All rows are read to buffer.
** mysql_data_seek may be used.
**************************************************************************/

MYSQL_RES * STDCALL
mysql_store_result(MYSQL *mysql)
{
  MYSQL_RES *result;
  DBUG_ENTER("mysql_store_result");

  if (!mysql->fields)
    DBUG_RETURN(0);
  if (mysql->status != MYSQL_STATUS_GET_RESULT)
  {
    SET_CLIENT_ERROR(mysql, CR_COMMANDS_OUT_OF_SYNC, unknown_sqlstate, 0);
    DBUG_RETURN(0);
  }
  mysql->status=MYSQL_STATUS_READY;		/* server is ready */
  if (!(result=(MYSQL_RES*) my_malloc(sizeof(MYSQL_RES)+
				      sizeof(ulong)*mysql->field_count,
				      MYF(MY_WME | MY_ZEROFILL))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
    DBUG_RETURN(0);
  }
  result->eof=1;				/* Marker for buffered */
  result->lengths=(ulong*) (result+1);
  if (!(result->data=mysql->methods->db_read_rows(mysql,mysql->fields,mysql->field_count)))
  {
    my_free(result);
    DBUG_RETURN(0);
  }
  mysql->affected_rows= result->row_count= result->data->rows;
  result->data_cursor=	result->data->data;
  result->fields=	mysql->fields;
  result->field_alloc=	mysql->field_alloc;
  result->field_count=	mysql->field_count;
  result->current_field=0;
  result->current_row=0;			/* Must do a fetch first */
  mysql->fields=0;				/* fields is now in result */
  DBUG_RETURN(result);				/* Data fetched */
}


/**************************************************************************
** Alloc struct for use with unbuffered reads. Data is fetched by domand
** when calling to mysql_fetch_row.
** mysql_data_seek is a noop.
**
** No other queries may be specified with the same MYSQL handle.
** There shouldn't be much processing per row because mysql server shouldn't
** have to wait for the client (and will not wait more than 30 sec/packet).
**************************************************************************/

MYSQL_RES * STDCALL
mysql_use_result(MYSQL *mysql)
{
  MYSQL_RES *result;
  DBUG_ENTER("mysql_use_result");

  if (!mysql->fields)
    DBUG_RETURN(0);
  if (mysql->status != MYSQL_STATUS_GET_RESULT)
  {
    SET_CLIENT_ERROR(mysql, CR_COMMANDS_OUT_OF_SYNC, unknown_sqlstate, 0);
    DBUG_RETURN(0);
  }
  if (!(result=(MYSQL_RES*) my_malloc(sizeof(*result)+
				      sizeof(ulong)*mysql->field_count,
				      MYF(MY_WME | MY_ZEROFILL))))
    DBUG_RETURN(0);
  result->lengths=(ulong*) (result+1);
  if (!(result->row=(MYSQL_ROW)
	my_malloc(sizeof(result->row[0])*(mysql->field_count+1), MYF(MY_WME))))
  {					/* Ptrs: to one row */
    my_free(result);
    DBUG_RETURN(0);
  }
  result->fields=	mysql->fields;
  result->field_alloc=	mysql->field_alloc;
  result->field_count=	mysql->field_count;
  result->current_field=0;
  result->handle=	mysql;
  result->current_row=	0;
  mysql->fields=0;			/* fields is now in result */
  mysql->status=MYSQL_STATUS_USE_RESULT;
  DBUG_RETURN(result);			/* Data is read to be fetched */
}

/**************************************************************************
** Return next field of the query results
**************************************************************************/
MYSQL_FIELD * STDCALL
mysql_fetch_field(MYSQL_RES *result)
{
  if (result->current_field >= result->field_count)
    return(NULL);
  return &result->fields[result->current_field++];
}

/**************************************************************************
**  Return next row of the query results
**************************************************************************/
MYSQL_ROW STDCALL
mysql_fetch_row(MYSQL_RES *res)
{
  DBUG_ENTER("mysql_fetch_row");
  if (!res)
    return 0;
  if (!res->data)
  {						/* Unbufferred fetch */
    if (!res->eof)
    {
      if (!(res->handle->methods->db_read_one_row(res->handle,res->field_count,res->row, res->lengths)))
      {
        res->row_count++;
        DBUG_RETURN(res->current_row=res->row);
      }
      DBUG_PRINT("info",("end of data"));
      res->eof=1;
      res->handle->status=MYSQL_STATUS_READY;
       /* Don't clear handle in mysql_free_results */
      res->handle=0;
    }
    DBUG_RETURN((MYSQL_ROW) NULL);
  }
  {
    MYSQL_ROW tmp;
    if (!res->data_cursor)
    {
      DBUG_PRINT("info",("end of data"));
      DBUG_RETURN(res->current_row=(MYSQL_ROW) NULL);
    }
    tmp = res->data_cursor->data;
    res->data_cursor = res->data_cursor->next;
    DBUG_RETURN(res->current_row=tmp);
  }
}

/**************************************************************************
** Get column lengths of the current row
** If one uses mysql_use_result, res->lengths contains the length information,
** else the lengths are calculated from the offset between pointers.
**************************************************************************/

ulong * STDCALL
mysql_fetch_lengths(MYSQL_RES *res)
{
  ulong *lengths,*prev_length;
  char *start;
  MYSQL_ROW column,end;

  if (!(column=res->current_row))
    return 0;					/* Something is wrong */
  if (res->data)
  {
    start=0;
    prev_length=0;				/* Keep gcc happy */
    lengths=res->lengths;
    for (end=column+res->field_count+1 ; column != end ; column++,lengths++)
    {
      if (!*column)
      {
	*lengths=0;				/* Null */
	continue;
      }
      if (start)				/* Found end of prev string */
	*prev_length= (uint) (*column-start-1);
      start= *column;
      prev_length=lengths;
    }
  }
  return res->lengths;
}

/**************************************************************************
** Move to a specific row and column
**************************************************************************/

void STDCALL
mysql_data_seek(MYSQL_RES *result, my_ulonglong row)
{
  MYSQL_ROWS	*tmp=0;
  DBUG_PRINT("info",("mysql_data_seek(%ld)",(long) row));
  if (result->data)
    for (tmp=result->data->data; row-- && tmp ; tmp = tmp->next) ;
  result->current_row=0;
  result->data_cursor = tmp;
}

/*************************************************************************
** put the row or field cursor one a position one got from mysql_row_tell()
** This doesn't restore any data. The next mysql_fetch_row or
** mysql_fetch_field will return the next row or field after the last used
*************************************************************************/

MYSQL_ROW_OFFSET STDCALL
mysql_row_seek(MYSQL_RES *result, MYSQL_ROW_OFFSET row)
{
  MYSQL_ROW_OFFSET return_value=result->data_cursor;
  result->current_row= 0;
  result->data_cursor= row;
  return return_value;
}


MYSQL_FIELD_OFFSET STDCALL
mysql_field_seek(MYSQL_RES *result, MYSQL_FIELD_OFFSET field_offset)
{
  MYSQL_FIELD_OFFSET return_value=result->current_field;
  result->current_field=field_offset;
  return return_value;
}

/*****************************************************************************
** List all databases
*****************************************************************************/

MYSQL_RES * STDCALL
mysql_list_dbs(MYSQL *mysql, const char *wild)
{
  char buff[255];
  DBUG_ENTER("mysql_list_dbs");

  append_wild(strmov(buff,"show databases"),buff+sizeof(buff),wild);
  if (mysql_query(mysql,buff))
    DBUG_RETURN(0);
  DBUG_RETURN (mysql_store_result(mysql));
}


/*****************************************************************************
** List all tables in a database
** If wild is given then only the tables matching wild is returned
*****************************************************************************/

MYSQL_RES * STDCALL
mysql_list_tables(MYSQL *mysql, const char *wild)
{
  char buff[255];
  DBUG_ENTER("mysql_list_tables");

  append_wild(strmov(buff,"show tables"),buff+sizeof(buff),wild);
  if (mysql_query(mysql,buff))
    DBUG_RETURN(0);
  DBUG_RETURN (mysql_store_result(mysql));
}


/**************************************************************************
** List all fields in a table
** If wild is given then only the fields matching wild is returned
** Instead of this use query:
** show fields in 'table' like "wild"
**************************************************************************/

MYSQL_RES * STDCALL
mysql_list_fields(MYSQL *mysql, const char *table, const char *wild)
{
  MYSQL_RES *result;
  MYSQL_DATA *query;
  char	     buff[257],*end;
  DBUG_ENTER("mysql_list_fields");
  DBUG_PRINT("enter",("table: '%s'  wild: '%s'",table,wild ? wild : ""));

  LINT_INIT(query);

  end=strmake(strmake(buff, table,128)+1,wild ? wild : "",128);
  if (simple_command(mysql,MYSQL_COM_FIELD_LIST,buff,(uint) (end-buff),1,0) ||
      !(query = mysql->methods->db_read_rows(mysql,(MYSQL_FIELD*) 0,8)))
    DBUG_RETURN(NULL);

  free_old_query(mysql);
  if (!(result = (MYSQL_RES *) my_malloc(sizeof(MYSQL_RES),
					 MYF(MY_WME | MY_ZEROFILL))))
  {
    free_rows(query);
    DBUG_RETURN(NULL);
  }
  result->field_alloc=mysql->field_alloc;
  mysql->fields=0;
  result->field_count = (uint) query->rows;
  result->fields= unpack_fields(query,&result->field_alloc,
				result->field_count,1,
				(my_bool) test(mysql->server_capabilities &
					       CLIENT_LONG_FLAG));
  result->eof=1;
  DBUG_RETURN(result);
}

/* List all running processes (threads) in server */

MYSQL_RES * STDCALL
mysql_list_processes(MYSQL *mysql)
{
  MYSQL_DATA *fields;
  uint field_count;
  uchar *pos;
  DBUG_ENTER("mysql_list_processes");

  LINT_INIT(fields);
  if (simple_command(mysql,MYSQL_COM_PROCESS_INFO,0,0,0,0))
    DBUG_RETURN(0);
  free_old_query(mysql);
  pos=(uchar*) mysql->net.read_pos;
  field_count=(uint) net_field_length(&pos);
  if (!(fields = mysql->methods->db_read_rows(mysql,(MYSQL_FIELD*) 0,5)))
    DBUG_RETURN(NULL);
  if (!(mysql->fields=unpack_fields(fields,&mysql->field_alloc,field_count,0,
				    (my_bool) test(mysql->server_capabilities &
						   CLIENT_LONG_FLAG))))
    DBUG_RETURN(0);
  mysql->status=MYSQL_STATUS_GET_RESULT;
  mysql->field_count=field_count;
  DBUG_RETURN(mysql_store_result(mysql));
}


int  STDCALL
mysql_create_db(MYSQL *mysql, const char *db)
{
  DBUG_ENTER("mysql_createdb");
  DBUG_PRINT("enter",("db: %s",db));
  DBUG_RETURN(simple_command(mysql,MYSQL_COM_CREATE_DB,db, (uint) strlen(db),0,0));
}


int  STDCALL
mysql_drop_db(MYSQL *mysql, const char *db)
{
  DBUG_ENTER("mysql_drop_db");
  DBUG_PRINT("enter",("db: %s",db));
  DBUG_RETURN(simple_command(mysql,MYSQL_COM_DROP_DB,db,(uint) strlen(db),0,0));
}

/* In 5.0 this version became an additional parameter shutdown_level */
int STDCALL
mysql_shutdown(MYSQL *mysql, enum mysql_enum_shutdown_level shutdown_level)
{
  uchar s_level[2];
  DBUG_ENTER("mysql_shutdown");
  s_level[0]= (uchar)shutdown_level;
  DBUG_RETURN(simple_command(mysql, MYSQL_COM_SHUTDOWN, (char *)s_level, 1, 0, 0));
}

int STDCALL
mysql_refresh(MYSQL *mysql,uint options)
{
  uchar bits[1];
  DBUG_ENTER("mysql_refresh");
  bits[0]= (uchar) options;
  DBUG_RETURN(simple_command(mysql,MYSQL_COM_REFRESH,(char*) bits,1,0,0));
}

int STDCALL
mysql_kill(MYSQL *mysql,ulong pid)
{
  char buff[12];
  DBUG_ENTER("mysql_kill");
  int4store(buff,pid);
  /* if we kill our own thread, reading the response packet will fail */ 
  DBUG_RETURN(simple_command(mysql,MYSQL_COM_PROCESS_KILL,buff,4,0,0));
}


int STDCALL
mysql_dump_debug_info(MYSQL *mysql)
{
  DBUG_ENTER("mysql_dump_debug_info");
  DBUG_RETURN(simple_command(mysql,MYSQL_COM_DEBUG,0,0,0,0));
}

char * STDCALL
mysql_stat(MYSQL *mysql)
{
  DBUG_ENTER("mysql_stat");
  if (simple_command(mysql,MYSQL_COM_STATISTICS,0,0,0,0))
    return mysql->net.last_error;
  mysql->net.read_pos[mysql->packet_length]=0;	/* End of stat string */
  if (!mysql->net.read_pos[0])
  {
    SET_CLIENT_ERROR(mysql, CR_WRONG_HOST_INFO , unknown_sqlstate, 0);
    return mysql->net.last_error;
  }
  DBUG_RETURN((char*) mysql->net.read_pos);
}


int STDCALL
mysql_ping(MYSQL *mysql)
{
  int rc;
  DBUG_ENTER("mysql_ping");
  rc= simple_command(mysql,MYSQL_COM_PING,0,0,0,0);

  /* if connection was terminated and reconnect is true, try again */
  if (rc!=0  && mysql->reconnect)
    rc= simple_command(mysql,MYSQL_COM_PING,0,0,0,0);
  return rc;
}


char * STDCALL
mysql_get_server_info(MYSQL *mysql)
{
  return((char*) mysql->server_version);
}

unsigned long STDCALL mysql_get_server_version(MYSQL *mysql)
{
  long major, minor, patch;
  char *p;

  if (!(p = mysql->server_version)) {
    return 0;
  }

  major = strtol(p, &p, 10);
  p += 1; /* consume the dot */
  minor = strtol(p, &p, 10);
  p += 1; /* consume the dot */
  patch = strtol(p, &p, 10);

  return (unsigned long)(major * 10000L + (unsigned long)(minor * 100L + patch));
}



char * STDCALL
mysql_get_host_info(MYSQL *mysql)
{
  return(mysql->host_info);
}


uint STDCALL
mysql_get_proto_info(MYSQL *mysql)
{
  return (mysql->protocol_version);
}

const char * STDCALL
mysql_get_client_info(void)
{
  return (char*) MYSQL_CLIENT_VERSION;
}

static size_t get_store_length(size_t length)
{
  if (length < (size_t) L64(251))
    return 1;
  if (length < (size_t) L64(65536))
    return 2;
  if (length < (size_t) L64(16777216))
    return 3;
  return 9;
}

uchar *ma_get_hash_key(const uchar *hash_entry, 
                       unsigned int *length,
                       my_bool not_used __attribute__((unused)))
{
  /* Hash entry has the following format:
     Offset: 0               key length
             sizeof(size_t)  key
             key_length +
             sizeof(size_t)  value length
                             value
  */
  uchar *p= (uchar *)hash_entry;
  size_t len=*((size_t*)p);
  p+= sizeof(size_t);
  *length= (uint)len;
  return p;
}

void ma_hash_free(void *p)
{
  my_free(p);
}


int STDCALL
mysql_optionsv(MYSQL *mysql,enum mysql_option option, ...)
{
  va_list ap;
  void *arg1;
  struct mysql_async_context *ctxt;
  size_t stacksize;  

  DBUG_ENTER("mysql_option");
  DBUG_PRINT("enter",("option: %d",(int) option));

  va_start(ap, option);

  arg1= va_arg(ap, void *);

  switch (option) {
  case MYSQL_OPT_CONNECT_TIMEOUT:
    mysql->options.connect_timeout= *(uint*) arg1;
    break;
  case MYSQL_OPT_COMPRESS:
    mysql->options.compress= 1;			/* Remember for connect */
    mysql->options.client_flag|= CLIENT_COMPRESS;
    break;
  case MYSQL_OPT_NAMED_PIPE:
    mysql->options.named_pipe=1;		/* Force named pipe */
    break;
  case MYSQL_OPT_LOCAL_INFILE:			/* Allow LOAD DATA LOCAL ?*/
    if (!arg1 || test(*(uint*) arg1))
      mysql->options.client_flag|= CLIENT_LOCAL_FILES;
    else
      mysql->options.client_flag&= ~CLIENT_LOCAL_FILES;
    break;
  case MYSQL_INIT_COMMAND:
    options_add_initcommand(&mysql->options, (char *)arg1);
    break;
  case MYSQL_READ_DEFAULT_FILE:
    my_free(mysql->options.my_cnf_file);
    mysql->options.my_cnf_file=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_READ_DEFAULT_GROUP:
    my_free(mysql->options.my_cnf_group);
    mysql->options.my_cnf_group=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_SET_CHARSET_DIR:
    /* not supported in this version. Since all character sets 
       are internally available, we don't throw an error */
    break;
  case MYSQL_SET_CHARSET_NAME:
    my_free(mysql->options.charset_name);
    mysql->options.charset_name=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_OPT_RECONNECT:
    mysql->reconnect= *(uint *)arg1;
    break;
  case MYSQL_OPT_PROTOCOL:
#ifdef _WIN32
    if (*(uint *)arg1 > MYSQL_PROTOCOL_PIPE)
#else
    if (*(uint *)arg1 > MYSQL_PROTOCOL_SOCKET)
#endif
      DBUG_RETURN(-1);
    mysql->options.protocol= *(uint *)arg1;
    break;
  case MYSQL_OPT_READ_TIMEOUT:
    mysql->options.read_timeout= *(uint *)arg1;
    break;
  case MYSQL_OPT_WRITE_TIMEOUT:
    mysql->options.write_timeout= *(uint *)arg1;
    break;
  case MYSQL_REPORT_DATA_TRUNCATION:
    mysql->options.report_data_truncation= *(uint *)arg1;
    break;
  case MYSQL_PROGRESS_CALLBACK:
    if (!mysql->options.extension)
      mysql->options.extension= (struct st_mysql_options_extension *)
        my_malloc(sizeof(struct st_mysql_options_extension),
                  MYF(MY_WME | MY_ZEROFILL));
    if (mysql->options.extension)
      mysql->options.extension->report_progress=
        (void (*)(const MYSQL *, uint, uint, double, const char *, uint)) arg1; 
    break;
  case MYSQL_PLUGIN_DIR:
    OPT_SET_EXTENDED_VALUE(&mysql->options, plugin_dir, (char *)arg1, 1);
    break;
  case MYSQL_DEFAULT_AUTH:
    OPT_SET_EXTENDED_VALUE(&mysql->options, default_auth, (char *)arg1, 1);
    break;
  case MYSQL_DATABASE_DRIVER:
    {
      MARIADB_DB_PLUGIN *db_plugin;
      if (!(db_plugin= (MARIADB_DB_PLUGIN *)mysql_client_find_plugin(mysql, (char *)arg1,
                                                          MYSQL_CLIENT_DB_PLUGIN)))
        break;
      if (!mysql->options.extension)
        mysql->options.extension= (struct st_mysql_options_extension *)
          my_malloc(sizeof(struct st_mysql_options_extension),
                    MYF(MY_WME | MY_ZEROFILL));
      if (!mysql->options.extension->db_driver)
        mysql->options.extension->db_driver= (MARIADB_DB_DRIVER *)
          my_malloc(sizeof(MARIADB_DB_DRIVER), MYF(MY_WME | MY_ZEROFILL));
      if (mysql->options.extension &&
          mysql->options.extension->db_driver)
      {  
        mysql->options.extension->db_driver->plugin = db_plugin;
        mysql->options.extension->db_driver->buffer= NULL;
        mysql->options.extension->db_driver->name= (char *)db_plugin->name;
        mysql->methods= db_plugin->methods;
      }
    }
    break;
    case MYSQL_OPT_NONBLOCK:
    if (mysql->options.extension &&
        (ctxt = mysql->options.extension->async_context) != 0)
    {
      /*
        We must not allow changing the stack size while a non-blocking call is
        suspended (as the stack is then in use).
      */
      if (ctxt->suspended)
        DBUG_RETURN(1);
      my_context_destroy(&ctxt->async_context);
      my_free(ctxt);
    }
    if (!(ctxt= (struct mysql_async_context *)
          my_malloc(sizeof(*ctxt), MYF(MY_ZEROFILL))))
    {
      SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
      DBUG_RETURN(1);
    }
    stacksize= 0;
    if (arg1)
      stacksize= *(const size_t *)arg1;
    if (!stacksize)
      stacksize= ASYNC_CONTEXT_DEFAULT_STACK_SIZE;
    if (my_context_init(&ctxt->async_context, stacksize))
    {
      my_free(ctxt);
      DBUG_RETURN(1);
    }
    if (!mysql->options.extension)
      if(!(mysql->options.extension= (struct st_mysql_options_extension *)
        my_malloc(sizeof(struct st_mysql_options_extension),
                  MYF(MY_WME | MY_ZEROFILL))))
      {
        SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
        DBUG_RETURN(1);
      }
    mysql->options.extension->async_context= ctxt;
    if (mysql->net.vio)
      mysql->net.vio->async_context= ctxt;
    break;

  case MYSQL_OPT_SSL_VERIFY_SERVER_CERT:
    if (*(uint *)arg1)
      mysql->options.client_flag |= CLIENT_SSL_VERIFY_SERVER_CERT;
    else
      mysql->options.client_flag &= ~CLIENT_SSL_VERIFY_SERVER_CERT;
    break;
  case MYSQL_OPT_SSL_KEY:
    my_free(mysql->options.ssl_key);
    mysql->options.ssl_key=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_OPT_SSL_CERT:
    my_free(mysql->options.ssl_cert);
    mysql->options.ssl_cert=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_OPT_SSL_CA:
    my_free(mysql->options.ssl_ca);
    mysql->options.ssl_ca=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_OPT_SSL_CAPATH:
    my_free(mysql->options.ssl_capath);
    mysql->options.ssl_capath=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_OPT_SSL_CIPHER:
    my_free(mysql->options.ssl_cipher);
    mysql->options.ssl_cipher=my_strdup((char *)arg1,MYF(MY_WME));
    break;
  case MYSQL_OPT_SSL_CRL:
    OPT_SET_EXTENDED_VALUE(&mysql->options, ssl_crl, (char *)arg1, 1);
    break;
  case MYSQL_OPT_SSL_CRLPATH:
    OPT_SET_EXTENDED_VALUE(&mysql->options, ssl_crlpath, (char *)arg1, 1);
    break;
  case MYSQL_OPT_CONNECT_ATTR_DELETE:
    {
      uchar *p;
      CHECK_OPT_EXTENSION_SET(&mysql->options);
      if (hash_inited(&mysql->options.extension->connect_attrs) &&
          (p= (uchar *)hash_search(&mysql->options.extension->connect_attrs, (uchar *)arg1,
                      arg1 ? (uint)strlen((char *)arg1) : 0)))
      {
        size_t key_len= *(size_t *)p;
        mysql->options.extension->connect_attrs_len-= key_len;
        mysql->options.extension->connect_attrs_len-= get_store_length(key_len);
        key_len= *(size_t *)(p + sizeof(size_t) + key_len);
        mysql->options.extension->connect_attrs_len-= key_len;
        mysql->options.extension->connect_attrs_len-= get_store_length(key_len);
        hash_delete(&mysql->options.extension->connect_attrs, p);
      }
          
    }
    break;
  case MYSQL_OPT_CONNECT_ATTR_RESET:
    CHECK_OPT_EXTENSION_SET(&mysql->options);
    if (hash_inited(&mysql->options.extension->connect_attrs))
    {
      hash_free(&mysql->options.extension->connect_attrs);
      mysql->options.extension->connect_attrs_len= 0;
    }
    break;
  case MYSQL_OPT_CONNECT_ATTR_ADD:
    {
      uchar *buffer;
      void *arg2= va_arg(ap, void *);
      size_t key_len= arg1 ? strlen((char *)arg1) : 0,
             value_len= arg2 ? strlen((char *)arg2) : 0;
      size_t storage_len= key_len + value_len + 
                          get_store_length(key_len) +
                          get_store_length(value_len);
      
      CHECK_OPT_EXTENSION_SET(&mysql->options);
      if (!key_len ||
          storage_len + mysql->options.extension->connect_attrs_len > 0xFFFF)
      {
        SET_CLIENT_ERROR(mysql, CR_INVALID_PARAMETER_NO, unknown_sqlstate, 0);
        goto end;
      }

      if (!hash_inited(&mysql->options.extension->connect_attrs))
      {
        if (_hash_init(&mysql->options.extension->connect_attrs,
                       0, 0, 0, ma_get_hash_key, ma_hash_free, 0))
        {
          SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
          goto end;
        }
      }
      if ((buffer= (uchar *)my_malloc(2 * sizeof(size_t) + key_len + value_len, 
                                      MYF(MY_WME | MY_ZEROFILL))))
      {
        uchar *p= buffer;
        *((size_t *)p)= key_len;
        p+= sizeof(size_t);
        memcpy(p, arg1, key_len);
        p+= key_len;
        *((size_t *)p)= value_len;
        p+= sizeof(size_t);
        if (arg2)
          memcpy(p, arg2, value_len);

        if (hash_insert(&mysql->options.extension->connect_attrs, buffer))
        {
          my_free(buffer);
          SET_CLIENT_ERROR(mysql, CR_INVALID_PARAMETER_NO, unknown_sqlstate, 0);
          goto end;
        }
        mysql->options.extension->connect_attrs_len+= storage_len;
      }
      else
      {
        SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, unknown_sqlstate, 0);
        goto end;
      }
    }
    break;
  case MYSQL_ENABLE_CLEARTEXT_PLUGIN:
    break;
  case MYSQL_SECURE_AUTH:
    mysql->options.secure_auth= *(my_bool *)arg1;
    break;
  default:
    va_end(ap);
    DBUG_RETURN(-1);
  }
  va_end(ap);
  DBUG_RETURN(0);
end:
  va_end(ap);
  DBUG_RETURN(1);
}


int STDCALL
mysql_options(MYSQL *mysql,enum mysql_option option, const void *arg)
{
  return mysql_optionsv(mysql, option, arg);
}


/****************************************************************************
** Functions to get information from the MySQL structure
** These are functions to make shared libraries more usable.
****************************************************************************/

/* MYSQL_RES */
my_ulonglong STDCALL mysql_num_rows(MYSQL_RES *res)
{
  return res->row_count;
}

unsigned int STDCALL mysql_num_fields(MYSQL_RES *res)
{
  return res->field_count;
}

/* deprecated */
my_bool STDCALL mysql_eof(MYSQL_RES *res)
{
  return res->eof;
}

MYSQL_FIELD * STDCALL mysql_fetch_field_direct(MYSQL_RES *res,uint fieldnr)
{
  return &(res)->fields[fieldnr];
}

MYSQL_FIELD * STDCALL mysql_fetch_fields(MYSQL_RES *res)
{
  return (res)->fields;
}

MYSQL_ROWS * STDCALL mysql_row_tell(MYSQL_RES *res)
{
  return res->data_cursor;
}

uint STDCALL mysql_field_tell(MYSQL_RES *res)
{
  return (res)->current_field;
}

/* MYSQL */

unsigned int STDCALL mysql_field_count(MYSQL *mysql)
{
  return mysql->field_count;
}

my_ulonglong STDCALL mysql_affected_rows(MYSQL *mysql)
{
  return (mysql)->affected_rows;
}

my_bool STDCALL mysql_autocommit(MYSQL *mysql, my_bool mode)
{
  DBUG_ENTER("mysql_autocommit");
  DBUG_RETURN((my_bool) mysql_real_query(mysql, (mode) ? "SET autocommit=1" : 
                                         "SET autocommit=0", 16)); 
}

my_bool STDCALL mysql_commit(MYSQL *mysql)
{
  DBUG_ENTER("mysql_commit");
  DBUG_RETURN((my_bool)mysql_real_query(mysql, "COMMIT", sizeof("COMMIT")));
}

my_bool STDCALL mysql_rollback(MYSQL *mysql)
{
  DBUG_ENTER("mysql_rollback");
  DBUG_RETURN((my_bool)mysql_real_query(mysql, "ROLLBACK", sizeof("ROLLBACK")));
}

my_ulonglong STDCALL mysql_insert_id(MYSQL *mysql)
{
  return (mysql)->insert_id;
}

uint STDCALL mysql_errno(MYSQL *mysql)
{
  return (mysql)->net.last_errno;
}

char * STDCALL mysql_error(MYSQL *mysql)
{
  return (mysql)->net.last_error;
}

char *STDCALL mysql_info(MYSQL *mysql)
{
  return (mysql)->info;
}

my_bool STDCALL mysql_more_results(MYSQL *mysql)
{
  DBUG_ENTER("mysql_more_results");
  DBUG_RETURN(test(mysql->server_status & SERVER_MORE_RESULTS_EXIST));
}

int STDCALL mysql_next_result(MYSQL *mysql)
{
  DBUG_ENTER("mysql_next_result");

  /* make sure communication is not blocking */
  if (mysql->status != MYSQL_STATUS_READY)
  {
    SET_CLIENT_ERROR(mysql, CR_COMMANDS_OUT_OF_SYNC, unknown_sqlstate, 0);
    DBUG_RETURN(1);
  }

  /* clear error, and mysql status variables */
  CLEAR_CLIENT_ERROR(mysql);
  mysql->affected_rows = (ulonglong) ~0;

  if (mysql->server_status & SERVER_MORE_RESULTS_EXIST)
  {
     DBUG_RETURN(mysql->methods->db_read_query_result(mysql));
  }

  DBUG_RETURN(-1);
}

ulong STDCALL mysql_thread_id(MYSQL *mysql)
{
  return (mysql)->thread_id;
}

const char * STDCALL mysql_character_set_name(MYSQL *mysql)
{
  return mysql->charset->csname;
}


uint STDCALL mysql_thread_safe(void)
{
#ifdef THREAD
  return 1;
#else
  return 0;
#endif
}

/****************************************************************************
** Some support functions
****************************************************************************/

/*
** Add escape characters to a string (blob?) to make it suitable for a insert
** to should at least have place for length*2+1 chars
** Returns the length of the to string
*/

ulong STDCALL
mysql_escape_string(char *to,const char *from, ulong length)
{
    return (ulong)mysql_cset_escape_slashes(default_charset_info, to, from, length);
}

ulong STDCALL
mysql_real_escape_string(MYSQL *mysql, char *to,const char *from,
			 ulong length)
{
  if (mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES)
    return (ulong)mysql_cset_escape_quotes(mysql->charset, to, from, length);
  else
    return (ulong)mysql_cset_escape_slashes(mysql->charset, to, from, length);
}

void STDCALL
myodbc_remove_escape(MYSQL *mysql,char *name)
{
  char *to;
  my_bool use_mb_flag= (mysql->charset->char_maxlen > 1);
  char *end= 0;
  if (use_mb_flag)
    for (end=name; *end ; end++) ;

  for (to=name ; *name ; name++)
  {
    int l;
    if (use_mb_flag && (l = mysql->charset->mb_valid(name , end)))
    {
      while (l--)
	*to++ = *name++;
      name--;
      continue;
    }
    if (*name == '\\' && name[1])
      name++;
    *to++= *name;
  }
  *to=0;
}

void STDCALL mysql_get_character_set_info(MYSQL *mysql, MY_CHARSET_INFO *cs)
{
  DBUG_ENTER("mysql_get_character_set_info");

  if (!cs)
    DBUG_VOID_RETURN;

  cs->number= mysql->charset->nr;
  cs->csname=  mysql->charset->csname;
  cs->name= mysql->charset->name;
  cs->state= 0;
  cs->comment= NULL;
  cs->dir= NULL;
  cs->mbminlen= mysql->charset->char_minlen;
  cs->mbmaxlen= mysql->charset->char_maxlen;

  DBUG_VOID_RETURN;
}

int STDCALL mysql_set_character_set(MYSQL *mysql, const char *csname)
{
  const CHARSET_INFO *cs;
  DBUG_ENTER("mysql_set_character_set");

  if (!csname)
    goto error;

  if ((cs= mysql_find_charset_name(csname)))
  {
    char buff[64];

    my_snprintf(buff, 63, "SET NAMES %s", cs->csname);
    if (!mysql_real_query(mysql, buff, (uint)strlen(buff)))
    {
      mysql->charset= cs;
      DBUG_RETURN(0);
    }
  }

error:
  my_set_error(mysql, CR_CANT_READ_CHARSET, SQLSTATE_UNKNOWN, 
               0, csname, "compiled_in");
  DBUG_RETURN(mysql->net.last_errno);
}

unsigned int STDCALL mysql_warning_count(MYSQL *mysql)
{
  return mysql->warning_count;
}

const char * STDCALL mysql_sqlstate(MYSQL *mysql)
{
  return mysql->net.sqlstate;
}

int STDCALL mysql_server_init(int argc __attribute__((unused)),
			      char **argv __attribute__((unused)),
			      char **groups __attribute__((unused)))
{
  int rc= 0;

  if (!mysql_client_init)
  {
    mysql_client_init=1;
    my_init();					/* Will init threads */
    init_client_errs();
    if (mysql_client_plugin_init())
      return 1;
    if (!mysql_port)
    {
      struct servent *serv_ptr;
      char *env;

	    mysql_port = MYSQL_PORT;
      if ((serv_ptr = getservbyname("mysql", "tcp")))
        mysql_port = (uint) ntohs((ushort) serv_ptr->s_port);
      if ((env = getenv("MYSQL_TCP_PORT")))
        mysql_port =(uint) atoi(env);
    }
    if (!mysql_unix_port)
    {
      char *env;
#ifdef _WIN32
      mysql_unix_port = (char*) MYSQL_NAMEDPIPE;
#else
      mysql_unix_port = (char*) MYSQL_UNIX_ADDR;
#endif
      if ((env = getenv("MYSQL_UNIX_PORT")))
        mysql_unix_port = env;
    }
    mysql_debug(NullS);
#if defined(SIGPIPE) && !defined(THREAD) && !defined(_WIN32)
    (void) signal(SIGPIPE,SIG_IGN);
#endif
  }
#ifdef THREAD
  else
    rc= mysql_thread_init();
#endif
  if (!mysql_ps_subsystem_initialized)
    mysql_init_ps_subsystem(); 
  return(rc);
}

void STDCALL mysql_server_end()
{
  if (!mysql_client_init)
    return;
#ifdef HAVE_OPENSSL
  my_ssl_end();
#endif  

  mysql_client_plugin_deinit();

  if (my_init_done)
    my_end(0);
  mysql_client_init= 0;
  my_init_done= 0;
}

my_bool STDCALL mysql_thread_init()
{
#ifdef THREAD
  return my_thread_init();
#endif
  return 0;
}

void STDCALL mysql_thread_end()
{
  #ifdef THREAD
  my_thread_end();
  #endif
}

int STDCALL mysql_set_server_option(MYSQL *mysql, 
                                    enum enum_mysql_set_option option)
{
  char buffer[2];
  DBUG_ENTER("mysql_set_server_option");
  int2store(buffer, (uint)option);
  DBUG_RETURN(simple_command(mysql, MYSQL_COM_SET_OPTION, buffer, sizeof(buffer), 0, 0));
}

ulong STDCALL mysql_get_client_version(void)
{
  return MYSQL_VERSION_ID;
}

ulong STDCALL mysql_hex_string(char *to, const char *from,
                               unsigned long len)
{
  char *start= to;
  char hexdigits[]= "0123456789ABCDEF";

  while (len--)
  {
    *to++= hexdigits[*from >> 4];
    *to++= hexdigits[*from & 0x0F];
    from++;
  }
  *to= 0;
  return (ulong)(to - start);
}

my_bool STDCALL mariadb_connection(MYSQL *mysql)
{
  return (strstr(mysql->server_version, "MariaDB") ||
          strstr(mysql->server_version, "-maria-"));
}

const char * STDCALL
mysql_get_server_name(MYSQL *mysql)
{
  if (mysql->options.extension && 
      mysql->options.extension->db_driver != NULL) 
    return mysql->options.extension->db_driver->name;
  return mariadb_connection(mysql) ? "MariaDB" : "MySQL";
}

MYSQL_PARAMETERS *STDCALL
mysql_get_parameters(void)
{
  return &mariadb_internal_parameters;
}

my_socket STDCALL
mysql_get_socket(const MYSQL *mysql)
{
  if (mysql->net.vio)
    return vio_fd(mysql->net.vio);
  return INVALID_SOCKET;
}

/*
 * Default methods for a connection. These methods are
 * stored in mysql->methods and can be overwritten by
 * a plugin, e.g. for using another database
 */
struct st_mysql_methods MARIADB_DEFAULT_METHODS = {
  /* open a connection */
  mthd_my_real_connect,
  /* close connection */
  mysql_close_slow_part,
  /* send command to server */
  mthd_my_send_cmd,
  /* skip result set */
  mthd_my_skip_result,
  /* read response packet */
  mthd_my_read_query_result,
  /* read all rows from a result set */
  mthd_my_read_rows,
  /* read one/next row */
  mthd_my_read_one_row,
  /* check if datatype is supported */
  mthd_supported_buffer_type,
  /* read response packet from prepare */
  mthd_stmt_read_prepare_response,
  /* read response from stmt execute */
  mthd_my_read_query_result,
  /* get result set metadata for a prepared statement */
  mthd_stmt_get_result_metadata,
  /* get param metadata for a prepared statement */
  mthd_stmt_get_param_metadata,
  /* read all rows (buffered) */
  mthd_stmt_read_all_rows,
  /* fetch one row (unbuffered) */
  mthd_stmt_fetch_row,
  /* store values in bind buffer */
  mthd_stmt_fetch_to_bind,
  /* skip unbuffered stmt result */
  mthd_stmt_flush_unbuffered
};
