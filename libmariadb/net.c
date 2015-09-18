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

/* Write and read of logical packets to/from socket
** Writes are cached into net_buffer_length big packets.
** Read packets are reallocated dynamicly when reading big packets.
** Each logical packet has the following pre-info:
** 3 byte length & 1 byte package-number.
*/

#include <my_global.h>
#include <violite.h>
#include <my_sys.h>
#include <m_string.h>
#include "mysql.h"
#include "mysqld_error.h"
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#ifndef _WIN32
#include <poll.h>
#endif

#define MAX_PACKET_LENGTH (256L*256L*256L-1)

/* net_buffer_length and max_allowed_packet are defined in mysql.h
   See bug conc-57
*/
#undef net_buffer_length

#undef max_allowed_packet
ulong max_allowed_packet=1024L * 1024L * 1024L;
ulong net_read_timeout=  NET_READ_TIMEOUT;
ulong net_write_timeout= NET_WRITE_TIMEOUT;
ulong net_buffer_length=8192;	/* Default length. Enlarged if necessary */

#if !defined(_WIN32) && !defined(MSDOS)
#include <sys/socket.h>
#else
#undef MYSQL_SERVER			/* Win32 can't handle interrupts */
#endif
#if !defined(MSDOS) && !defined(_WIN32) && !defined(HAVE_BROKEN_NETINET_INCLUDES) && !defined(__BEOS__)
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#if !defined(alpha_linux_port)
#include <netinet/tcp.h>
#endif
#endif
#include "mysqld_error.h"
#ifdef MYSQL_SERVER
#include "my_pthread.h"
#include "thr_alarm.h"
void sql_print_error(const char *format,...);
#define RETRY_COUNT mysqld_net_retry_count
extern ulong mysqld_net_retry_count;
#else

#ifdef OS2				/* avoid name conflict */
#define thr_alarm_t  thr_alarm_t_net
#define ALARM        ALARM_net
#endif

typedef my_bool thr_alarm_t;
typedef my_bool ALARM;
#define thr_alarm_init(A) (*(A))=0
#define thr_alarm_in_use(A) (*(A))
#define thr_end_alarm(A)
#define thr_alarm(A,B,C) local_thr_alarm((A),(B),(C))
static inline int local_thr_alarm(my_bool *A,int B __attribute__((unused)),ALARM *C __attribute__((unused)))
{
  *A=1;
  return 0;
}
#define thr_got_alarm(A) 0
#define RETRY_COUNT 1
#endif

#ifdef MYSQL_SERVER
extern ulong bytes_sent, bytes_received; 
extern pthread_mutex_t LOCK_bytes_sent , LOCK_bytes_received;
#else
#undef statistic_add
#define statistic_add(A,B,C)
#endif

/*
** Give error if a too big packet is found
** The server can change this with the -O switch, but because the client
** can't normally do this the client should have a bigger max-buffer.
*/

#define TEST_BLOCKING		8
static int net_write_buff(NET *net,const char *packet, size_t len);


	/* Init with packet info */

int my_net_init(NET *net, Vio* vio)
{
  if (!(net->buff=(uchar*) my_malloc(net_buffer_length,MYF(MY_WME | MY_ZEROFILL))))
    return 1;
  max_allowed_packet= net->max_packet_size= MAX(net_buffer_length, max_allowed_packet);
  net->buff_end=net->buff+(net->max_packet=net_buffer_length);
  net->vio = vio;
  net->error=0; net->return_status=0;
  net->read_timeout=(uint) net_read_timeout;		/* Timeout for read */
  net->compress_pkt_nr= net->pkt_nr= 0;
  net->write_pos=net->read_pos = net->buff;
  net->last_error[0]= net->sqlstate[0] =0;
  
  net->compress=0; net->reading_or_writing=0;
  net->where_b = net->remain_in_buf=0;
  net->last_errno=0;

  if (vio != 0)					/* If real connection */
  {
    net->fd  = vio_fd(vio);			/* For perl DBI/DBD */
#if defined(MYSQL_SERVER) && !defined(__WIN32) && !defined(__EMX__) && !defined(OS2)
    if (!(test_flags & TEST_BLOCKING))
      vio_blocking(vio, FALSE, 0);
#endif
    vio_fastsend(vio);
  }
  return 0;
}

void net_end(NET *net)
{
  my_free(net->buff);
  net->buff=0;
}

/* Realloc the packet buffer */

static my_bool net_realloc(NET *net, size_t length)
{
  uchar *buff;
  size_t pkt_length;

  DBUG_ENTER("net_realloc");
  DBUG_PRINT("info", ("length: %lu max_allowed_packet: %lu",
              (ulong)length, max_allowed_packet));

  if (length >= net->max_packet_size)
  {
    DBUG_PRINT("error",("Packet too large (%lu)", length));
    net->error=1;
    net->last_errno=ER_NET_PACKET_TOO_LARGE;
    DBUG_RETURN(1);
  }
  pkt_length = (length+IO_SIZE-1) & ~(IO_SIZE-1);
  /* reallocate buffer:
     size= pkt_length + NET_HEADER_SIZE + COMP_HEADER_SIZE */
  if (!(buff=(uchar*) my_realloc((char*) net->buff, 
                                 pkt_length + NET_HEADER_SIZE + COMP_HEADER_SIZE,
                                 MYF(MY_WME))))
  {
    DBUG_PRINT("info", ("Out of memory"));
    net->error=1;
    DBUG_RETURN(1);
  }
  net->buff=net->write_pos=buff;
  net->buff_end=buff+(net->max_packet=pkt_length);
  DBUG_RETURN(0);
}


/* check if the socket is still alive */
static my_bool net_check_socket_status(my_socket sock)
{
#ifndef _WIN32
  struct pollfd poll_fd;
#else
  FD_SET sfds;
  struct timeval tv= {0,0};
#endif
  int res;
#ifndef _WIN32
  memset(&poll_fd, 0, sizeof(struct pollfd));
  poll_fd.events= POLLPRI | POLLIN;
  poll_fd.fd= sock;

  res= poll(&poll_fd, 1, 0);
  if (res <= 0) /* timeout or error */
    return FALSE;
  if (!(poll_fd.revents & (POLLIN | POLLPRI)))
    return FALSE;
  return TRUE;
#else
  /* We can't use the WSAPoll function, it's broken :-(
     (see Windows 8 Bugs 309411 - WSAPoll does not report failed connections)
     Instead we need to use select function:
     If TIMEVAL is initialized to {0, 0}, select will return immediately; 
     this is used to poll the state of the selected sockets.
  */
  FD_ZERO(&sfds);
  FD_SET(sock, &sfds);

  res= select(sock + 1, &sfds, NULL, NULL, &tv);
  if (res > 0 && FD_ISSET(sock, &sfds))
    return TRUE;
  return FALSE;
#endif

}

	/* Remove unwanted characters from connection */

void net_clear(NET *net)
{
  DBUG_ENTER("net_clear");

  /* see conc-71: we need to check the socket status first:
     if the socket is dead we set net->error, so net_flush
     will report an error */
  while (net_check_socket_status(net->vio->sd))
  {
    /* vio_read returns size_t. so casting to long is required to check for -1 */
    if ((long)vio_read(net->vio, (gptr)net->buff, (size_t) net->max_packet) <= 0)
    {
      net->error= 2;
      DBUG_PRINT("info", ("socket disconnected"));
      DBUG_VOID_RETURN;
    }
  }
  net->compress_pkt_nr= net->pkt_nr=0;				/* Ready for new command */
  net->write_pos=net->buff;
  DBUG_VOID_RETURN;
}


	/* Flush write_buffer if not empty. */

int net_flush(NET *net)
{
  int error=0;
  DBUG_ENTER("net_flush");
  if (net->buff != net->write_pos)
  {
    error=net_real_write(net,(char*) net->buff,
			 (size_t) (net->write_pos - net->buff));
    net->write_pos=net->buff;
  }
  if (net->compress)
    net->pkt_nr= net->compress_pkt_nr;
  DBUG_RETURN(error);
}


/*****************************************************************************
** Write something to server/client buffer
*****************************************************************************/


/*
** Write a logical packet with packet header
** Format: Packet length (3 bytes), packet number(1 byte)
**         When compression is used a 3 byte compression length is added
** NOTE: If compression is used the original package is destroyed!
*/

int
my_net_write(NET *net, const char *packet, size_t len)
{
  uchar buff[NET_HEADER_SIZE];
  while (len >= MAX_PACKET_LENGTH)
  {
    const ulong max_len= MAX_PACKET_LENGTH;
    int3store(buff,max_len);
    buff[3]= (uchar)net->pkt_nr++;
    if (net_write_buff(net,(char*) buff,NET_HEADER_SIZE) ||
        net_write_buff(net, packet, max_len))
      return 1;
    packet+= max_len;
    len-= max_len;
  }
  /* write last remaining packet, size can be zero */
  int3store(buff, len);
  buff[3]= (uchar)net->pkt_nr++;
  if (net_write_buff(net,(char*) buff,NET_HEADER_SIZE) ||
      net_write_buff(net, packet, len))
    return 1;
  return 0;
}

int
net_write_command(NET *net, uchar command,
                  const char *packet, size_t len)
{
  uchar buff[NET_HEADER_SIZE+1];
  size_t buff_size= NET_HEADER_SIZE + 1;
  size_t length= 1 + len; /* 1 extra byte for command */
  int rc;

  buff[NET_HEADER_SIZE]= 0;
  buff[4]=command;

  if (length >= MAX_PACKET_LENGTH)
  {
    len= MAX_PACKET_LENGTH - 1;
    do
    {
      int3store(buff, MAX_PACKET_LENGTH);
      buff[3]= (net->compress) ? 0 : (uchar) (net->pkt_nr++);
 
      if (net_write_buff(net, (char *)buff, buff_size) ||
          net_write_buff(net, packet, len))
        return(1);
      packet+= len;
      length-= MAX_PACKET_LENGTH;
      len= MAX_PACKET_LENGTH;
      buff_size= NET_HEADER_SIZE; /* don't send command for further packets */
    } while (length >= MAX_PACKET_LENGTH);
    len= length;
  }
  int3store(buff,length);
  buff[3]= (net->compress) ? 0 : (uchar) (net->pkt_nr++);
  rc= test (net_write_buff(net,(char *)buff, buff_size) || 
            net_write_buff(net,packet,len) || 
            net_flush(net));
  return rc;
}


static int
net_write_buff(NET *net,const char *packet, size_t len)
{
  size_t left_length;

  if (net->max_packet > MAX_PACKET_LENGTH &&
      net->compress)
    left_length= (size_t)(MAX_PACKET_LENGTH - (net->write_pos - net->buff));
  else
    left_length=(size_t) (net->buff_end - net->write_pos);

  if (len > left_length)
  {
    if (net->write_pos != net->buff)
    {
      memcpy((char*) net->write_pos,packet,left_length);
      if (net_real_write(net,(char*) net->buff,
                         (size_t)(net->write_pos - net->buff) + left_length))
        return 1;
      packet+=left_length;
      len-=left_length;
      net->write_pos= net->buff;
    }
    if (net->compress)
    {
      /* uncompressed length is stored in 3 bytes,so
         packet can't be > 0xFFFFFF */
      left_length= MAX_PACKET_LENGTH;
      while (len > left_length)
      {
        if (net_real_write(net, packet, left_length))
          return 1;
        packet+= left_length;
        len-= left_length;
      }
    }
    if (len > net->max_packet)
      return(test(net_real_write(net, packet, len)));
  }
  memcpy((char*) net->write_pos,packet,len);
  net->write_pos+=len;
  return 0;
}

/*  Read and write using timeouts */

int
net_real_write(NET *net,const char *packet,size_t  len)
{
  size_t length;
  char *pos,*end;
  thr_alarm_t alarmed;
#if !defined(_WIN32) && !defined(__EMX__) && !defined(OS2)
  ALARM alarm_buff;
#endif
  uint retry_count=0;
  my_bool net_blocking = vio_is_blocking(net->vio);
  DBUG_ENTER("net_real_write");

  if (net->error == 2)
    DBUG_RETURN(-1);				/* socket can't be used */

  net->reading_or_writing=2;
#ifdef HAVE_COMPRESS
  if (net->compress)
  {
    size_t complen;
    uchar *b;
    uint header_length=NET_HEADER_SIZE+COMP_HEADER_SIZE;
    if (!(b=(uchar*) my_malloc(len + NET_HEADER_SIZE + COMP_HEADER_SIZE + 1,
				    MYF(MY_WME))))
    {
      net->last_errno=ER_OUT_OF_RESOURCES;
      net->error=2;
      net->reading_or_writing=0;
      DBUG_RETURN(1);
    }
    memcpy(b+header_length,packet,len);

    if (my_compress((unsigned char*) b+header_length,&len,&complen))
    {
      DBUG_PRINT("warning",
		 ("Compression error; Continuing without compression"));
      complen=0;
    }
    int3store(&b[NET_HEADER_SIZE],complen);
    int3store(b,len);
    b[3]=(uchar) (net->compress_pkt_nr++);
    len+= header_length;
    packet= (char*) b;
  }
#endif /* HAVE_COMPRESS */

  alarmed=0;

  pos=(char*) packet; end=pos+len;
  while (pos != end)
  {
    if ((long) (length=vio_write(net->vio,pos,(size_t) (end-pos))) <= 0)
    {
      my_bool interrupted = vio_should_retry(net->vio);
#if (!defined(_WIN32) && !defined(__EMX__) && !defined(OS2))
      if ((interrupted || length==0) && !thr_alarm_in_use(&alarmed))
      {
        if (!thr_alarm(&alarmed,(uint) net_write_timeout,&alarm_buff))
        {                                       /* Always true for client */
	  if (!vio_is_blocking(net->vio))
	  {
	    while (vio_blocking(net->vio, TRUE, 0) < 0)
	    {
	      if (vio_should_retry(net->vio) && retry_count++ < RETRY_COUNT)
		continue;
#ifdef EXTRA_DEBUG
	      fprintf(stderr,
		      "%s: my_net_write: fcntl returned error %d, aborting thread\n",
		      my_progname,vio_errno(net->vio));
#endif /* EXTRA_DEBUG */
	      net->error=2;                     /* Close socket */
        net->last_errno= (interrupted ?
                          ER_NET_WRITE_INTERRUPTED : ER_NET_ERROR_ON_WRITE);
	      goto end;
	    }
	  }
	  retry_count=0;
	  continue;
	}
      }
      else
#endif /* (!defined(_WIN32) && !defined(__EMX__)) */
	if (thr_alarm_in_use(&alarmed) && !thr_got_alarm(&alarmed) &&
	    interrupted)
      {
	if (retry_count++ < RETRY_COUNT)
	    continue;
#ifdef EXTRA_DEBUG
	  fprintf(stderr, "%s: write looped, aborting thread\n",
		  my_progname);
#endif /* EXTRA_DEBUG */
      }
#if defined(THREAD_SAFE_CLIENT) && !defined(MYSQL_SERVER)
      if (vio_errno(net->vio) == SOCKET_EINTR)
      {
	DBUG_PRINT("warning",("Interrupted write. Retrying..."));
	continue;
      }
#endif /* defined(THREAD_SAFE_CLIENT) && !defined(MYSQL_SERVER) */
      net->error=2;				/* Close socket */
      net->last_errno= (interrupted ? ER_NET_WRITE_INTERRUPTED :
			ER_NET_ERROR_ON_WRITE);
      break;
    }
    pos+=length;
    statistic_add(bytes_sent,length,&LOCK_bytes_sent);
  }
#ifndef _WIN32
 end:
#endif
#ifdef HAVE_COMPRESS
  if (net->compress)
    my_free((void *)packet);
#endif
  if (thr_alarm_in_use(&alarmed))
  {
    thr_end_alarm(&alarmed);
    vio_blocking(net->vio, net_blocking, 0);
  }
  net->reading_or_writing=0;
  DBUG_RETURN(((int) (pos != end)));
}


/*****************************************************************************
** Read something from server/clinet
*****************************************************************************/

#ifdef MYSQL_SERVER

/*
  Help function to clear the commuication buffer when we get a too
  big packet
*/

static void my_net_skip_rest(NET *net, ulong remain, thr_alarm_t *alarmed,
			     ALARM *alarm_buff)
{
  uint retry_count=0;
  if (!thr_alarm_in_use(alarmed))
  {
    if (thr_alarm(alarmed,net->timeout,alarm_buff) ||
	(!vio_is_blocking(net->vio) && vio_blocking(net->vio,TRUE, 0) < 0))
      return;					/* Can't setup, abort */
  }
  while (remain > 0)
  {
    ulong length;
    if ((int) (length=vio_read(net->vio,(char*) net->buff,remain)) <= 0L)
    {
      my_bool interrupted = vio_should_retry(net->vio);
      if (!thr_got_alarm(alarmed) && interrupted)
      {					/* Probably in MIT threads */
	if (retry_count++ < RETRY_COUNT)
	  continue;
      }
      return;
    }
    remain -=(ulong) length;
    statistic_add(bytes_received,(ulong) length,&LOCK_bytes_received);
  }
}
#endif /* MYSQL_SERVER */


static ulong
my_real_read(NET *net, size_t *complen)
{
  uchar *pos;
  size_t length;
  uint i,retry_count=0;
  ulong len=packet_error;
  thr_alarm_t alarmed;
#if (!defined(_WIN32) && !defined(__EMX__) && !defined(OS2)) || defined(MYSQL_SERVER)
  ALARM alarm_buff;
#endif
  my_bool net_blocking=vio_is_blocking(net->vio);
  size_t remain= (net->compress ? NET_HEADER_SIZE+COMP_HEADER_SIZE :
		 NET_HEADER_SIZE);
  *complen = 0;

  net->reading_or_writing=1;
  thr_alarm_init(&alarmed);
#ifdef MYSQL_SERVER
  if (net_blocking)
    thr_alarm(&alarmed,net->timeout,&alarm_buff);
#endif /* MYSQL_SERVER */

    pos = net->buff + net->where_b;		/* net->packet -4 */
    for (i=0 ; i < 2 ; i++)
    {
      while (remain > 0)
      {
	/* First read is done with non blocking mode */
        if ((long) (length=vio_read(net->vio,(char*) pos,remain)) <= 0L)
        {
          my_bool interrupted = vio_should_retry(net->vio);

	  DBUG_PRINT("info",("vio_read returned %d,  errno: %d",
			     length, vio_errno(net->vio)));
#if (!defined(_WIN32) && !defined(__EMX__) && !defined(OS2)) || defined(MYSQL_SERVER)
	  /*
	    We got an error that there was no data on the socket. We now set up
	    an alarm to not 'read forever', change the socket to non blocking
	    mode and try again
	  */
	  if ((interrupted || length == 0) && !thr_alarm_in_use(&alarmed))
	  {
	    if (!thr_alarm(&alarmed,net->read_timeout,&alarm_buff)) /* Don't wait too long */
	    {
              if (!vio_is_blocking(net->vio))
              {
                while (vio_blocking(net->vio,TRUE, 0) < 0)
                {
                  if (vio_should_retry(net->vio) &&
		      retry_count++ < RETRY_COUNT)
                    continue;
                  DBUG_PRINT("error",
			     ("fcntl returned error %d, aborting thread",
			      vio_errno(net->vio)));
#ifdef EXTRA_DEBUG
                  fprintf(stderr,
                          "%s: read: fcntl returned error %d, aborting thread\n",
                          my_progname,vio_errno(net->vio));
#endif /* EXTRA_DEBUG */
                  len= packet_error;
                  net->error=2;                 /* Close socket */
#ifdef MYSQL_SERVER
		  net->last_errno=ER_NET_FCNTL_ERROR;
#endif
		  goto end;
                }
              }
	      retry_count=0;
	      continue;
	    }
	  }
#endif /* (!defined(_WIN32) && !defined(__EMX__)) || defined(MYSQL_SERVER) */
	  if (thr_alarm_in_use(&alarmed) && !thr_got_alarm(&alarmed) &&
	      interrupted)
	  {					/* Probably in MIT threads */
	    if (retry_count++ < RETRY_COUNT)
	      continue;
#ifdef EXTRA_DEBUG
	    fprintf(stderr, "%s: read looped with error %d, aborting thread\n",
		    my_progname,vio_errno(net->vio));
#endif /* EXTRA_DEBUG */
	  }
#if defined(THREAD_SAFE_CLIENT) && !defined(MYSQL_SERVER)
	  if (vio_should_retry(net->vio))
	  {
	    DBUG_PRINT("warning",("Interrupted read. Retrying..."));
	    continue;
	  }
#endif
	  DBUG_PRINT("error",("Couldn't read packet: remain: %d  errno: %d  length: %d  alarmed: %d", remain,vio_errno(net->vio),length,alarmed));
	  len= packet_error;
	  net->error=2;				/* Close socket */
	  goto end;
	}
	remain -= (ulong) length;
	pos+= (ulong) length;
	statistic_add(bytes_received,(ulong) length,&LOCK_bytes_received);
      }
      if (i == 0)
      {					/* First parts is packet length */
	ulong helping;
	if (net->buff[net->where_b + 3] != (uchar) net->pkt_nr)
	{
	  if (net->buff[net->where_b] != (uchar) 255)
	  {
	    DBUG_PRINT("error",
		       ("Packets out of order (Found: %d, expected %d)",
			(int) net->buff[net->where_b + 3],
			(uint) (uchar) net->pkt_nr));
#ifdef EXTRA_DEBUG
	    fprintf(stderr,"Packets out of order (Found: %d, expected %d)\n",
		    (int) net->buff[net->where_b + 3],
		    (uint) (uchar) net->pkt_nr);
#endif
	  }
	  len= packet_error;
#ifdef MYSQL_SERVER
	  net->last_errno=ER_NET_PACKETS_OUT_OF_ORDER;
#endif
	  goto end;
	}
	net->compress_pkt_nr= ++net->pkt_nr;
#ifdef HAVE_COMPRESS
	if (net->compress)
	{
	  /* complen is > 0 if package is really compressed */
	  *complen=uint3korr(&(net->buff[net->where_b + NET_HEADER_SIZE]));
	}
#endif

	len=uint3korr(net->buff+net->where_b);
        if (!len)
          goto end;
	helping = max(len,(ulong)*complen) + net->where_b;
	/* The necessary size of net->buff */
	if (helping >= net->max_packet)
	{
	  if (net_realloc(net,helping))
	  {
#ifdef MYSQL_SERVER
	    if (i == 1)
	      my_net_skip_rest(net, len, &alarmed, &alarm_buff);
#endif
	    len= packet_error;		/* Return error */
	    goto end;
	  }
	}
	pos=net->buff + net->where_b;
	remain = len;
      }
    }

end:
  if (thr_alarm_in_use(&alarmed))
  {
    thr_end_alarm(&alarmed);
    vio_blocking(net->vio, net_blocking, 0);
  }
  net->reading_or_writing=0;
  return(len);
}

ulong my_net_read(NET *net)
{
  size_t len,complen;

#ifdef HAVE_COMPRESS
  if (!net->compress)
  {
#endif
    len = my_real_read (net,(size_t *)&complen);
    if (len == MAX_PACKET_LENGTH)
    {
      /* multi packet read */
      size_t length= 0;
      ulong last_pos= net->where_b;

      do 
      {
        length+= len;
        net->where_b+= (unsigned long)len;
        len= my_real_read(net, &complen);
      } while (len == MAX_PACKET_LENGTH);
      net->where_b= last_pos;
      if (len != packet_error)
        len+= length;
    }
    net->read_pos = net->buff + net->where_b;
    if (len != packet_error)
      net->read_pos[len]=0;		/* Safeguard for mysql_use_result */
    return (ulong)len;
#ifdef HAVE_COMPRESS
  }
  else
  {
    /* 
    compressed protocol:

    --------------------------------------
    packet_lengt h      3 
    sequence_id         1
    uncompressed_length 3
    --------------------------------------
    compressed data     packet_length - 7
    --------------------------------------

    Another packet will follow if:
    packet_length == MAX_PACKET_LENGTH

    Last package will be identified by
    - packet_length is zero (special case)
    - packet_length < MAX_PACKET_LENGTH
    */

    size_t packet_length,
           buffer_length;
    size_t current= 0, start= 0;
    my_bool is_multi_packet= 0;

    /* check if buffer is empty */
    if (!net->remain_in_buf)
    {
      buffer_length= 0;
    }
    else
    {
      /* save position and restore \0 character */
      buffer_length= net->buf_length;
      current= net->buf_length - net->remain_in_buf;
      start= current;
      net->buff[net->buf_length - net->remain_in_buf]=net->save_char;
    }
    for (;;)
    {
      if (buffer_length - current >= 4)
      {
        uchar *pos= net->buff + current;
        packet_length= uint3korr(pos);

        /* check if we have last package (special case: zero length) */
        if (!packet_length)
        {
          current+= 4; /* length + sequence_id,
                          no more data will follow */
          break;
        }
        if (packet_length + 4 <= buffer_length - current)
        {
          if (!is_multi_packet)
          {
            current= current + packet_length + 4;
          }
          else
          {
            /* remove packet_header */
            memmove(net->buff + current, 
                     net->buff + current + 4, 
                     buffer_length - current);
            buffer_length-= 4;
            current+= packet_length;
          }
          /* do we have last packet ? */
          if (packet_length != MAX_PACKET_LENGTH)
          {
            is_multi_packet= 0;
            break;
          }
          else
            is_multi_packet= 1;
          if (start)
          {
            memmove(net->buff, net->buff + start,
                    buffer_length - start);
            /* decrease buflen*/
            buffer_length-= start;
            start= 0;
          }
          continue;
        }
      }
      if (start)
      { 
        memmove(net->buff, net->buff + start, buffer_length - start);
        /* decrease buflen and current */
        current -= start;
        buffer_length-= start;
        start= 0;
      }

      net->where_b=buffer_length;

      if ((packet_length = my_real_read(net,(size_t *)&complen)) == packet_error)
        return packet_error;
      if (my_uncompress((unsigned char*) net->buff + net->where_b, &packet_length, &complen))
      {
        len= packet_error;
        net->error=2;			/* caller will close socket */
        net->last_errno=ER_NET_UNCOMPRESS_ERROR;
        break;
        return packet_error;
      }
      buffer_length+= complen;
    }
    /* set values */
    net->buf_length= buffer_length;
    net->remain_in_buf= buffer_length - current;
    net->read_pos= net->buff + start + 4;
    len= current - start - 4;
    if (is_multi_packet)
      len-= 4;
    net->save_char= net->read_pos[len];	/* Must be saved */
    net->read_pos[len]=0;		/* Safeguard for mysql_use_result */
  }
#endif
  return (ulong)len;
}
