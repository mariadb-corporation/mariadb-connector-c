/************************************************************************************
    Copyright (C) 2012-2015 Monty Program AB, MariaDB Corporation AB,
                  
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

   Originally written by Sergei Golubchik
*************************************************************************************/
#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>
#include <errmsg.h>
#include <ma_common.h>
#include <mysql/client_plugin.h>
#include <violite.h>
#ifdef HAVE_OPENSSL
#include <ma_secure.h>
#endif

typedef struct st_mysql_client_plugin_AUTHENTICATION auth_plugin_t;
static int client_mpvio_write_packet(struct st_plugin_vio*, const uchar*, size_t);
static int native_password_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql);
static int old_password_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql);
extern void read_user_name(char *name);
extern uchar *ma_send_connect_attr(MYSQL *mysql, uchar *buffer);

#define compile_time_assert(A) \
do {\
  typedef char constraint[(A) ? 1 : -1];\
} while (0);

static auth_plugin_t native_password_client_plugin=
{
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN,
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN_INTERFACE_VERSION,
  native_password_plugin_name,
  "R.J.Silk, Sergei Golubchik",
  "Native MySQL authentication",
  {1, 0, 0},
  NULL,
  NULL,
  native_password_auth_client
};

static auth_plugin_t old_password_client_plugin=
{
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN,
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN_INTERFACE_VERSION,
  old_password_plugin_name,
  "R.J.Silk, Sergei Golubchik",
  "Old MySQL-3.23 authentication",
  {1, 0, 0},
  NULL,
  NULL,
  old_password_auth_client
};
typedef struct st_mariadb_client_plugin_DBAPI dbapi_plugin_t;

#ifdef HAVE_SQLITE
extern dbapi_plugin_t sqlite3_plugin;
#endif

struct st_mysql_client_plugin *mysql_client_builtins[]=
{
  (struct st_mysql_client_plugin *)&old_password_client_plugin,
  (struct st_mysql_client_plugin *)&native_password_client_plugin,
#ifdef HAVE_SQLITE
  (struct st_mysql_client_plugin *)&sqlite3_plugin,
#endif
  0
};

typedef struct {
  int (*read_packet)(struct st_plugin_vio *vio, uchar **buf);
  int (*write_packet)(struct st_plugin_vio *vio, const uchar *pkt, size_t pkt_len);
  void (*info)(struct st_plugin_vio *vio, struct st_plugin_vio_info *info);
  /* -= end of MYSQL_PLUGIN_VIO =- */
  MYSQL *mysql;
  auth_plugin_t *plugin;             /**< what plugin we're under */
  const char *db;
  struct {
    uchar *pkt;                      /**< pointer into NET::buff */
    uint pkt_len;
  } cached_server_reply;
  uint packets_read, packets_written; /**< counters for send/received packets */
  my_bool mysql_change_user;          /**< if it's mysql_change_user() */
  int last_read_packet_len;           /**< the length of the last *read* packet */
} MCPVIO_EXT;

static int native_password_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  int pkt_len;
  uchar *pkt;

  if (((MCPVIO_EXT *)vio)->mysql_change_user)
  {
    /*
      in mysql_change_user() the client sends the first packet.
      we use the old scramble.
    */
    pkt= (uchar*)mysql->scramble_buff;
    pkt_len= SCRAMBLE_LENGTH + 1;
  }
  else
  {
    /* read the scramble */
    if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
      return CR_ERROR;

    if (pkt_len != SCRAMBLE_LENGTH + 1)
      return CR_SERVER_HANDSHAKE_ERR;

    /* save it in MYSQL */
    memmove(mysql->scramble_buff, pkt, SCRAMBLE_LENGTH);
    mysql->scramble_buff[SCRAMBLE_LENGTH] = 0;
  }

  if (mysql->passwd[0])
  {
    char scrambled[SCRAMBLE_LENGTH + 1];
    my_scramble_41((uchar *)scrambled, (char*)pkt, mysql->passwd);
    if (vio->write_packet(vio, (uchar*)scrambled, SCRAMBLE_LENGTH))
      return CR_ERROR;
  }
  else
    if (vio->write_packet(vio, 0, 0)) /* no password */
      return CR_ERROR;

  return CR_OK;
}


/**
  client authentication plugin that does old MySQL authentication
  using an 8-byte (4.0-) scramble
*/

static int old_password_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  uchar *pkt;
  int pkt_len;

  if (((MCPVIO_EXT *)vio)->mysql_change_user)
  {
    /*
      in mysql_change_user() the client sends the first packet.
      we use the old scramble.
    */
    pkt= (uchar*)mysql->scramble_buff;
    pkt_len= SCRAMBLE_LENGTH_323 + 1;
  }
  else
  {
    /* read the scramble */
    if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
      return CR_ERROR;

    if (pkt_len != SCRAMBLE_LENGTH_323 + 1 &&
        pkt_len != SCRAMBLE_LENGTH + 1)
        return CR_SERVER_HANDSHAKE_ERR;

    /* save it in MYSQL */
    memcpy(mysql->scramble_buff, pkt, pkt_len);
    mysql->scramble_buff[pkt_len] = 0;
  }

  if (mysql->passwd[0])
  {
    char scrambled[SCRAMBLE_LENGTH_323 + 1];
    scramble_323(scrambled, (char*)pkt, mysql->passwd);
    if (vio->write_packet(vio, (uchar*)scrambled, SCRAMBLE_LENGTH_323 + 1))
      return CR_ERROR;
  }
  else
    if (vio->write_packet(vio, 0, 0)) /* no password */
      return CR_ERROR;

  return CR_OK;
}

static int send_change_user_packet(MCPVIO_EXT *mpvio,
                                   const uchar *data, int data_len)
{
  MYSQL *mysql= mpvio->mysql;
  char *buff, *end;
  int res= 1;
  size_t conn_attr_len= (mysql->options.extension) ? 
                         mysql->options.extension->connect_attrs_len : 0;

  buff= my_alloca(USERNAME_LENGTH+1 + data_len+1 + NAME_LEN+1 + 2 + NAME_LEN+1 + 9 + conn_attr_len);

  end= strmake(buff, mysql->user, USERNAME_LENGTH) + 1;

  if (!data_len)
    *end++= 0;
  else
  {
    if (mysql->client_flag & CLIENT_SECURE_CONNECTION)
    {
      DBUG_ASSERT(data_len <= 255);
      if (data_len > 255)
      {
        my_set_error(mysql, CR_MALFORMED_PACKET, SQLSTATE_UNKNOWN, 0);
        goto error;
      }
      *end++= data_len;
    }
    else
    {
      DBUG_ASSERT(data_len == SCRAMBLE_LENGTH_323 + 1);
      DBUG_ASSERT(data[SCRAMBLE_LENGTH_323] == 0);
    }
    memcpy(end, data, data_len);
    end+= data_len;
  }
  end= strmake(end, mpvio->db ? mpvio->db : "", NAME_LEN) + 1;

  if (mysql->server_capabilities & CLIENT_PROTOCOL_41)
  {
    int2store(end, (ushort) mysql->charset->nr);
    end+= 2;
  }

  if (mysql->server_capabilities & CLIENT_PLUGIN_AUTH)
    end= strmake(end, mpvio->plugin->name, NAME_LEN) + 1;

  end= ma_send_connect_attr(mysql, end);

  res= simple_command(mysql, MYSQL_COM_CHANGE_USER,
                      buff, (ulong)(end-buff), 1, NULL);

error:
  my_afree(buff);
  return res;
}



static int send_client_reply_packet(MCPVIO_EXT *mpvio,
                                    const uchar *data, int data_len)
{
  MYSQL *mysql= mpvio->mysql;
  NET *net= &mysql->net;
  char *buff, *end;
  size_t conn_attr_len= (mysql->options.extension) ? 
                         mysql->options.extension->connect_attrs_len : 0;

  /* see end= buff+32 below, fixed size of the packet is 32 bytes */
  buff= my_alloca(33 + USERNAME_LENGTH + data_len + NAME_LEN + NAME_LEN + conn_attr_len + 9);
  
  mysql->client_flag|= mysql->options.client_flag;
  mysql->client_flag|= CLIENT_CAPABILITIES;

  if (mysql->client_flag & CLIENT_MULTI_STATEMENTS)
    mysql->client_flag|= CLIENT_MULTI_RESULTS;

#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
  if (mysql->options.ssl_key || mysql->options.ssl_cert ||
      mysql->options.ssl_ca || mysql->options.ssl_capath ||
      mysql->options.ssl_cipher)
    mysql->options.use_ssl= 1;
  if (mysql->options.use_ssl)
    mysql->client_flag|= CLIENT_SSL;

  /* if server doesn't support SSL and verification of server certificate
     was set to mandatory, we need to return an error */
  if (mysql->options.use_ssl && !(mysql->server_capabilities & CLIENT_SSL))
  {
    if ((mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT) ||
        (mysql->options.extension && (mysql->options.extension->ssl_fp || 
                                      mysql->options.extension->ssl_fp_list)))
    {
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                          ER(CR_SSL_CONNECTION_ERROR), 
                          "Server doesn't support SSL");
      goto error;
    }
  }
  
#endif /* HAVE_OPENSSL && !EMBEDDED_LIBRARY*/
  if (mpvio->db)
    mysql->client_flag|= CLIENT_CONNECT_WITH_DB;

  /* Remove options that server doesn't support */
  mysql->client_flag= mysql->client_flag &
                       (~(CLIENT_COMPRESS | CLIENT_SSL | CLIENT_PROTOCOL_41) 
                       | mysql->server_capabilities);

#ifndef HAVE_COMPRESS
  mysql->client_flag&= ~CLIENT_COMPRESS;
#endif

  if (mysql->client_flag & CLIENT_PROTOCOL_41)
  {
    /* 4.1 server and 4.1 client has a 32 byte option flag */
    int4store(buff,mysql->client_flag);
    int4store(buff+4, net->max_packet_size);
    buff[8]= (char) mysql->charset->nr;
    bzero(buff+9, 32-9);
    end= buff+32;
  }
  else
  {
    int2store(buff, mysql->client_flag);
    int3store(buff+2, net->max_packet_size);
    end= buff+5;
  }
#ifdef HAVE_OPENSSL
  if (mysql->options.ssl_key ||
      mysql->options.ssl_cert ||
      mysql->options.ssl_ca ||
      mysql->options.ssl_capath ||
      mysql->options.ssl_cipher
#ifdef CRL_IMPLEMENTED
      || (mysql->options.extension &&
       (mysql->options.extension->ssl_crl ||
        mysql->options.extension->ssl_crlpath))
#endif
      )
    mysql->options.use_ssl= 1;

  if (mysql->options.use_ssl &&
      (mysql->client_flag & CLIENT_SSL))
  {
    SSL *ssl;
    /*
      Send mysql->client_flag, max_packet_size - unencrypted otherwise
      the server does not know we want to do SSL
    */
    if (my_net_write(net, (char*)buff, (size_t) (end-buff)) || net_flush(net))
    {
      my_set_error(mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                          ER(CR_SERVER_LOST_EXTENDED),
                          "sending connection information to server",
                          errno);
      goto error;
    }

    /* Create SSL */
    if (!(ssl= my_ssl_init(mysql)))
      goto error; 

    /* Connect to the server */
    if (my_ssl_connect(ssl))
    {
      SSL_free(ssl);
      goto error;
    }

    if (mysql->options.extension &&
        (mysql->options.extension->ssl_fp || mysql->options.extension->ssl_fp_list))
    {
      if (ma_ssl_verify_fingerprint(ssl))
        goto error;
    }

    if ((mysql->options.ssl_ca || mysql->options.ssl_capath) &&
        (mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT) &&
         my_ssl_verify_server_cert(ssl))
      goto error;
  }
#endif /* HAVE_OPENSSL */

  DBUG_PRINT("info",("Server version = '%s'  capabilites: %lu  status: %u  client_flag: %lu",
		     mysql->server_version, mysql->server_capabilities,
		     mysql->server_status, mysql->client_flag));

  compile_time_assert(MYSQL_USERNAME_LENGTH == USERNAME_LENGTH);

  /* This needs to be changed as it's not useful with big packets */
  if (mysql->user[0])
    strmake(end, mysql->user, USERNAME_LENGTH);
  else
    read_user_name(end);

  /* We have to handle different version of handshake here */
  DBUG_PRINT("info",("user: %s",end));
  end= strend(end) + 1;
  if (data_len)
  {
    if (mysql->server_capabilities & CLIENT_SECURE_CONNECTION)
    {
      *end++= data_len;
      memcpy(end, data, data_len);
      end+= data_len;
    }
    else
    {
      DBUG_ASSERT(data_len == SCRAMBLE_LENGTH_323 + 1); /* incl. \0 at the end */
      memcpy(end, data, data_len);
      end+= data_len;
    }
  }
  else
    *end++= 0;

  /* Add database if needed */
  if (mpvio->db && (mysql->server_capabilities & CLIENT_CONNECT_WITH_DB))
  {
    end= strmake(end, mpvio->db, NAME_LEN) + 1;
    mysql->db= my_strdup(mpvio->db, MYF(MY_WME));
  }

  if (mysql->server_capabilities & CLIENT_PLUGIN_AUTH)
    end= strmake(end, mpvio->plugin->name, NAME_LEN) + 1;

  end= ma_send_connect_attr(mysql, end);

  /* Write authentication package */
  if (my_net_write(net, buff, (size_t) (end-buff)) || net_flush(net))
  {
    my_set_error(mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                        ER(CR_SERVER_LOST_EXTENDED),
                        "sending authentication information",
                        errno);
    goto error;
  }
  my_afree(buff);
  return 0;
  
error:
  my_afree(buff);
  return 1;
}

/**
  vio->read_packet() callback method for client authentication plugins

  This function is called by a client authentication plugin, when it wants
  to read data from the server.
*/

static int client_mpvio_read_packet(struct st_plugin_vio *mpv, uchar **buf)
{
  MCPVIO_EXT *mpvio= (MCPVIO_EXT*)mpv;
  MYSQL *mysql= mpvio->mysql;
  ulong  pkt_len;

  /* there are cached data left, feed it to a plugin */
  if (mpvio->cached_server_reply.pkt)
  {
    *buf= mpvio->cached_server_reply.pkt;
    mpvio->cached_server_reply.pkt= 0;
    mpvio->packets_read++;
    return mpvio->cached_server_reply.pkt_len;
  }

  if (mpvio->packets_read == 0)
  {
    /*
      the server handshake packet came from the wrong plugin,
      or it's mysql_change_user(). Either way, there is no data
      for a plugin to read. send a dummy packet to the server
      to initiate a dialog.
    */
    if (client_mpvio_write_packet(mpv, 0, 0))
      return (int)packet_error;
  }

  /* otherwise read the data */
  pkt_len= net_safe_read(mysql);
  mpvio->last_read_packet_len= pkt_len;
  *buf= mysql->net.read_pos;

  /* was it a request to change plugins ? */
  if (**buf == 254)
    return (int)packet_error; /* if yes, this plugin shan't continue */

  /*
    the server sends \1\255 or \1\254 instead of just \255 or \254 -
    for us to not confuse it with an error or "change plugin" packets.
    We remove this escaping \1 here.

    See also server_mpvio_write_packet() where the escaping is done.
  */
  if (pkt_len && **buf == 1)
  {
    (*buf)++;
    pkt_len--;
  }
  mpvio->packets_read++;
  return pkt_len;
}

/**
  vio->write_packet() callback method for client authentication plugins

  This function is called by a client authentication plugin, when it wants
  to send data to the server.

  It transparently wraps the data into a change user or authentication
  handshake packet, if neccessary.
*/

static int client_mpvio_write_packet(struct st_plugin_vio *mpv,
                                     const uchar *pkt, size_t pkt_len)
{
  int res;
  MCPVIO_EXT *mpvio= (MCPVIO_EXT*)mpv;

  if (mpvio->packets_written == 0)
  {
    if (mpvio->mysql_change_user)
      res= send_change_user_packet(mpvio, pkt, (int)pkt_len);
    else
      res= send_client_reply_packet(mpvio, pkt, (int)pkt_len);
  }
  else
  {
    NET *net= &mpvio->mysql->net;
    if (mpvio->mysql->thd)
      res= 1; /* no chit-chat in embedded */
    else
      res= my_net_write(net, (char *)pkt, pkt_len) || net_flush(net);
    if (res)
      my_set_error(mpvio->mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                                 ER(CR_SERVER_LOST_EXTENDED),
                                 "sending authentication information",
                                 errno);
  }
  mpvio->packets_written++;
  return res;
}

/**
  fills MYSQL_PLUGIN_VIO_INFO structure with the information about the
  connection
*/

void mpvio_info(Vio *vio, MYSQL_PLUGIN_VIO_INFO *info)
{
  bzero(info, sizeof(*info));
  switch (vio->type) {
  case VIO_TYPE_TCPIP:
    info->protocol= MYSQL_VIO_TCP;
    info->socket= vio->sd;
    return;
  case VIO_TYPE_SOCKET:
    info->protocol= MYSQL_VIO_SOCKET;
    info->socket= vio->sd;
    return;
  case VIO_TYPE_SSL:
    {
      struct sockaddr addr;
      SOCKET_SIZE_TYPE addrlen= sizeof(addr);
      if (getsockname(vio->sd, &addr, &addrlen))
        return;
      info->protocol= addr.sa_family == AF_UNIX ?
        MYSQL_VIO_SOCKET : MYSQL_VIO_TCP;
      info->socket= vio->sd;
      return;
    }
#ifdef _WIN32
  case VIO_TYPE_NAMEDPIPE:
    info->protocol= MYSQL_VIO_PIPE;
    info->handle= vio->hPipe;
    return;
/* not supported yet
  case VIO_TYPE_SHARED_MEMORY:
    info->protocol= MYSQL_VIO_MEMORY;
    info->handle= vio->handle_file_map; 
    return;
*/
#endif
  default: DBUG_ASSERT(0);
  }
}

static void client_mpvio_info(MYSQL_PLUGIN_VIO *vio,
                              MYSQL_PLUGIN_VIO_INFO *info)
{
  MCPVIO_EXT *mpvio= (MCPVIO_EXT*)vio;
  mpvio_info(mpvio->mysql->net.vio, info);
}

/**
  Client side of the plugin driver authentication.

  @note this is used by both the mysql_real_connect and mysql_change_user

  @param mysql       mysql
  @param data        pointer to the plugin auth data (scramble) in the
                     handshake packet
  @param data_len    the length of the data
  @param data_plugin a plugin that data were prepared for
                     or 0 if it's mysql_change_user()
  @param db          initial db to use, can be 0

  @retval 0 ok
  @retval 1 error
*/

int run_plugin_auth(MYSQL *mysql, char *data, uint data_len,
                    const char *data_plugin, const char *db)
{
  const char    *auth_plugin_name;
  auth_plugin_t *auth_plugin;
  MCPVIO_EXT    mpvio;
  ulong		pkt_length;
  int           res;

  /* determine the default/initial plugin to use */
  if (mysql->options.extension && mysql->options.extension->default_auth &&
      mysql->server_capabilities & CLIENT_PLUGIN_AUTH)
  {
    auth_plugin_name= mysql->options.extension->default_auth;
    if (!(auth_plugin= (auth_plugin_t*) mysql_client_find_plugin(mysql,
                       auth_plugin_name, MYSQL_CLIENT_AUTHENTICATION_PLUGIN)))
      return 1; /* oops, not found */
  }
  else
  {
    auth_plugin= mysql->server_capabilities & CLIENT_PROTOCOL_41 ?
      &native_password_client_plugin : &old_password_client_plugin;
    auth_plugin_name= auth_plugin->name;
  }

  mysql->net.last_errno= 0; /* just in case */

  if (data_plugin && strcmp(data_plugin, auth_plugin_name))
  {
    /* data was prepared for a different plugin, don't show it to this one */
    data= 0;
    data_len= 0;
  }

  mpvio.mysql_change_user= data_plugin == 0;
  mpvio.cached_server_reply.pkt= (uchar*)data;
  mpvio.cached_server_reply.pkt_len= data_len;
  mpvio.read_packet= client_mpvio_read_packet;
  mpvio.write_packet= client_mpvio_write_packet;
  mpvio.info= client_mpvio_info;
  mpvio.mysql= mysql;
  mpvio.packets_read= mpvio.packets_written= 0;
  mpvio.db= db;
  mpvio.plugin= auth_plugin;

  res= auth_plugin->authenticate_user((struct st_plugin_vio *)&mpvio, mysql);

  compile_time_assert(CR_OK == -1);
  compile_time_assert(CR_ERROR == 0);
  if (res > CR_OK && mysql->net.read_pos[0] != 254)
  {
    /*
      the plugin returned an error. write it down in mysql,
      unless the error code is CR_ERROR and mysql->net.last_errno
      is already set (the plugin has done it)
    */
    if (res > CR_ERROR)
      my_set_error(mysql, res, SQLSTATE_UNKNOWN, 0);
    else
      if (!mysql->net.last_errno)
        my_set_error(mysql, CR_UNKNOWN_ERROR, SQLSTATE_UNKNOWN, 0);
    return 1;
  }

  /* read the OK packet (or use the cached value in mysql->net.read_pos */
  if (res == CR_OK)
    pkt_length= net_safe_read(mysql);
  else /* res == CR_OK_HANDSHAKE_COMPLETE */
    pkt_length= mpvio.last_read_packet_len;

  if (pkt_length == packet_error)
  {
    if (mysql->net.last_errno == CR_SERVER_LOST)
      my_set_error(mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                          ER(CR_SERVER_LOST_EXTENDED),
                          "reading authorization packet",
                          errno);
    return 1;
  }

  if (mysql->net.read_pos[0] == 254)
  {
    /* The server asked to use a different authentication plugin */
    if (pkt_length == 1)
    {
      /* old "use short scramble" packet */
      auth_plugin_name= old_password_plugin_name;
      mpvio.cached_server_reply.pkt= (uchar*)mysql->scramble_buff;
      mpvio.cached_server_reply.pkt_len= SCRAMBLE_LENGTH + 1;
    }
    else
    {
      /* new "use different plugin" packet */
      uint len;
      auth_plugin_name= (char*)mysql->net.read_pos + 1;
      len= (uint)strlen(auth_plugin_name); /* safe as my_net_read always appends \0 */
      mpvio.cached_server_reply.pkt_len= pkt_length - len - 2;
      mpvio.cached_server_reply.pkt= mysql->net.read_pos + len + 2;
    }

    if (!(auth_plugin= (auth_plugin_t *) mysql_client_find_plugin(mysql,
                         auth_plugin_name, MYSQL_CLIENT_AUTHENTICATION_PLUGIN)))
      return 1;

    mpvio.plugin= auth_plugin;
    res= auth_plugin->authenticate_user((struct st_plugin_vio *)&mpvio, mysql);

    if (res > CR_OK)
    {
      if (res > CR_ERROR)
        my_set_error(mysql, res, SQLSTATE_UNKNOWN, 0);
      else
        if (!mysql->net.last_errno)
          my_set_error(mysql, CR_UNKNOWN_ERROR, SQLSTATE_UNKNOWN, 0);
      return 1;
    }

    if (res != CR_OK_HANDSHAKE_COMPLETE)
    {
      /* Read what server thinks about out new auth message report */
      if (net_safe_read(mysql) == packet_error)
      {
        if (mysql->net.last_errno == CR_SERVER_LOST)
          my_set_error(mysql, CR_SERVER_LOST, SQLSTATE_UNKNOWN,
                              ER(CR_SERVER_LOST_EXTENDED),
                              "reading final connect information",
                              errno);
        return 1;
      }
    }
  }
  /*
    net->read_pos[0] should always be 0 here if the server implements
    the protocol correctly
  */
  return mysql->net.read_pos[0] != 0;
}

