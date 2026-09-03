/* Copyright (c) 2015-2016, Shuang Qiu, Robbie Harwood,
Vladislav Vaintroub & MariaDB Corporation

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

/**
  @file

  GSSAPI authentication plugin, client side
*/
#include <string.h>
#include <stdarg.h>
#include <ma_global.h>
#include <mysql.h>
#include <ma_server_error.h>
#include <mysql/client_plugin.h>
#include <mysql.h>
#include <stdio.h>
#include "common.h"

extern int auth_client(char *principal_name,
                       char *mech,
                       MYSQL *mysql,
                       MYSQL_PLUGIN_VIO *vio);

static void parse_server_packet(char *packet, size_t packet_len, char *spn, char *mech)
{
  const char *nul;
  const char *mech_end;
  size_t len;

  if (!spn || !mech)
    return;

  *spn= *mech= '\0';

  if (!packet || packet_len == 0)
    return;

  /* Find the SPN terminator within the packet. */
  nul= memchr(packet, '\0', packet_len);

  /* Copy SPN up to NUL or packet end, capped at PRINCIPAL_NAME_MAX. */
  len= nul ? (size_t)(nul - packet) : packet_len;
  if (len > PRINCIPAL_NAME_MAX)
    len= PRINCIPAL_NAME_MAX;

  memcpy(spn, packet, len);
  spn[len]= '\0';

  /* Stop if there was no NUL, or no remaining bytes after the NUL. */
  if (!nul || ++nul >= packet + packet_len)
    return;

  /* Find the mechanism terminator. */
  mech_end = memchr(nul, '\0', (size_t)(packet + packet_len - nul));

  len= mech_end ? (size_t)(mech_end - nul) : (size_t)(packet + packet_len - nul);
  if (len > MECH_NAME_MAX)
    len= MECH_NAME_MAX;

  memcpy(mech, nul, len);
  mech[len]= '\0';
}

/**
  Set client error message.
 */
void log_client_error(MYSQL *mysql,  const char *format, ...)
{
  NET *net= &mysql->net;
  va_list args;

  net->last_errno= ER_UNKNOWN_ERROR;
  va_start(args, format);
  vsnprintf(net->last_error, sizeof(net->last_error) - 1,
          format, args);
  va_end(args);
  memcpy(net->sqlstate, "HY000", sizeof(net->sqlstate));
}

/**
  The main client function of the GSSAPI plugin.
 */
static int gssapi_auth_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  int packet_len;
  unsigned char *packet;
  char spn[PRINCIPAL_NAME_MAX + 1];
  char mech[MECH_NAME_MAX + 1];

  /* read from server for service principal name */
  packet_len= vio->read_packet(vio, &packet);
  if (packet_len < 0)
  {
    return CR_ERROR;
  }
  parse_server_packet((char *)packet, (size_t)packet_len, spn, mech);
  return auth_client(spn, mech, mysql, vio);
}


/* register client plugin */
#ifndef PLUGIN_DYNAMIC
struct st_mysql_client_plugin_AUTHENTICATION auth_gssapi_client_client_plugin=
#else
MARIADB_CLIENT_PLUGIN_EXPORT struct st_mysql_client_plugin_AUTHENTICATION
    _mysql_client_plugin_declaration_=
#endif
{
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN,
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN_INTERFACE_VERSION,
  "auth_gssapi_client",
  "Shuang Qiu, Robbie Harwood, Vladislav Vaintroub, Georg Richter",
  "GSSAPI/SSPI-based authentication",
  {0, 1, 0},
  "BSD",
  NULL,
  NULL,
  NULL,
  NULL,
  gssapi_auth_client,
  NULL
};
