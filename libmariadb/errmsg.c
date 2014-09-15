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

/* Error messages for MySQL clients */
/* error messages for the demon is in share/language/errmsg.sys */

#include <my_global.h>
#include <my_sys.h>
#include "errmsg.h"
#include <stdarg.h>

#ifdef GERMAN
const char *client_errors[]=
{
  "Unbekannter MySQL Fehler",
  "Kann UNIX-Socket nicht anlegen (%d)",
  "Keine Verbindung zu lokalem MySQL Server, socket: '%-.64s' (%d)",
  "Keine Verbindung zu MySQL Server auf %-.64s (%d)",
  "Kann TCP/IP-Socket nicht anlegen (%d)",
  "Unbekannter MySQL Server Host (%-.64s) (%d)",
  "MySQL Server nicht vorhanden",
  "Protokolle ungleich. Server Version = % d Client Version = %d",
  "MySQL client got out of memory",
  "Wrong host info",
  "Localhost via UNIX socket",
  "%-.64s via TCP/IP",
  "Error in server handshake",
  "Lost connection to MySQL server during query",
  "Commands out of sync; you can't run this command now",
  "Verbindung ueber Named Pipe; Host: %-.64s",
  "Kann nicht auf Named Pipe warten. Host: %-.64s  pipe: %-.32s (%lu)",
  "Kann Named Pipe nicht oeffnen. Host: %-.64s  pipe: %-.32s (%lu)",
  "Kann den Status der Named Pipe nicht setzen.  Host: %-.64s  pipe: %-.32s (%lu)",
  "Can't initialize character set %-.64s (path: %-.64s)",
  "Got packet bigger than 'max_allowed_packet'"
};

/* Start of code added by Roberto M. Serqueira - martinsc@uol.com.br - 05.24.2001 */

#elif defined PORTUGUESE
const char *client_errors[]=
{
  "Erro desconhecido do MySQL",
  "Não pode criar 'UNIX socket' (%d)",
  "Não pode se conectar ao servidor MySQL local através do 'socket' '%-.64s' (%d)", 
  "Não pode se conectar ao servidor MySQL em '%-.64s' (%d)",
  "Não pode criar 'socket TCP/IP' (%d)",
  "'Host' servidor MySQL '%-.64s' (%d) desconhecido", 
  "Servidor MySQL desapareceu",
  "Incompatibilidade de protocolos. Versão do Servidor: %d - Versão do Cliente: %d",
  "Cliente do MySQL com falta de memória",
  "Informação inválida de 'host'",
  "Localhost via 'UNIX socket'",
  "%-.64s via 'TCP/IP'",
  "Erro na negociação de acesso ao servidor",
  "Conexão perdida com servidor MySQL durante 'query'",
  "Comandos fora de sincronismo. Você não pode executar este comando agora",
  "%-.64s via 'named pipe'",
  "Não pode esperar pelo 'named pipe' para o 'host' %-.64s - 'pipe' %-.32s (%lu)",
  "Não pode abrir 'named pipe' para o 'host' %-.64s - 'pipe' %-.32s (%lu)",
  "Não pode estabelecer o estado do 'named pipe' para o 'host' %-.64s - 'pipe' %-.32s (%lu)",
  "Não pode inicializar conjunto de caracteres %-.64s (caminho %-.64s)",
  "Obteve pacote maior do que 'max_allowed_packet'"
};

#else /* ENGLISH */
const char *client_errors[]=
{
/* 2000 */  "Unknown MySQL error",
/* 2001 */  "Can't create UNIX socket (%d)",
/* 2002 */  "Can't connect to local MySQL server through socket '%-.64s' (%d)",
/* 2003 */  "Can't connect to MySQL server on '%-.64s' (%d)",
/* 2004 */  "Can't create TCP/IP socket (%d)",
/* 2005 */  "Unknown MySQL Server Host '%-.64s' (%d)",
/* 2006 */  "MySQL server has gone away",
/* 2007 */  "Protocol mismatch. Server Version = %d Client Version = %d",
/* 2008 */  "MySQL client run out of memory",
/* 2009 */  "Wrong host info",
/* 2010 */  "Localhost via UNIX socket",
/* 2011 */  "%-.64s via TCP/IP",
/* 2012 */  "Error in server handshake",
/* 2013 */  "Lost connection to MySQL server during query",
/* 2014 */  "Commands out of sync; you can't run this command now",
/* 2015 */  "%-.64s via named pipe",
/* 2016 */  "Can't wait for named pipe to host: %-.64s  pipe: %-.32s (%lu)",
/* 2017 */  "Can't open named pipe to host: %-.64s  pipe: %-.32s (%lu)",
/* 2018 */  "Can't set state of named pipe to host: %-.64s  pipe: %-.32s (%lu)",
/* 2019 */  "Can't initialize character set %-.64s (path: %-.64s)",
/* 2020 */  "Got packet bigger than 'max_allowed_packet'",
/* 2021 */  "",
/* 2022 */  "",
/* 2023 */  "",
/* 2024 */  "",
/* 2025 */  "",
/* 2026 */  "SSL connection error: %100s",
/* 2027 */  "received malformed packet",
/* 2028 */  "",
/* 2029 */  "",
/* 2030 */  "Statement is not prepared",
/* 2031 */  "No data supplied for parameters in prepared statement",
/* 2032 */  "",
/* 2033 */  "",
/* 2034 */  "",
/* 2035 */  "",
/* 2036 */  "Buffer type is not supported",
/* 2037 */  "",
/* 2038 */  "",
/* 2039 */  "",
/* 2040 */  "",
/* 2041 */  "",
/* 2042 */  "",
/* 2043 */  "",
/* 2044 */  "",
/* 2045 */  "",
/* 2046 */  "",
/* 2047 */  "",
/* 2048 */  "",
/* 2049 */  "Connection with old authentication protocol refused.",
/* 2050 */  "",
/* 2051 */  "",
/* 2052 */  "Prepared statement contains no metadata",
/* 2053 */  "",
/* 2054 */  "This feature is not implemented or disabled",
/* 2055 */  "Lost connection to MySQL server at '%s', system error: %d",
/* 2056 */  "",
/* 2057 */  "The number of parameters in bound buffers differs from number of columns in resultset",
/* 2058 */  "Plugin %s could not be loaded: %s",
/* 2059 */  "Can't connect twice. Already connected",
/* 2060 */  "Plugin doesn't support this function",
            ""
};
#endif


void init_client_errs(void)
{
  my_errmsg[CLIENT_ERRMAP] = &client_errors[0];
}
