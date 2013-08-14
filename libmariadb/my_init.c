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

#include "mysys_priv.h"
#include "my_static.h"
#include "mysys_err.h"
#include "m_ctype.h"
#include <m_string.h>
#include <m_ctype.h>
#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
/* extern int     getrusage(int, struct rusage *); */
#endif
#include <signal.h>
#ifdef VMS
#include <my_static.c>
#include <m_ctype.h>
#endif
#ifdef _WIN32
#ifdef _MSC_VER
#include <locale.h>
#include <crtdbg.h>
#endif
my_bool have_tcpip=0;
static void my_win_init(void);
static my_bool win32_have_tcpip(void);
static my_bool win32_init_tcp_ip();
#else
#define my_win_init()
#endif

my_bool my_init_done=0;



static ulong atoi_octal(const char *str)
{
  long int tmp;
  while (*str && isspace(*str))
    str++;
  str2int(str,
	  (*str == '0' ? 8 : 10),		/* Octalt or decimalt */
	  0, INT_MAX, &tmp);
  return (ulong) tmp;
}


	/* Init my_sys functions and my_sys variabels */

void my_init(void)
{
  my_string str;
  if (my_init_done)
    return;
  my_init_done=1;
#ifdef THREAD
#if defined(HAVE_PTHREAD_INIT)
  pthread_init();			/* Must be called before DBUG_ENTER */
#endif
  my_thread_global_init();
#ifndef _WIN32
  sigfillset(&my_signals);		/* signals blocked by mf_brkhant */
#endif
#endif /* THREAD */
#ifdef UNIXWARE_7
  (void) isatty(0);			/* Go around connect() bug in UW7 */
#endif
  {
    DBUG_ENTER("my_init");
    DBUG_PROCESS(my_progname ? my_progname : (char*) "unknown");
    if (!home_dir)
    {					/* Don't initialize twice */
      if ((home_dir=getenv("HOME")) != 0)
        home_dir=intern_filename(home_dir_buff,home_dir);
#ifndef VMS
      /* Default creation of new files */
      if ((str=getenv("UMASK")) != 0)
        my_umask=(int) (atoi_octal(str) | 0600);
	/* Default creation of new dir's */
      if ((str=getenv("UMASK_DIR")) != 0)
        my_umask_dir=(int) (atoi_octal(str) | 0700);
#endif
#ifdef VMS
      init_ctype();			/* Stupid linker don't link _ctype.c */
#endif
      DBUG_PRINT("exit",("home: '%s'",home_dir));
    }
#ifdef _WIN32
    my_win_init();
#endif
    DBUG_VOID_RETURN;
  }
} /* my_init */


	/* End my_sys */

void my_end(int infoflag)
{
  FILE *info_file;
  if (!(info_file=DBUG_FILE))
    info_file=stderr;
  if (infoflag & MY_CHECK_ERROR || info_file != stderr)
  {					/* Test if some file is left open */
    if (my_file_opened | my_stream_opened)
    {
      sprintf(errbuff[0],EE(EE_OPEN_WARNING),my_file_opened,my_stream_opened);
      (void) my_message_no_curses(EE_OPEN_WARNING,errbuff[0],ME_BELL);
      DBUG_PRINT("error",("%s",errbuff[0]));
    }
  }
  if (infoflag & MY_GIVE_INFO || info_file != stderr)
  {
#ifdef HAVE_GETRUSAGE
    struct rusage rus;
    if (!getrusage(RUSAGE_SELF, &rus))
      fprintf(info_file,"\n\
User time %.2f, System time %.2f\n\
Maximum resident set size %ld, Integral resident set size %ld\n\
Non-physical pagefaults %ld, Physical pagefaults %ld, Swaps %ld\n\
Blocks in %ld out %ld, Messages in %ld out %ld, Signals %ld\n\
Voluntary context switches %ld, Involuntary context switches %ld\n",
	      (rus.ru_utime.tv_sec * SCALE_SEC +
	       rus.ru_utime.tv_usec / SCALE_USEC) / 100.0,
	      (rus.ru_stime.tv_sec * SCALE_SEC +
	       rus.ru_stime.tv_usec / SCALE_USEC) / 100.0,
	      rus.ru_maxrss, rus.ru_idrss,
	      rus.ru_minflt, rus.ru_majflt,
	      rus.ru_nswap, rus.ru_inblock, rus.ru_oublock,
	      rus.ru_msgsnd, rus.ru_msgrcv, rus.ru_nsignals,
	      rus.ru_nvcsw, rus.ru_nivcsw);
#endif
#if defined(MSDOS) && !defined(_WIN32)
    fprintf(info_file,"\nRun time: %.1f\n",(double) clock()/CLOCKS_PER_SEC);
#endif
#if defined(SAFEMALLOC)
    TERMINATE(stderr);		/* Give statistic on screen */
#elif defined(_WIN32) && defined(_MSC_VER)
   _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
   _CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDERR );
   _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
   _CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDERR );
   _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
   _CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDERR );
   _CrtCheckMemory();
   _CrtDumpMemoryLeaks();
#endif
  }
#ifdef THREAD
  pthread_mutex_destroy(&THR_LOCK_malloc);
  pthread_mutex_destroy(&THR_LOCK_open);
  pthread_mutex_destroy(&THR_LOCK_net);
  DBUG_END();				/* Must be done before my_thread_end */
  my_thread_end();
  my_thread_global_end();
#endif
#ifdef _WIN32
  if (have_tcpip);
    WSACleanup( );
#endif /* _WIN32 */
    my_init_done=0;
} /* my_end */

#ifdef _WIN32

/*
  This code is specially for running MySQL, but it should work in
  other cases too.

  Inizializzazione delle variabili d'ambiente per Win a 32 bit.

  Vengono inserite nelle variabili d'ambiente (utilizzando cosi'
  le funzioni getenv e putenv) i valori presenti nelle chiavi
  del file di registro:

  HKEY_LOCAL_MACHINE\software\MySQL

  Se la kiave non esiste nonn inserisce nessun valore
*/

/* Crea la stringa d'ambiente */

void setEnvString(char *ret, const char *name, const char *value)
{
  DBUG_ENTER("setEnvString");
  strxmov(ret, name,"=",value,NullS);
  DBUG_VOID_RETURN ;
}

static void my_win_init(void)
{
  DBUG_ENTER("my_win_init");
  win32_init_tcp_ip();
  DBUG_VOID_RETURN ;
}


/*------------------------------------------------------------------
** Name: CheckForTcpip| Desc: checks if tcpip has been installed on system
** According to Microsoft Developers documentation the first registry
** entry should be enough to check if TCP/IP is installed, but as expected
** this doesn't work on all Win32 machines :(
------------------------------------------------------------------*/

#define TCPIPKEY  "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define WINSOCK2KEY "SYSTEM\\CurrentControlSet\\Services\\Winsock2\\Parameters"
#define WINSOCKKEY  "SYSTEM\\CurrentControlSet\\Services\\Winsock\\Parameters"

static my_bool win32_have_tcpip(void)
{
  HKEY hTcpipRegKey;
  if (RegOpenKeyEx ( HKEY_LOCAL_MACHINE, TCPIPKEY, 0, KEY_READ,
		      &hTcpipRegKey) != ERROR_SUCCESS)
  {
    if (RegOpenKeyEx ( HKEY_LOCAL_MACHINE, WINSOCK2KEY, 0, KEY_READ,
		      &hTcpipRegKey) != ERROR_SUCCESS)
    {
      if (RegOpenKeyEx ( HKEY_LOCAL_MACHINE, WINSOCKKEY, 0, KEY_READ,
			 &hTcpipRegKey) != ERROR_SUCCESS)
	if (!getenv("HAVE_TCPIP") || have_tcpip)	/* Provide a workaround */
	  return (FALSE);
    }
  }
  RegCloseKey ( hTcpipRegKey);
  return (TRUE);
}

static my_bool win32_init_tcp_ip()
{
  if (win32_have_tcpip())
  {
    WORD wVersionRequested = MAKEWORD( 2, 0 );
    WSADATA wsaData;
 	/* Be a good citizen: maybe another lib has already initialised
 		sockets, so dont clobber them unless necessary */
    if (WSAStartup( wVersionRequested, &wsaData ))
    {
      /* Load failed, maybe because of previously loaded
	 incompatible version; try again */
      WSACleanup( );
      if (!WSAStartup( wVersionRequested, &wsaData ))
	have_tcpip=1;
    }
    else
    {
      if (wsaData.wVersion != wVersionRequested)
      {
	/* Version is no good, try again */
	WSACleanup( );
	if (!WSAStartup( wVersionRequested, &wsaData ))
	  have_tcpip=1;
      }
      else
	have_tcpip=1;
    }
  }
  return(0);
}
#endif
