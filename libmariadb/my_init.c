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
static my_bool my_win_init(void);
#else
#define my_win_init()
#endif

my_bool ma_init_done=0;



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

void ma_init(void)
{
  my_string str;
  if (ma_init_done)
    return;
  ma_init_done=1;
#ifdef THREAD
#if defined(HAVE_PTHREAD_INIT)
  pthread_init();			/* Must be called before DBUG_ENTER */
#endif
  ma_thread_global_init();
#ifndef _WIN32
  sigfillset(&my_signals);		/* signals blocked by mf_brkhant */
#endif
#endif /* THREAD */
#ifdef UNIXWARE_7
  (void) isatty(0);			/* Go around connect() bug in UW7 */
#endif
  {
    DBUG_ENTER("ma_init");
    DBUG_PROCESS(ma_progname ? ma_progname : (char*) "unknown");
    if (!ma_ma_ma_home_dir)
    {					/* Don't initialize twice */
      if ((ma_ma_ma_home_dir=getenv("HOME")) != 0)
        ma_ma_ma_home_dir=ma_intern_filename(ma_ma_ma_ma_ma_ma_home_dir_buff,ma_ma_ma_home_dir);
#ifndef VMS
      /* Default creation of new files */
      if ((str=getenv("UMASK")) != 0)
        ma_umask=(int) (atoi_octal(str) | 0600);
	/* Default creation of new dir's */
      if ((str=getenv("UMASK_DIR")) != 0)
        ma_umask_dir=(int) (atoi_octal(str) | 0700);
#endif
#ifdef VMS
      init_ctype();			/* Stupid linker don't link _ctype.c */
#endif
      DBUG_PRINT("exit",("home: '%s'",ma_ma_ma_home_dir));
    }
#ifdef _WIN32
    my_win_init();
#endif
    DBUG_VOID_RETURN;
  }
} /* ma_init */


	/* End my_sys */

void ma_end(int infoflag)
{
  FILE *info_file;
  if (!(info_file=DBUG_FILE))
    info_file=stderr;
  if (infoflag & MY_CHECK_ERROR || info_file != stderr)
  {					/* Test if some file is left open */
    if (ma_file_opened | ma_stream_opened)
    {
      sprintf(errbuff[0],EE(EE_OPEN_WARNING),ma_file_opened,ma_stream_opened);
      (void) ma_message_no_curses(EE_OPEN_WARNING,errbuff[0],ME_BELL);
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
  DBUG_END();				/* Must be done before ma_thread_end */
  ma_thread_end();
  ma_thread_global_end();
#endif
#ifdef _WIN32
  WSACleanup( );
#endif /* _WIN32 */
  ma_init_done=0;
} /* ma_end */

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

static my_bool my_win_init()
{
  WORD VersionRequested;
  int err;
  WSADATA WsaData;
  const unsigned int MajorVersion=2,
                     MinorVersion=2;
  VersionRequested= MAKEWORD(MajorVersion, MinorVersion);
  /* Load WinSock library */
  if ((err= WSAStartup(VersionRequested, &WsaData)))
  {
    return 0;
  }
  /* make sure 2.2 or higher is supported */
  if ((LOBYTE(WsaData.wVersion) * 10 + HIBYTE(WsaData.wVersion)) < 22)
  {
    WSACleanup();
    return 1;
  }
  return 0;
}
#endif

