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
  Static variables for mysys library. All definied here for easy making of
  a shared library
*/

#if !defined(stdin) || defined(OS2)
#include "mysys_priv.h"
#include "my_static.h"
#include "my_alarm.h"
#endif

	/* from ma_init */
my_string	ma_ma_ma_home_dir=0,ma_progname=0;
char		NEAR ma_cur_dir[FN_REFLEN]= {0},
		NEAR ma_ma_ma_ma_ma_ma_home_dir_buff[FN_REFLEN]= {0};
ulong		ma_stream_opened=0,ma_file_opened=0, ma_tmp_file_created=0;
int		NEAR ma_umask=0664, NEAR ma_umask_dir=0777;
#ifndef THREAD
int		NEAR my_errno=0;
#endif
struct ma_file_info ma_file_info[MY_NFILE]= {{0,UNOPEN}};

	/* From mf_brkhant */
int			NEAR ma_dont_interrupt=0;
volatile int		_ma_signals=0;
struct st_remember _ma_sig_remember[MAX_SIGNALS]={{0,0}};
#ifdef THREAD
sigset_t my_signals;			/* signals blocked by mf_brkhant */
#endif

	/* from mf_keycache.c */
my_bool key_cache_inited=0;

	/* from mf_reccache.c */
ulong ma_default_record_cache_size=RECORD_CACHE_SIZE;

	/* from soundex.c */
				/* ABCDEFGHIJKLMNOPQRSTUVWXYZ */
				/* :::::::::::::::::::::::::: */
const char *ma_soundex_map=	  "01230120022455012623010202";

	/* from ma_malloc */
MA_USED_MEM* ma_once_root_block=0;			/* pointer to first block */
uint	  ma_once_extra=ONCE_ALLOC_INIT;	/* Memory to alloc / block */

	/* from my_tempnam */
#if !defined(HAVE_TEMPNAM) || defined(HPUX11)
int _my_tempnam_used=0;
#endif

	/* from safe_malloc */
uint sf_malloc_prehunc=0,		/* If you have problem with core- */
     sf_malloc_endhunc=0,		/* dump when malloc-message.... */
					/* set theese to 64 or 128  */
     sf_malloc_quick=0;			/* set if no calls to sanity */
size_t lCurMemory = 0L;			/* Current memory usage */
size_t lMaxMemory = 0L;			/* Maximum memory usage */
uint cNewCount = 0;			/* Number of times NEW() was called */

/* Root of the linked list of remembers */
struct remember *pRememberRoot = NULL;

	/* from my_alarm */
int volatile ma_have_got_alarm=0;	/* declare variable to reset */
ulong ma_time_to_wait_for_lock=2;	/* In seconds */

	/* from errors.c */
#ifdef SHARED_LIBRARY
char * NEAR ma_globerrs[GLOBERRS];		/* ma_error_messages is here */
#endif
void (*my_abort_hook)(int) = (void(*)(int)) exit;
int (*ma_error_handler_hook)(uint error,const char *str,myf MyFlags)=
    ma_message_no_curses;
int (*fatal_ma_error_handler_hook)(uint error,const char *str,myf MyFlags)=
  ma_message_no_curses;

	/* How to disable options */
my_bool NEAR ma_disable_locking=0;
my_bool NEAR ma_disable_async_io=0;
my_bool NEAR ma_disable_flush_key_blocks=0;
my_bool NEAR ma_disable_symlinks=0;
my_bool NEAR mysys_uses_curses=0;
