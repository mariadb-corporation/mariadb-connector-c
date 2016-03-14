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
** Functions to handle initializating and allocationg of all mysys & debug
** thread variables.
*/

#include "mysys_priv.h"
#include <m_string.h>
#include <dbug.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifdef THREAD
#ifdef USE_TLS
pthread_key(struct st_my_thread_var*, THR_KEY_mysys);
#else
pthread_key(struct st_my_thread_var, THR_KEY_mysys);
#endif /* USE_TLS */
pthread_mutex_t THR_LOCK_malloc,THR_LOCK_open,
	        THR_LOCK_lock, THR_LOCK_net, THR_LOCK_mysys; 
#ifdef HAVE_OPENSSL
pthread_mutex_t LOCK_ssl_config;
#endif
#ifndef HAVE_LOCALTIME_R
pthread_mutex_t LOCK_localtime_r;
#endif
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
pthread_mutexattr_t my_fast_mutexattr;
#endif
#ifdef PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
pthread_mutexattr_t my_errchk_mutexattr;
#endif
my_bool THR_KEY_mysys_initialized= FALSE;

/* FIXME  Note.  TlsAlloc does not set an auto destructor, so
	the function my_thread_global_free must be called from
	somewhere before final exit of the library */

my_bool my_thread_global_init(void)
{
  if (pthread_key_create(&THR_KEY_mysys,free))
  {
    fprintf(stderr,"Can't initialize threads: error %d\n",errno);
    exit(1);
  }
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
  pthread_mutexattr_init(&my_fast_mutexattr);
  pthread_mutexattr_setkind_np(&my_fast_mutexattr,PTHREAD_MUTEX_ADAPTIVE_NP);
#endif
#ifdef PPTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
  pthread_mutexattr_init(&my_errchk_mutexattr);
  pthread_mutexattr_setkind_np(&my_errchk_mutexattr,
			       PTHREAD_MUTEX_ERRORCHECK_NP);
#endif
  THR_KEY_mysys_initialized= TRUE;
#ifdef HAVE_OPENSSL
  pthread_mutex_init(&LOCK_ssl_config,MY_MUTEX_INIT_FAST);
#endif
  pthread_mutex_init(&THR_LOCK_malloc,MY_MUTEX_INIT_FAST);
  pthread_mutex_init(&THR_LOCK_open,MY_MUTEX_INIT_FAST);
  pthread_mutex_init(&THR_LOCK_lock,MY_MUTEX_INIT_FAST);
  pthread_mutex_init(&THR_LOCK_net,MY_MUTEX_INIT_FAST);
#ifdef _WIN32
  /* win_pthread_init(); */
#endif
#ifndef HAVE_LOCALTIME_R
  pthread_mutex_init(&LOCK_localtime_r,MY_MUTEX_INIT_SLOW);
#endif
  return my_thread_init();
}

void my_thread_global_end(void)
{
#if defined(USE_TLS)
  (void) TlsFree(THR_KEY_mysys);
#endif
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
  pthread_mutexattr_destroy(&my_fast_mutexattr);
#endif
#ifdef PPTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
  pthread_mutexattr_destroy(&my_errchk_mutexattr);
#endif
#ifdef HAVE_OPENSSL
  pthread_mutex_destroy(&LOCK_ssl_config);
#endif
}

static long thread_id=0;

/*
  We can't use mutex_locks here if we are using windows as
  we may have compiled the program with SAFE_MUTEX, in which
  case the checking of mutex_locks will not work until
  the pthread_self thread specific variable is initialized.
*/

my_bool my_thread_init(void)
{
  struct st_my_thread_var *tmp;
  if (my_pthread_getspecific(struct st_my_thread_var *,THR_KEY_mysys))
  {
    DBUG_PRINT("info", ("my_thread_init was already called. Thread id: %lu",
                       pthread_self()));
    return 0;						/* Safequard */
  }
  /* We must have many calloc() here because these are freed on
     pthread_exit */
  if (!(tmp=(struct st_my_thread_var *)
	calloc(1,sizeof(struct st_my_thread_var))))
  {
    return 1;
  }
  pthread_setspecific(THR_KEY_mysys,tmp);

  if (tmp->initialized)   /* Already initialized */
  {
    return 0;
  }

  pthread_mutex_init(&tmp->mutex,MY_MUTEX_INIT_FAST);
  pthread_cond_init(&tmp->suspend, NULL);
  pthread_mutex_lock(&THR_LOCK_lock);
  tmp->id= ++thread_id;
  pthread_mutex_unlock(&THR_LOCK_lock);
  tmp->initialized= TRUE;
  return 0;
}

void my_thread_end(void)
{
  struct st_my_thread_var *tmp= 
            my_pthread_getspecific(struct st_my_thread_var *, THR_KEY_mysys);

  if (tmp && tmp->initialized)
  {
#ifdef HAVE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x10000001L
    ERR_remove_thread_state(NULL);
#else
    ERR_remove_state(0);
#endif
#endif
#if !defined(DBUG_OFF)
    if (tmp->dbug)
    {
      DBUG_POP();
      free(tmp->dbug);
      tmp->dbug=0;
    }
#endif
#if !defined(__bsdi__) || defined(HAVE_mit_thread) /* bsdi dumps core here */
    pthread_cond_destroy(&tmp->suspend);
#endif
    pthread_mutex_destroy(&tmp->mutex);
    free(tmp);
    pthread_setspecific(THR_KEY_mysys,0);
  }
  else
    pthread_setspecific(THR_KEY_mysys,0); 
}

struct st_my_thread_var *_my_thread_var(void)
{
  struct st_my_thread_var *tmp=
    my_pthread_getspecific(struct st_my_thread_var*,THR_KEY_mysys);
#if defined(USE_TLS)
  if (!tmp)
  {
    my_thread_init();
    tmp=my_pthread_getspecific(struct st_my_thread_var*,THR_KEY_mysys);
  }
#endif
  return tmp;
}

/****************************************************************************
** Get name of current thread.
****************************************************************************/

#define UNKNOWN_THREAD -1

long my_thread_id()
{
#if defined(HAVE_PTHREAD_GETSEQUENCE_NP)
  return pthread_getsequence_np(pthread_self());
#elif (defined(__sun) || defined(__sgi) || defined(__linux__)) && !defined(HAVE_mit_thread)
  return pthread_self();
#else
  return my_thread_var->id;
#endif
}

#ifdef DBUG_OFF
const char *my_thread_name(void)
{
  return "no_name";
}

#else

const char *my_thread_name(void)
{
  char name_buff[100];
  struct st_my_thread_var *tmp=my_thread_var;
  if (!tmp->name[0])
  {
    long id=my_thread_id();
    sprintf(name_buff,"T@%ld", id);
    strmake(tmp->name,name_buff,THREAD_NAME_SIZE);
  }
  return tmp->name;
}

extern void **my_thread_var_dbug()
{
  struct st_my_thread_var *tmp;
  /*
    Instead of enforcing DBUG_ASSERT(THR_KEY_mysys_initialized) here,
    which causes any DBUG_ENTER and related traces to fail when
    used in init / cleanup code, we are more tolerant:
    using DBUG_ENTER / DBUG_PRINT / DBUG_RETURN
    when the dbug instrumentation is not in place will do nothing.
  */
  if (! THR_KEY_mysys_initialized)
    return NULL;
  tmp= _my_thread_var();
  return tmp && tmp->initialized ? (void **)&tmp->dbug : 0;
}
#endif /* DBUG_OFF */

#endif /* THREAD */
