/*****************************************************************\
 * sbthread - system-independent basic threads                   *
 * (C)Copyright 2001 Simon Urbanek                               *
 *---------------------------------------------------------------*
 * Supported platforms: unix w pthread, Win32                    *
\*****************************************************************/

#ifndef __SBTHREAD_H__
#define __SBTHREAD_H__

#ifdef unix /* begin unix (pthread) implementation */

#include <pthread.h>

#define decl_sbthread void *
#define sbthread_result(A) (void *)(A)
#define sbthread_mutex pthread_mutex_t

sbthread_mutex *sbthread_create_mutex() {
  pthread_mutex_t lm=PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_t *m=(pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  memcpy(m,&lm,sizeof(pthread_mutex_t));
  return m;
};

#define sbthread_lock_mutex(M) pthread_mutex_lock(M);
#define sbthread_unlock_mutex(M) pthread_mutex_unlock(M);
void sbthread_destroy_mutex(sbthread_mutex *m) {
  pthread_mutex_destroy(m); free(m);
};

int sbthread_create(void * (thr)(void *), void *par) {
  pthread_t Thread;
  pthread_attr_t ThreadAttr;

  pthread_attr_init(&ThreadAttr);
  pthread_attr_setdetachstate(&ThreadAttr,PTHREAD_CREATE_DETACHED);
  return pthread_create(&Thread,&ThreadAttr,*thr,par);
};

#else /* end of unix, begin of Win32 */

#include <windows.h>

#define decl_sbthread DWORD WINAPI
#define sbthread_result(A) (DWORD)(A)
#define sbthread_mutex char

#ifndef sleep /* this has nothing to do with threads, but may be usefull */
#define sleep(A) Sleep((A)*1000)
#endif

unsigned int sbthread_mutex_counter=1;

sbthread_mutex *sbthread_create_mutex(void) {
  char mtxn[64],*c;
  unsigned int i,j;
  HANDLE m;
  strcpy(mtxn,"sbthread_mutex");
  /* this isn't really thread-safe, but creating more mutexes
     at exactly the same time by different threads on an SMP machine
     is ... let's say inprobable. moreover ++ might be atomic.
     creating yet another mutex for this single operation seems
     to me as an overkill. but if you need 100% thread-safe code,
     feel free to implement it here ;) */
  sbthread_mutex_counter++;
  
  i=15; j=sbthread_mutex_counter;
  while (j>0) { mtxn[i]=65+(j&15); i++; j>>=4; };
  mtxn[i]=0; i++;
  m=CreateMutex(0,0,mtxn);
  if (!m) return 0;
  memcpy(&mtxn[i],&m,sizeof(m));
  i+=sizeof(m)*2+1;
  c=(char*)malloc(i); memcpy(c,mtxn,i);
  /* content: name\0[createHANDLE][ownershipHANDLE] */
  return c;
};

int sbthread_lock_mutex(sbthread_mutex *m) {
  HANDLE h;
  int i;
  h=OpenMutex(MUTEX_ALL_ACCESS,0,m);
  if (!h) return 0;
  if (WaitForSingleObject(h,INFINITE)==WAIT_FAILED) return 0;
  i=strlen(m);
  i+=sizeof(h)+1;
  memcpy(&m[i],&h,sizeof(h));
  return 1;
};

int sbthread_unlock_mutex(sbthread_mutex *m) {
  HANDLE h;
  int i;
  i=strlen(m); i+=sizeof(h)+1;  
  memcpy(&h,&m[i],sizeof(h));
  if (!h) return 0;
  memset(&m[i],0,sizeof(h));
  ReleaseMutex(h);
  CloseHandle(h);
  return 1;
};

void sbthread_destroy_mutex(sbthread_mutex *m) {
  HANDLE h;
  int i;
  i=strlen(m); i+=sizeof(h)+1;
  memcpy(&h,&m[i],sizeof(h));
  if (h) return; // oh, mutex is still in use  
  memcpy(&h,&m[i-sizeof(h)],sizeof(h));
  CloseHandle(h);
  free(m);
};

int sbthread_create(LPTHREAD_START_ROUTINE sa, void *par) {
  DWORD tid;
  return CreateThread(0,0,sa,par,0,&tid);
};

#endif /* Windows implementation */

#endif /* __SBTHREAD_H__ */
