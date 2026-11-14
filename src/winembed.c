/*
 *  R : A Computer Language for Statistical Data Analysis
 *  Copyright (C) 1998--2002  R Development Core Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef WIN32

/* based on rtest.c
   implements Rf_initEmbeddedR which is missing in the Windows-version
   of R shared library */

/* 27/03/2000 win32-api needs this */
#define NONAMELESSUNION
#include <windows.h>
#include <winreg.h>
#include <stdio.h>
#include <config.h>
#include "Rversion.h"

#if R_VERSION < 0x2010
#include "Startup.h"
#else
#include <Rembedded.h>
#include <R_ext/RStartup.h>
#endif

/* flag governing interactivity - from Rserv.c */
extern int Rsrv_interactive;

/* I didn't actually check if 2.10.x is really the point where initEmbedded was introduced but it makes pretty much all this file obsolete */
#if R_VERSION > R_Version(2,10,0)

__declspec(dllimport) int R_Interactive;

#if R_VERSION >= R_Version(4,2,0) /* R_DefParamsEx and Rstart version 1 */

/* Windows R has no ptr_R_* console hooks: the console callbacks can only be
   set in Rstart before R starts. So instead of R.dll's Rf_initialize_R (which
   installs stdio callbacks) we do the same set-up here with callbacks that
   forward to Rserve's OOB console functions once Rserv.c registers them
   (OCAP connection with console.oob enabled), and use stdio until then. This
   follows R's src/gnuwin32/embeddedR.c. */

#include <signal.h>
#include <string.h>

/* Rembedded.h declares the R.dll entry points used below (getDLLVersion,
   getRUser, get_R_HOME, R_setStartTime, UserBreak) */

static struct {
	int  (*read)(const char *, unsigned char *, int, int);
	void (*write)(const char *, int, int);
	void (*message)(const char *);
	void (*reset)(void);
	void (*flush)(void);
	void (*clearerr)(void);
	void (*busy)(int);
} oob_con;

/* called by Rserv.c when an OCAP connection with console.oob starts */
void Rserve_win_console(int (*read)(const char *, unsigned char *, int, int),
						void (*write)(const char *, int, int),
						void (*message)(const char *),
						void (*reset)(void), void (*flush)(void),
						void (*clearerr)(void), void (*busy)(int))
{
	oob_con.read = read;
	oob_con.write = write;
	oob_con.message = message;
	oob_con.reset = reset;
	oob_con.flush = flush;
	oob_con.clearerr = clearerr;
	oob_con.busy = busy;
}

static int win_ReadConsole(const char *prompt, unsigned char *buf, int len, int history)
{
	if (oob_con.read) {
		return oob_con.read(prompt, buf, len, history);
	}
	fputs(prompt, stdout);
	fflush(stdout);
	return fgets((char *) buf, len, stdin) ? 1 : 0;
}

static void win_WriteConsoleEx(const char *buf, int len, int otype)
{
	if (oob_con.write) oob_con.write(buf, len, otype);
	else {
		fwrite(buf, 1, len, stdout);
		fflush(stdout);
	}
}

static void win_ShowMessage(const char *msg)
{
	if (oob_con.message) oob_con.message(msg);
	else if (msg) printf("%s\n", msg);
}

static int win_YesNoCancel(const char *msg)
{
	unsigned char a[4];
	char prompt[256];
	snprintf(prompt, sizeof(prompt), "%s [y/n/c]: ", msg);
	if (win_ReadConsole(prompt, a, sizeof(a), 0) <= 0) return 0;
	return (a[0] == 'y' || a[0] == 'Y') ? 1 : (a[0] == 'n' || a[0] == 'N') ? -1 : 0;
}

static void win_ResetConsole(void)    { if (oob_con.reset) oob_con.reset(); }
static void win_FlushConsole(void)    { if (oob_con.flush) oob_con.flush(); else fflush(stdout); }
static void win_ClearerrConsole(void) { if (oob_con.clearerr) oob_con.clearerr(); }
static void win_Busy(int which)       { if (oob_con.busy) oob_con.busy(which); }
static void win_CallBack(void)        { }

static void win_onintr(int sig)
{
	UserBreak = 1;
}

int Rf_initEmbeddedR(int argc, char **argv)
{
	structRstart rp;
	Rstart Rp = &rp;
	char Rversion[25], *RHome, *RUser;

	snprintf(Rversion, sizeof(Rversion), "%s.%s", R_MAJOR, R_MINOR);
	if (strncmp(getDLLVersion(), Rversion, sizeof(Rversion)) != 0) {
		fprintf(stderr, "Error: R.DLL version (%s) does not match (%s)\n", getDLLVersion(), Rversion);
		return -1;
	}

	R_setStartTime();
	R_DefParamsEx(Rp, RSTART_VERSION);
	if (!(RHome = get_R_HOME())) {
		fprintf(stderr, "R_HOME must be set in the environment or Registry\n");
		return -2;
	}
	Rp->rhome = RHome;
	RUser = getRUser();
	Rp->home = RUser;
	Rp->CharacterMode = LinkDLL;
	Rp->EmitEmbeddedUTF8 = FALSE;
	Rp->ReadConsole = win_ReadConsole;
	Rp->WriteConsole = NULL; /* so that WriteConsoleEx is used */
	Rp->WriteConsoleEx = win_WriteConsoleEx;
	Rp->CallBack = win_CallBack;
	Rp->ShowMessage = win_ShowMessage;
	Rp->YesNoCancel = win_YesNoCancel;
	Rp->Busy = win_Busy;
	Rp->ResetConsole = win_ResetConsole;
	Rp->FlushConsole = win_FlushConsole;
	Rp->ClearerrConsole = win_ClearerrConsole;

	Rp->R_Quiet = TRUE;
	Rp->R_Interactive = Rsrv_interactive;
	Rp->RestoreAction = SA_RESTORE;
	Rp->SaveAction = SA_NOSAVE;
	R_SetParams(Rp);
	freeRUser(RUser);
	free_R_HOME(RHome);
	R_set_command_line_arguments(argc, argv);

	FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));

	signal(SIGBREAK, win_onintr);
	{ /* GA_initapp lives in Rgraphapp.dll (loaded by R.dll), which Rserve
		 does not link against */
		HMODULE ga = GetModuleHandleA("Rgraphapp.dll");
		int (*initapp)(int, char **) = ga ? (int (*)(int, char **)) GetProcAddress(ga, "GA_initapp") : 0;
		if (initapp) initapp(0, 0);
	}

	setup_Rmainloop();
	return 0;
}

#else /* R < 4.2.0: use R.dll's start-up (no console forwarding) */

int Rf_initEmbeddedR(int argc, char **argv)
{
	Rf_initialize_R(argc, argv);
	R_Interactive = Rsrv_interactive;
	setup_Rmainloop();
	return 0;
}

#endif

#else /* otherwise we have to do all this manually ... */

/* for signal-handling code */
#include "psignal.h"

/* one way to allow user interrupts: called in ProcessEvents */
#if defined _MSC_VER || defined WIN64
__declspec(dllimport) int UserBreak;
#else
#define UserBreak     (*_imp__UserBreak)
extern int UserBreak;
#endif

/* calls into the R DLL */
extern char *getDLLVersion();
extern void R_DefParams(Rstart);
extern void R_SetParams(Rstart);
extern void setup_term_ui(void);
extern void ProcessEvents(void);
extern void end_Rmainloop(void), R_ReplDLLinit(void);
extern int R_ReplDLLdo1();
extern void run_Rmainloop(void);

#ifndef YES
#define YES    1
#endif
#ifndef NO
#define NO    -1
#endif
#ifndef CANCEL
#define CANCEL 0
#endif

/* simple input, simple output */
/* This version blocks all events: a real one needs to call ProcessEvents
   frequently. See rterm.c and ../system.c for one approach using
   a separate thread for input */
int myReadConsole(const char *prompt, char *buf, int len, int addtohistory)
{
    fputs(prompt, stdout);
    fflush(stdout);
    if(fgets(buf, len, stdin)) return 1;
    else return 0;
}

void myWriteConsole(const char *buf, int len)
{
    printf("%s", buf);
}

void myCallBack()
{
    /* called during i/o, eval, graphics in ProcessEvents */
}

void myBusy(int which)
{
    /* set a busy cursor ... if which = 1, unset if which = 0 */
}

void myMessage(const char *s)
{
    if (!s) return;
    myWriteConsole(s, strlen(s));
}

int myYesNoCancel(const char *s)
{
    char  ss[128];
    char a[3];

    snprintf(ss, sizeof(ss)-1, "%s [y/n/c]: ", s);
    myReadConsole(ss, a, 3, 0);
    switch (a[0]) {
    case 'y':
    case 'Y':
	return YES;
    case 'n':
    case 'N':
	return NO;
    default:
	return CANCEL;
    }
}

static void my_onintr(int sig)
{
    UserBreak = 1;
}

static char Rversion[25], RUser[MAX_PATH], RHome[MAX_PATH];

static int dir_exists(const char* dn)
{
  DWORD att = GetFileAttributes(dn); /* this actually needs Win2k or higher but I suppose that's ok these days ... */
  return (att != INVALID_FILE_ATTRIBUTES && ((att & FILE_ATTRIBUTE_DIRECTORY) != 0 || att == FILE_ATTRIBUTE_NORMAL));
  /* the last one is weird, but according to MS docs it can happen any we cannot tell whether it's a file or a directory */
}

static char tmpbuf[8192];

int Rf_initEmbeddedR(int argc, char **argv)
{
    structRstart rp;
    Rstart Rp = &rp;
    char *p;
    char rhb[MAX_PATH+10];
   DWORD t,s=MAX_PATH;
   HKEY k;
   const char *arch = 0;
   const char *path_suf = 0;

   snprintf(Rversion, sizeof(Rversion)-1, "%s.%s", R_MAJOR, R_MINOR);
   { char *c = Rversion, *d = Rversion; while (*c) { if (*c=='.') d=c; c++; }; *d=0; }


#ifdef RSERV_DEBUG
   printf("Windows: Rf_initEmbeddedR; compiled as %s.%s, DLL is %s\n",  R_MAJOR, R_MINOR, getDLLVersion());
#endif

   if(strncmp(Rversion, getDLLVersion(), strlen(Rversion)) != 0) {
     fprintf(stderr, "Error: R.DLL version (%s) does not match (%s.%s)\n",  getDLLVersion(),
	     R_MAJOR, R_MINOR);
     return -1;
   }

    R_DefParams(Rp);
    if(getenv("R_HOME")) {
	strcpy(RHome, getenv("R_HOME"));
    } else { /* fetch R_HOME from the registry */
      /* try HKCU first such that users can override the system setting */
      if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\R-core\\R", 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS ||
	  RegQueryValueEx(k, "InstallPath", 0, &t, (LPVOID)RHome, &s) != ERROR_SUCCESS ||
	  !dir_exists(RHome)) {
	/* then try HKLM where teh system-wide installs would be */
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\R-core\\R", 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS ||
	    RegQueryValueEx(k, "InstallPath", 0, &t, (LPVOID)RHome, &s) != ERROR_SUCCESS) {
	  fprintf(stderr, "R_HOME must be set or R properly installed (\\Software\\R-core\\R\\InstallPath registry entry must exist).\n");
	  return -2;
	}
      }
      snprintf(rhb, sizeof(rhb)-1, "R_HOME=%s",RHome);
      putenv(rhb);
    }
    /* on Win32 this should set R_Home (in R_SetParams) as well */
    Rp->rhome = RHome;
#ifdef RSERV_DEBUG
    printf("R_HOME: %s\n", RHome);
#endif

    /* check for multi-arch R */
    if (!getenv("R_ARCH")) {
	strcpy(tmpbuf, RHome);
#ifdef WIN64
	strcat(tmpbuf, "\\bin\\x64\\R.dll");
	arch = "R_ARCH=/x64";
#else
	strcat(tmpbuf, "\\bin\\i386\\R.dll");
	arch = "R_ARCH=/i386";
#endif
	if (GetFileAttributes(tmpbuf) != -1) { /* muti-arch R, DLL found */
	    putenv(arch);
#ifdef RSERV_DEBUG
	    printf("Multi-architecture R found, setting %s\n", arch);
#endif
	} else
	    arch = 0;
    }
    if (!arch) {
	strcpy(tmpbuf, RHome);
	strcat(tmpbuf, "\\bin\\R.dll");
	if (GetFileAttributes(tmpbuf) == -1)
	    printf("WARNING: cannot find R DDL at %s\n         check your R installation or make sure PATH is set accordingly\n");
    }

/*
 * try R_USER then HOME then working directory
 */
    if (getenv("R_USER")) {
	strcpy(RUser, getenv("R_USER"));
    } else if (getenv("HOME")) {
	strcpy(RUser, getenv("HOME"));
    } else if (getenv("HOMEDIR")) {
	strcpy(RUser, getenv("HOMEDIR"));
	strcat(RUser, getenv("HOMEPATH"));
    } else
	GetCurrentDirectory(MAX_PATH, RUser);
    p = RUser + (strlen(RUser) - 1);
    if (*p == '/' || *p == '\\') *p = '\0';
    Rp->home = RUser;
    Rp->CharacterMode = LinkDLL;
    Rp->ReadConsole = myReadConsole;
    Rp->WriteConsole = myWriteConsole;
    Rp->CallBack = myCallBack;

#if R_VERSION < 0x2010
    Rp->message = myMessage;
    Rp->yesnocancel = myYesNoCancel;
    Rp->busy = myBusy;
#else
    Rp->ShowMessage = myMessage;
    Rp->YesNoCancel = myYesNoCancel;
    Rp->Busy = myBusy;
#endif

    Rp->R_Quiet = TRUE;
    Rp->R_Interactive = Rsrv_interactive;
    Rp->RestoreAction = SA_RESTORE;
    Rp->SaveAction = SA_NOSAVE;
#if R_VERSION < 0x2000
    Rp->CommandLineArgs = NULL;
    Rp->NumCommandLineArgs = 0;
#endif
    /* Rp->nsize = 300000;
       Rp->vsize = 6e6; */
    R_SetParams(Rp); /* so R_ShowMessage is set */
    R_SizeFromEnv(Rp);
    R_SetParams(Rp);

    FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));

    signal(SIGBREAK, my_onintr);
    setup_term_ui();
    setup_Rmainloop();

    return 0;
}

#endif

#else
#include <R.h>
#endif
