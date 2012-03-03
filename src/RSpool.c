/*
 *  RSpool : pool manager for synchronous Rserve workes instances
 *  Part of the Rserve project.
 *  Copyright (C) 2002-12 Simon Urbanek
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "Rsrv.h"
#include "RSserver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define default_max_pool 200
#define default_workers 20

typedef struct worker {
#ifdef WIN32
	HANDLE w_in, w_out; /* worker pipe I/O handles */
#else
	int w_in, w_out; /* worker pipe I/O handles, in = pool->worker, out = pool<-worker */
#endif
} worker_t;

static const char **RSargv;
static int RSargc;

/* spawns a new worker and returns worker structure to be used in the communication
   Returns only on the pool side, worker side. */
static worker_t* create_worker() {
	worker_t *w = (worker_t*) calloc(1, sizeof(worker_t));
	if (!w) {
		fprintf(stderr, "ERROR: cannot allocate memory for a worker\n");
		return w;
	}

	{
#ifdef unix
		int pfd_in[2], pfd_out[2];
		pid_t pid;
		
		if (pipe(pfd_in) != 0) {
			fprintf(stderr, "ERROR: cannot create I/O pipe 1\n");
			free(w);
			return 0;
		}
		if (pipe(pfd_out) != 0) {
			fprintf(stderr, "ERROR: cannot create I/O pipe 2\n");
			close(pfd_in[0]);
			close(pfd_in[1]);
			free(w);
			return 0;
		}
		
		w->w_in  = pfd_in[1]; /* we write to w_in */
		w->w_out = pfd_out[0];/* we read from w_out */

		pid = fork();
		if (pid == -1) {
			fprintf(stderr, "ERROR: cannot fork to exec\n");
			close(pfd_in[0]); close(pfd_in[1]);
			close(pfd_out[0]); close(pfd_out[1]);
			free(w);
			return 0;
		}
		if (pid == 0) { /* child -> exec */
			char buf1[48];
			/* close pool's side of the pipes */
			close(pfd_in[1]);
			close(pfd_out[0]);
			/* add FD arguments for communication */
			snprintf(buf, "--RS-pipe-io=%d,%d", pfd_in[0], pfd_out[1]);
			RSargv[RSargc++] = buf;
			RSargv[RSargc] = 0;
			/* exec */
			execvp(RSargv[0], RSargv);
			/* should not return */
			fprintf(stderr, "ERROR: cannot exec %s\n", RSargv[0]);
			perror("exec error");
			exit(1);
		}
		/* successful fork */
#else
#endif
	}
	return w;
}

		static int workers = default_workers, max_pool = default_max_pool;
static worker_t **worker;
static server_t *srv;

/* new request - find or spawn a worker */
static void RSP_connected(void *par) {
	args_t *arg = (args_t*) par;
	
}

static void RSP_fin(void *par) {
	args_t *arg = (args_t*) par;
	
}

int main(int argc, char **argv) {
	int i = 0;
	int port = default_Rsrv_port;

	while (++i < argc)
		if (argv[i][0] == '-')
			switch (argv[i][1]) {
			case 'h': printf("\n Usage: %s [<options>] <Rserve startup>\n\n Options: -w <workers> - specifies the number of workers (default %d)\n          -p <port> - port to listen on (default %d)\n          -h - show this help\n\n Example: %s -w 30 R CMD Rserve --vanilla --no-save\n\n", argv[0], default_workers, default_Rsrv_port, argv[0]); return 0;
			case 'p': if (++i < argc) port = atoi(argv[i]); else { fprintf(stderr, "ERROR: missing port specification in -p <port>\n"); return 1; }; break;
			case 'w': if (++i < argc) workers = atoi(argv[i]); else { fprintf(stderr, "ERROR: missing workers specification in -w <workers>\n"); return 1; }; break;
			default:
				fprintf(stderr, "ERROR: unknown option %s\n", argv[i]);
				return 1;
			}
		else break;
	if (i >= argc) {
		fprintf(stderr, "ERROR: missing Rserve startup command. See %s -h for usage.\n", argv[0]);
		return 0;
	}
	
	RSargv = (const char**) calloc(argc - i + 3, sizeof(const char*));
	RSargc = argc - i;
	{ /* Fill RSargv with startup + sentinel */
		int j;
		for (j = 0; j < RSargc; j++)
			RSargv[j] = strdup(argv[i + j]);
		RSargv[j] = 0;
	}

	srv = create_server(port, 0, 0);
	if (!srv) return 0;
	srv->connected = RSP_connected;
	srv->fin = RSP_fin;

	if (max_pool < workers) max_pool = workers;
	
	worker = (worker_t**) calloc(max_pool, sizeof(worker_t));
	for (i = 0; i < workers; i++)
		worker[i] = create_worker();

	serverLoop();
	
	return 0;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
