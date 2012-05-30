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

#include <sisocks.h>
#ifdef unix
#include <sys/un.h> /* needed for unix sockets */
#endif
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define default_max_pool 200
#define default_workers 20

static int active = 1, localonly = 1;

typedef struct worker {
#ifdef WIN32
	SOCKET s;
	HANDLE w_in, w_out; /* worker pipe I/O handles */
#else
	int s;
	int w_in, w_out; /* worker pipe I/O handles, in = pool->worker, out = pool<-worker */
#endif
	long io_in_packet;
	long s_in_packet;
} worker_t;

static char **RSargv;
static int RSargc;

static char **allowed_ips = 0;

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
		w->io_in_packet = -1;
		w->s_in_packet = -1;
		w->s = -1; /* all workers are unconnected first */

		pid = fork();
		if (pid == -1) {
			fprintf(stderr, "ERROR: cannot fork to exec\n");
			close(pfd_in[0]); close(pfd_in[1]);
			close(pfd_out[0]); close(pfd_out[1]);
			free(w);
			return 0;
		}
		if (pid == 0) { /* child -> exec */
			char buf[48];
			/* close pool's side of the pipes */
			close(pfd_in[1]);
			close(pfd_out[0]);
			/* add FD arguments for communication */
			snprintf(buf, sizeof(buf), "--RS-pipe-io=%d,%d", pfd_in[0], pfd_out[1]);
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

static void remove_worker(worker_t *w) {
	close(w->w_out);
	close(w->w_in);
	free(w);
}

static int workers = default_workers, max_pool = default_max_pool;
static worker_t **worker;
static server_t *srv;

static void connected(SOCKET s) {
	int i;
	worker_t *w = 0;
	for (i = 0; i < workers; i++) /* find any unconnected worker */
		if (worker[i] && worker[i]->s == -1) {
			w = worker[i];
			break;
		}
	if (!w) { /* no unconnected workers, need to spawn new one - find a slot for it*/
		for (i = 0; i < max_pool; i++)
			if (!worker[i]) {
				w = worker[i] = create_worker();
				if (i >= workers)
					workers = i + 1;
				break;
			}
		if (!w) { /* no slot */
			fprintf(stderr, "ERROR: too many connections\n");
			close(s);
			return;
		}
	}
	w->s = s;
	/* this should be unnecessary since the workes should be "fresh", but just in case ... */
	w->s_in_packet = -1;
	w->io_in_packet = -1;
}

static char server_io_buffer[65536];

/* pool server loop - the server part is the same as Rserve, but it also has to include the workers part */
static void RSpool_serverLoop() {
#ifdef unix
    struct timeval timv;
    int selRet = 0;
    fd_set readfds;
#endif
    
    while(active) { /* main serving loop */
		int i;
#ifdef unix
		int maxfd = 0;

		while (waitpid(-1, 0, WNOHANG) > 0);

		/* 500ms (used to be 10ms) - it shouldn't really matter since
		   it's ok for us to sleep -- the timeout will only influence
		   how often we collect terminated children and (maybe) how
		   quickly we react to shutdown */
		timv.tv_sec = 0; timv.tv_usec = 500000;
		FD_ZERO(&readfds);
		if (srv) {
			int ss = srv->ss;
			if (ss > maxfd)
				maxfd = ss;
			FD_SET(ss, &readfds);
		}
		
		for (i = 0; i < workers; i++)
			if (worker[i]) { /* register output from workers as well as their sockets */
				int fd = worker[i]->w_out;
				if (fd > maxfd)
					maxfd = fd;
				FD_SET(fd, &readfds);
				fd = worker[i]->s;
				if (fd > maxfd)
					maxfd = fd;
				if (fd != -1)
					FD_SET(fd, &readfds);
			}

		selRet = select(maxfd + 1, &readfds, 0, 0, &timv);

		if (selRet > 0) {
			/* for (i = 0; i < servers; i++) */
			{
				socklen_t al;
				/* server_t *srv = server[i]; */
				int ss = srv->ss;
				if (FD_ISSET(ss, &readfds)) {
#endif
					SOCKET s;
					SAIN sa;
#ifdef unix
					struct sockaddr_un su;
					if (srv->unix_socket) {
						
						al = sizeof(su);
						s = accept(ss, (SA*)&su, &al);
					} else
#endif
						s = accept(ss, (SA*)&sa, &al);

					if (s != -1) {
						if (localonly && !srv->unix_socket) {
							char **laddr = allowed_ips;
							int allowed = 0;
							if (!laddr) { 
								allowed_ips = (char**) malloc(sizeof(char*)*2);
								allowed_ips[0] = strdup("127.0.0.1");
								allowed_ips[1] = 0;
								laddr = allowed_ips;
							}
							
							while (*laddr)
								if (sa.sin_addr.s_addr == inet_addr(*(laddr++)))
									{ allowed = 1; break; };
							if (allowed) {
#ifdef RSERV_DEBUG
								printf("INFO: accepted connection for server %p, calling connected\n", (void*) srv);
#endif
								connected(s);
							} else
								closesocket(s);
						} else { /* ---> remote enabled */
#ifdef RSERV_DEBUG
							printf("INFO: accepted connection for server %p, calling connected\n", (void*) srv);
#endif
							connected(s);
						}
					}
#ifdef unix
				}
			} /* end loop over servers */

			for (i = 0; i < workers; i++) {
				worker_t *w = worker[i];
				int remove = 0;
				/* socket read */
				if (w && FD_ISSET(w->s, &readfds)) {
					remove = 1;
					if (w->s_in_packet <= 0) { /* new packet */
						struct phdr hdr;
						int n = recv(w->s, &hdr, sizeof(hdr), 0);
						if (n == sizeof(hdr)) {
							n = write(w->w_in, &hdr, sizeof(hdr));
							if (n == sizeof(hdr)) {
								long sz = hdr.len;
								if (hdr.res)
									sz |= ((long) hdr.res) << 32;
								remove = 0;
								w->s_in_packet = sz;
							}
						}
					} else { /* buffer IO */
						int to_go = (int) (w->s_in_packet > sizeof(server_io_buffer)) ? sizeof(server_io_buffer) : w->s_in_packet;
						int n = recv(w->s, server_io_buffer, to_go, 0);
						if (n > 0 && write(w->w_in, server_io_buffer, n) == n) {
							remove = 0;
							w->s_in_packet -= to_go;
						}
					}
				}
				/* fd read */
				if (w && FD_ISSET(w->w_out, &readfds)) {
					remove = 1;
					if (w->io_in_packet == -1) { /* first is the ID string */
						char ids[32];
						int n = read(w->w_out, ids, sizeof(ids));
						if (n == sizeof(ids)) {
							n = send(w->s, ids, sizeof(ids), 0);
							if (n == sizeof(ids)) {
								w->io_in_packet = 0; /* done with ID, back to messages */
								remove = 0;
							}
						}
					} else if (w->io_in_packet <= 0) { /* new packet */
						struct phdr hdr;
						int n = read(w->w_out, &hdr, sizeof(hdr));
						if (n == sizeof(hdr)) {
							n = send(w->s, &hdr, sizeof(hdr), 0);
							if (n == sizeof(hdr)) {
								long sz = hdr.len;
								if (hdr.res)
									sz |= ((long) hdr.res) << 32;
								remove = 0;
								w->io_in_packet = sz;
							}
						}
					} else { /* buffer IO */
						int to_go = (int) (w->io_in_packet > sizeof(server_io_buffer)) ? sizeof(server_io_buffer) : w->io_in_packet;
						int n = read(w->w_out, server_io_buffer, to_go);
						if (n > 0 && send(w->s, server_io_buffer, n, 0) == n) {
							remove = 0;
							w->io_in_packet -= to_go;
						}
					}
				}
				if (remove) {
					remove_worker(w);
					/* FIXME: we should only create if it was not a surplus worker - but we have not recorded that number */
					worker[i] = create_worker();
				}
			} /* loop over workers */
		} /* end if (selRet > 0) */
#endif
    } /* end while(active) */
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
	
	RSargv = (char**) calloc(argc - i + 3, sizeof(char*));
	RSargc = argc - i;
	{ /* Fill RSargv with startup + sentinel */
		int j;
		for (j = 0; j < RSargc; j++)
			RSargv[j] = strdup(argv[i + j]);
		RSargv[j] = 0;
	}

	srv = create_server(port, 0, 0, 0);
	if (!srv) return 0;

	if (max_pool < workers) max_pool = workers;
	
	worker = (worker_t**) calloc(max_pool, sizeof(worker_t));
	for (i = 0; i < workers; i++)
		worker[i] = create_worker();

	RSpool_serverLoop();
	
	return 0;
}

#ifdef RSERVE_PKG

#include <Rinternals.h>

SEXP RSpool_run(SEXP args) {
	int argc, i, n;
	char **argv;
	if (TYPEOF(args) != STRSXP) Rf_error("Start arguments must be a character vector.");
	argc = LENGTH(args) + 1;
	argv = (char**) calloc(argc, sizeof(char*));
	if (!argv) Rf_error("Cannot allocate memory for arguments");
	for (i = 1; i < argc; i++)
		argv[i] = strdup(CHAR(STRING_ELT(args, i - 1)));
	argv[0] = "RSpool";
	n = main(argc, argv);
	for (i = 1; i < argc; i++)
		free(argv[i]);
	free(argv);
	return ScalarLogical((n == 0) ? TRUE : FALSE);
}

#endif

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
