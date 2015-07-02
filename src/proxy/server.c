#include "rserr.h"
#include "server.h"

#define SOCK_ERRORS
#define LISTENQ 16

#ifndef WIN32
#include <sys/un.h> /* needed for unix sockets */
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* AF_LOCAL is the POSIX version of AF_UNIX - we need this e.g. for AIX */
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

/* keep track of all bound server sockets so they can be easily all closed after fork
   this is important for two reasons: so ports don't get stuck bound after the server
   has been shut down but children are still around, and so that a rogue child cannot
   impersonate the server after the server has been shut down (since the port may have
   been bound at higher privileges than the child may have at this point) */
#define MAX_SRVS 512
static int active_srv_sockets[MAX_SRVS];

static int active = 1;

static void add_active_srv_socket(int s) {
	int i = 0;
	while (active_srv_sockets[i] && i < MAX_SRVS) {
		if (active_srv_sockets[i] == s) return;
		i++;
	}
	if (i < MAX_SRVS)
		active_srv_sockets[i] = s;
}

static void rm_active_srv_socket(int s) {
	int i = 0;
	while (i < MAX_SRVS) {
		if (active_srv_sockets[i] == s) {
			active_srv_sockets[i] = 0;
			break;
		}
		i++;
	}
}

/* this is typically used after fork in the child process */
void close_all_srv_sockets() {
	int i = 0;
	while (i < MAX_SRVS) {
		if (active_srv_sockets[i]) closesocket(active_srv_sockets[i]);
		i++;
	}
}

/* provides client socket from accept() to the server so that it can
   modify the socket as needed according to the server flags */
void accepted_server(server_t *srv, int cs) {
#ifdef SO_KEEPALIVE
	/* if keep-alive is enabled and supported - try to set it */
	if (srv->flags & SRV_KEEPALIVE) {
		int ka = 1;
		setsockopt(cs, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
	}
#endif
}

server_t *create_server(int port, const char *localSocketName, int localSocketMode, int flags) {
	server_t *srv;
	SAIN ssa;
	int reuse, ss;
#ifdef HAVE_IPV6
	struct sockaddr_in6 ssa6;
#endif

#ifndef WIN32
	struct sockaddr_un lusa;
#endif
    
#ifdef RSERV_DEBUG
	printf(" - create_server(port = %d, socket = %s, mode = %d, flags = 0x%x)\n", port, localSocketName ? localSocketName : "<NULL>", localSocketMode, flags);
#endif

#ifdef WIN32
	{
		WSADATA dt;
		/* initialize WinSock 1.1 */
		WSAStartup(0x0101, &dt);
	}
#endif

	if (localSocketName) {
#ifdef WIN32
		RSEprintf("ERROR: Local sockets are not supported on non-unix systems.\n");
		return 0;
#else
		if ((ss = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
			RSEprintf("ERROR: cannot create local socket: %s\n", strerror(errno));
			return 0;
		}

		memset(&lusa, 0, sizeof(lusa));
		lusa.sun_family = AF_LOCAL;
		if (strlen(localSocketName) > sizeof(lusa.sun_path) - 2) {
			RSEprintf("ERROR: Local socket name is too long for this system.\n");
			return 0;
		}
		strcpy(lusa.sun_path, localSocketName);
		remove(localSocketName); /* remove existing if possible */
#endif
	} else
#ifdef HAVE_IPV6
		ss = socket((flags & SRV_IPV6) ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
#else
	    ss = socket(AF_INET, SOCK_STREAM, 0);
#endif

	if (ss == INVALID_SOCKET) {
		RSEprintf("ERROR: no available socket: %s\n", strerror(errno));
		return 0;
	}

	srv = (server_t*) calloc(1, sizeof(server_t));
	if (!srv) {
		RSEprintf("ERROR: cannot allocate memory for server structure\n");
		return 0;
	}

	srv->ss = ss;
	srv->unix_socket = localSocketName ? 1 : 0;
	srv->flags = flags;
	srv->parent = 0;

	reuse = 1; /* enable socket address reusage */
	setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

#ifndef WIN32
	if (localSocketName) {
		if (bind(ss, (SA*) &lusa, sizeof(lusa))) {
			RSEprintf("ERROR: unable to bind to %s: %s\n", lusa.sun_path, strerror(errno));
			return 0;
		}
		if (localSocketMode)
			chmod(localSocketName, localSocketMode);
	} else {
#endif
#ifdef HAVE_IPV6
		if (flags & SRV_IPV6) {
			memset(&ssa6, 0, sizeof(ssa6));
			ssa6.sin6_family = AF_INET6;
			ssa6.sin6_port = htons(port);
			ssa6.sin6_addr = (flags & SRV_LOCAL) ? in6addr_loopback : in6addr_any;
			if (bind(ss, (struct sockaddr*) &ssa6, sizeof(ssa6))) {
				RSEprintf("ERROR: unable to bind to IPv6 port %d: %s\n", port, strerror(errno));
				closesocket(ss);
				return 0;
			}
		} else {
#endif
			memset(&ssa, 0, sizeof(ssa));
			ssa.sin_family = AF_INET;
			ssa.sin_port = htons(port);
			ssa.sin_addr.s_addr = htonl((flags & SRV_LOCAL) ? INADDR_LOOPBACK : INADDR_ANY);
			if (bind(ss, (struct sockaddr*) &ssa, sizeof(ssa))) {
				RSEprintf("ERROR: unable to bind to IPv4 port %d: %s\n", port, strerror(errno));
				closesocket(ss);
				return 0;
			}
#ifdef HAVE_IPV6
		} /* if (flags & SRV_IPV6) else */
#endif
#ifndef WIN32
	} /* if (localSocketName) else */
#endif
    
	if (listen(ss, LISTENQ)) {
		RSEprintf("ERROR: listen failed: %s\n", strerror(errno));
		closesocket(ss);
		return 0;
	}

	add_active_srv_socket(ss);

	return srv;
}

void server_fin(void *x) {
	server_t *srv = (server_t*) x;
	if (srv) {
		closesocket(srv->ss);
		if (srv->ss != -1) rm_active_srv_socket(srv->ss);
	}
}

#define NSPS 16
struct server_stack {
	server_stack_t *prev, *next;
	int ns;
	server_t *srv[NSPS];
};

server_stack_t* create_server_stack() {
	server_stack_t *s = (server_stack_t*) malloc(sizeof(server_stack_t));
	s->prev = s->next = 0;
	s->ns = 0;
	return s;
}

void push_server(server_stack_t *s, server_t *srv) {
	while (s->ns >= NSPS && s->next) s = s->next;
	if (s->ns >= NSPS) {
		server_stack_t *ns = create_server_stack();
		ns->prev = s;
		s = s->next = ns;
	}
	s->srv[s->ns++] = srv;
}

void release_server_stack(server_stack_t *s) {
	while (s && s->next) s = s->next;
	while (s) {
		int i = s->ns;
		while (i-- > 0) {
			rm_server(s->srv[i]);
			free(s->srv[i]);
		}
		s->ns = 0;
		s = s->prev;
	}
}

int server_stack_size(server_stack_t *s) {
	int n = 0;
	while (s) {
		n += s->ns;
		s = s->next;
	}
	return n;
}

#define MAX_SERVERS 128
static int servers;
static server_t *server[MAX_SERVERS];

int add_server(server_t *srv) {
	if (!srv) return 0;
	if (servers >= MAX_SERVERS) {
		RSEprintf("ERROR: too many servers\n");
		return 0;
	}
	server[servers++] = srv;
#ifdef RSERV_DEBUG
	printf("INFO: adding server %p (total %d servers)\n", (void*) srv, servers);
#endif

	return 1;
}

int rm_server(server_t *srv) {
	int i = 0;
	if (!srv) return 0;
	while (i < servers) {
		if (server[i] == srv) {
			int j = i + 1;
			while (j < servers) { server[j - 1] = server[j]; j++; }
			servers--;
		} else i++;
	}
	if (srv->fin) srv->fin(srv);
#ifdef RSERV_DEBUG
	printf("INFO: removing server %p (total %d servers left)\n", (void*) srv, servers);
#endif
	return 1;
}

/* FIXME: those are copied from Rserve.c for now - clean it up ! */
static int UCIX = 1;
static int use_ipv6 = 0;
static int is_child = 0;
static char **allowed_ips;

struct args {
	server_t *srv; /* server that instantiated this connection */
    SOCKET s;
	SOCKET ss;
	int msg_id;
	void *res1, *res2;
	/* the following entries are not populated by Rserve but can be used by server implemetations */
	char *buf, *sbuf;
	int   ver, bp, bl, sp, sl, flags;
	long  l1, l2;
	/* The following fields are informational, populated by Rserve */
    SAIN sa;
    int ucix;
#ifndef WIN32
    struct sockaddr_un su;
#endif
};

int server_recv(args_t *arg, void *buf, size_t len) {
	return recv(arg->s, buf, len, 0);
}

int server_send(args_t *arg, const void *buf, size_t len) {
	return send(arg->s, buf, len, 0);
}

typedef void (*sig_fn_t)(int);

#ifndef WIN32

#include <signal.h>

/* NULL ptr is used on some systems as SIG_DFL so we have
   to define our own value for "not set" */
static void sig_not_set(int x) {}

#ifdef FORKED
static void sigHandler(int i) {
	active = 0;
}
#endif

sig_fn_t old_HUP = sig_not_set, old_TERM = sig_not_set, old_INT = sig_not_set;

static void setup_signal_handlers() {
#ifdef FORKED
	if (old_HUP == sig_not_set)  old_HUP  = signal(SIGHUP,  sigHandler);
	if (old_TERM == sig_not_set) old_TERM = signal(SIGTERM, sigHandler);
	if (old_INT == sig_not_set)  old_INT  = signal(SIGINT,  sigHandler);
#endif
}

static void restore_signal_handlers() {
	if (old_HUP != sig_not_set) {
		signal(SIGHUP, old_HUP);
		old_HUP = sig_not_set;
	}
	if (old_TERM != sig_not_set) {
		signal(SIGTERM, old_TERM);
		old_TERM = sig_not_set;
	}
	if (old_INT != sig_not_set) {
		signal(SIGINT, old_INT);
		old_INT = sig_not_set;
	}
}
#else
static void setup_signal_handlers() {
}
static void restore_signal_handlers() {
}
#endif

static int RS_fork(args_t *arg) {
#ifndef WIN32
	return (arg->srv && arg->srv->fork) ? arg->srv->fork(arg) : fork();
#else
	return -1;
#endif
}

void serverLoop() {
    struct timeval timv;
    int selRet = 0;
    fd_set readfds;

	setup_signal_handlers();

    while(active && servers) { /* main serving loop */
		int i;
		int maxfd = 0;
#ifdef FORKED
		while (waitpid(-1, 0, WNOHANG) > 0);
#endif
		/* 500ms (used to be 10ms) - it shouldn't really matter since
		   it's ok for us to sleep -- the timeout will only influence
		   how often we collect terminated children and (maybe) how
		   quickly we react to shutdown */
		timv.tv_sec = 0; timv.tv_usec = 500000;
		FD_ZERO(&readfds);
		for (i = 0; i < servers; i++)
			if (server[i])
				{
					int ss = server[i]->ss;
					if (ss > maxfd)
						maxfd = ss;
					FD_SET(ss, &readfds);
				}

		selRet = select(maxfd + 1, &readfds, 0, 0, &timv);

		if (selRet > 0) {
			for (i = 0; i < servers; i++) {
				socklen_t al;
				struct args *sa;
				server_t *srv = server[i];
				int ss = srv->ss;
				int succ = 0;
				if (server[i] && FD_ISSET(ss, &readfds)) {
					/* we may not know the size of args since servers may
					   choose to add fileds, so allocate 1k which is safe */
					sa = (struct args*)malloc(1024);
					memset(sa, 0, 1024);
					al = sizeof(sa->sa);
#ifndef WIN32
					if (server[i]->unix_socket) {
						al = sizeof(sa->su);
						sa->s = accept(ss, (SA*)&(sa->su), &al);
					} else
#endif
						sa->s = accept(ss, (SA*)&(sa->sa), &al);
					if (sa->s == INVALID_SOCKET) {
						RSEprintf("accept failed: %s", strerror(errno));
						continue;
					}

					accepted_server(srv, sa->s);
					sa->ucix = UCIX++;
					sa->ss = ss;
					sa->srv = srv;
					/*
					  memset(sa->sk,0,16);
					  sa->sfd=-1;
					  #if defined SESSIONS && defined FORKED
					  {
					  int pd[2];
					  if (!pipe(&pd)) {
					  
					  }
					  }
					  #endif
					*/
					if (allowed_ips && !srv->unix_socket && !use_ipv6) {
						/* FIXME: IPv6 unsafe - filtering won't work on IPv6 addresses */
						char **laddr = allowed_ips;
						int allowed = 0;
						while (*laddr)
							if (sa->sa.sin_addr.s_addr == inet_addr(*(laddr++)))
								{ allowed=1; break; }
						if (allowed) {
#ifdef RSERV_DEBUG
							printf("INFO: accepted connection for server %p, calling connected\n", (void*) srv);
#endif
							srv->connected(sa);
							succ = 1;
#ifdef FORKED
							/* when the child returns it means it's done (likely an error)
							   but it is forked, so the only right thing to do is to exit */
							if (is_child)
								exit(2);
#endif
						} else {
#ifdef RSERV_DEBUG
							printf("INFO: peer is not on allowed IP list, closing connection\n");
#endif
							closesocket(sa->s);
						}
					} else { /* ---> remote enabled */
#ifdef RSERV_DEBUG
						printf("INFO: accepted connection for server %p, calling connected\n", (void*) srv);
#endif
						srv->connected(sa);
						succ = 1;
						if (is_child) /* same as above */
							exit(2);
					}
					if (!succ) free(sa);
				} /* ready server */
			} /* severs loop */
		} /* select */
    } /* end while(active) */
}

#include <time.h>

static pid_t lastChild, parentPID;
static args_t *self_args;

int prepare_child(args_t *args) {
#ifdef FORKED  
	long rseed = random();

    rseed ^= time(0);

	if (is_child) return 0; /* this is a no-op if we are already a child
							   FIXME: thould this be an error ? */

    if ((lastChild = RS_fork(args)) != 0) { /* parent/master part */
		int forkErrno = errno; //grab errno close to source before it can be changed by other failures
		/* close the connection socket - the child has it already */
		closesocket(args->s);
		if (lastChild == -1)
			RSEprintf("WARNING: fork() failed in prepare_child(): %s\n",strerror(forkErrno));
		return lastChild;
    }

	/* child part */
	restore_signal_handlers(); /* the handlers handle server shutdown so not needed in the child */

#if 0
	if (main_argv && tag_argv && strlen(main_argv[0]) >= 8)
		strcpy(main_argv[0] + strlen(main_argv[0]) - 8, "/RsrvCHx");
#endif
	is_child = 1;

	srandom(rseed);
    
    parentPID = getppid();
    close_all_srv_sockets(); /* close all server sockets - this includes arg->ss */

#ifdef CAN_TCP_NODELAY
    {
     	int opt = 1;
        setsockopt(args->s, IPPROTO_TCP, TCP_NODELAY, (const char*) &opt, sizeof(opt));
    }
#endif

#endif

	self_args = args;

	return 0;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
