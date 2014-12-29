#include "RSserver.h"
#include "rserr.h"

#define SOCK_ERRORS
#define LISTENQ 16

#include <sisocks.h>
#ifdef unix
#include <sys/un.h> /* needed for unix sockets */
#endif
#include <sys/types.h>
#include <sys/stat.h>

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

#ifdef unix
	struct sockaddr_un lusa;
#endif
    
#ifdef RSERV_DEBUG
	printf(" - create_server(port = %d, socket = %s, mode = %d, flags = 0x%x)\n", port, localSocketName ? localSocketName : "<NULL>", localSocketMode, flags);
#endif
	initsocks();
	if (localSocketName) {
#ifndef unix
		RSEprintf("ERROR: Local sockets are not supported on non-unix systems.\n");
		return 0;
#else
		ss = FCF("open socket", socket(AF_LOCAL, SOCK_STREAM, 0));
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
		ss = FCF("open socket", socket((flags & SRV_IPV6) ? AF_INET6 : AF_INET, SOCK_STREAM, 0));
#else
		ss = FCF("open socket", socket(AF_INET, SOCK_STREAM, 0));
#endif

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

#ifdef unix
	if (localSocketName) {
		FCF("bind", bind(ss, (SA*) &lusa, sizeof(lusa)));    
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
			FCF("bind", bind(ss, (struct sockaddr*) &ssa6, sizeof(ssa6)));
		} else {
#endif
			memset(&ssa, 0, sizeof(ssa));
			ssa.sin_family = AF_INET;
			ssa.sin_port = htons(port);
			ssa.sin_addr.s_addr = htonl((flags & SRV_LOCAL) ? INADDR_LOOPBACK : INADDR_ANY);
			FCF("bind", bind(ss, (struct sockaddr*) &ssa, sizeof(ssa)));
#ifdef HAVE_IPV6
		} /* if (flags & SRV_IPV6) else */
#endif
#ifdef unix
	} /* if (localSocketName) else */
#endif
    
	add_active_srv_socket(ss);

	FCF("listen", listen(ss, LISTENQ));

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

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
