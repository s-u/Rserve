#include "RSserver.h"

#define SOCK_ERRORS
#define LISTENQ 16

#include <sisocks.h>
#ifdef unix
#include <sys/un.h> /* needed for unix sockets */
#endif
#include <sys/types.h>
#include <sys/stat.h>

server_t *create_server(int port, const char *localSocketName, int localSocketMode, int flags) {
	server_t *srv;
	SAIN ssa;
	int reuse, ss;
#ifdef HAVE_IPV6
	struct sockaddr_in6 ssa6;
#endif
	struct sockaddr_un lusa;
    
	initsocks();
	if (localSocketName) {
#ifndef unix
		fprintf(stderr,"Local sockets are not supported on non-unix systems.\n");
		return 0;
#else
		ss = FCF("open socket", socket(AF_LOCAL, SOCK_STREAM, 0));
		memset(&lusa, 0, sizeof(lusa));
		lusa.sun_family = AF_LOCAL;
		if (strlen(localSocketName) > sizeof(lusa.sun_path) - 2) {
			fprintf(stderr,"Local socket name is too long for this system.\n");
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
		fprintf(stderr, "ERROR: cannot allocate memory for server structure\n");
		return 0;
	}

	srv->ss = ss;
	srv->unix_socket = localSocketName ? 1 : 0;
	srv->flags = flags;

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
    
	FCF("listen", listen(ss, LISTENQ));

	return srv;
}

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
