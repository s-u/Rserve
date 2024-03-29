#ifndef RS_SERVER_H__
#define RS_SERVER_H__

/* this is a voluntary standart flag to request TLS support */
#define SRV_TLS       0x0800

/* these flags are global and respected by the default socket server */
#define SRV_IPV6      0x1000 /* use IPv6 */
#define SRV_LOCAL     0x4000 /* bind to local loopback interface only */
#define SRV_KEEPALIVE 0x8000 /* enable keep-alive - note that this is really
							    a client option sice inheritance is not
								guaranteed */

#include <unistd.h>
#include <stddef.h>

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#define sockerrno errno

#define SOCKET int
#define INVALID_SOCKET (-1)
#define closesocket(A) close(A)

#else
#define windows
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#define inet_aton(A,B) (0, B.s_addr=inet_addr(A))

#define sockerrno WSAGetLastError()
#endif

#define SA struct sockaddr
#define SAIN struct sockaddr_in

typedef struct args args_t;

typedef void    (*work_fn_t)(void *par);
typedef int     (*send_fn_t)(args_t *arg, int rsp, size_t len, const void *buf);
typedef ssize_t (*buf_fn_t) (args_t *arg, void *buf, size_t len);
typedef ssize_t (*cbuf_fn_t)(args_t *arg, const void *buf, size_t len);
typedef int     (*fork_fn_t)(args_t *arg);

/* definition of a server */
typedef struct server {
	int ss;               /* server socket */
	int unix_socket;      /* 0 = TCP/IP, 1 = unix socket */
	int flags;            /* optional server-specific flags */
	work_fn_t connected;  /* function called for each new connection */
	work_fn_t fin;        /* optional finalization function */
	send_fn_t send_resp;  /* send response */
	cbuf_fn_t send;       /* direct send */
	buf_fn_t  recv;       /* direct receive */
    fork_fn_t fork;       /* fork */
	struct server *parent;/* parent server - used only by multi-layer servers */
	void   *aux;
} server_t;

/* this flag can be passed to create_server for an IP socket to modify the behavior */
#define LSM_IP_LOCAL 1 /* bind to loopback address only */
#define LSM_IPV6     2 /* use IPv6 (if available) */

server_t *create_server(int port, const char *localSocketName, int localSocketMode, int flags);
void accepted_server(server_t *srv, int cs); /* performs additional tasks on client socket (eg SO_KEEPALIVE) */
int add_server(server_t *srv);
int rm_server(server_t *srv);

/* server stacks */
typedef struct server_stack server_stack_t;
server_stack_t* create_server_stack(void);
void push_server(server_stack_t *s, server_t *srv);
int server_stack_size(server_stack_t *s);
void release_server_stack(server_stack_t *s);

/* some generic implementations */
void server_fin(void *x);
ssize_t server_recv(args_t *arg, void *buf, size_t len);
ssize_t server_send(args_t *arg, const void *buf, size_t len);

void stop_server_loop(void);
void serverLoop(void);

/* helper function that prepares the process just like Rserve
   internal impleemntation - forking when desired, establishing
   pipes, setting see, uid/gid, cwd etc.
   returns 0 for the child */
int prepare_child(args_t *arg);

/* this one is called by the former to close all server sockets in the child */
void close_all_srv_sockets(void);

#endif

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
