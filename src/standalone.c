#include <stdlib.h>

#ifdef STANDALONE_RSERVE

/* this is a bad hack for compatibility. Eventually we should have a defined layer */
#include "Rserv.c"

extern int Rf_initEmbeddedR(int, char**);

#include <R_ext/Rdynload.h>

/* R API from oc.c */
SEXP Rserve_oc_register(SEXP what, SEXP sName);
SEXP Rserve_oc_resolve(SEXP what);

static int ex(int res) {
	RSsrv_done();
	return res;
}

/* main function - start Rserve */
int main(int argc, char **argv)
{
    int stat, i, http_flags;
	char **top_argv;
	int    top_argc;

	main_argv = argv;
	main_argc = argc;

    rserve_rev[0] = 0;
    { /* cut out the SVN revision from the Id string */
		const char *c = strstr(rserve_ver_id, ".c ");
		if (c) {
			const char *d = c + 3;
			c = d; while (*c && *c != ' ') c++;
			strncpy(rserve_rev, d, c - d);
		}
    }

#ifdef RSERV_DEBUG
    printf("Rserve %d.%d-%d (%s) (C)Copyright 2002-2013 Simon Urbanek\n%s\n\n",RSRV_VER>>16,(RSRV_VER>>8)&255,RSRV_VER&255, rserve_rev, rserve_ver_id);
#endif
    if (!isByteSexOk()) {
		fprintf(stderr, "FATAL ERROR: This program was not correctly compiled - the endianess is wrong!\nUse -DSWAPEND when compiling on PPC or similar platforms.\n");
		return -100;
    }
    
    loadConfig(CONFIG_FILE);
    
    /** copy argv while removing Rserve specific parameters */
    top_argc = 1;
    top_argv = (char**) malloc(sizeof(char*) * (argc + 1));
    top_argv[0] = argv[0];
    i = 0;
    while (++i < argc) {
		int isRSP = 0;
		if (argv[i] && *argv[i] == '-' && argv[i][1] == '-') {
			if (!strcmp(argv[i] + 2, "RS-port")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing port specification for --RS-port.\n");
				else {
					port = satoi(argv[i]);
					if (port < 1) {
						fprintf(stderr,"Invalid port number in --RS-port, using default port.\n");
						port = default_Rsrv_port;
					}
				}
			}
			if (!strcmp(argv[i] + 2, "RS-dumplimit")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing limit specification for --RS-dumplimit.\n");
				else {
#ifdef RSERV_DEBUG
					dumpLimit = satoi(argv[i]);
#endif
				}
			}
			if (!strcmp(argv[i] + 2, "RS-socket")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing socket specification for --RS-socket.\n");
				else
					localSocketName = argv[i];
			}
			if (!strcmp(argv[i] + 2, "RS-encoding")) {
				isRSP = 1;
				if (++i == argc)
		    fprintf(stderr,"Missing socket specification for --RS-encoding.\n");
				else
					set_string_encoding(argv[i], 1);
			}
			if (!strcmp(argv[i] + 2, "RS-workdir")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing directory specification for --RS-workdir.\n");
				else
					workdir=argv[i];
			}
			if (!strcmp(argv[i] + 2, "RS-conf")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing config file specification for --RS-conf.\n");
				else
					loadConfig(argv[i]);
			}
			if (!strcmp(argv[i] + 2, "RS-source")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing R file specification for --RS-source.\n");
				else
					setConfig("source", argv[i]);
			}
			if (!strcmp(argv[i] + 2, "RS-pidfile")) {
				isRSP = 1;
				if (++i == argc)
					fprintf(stderr,"Missing file specification for --RS-pidfile.\n");
				else
					setConfig("pid.file", argv[i]);
			}
			if (!strcmp(argv[i] + 2, "RS-enable-control")) {
				isRSP = 1;
				setConfig("control", "enable");
			}
			if (!strcmp(argv[i] + 2, "RS-enable-remote")) {
				isRSP = 1;
				setConfig("remote", "enable");
			}
			if (!strcmp(argv[i] + 2, "RS-set")) {
				isRSP = 1;
                if (++i == argc)
					fprintf(stderr,"Missing argument for --RS-set.\n");
				else {
					char *c = argv[i], *c2 = strchr(c, '=');
					if (!c2) 
						c2 = "";
					else {
						*c2 = 0;
						c2++;
					}
					if (!setConfig(c, c2))
						fprintf(stderr, "WARNING: configuration directive '%s' is not supported (used in --RS-set)\n", c);
				}
			}
			if (!strcmp(argv[i] + 2, "RS-settings")) {
				printf("Rserve v%d.%d-%d\n\nconfig file: %s\nworking root: %s\nport: %d\nlocal socket: %s\nauthorization required: %s\nplain text password: %s\npasswords file: %s\nallow I/O: %s\nallow remote access: %s\ncontrol commands: %s\ninteractive: %s\nmax.input buffer size: %ld kB\n\n",
					   RSRV_VER>>16, (RSRV_VER>>8)&255, RSRV_VER&255,
					   CONFIG_FILE, workdir, port, localSocketName ? localSocketName : "[none, TCP/IP used]",
					   authReq ? "yes" : "no", usePlain ? "allowed" : "not allowed", pwdfile ? pwdfile : "[none]",
					   allowIO ? "yes" : "no", localonly ? "no" : "yes",
					   child_control ? "yes" : "no", Rsrv_interactive ? "yes" : "no", maxInBuf / 1024L);
				return 0;	       
			}
			if (!strcmp(argv[i] + 2, "version")) {
				printf("Rserve v%d.%d-%d (%s)\n",RSRV_VER>>16,(RSRV_VER>>8)&255,RSRV_VER&255,rserve_rev);
			}
			if (!strcmp(argv[i] + 2, "help")) {
				printf("Usage: R CMD Rserve [<options>]\n\nOptions: --help  this help screen\n --version  prints Rserve version (also passed to R)\n --RS-port <port>  listen on the specified TCP port\n --RS-socket <socket>  use specified local (unix) socket instead of TCP/IP.\n --RS-workdir <path>  use specified working directory root for connections.\n --RS-encoding <enc>  set default server string encoding to <enc>.\n --RS-conf <file>  load additional config file.\n --RS-settings  dumps current settings of the Rserve\n --RS-source <file>  source the specified file on startup.\n --RS-enable-control  enable control commands\n --RS-enable-remote  enable remote connections\n --RS-set <config>=<value>   set configuration option as if it was\n                              read from a configuration file\n\nAll other options are passed to the R engine.\n\n");
#ifdef RSERV_DEBUG
				printf("debugging flag:\n --RS-dumplimit <number>  sets limit of items/bytes to dump in debugging output. set to 0 for unlimited\n\n");
#endif
				return 0;
			}
		}
		if (!isRSP)
			top_argv[top_argc++]=argv[i];
    }
	
	performConfig(SU_NOW);
	
    stat = Rf_initEmbeddedR(top_argc,top_argv);
    if (stat < 0) {
		printf("Failed to initialize embedded R! (stat=%d)\n",stat);
		return 2;
    }
#ifndef WIN32
    /* windows uses this in init, unix doesn't so we set it here */
    R_Interactive = Rsrv_interactive;

	/* we let R install sig handlers, but remove those that are bad */
	signal(SIGSEGV, SIG_DFL);
	signal(SIGILL, SIG_DFL);
#ifdef SIGBUS
	signal(SIGBUS, SIG_DFL);
#endif
	/* FIXME: not sure about SIGPIPE - it's ok to use R's handling when
	   caused by R code, but it's unclear if it can be caused by
	   Rserve's internal code which would prefer death to surrender ... */
#endif

	/* registration must happen *before* source/eval */
	{ /* NOTE: R_registerRoutines *replaces* all existing registrations !!
		 So we have to register everything for all. */
		R_CallMethodDef mainCallMethods[]  = {
			{"Rserve_ctrlEval", (DL_FUNC) &Rserve_ctrlEval, 1},
			{"Rserve_ctrlSource", (DL_FUNC) &Rserve_ctrlSource, 1},
			{"Rserve_oobSend", (DL_FUNC) &Rserve_oobSend, 2},
			{"Rserve_oobMsg", (DL_FUNC) &Rserve_oobMsg, 2},
			{"Rserve_oc_register", (DL_FUNC) &Rserve_oc_register, 2},
			{"Rserve_oc_resolve", (DL_FUNC) &Rserve_oc_resolve, 1},
			{NULL, NULL, 0}
		};
		R_registerRoutines(R_getEmbeddingDllInfo(), 0, mainCallMethods, 0, 0);
	}
	
    if (src_list) { /* do any sourcing if necessary */
		struct source_entry *se=src_list;
#ifdef RSERV_DEBUG
		printf("Executing source/eval commands from the config file.\n");
#endif
		while (se) {
#ifdef RSERV_DEBUG
			printf("voidEval(\"%s\")\n", se->line);
#endif
			voidEval(se->line);
			se = se->next;
		}
#ifdef RSERV_DEBUG
		printf("Done with initial commands.\n");
#endif
    }
	
	performConfig(SU_SERVER);

#if defined RSERV_DEBUG || defined Win32
    printf("Rserve: Ok, ready to answer queries.\n");
#endif      
    
#if defined DAEMON && defined unix
	if (daemonize) {
		/* ok, we're in unix, so let's daemonize properly */
		if (fork() != 0) {
			puts("Rserv started in daemon mode.");
			exit(0);
		}
		setsid();
		if (chdir("/")) {} /* start in root which is guaranteed to exist */
	} else puts("Rserve started in non-daemon mode.");
#endif
	RSsrv_init();

#ifdef unix
    umask(umask_value);
#endif
    
	if (enable_qap && !create_Rserve_QAP1(global_srv_flags | (qap_oc ? SRV_QAP_OC : 0))) {
		fprintf(stderr, "ERROR: unable to start Rserve server\n");
		return ex(1);
	}

 	if (tls_port > 0 && !create_Rserve_QAP1(global_srv_flags | SRV_TLS | (qap_oc ? SRV_QAP_OC : 0))) {
		fprintf(stderr, "ERROR: unable to start Rserve TLS server\n");
		return ex(1);
	}

	http_flags = global_srv_flags;
	if (ws_upgrade) {
		http_flags = global_srv_flags | (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) | (ws_qap_oc ? SRV_QAP_OC : 0);
		if (http_flags & (WS_PROT_TEXT | WS_PROT_QAP))
			http_flags |= HTTP_WS_UPGRADE;
		else
			fprintf(stderr, "WARNING: http.upgrade.websockets is enabled but no WS sub-protocol is enabled, ignoring\n");
	}
	if (http_port > 0) {
		server_t *srv = create_HTTP_server(http_port, http_flags);
		if (!srv) {
			fprintf(stderr, "ERROR: unable to start Rserve HTTP server\n");
			return ex(1);
		}
		srv->fork = fork_http;
	}

	if (https_port > 0) {
		server_t *srv = create_HTTP_server(https_port, http_flags | SRV_TLS);
		if (!srv) {
			fprintf(stderr, "ERROR: unable to start Rserve HTTPS server\n");
			return ex(1);
		}
		srv->fork = fork_https;
	}

	if (enable_ws_text || enable_ws_qap) {
		if (ws_port < 1 && wss_port < 1) {
			if (!ws_upgrade)
				fprintf(stderr, "WARNING: Invalid or missing websockets port, WebSockets server will not start\n");
		} else {
			if (ws_port > 0) {
				server_t *srv = create_WS_server(ws_port, global_srv_flags | (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) | (ws_qap_oc ? SRV_QAP_OC : 0));
				if (srv) srv->fork = fork_ws;
			}
			if (wss_port > 0) {
				server_t *srv = create_WS_server(wss_port, global_srv_flags | (enable_ws_qap ? WS_PROT_QAP : 0) | (enable_ws_text ? WS_PROT_TEXT : 0) | (ws_qap_oc ? SRV_QAP_OC : 0) | WS_TLS);
				if (srv) srv->fork = fork_ws;
			}
		}
	}

	setup_signal_handlers();

    serverLoop();
#ifdef unix
    if (localSocketName)
		remove(localSocketName);
#endif
    
#ifdef RSERV_DEBUG
    printf("\nServer terminated normally.\n");
#endif

	restore_signal_handlers();

    return ex(0);
}

#endif

/*--- The following makes the indenting behavior of emacs compatible
      with Xcode's 4/4 setting ---*/
/* Local Variables: */
/* indent-tabs-mode: t */
/* tab-width: 4 */
/* c-basic-offset: 4 */
/* End: */
