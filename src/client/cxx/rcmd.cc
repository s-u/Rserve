/*
 *  Small demo to illustrate the use of the C++ interface to Rserve
 *  Copyright (C) 2004 Simon Urbanek, All rights reserved.
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
 *
 *  $Id$
 */

#define MAIN         // we are the main program, we need to define this
#define SOCK_ERRORS  // we will use verbose socket errors

#include "sisocks.h"
#include "Rconnection.h"

char buf[1024];

int main(int ac, char **av) {
    initsocks(); // this is needed for Win32 - it does nothing on unix

    Rconnection *rc = 0;
    int port = -1, help = 0;
    const char *sock_name = 0;
    const char *host_name = 0;
    const char *pwd = 0;

    int i = 1;
    while (i < ac) {
      if (av[i][0] == '-') {
        switch (av[i][1]) {
        case 'h': help = 1; break;
        case 'p': if (++i < ac) port = atoi(av[i]); break;
        case 'P': if (++i < ac) pwd = av[i]; else pwd = getpass("password: "); break;
        case 's': if (++i < ac) sock_name = av[i]; break;
	case 'c': i++;
        }
      } else if (!host_name) host_name = av[i];
      i++;
    }
     
    if (help) {
      printf("\n Usage: %s [<host>] [-c <cmd>] [-p <port>] [-s <socket>] [-P <password>] [-h] <file1> [<file2> [...]]\n\n", av[0]);
      return 0;
    }
    if (host_name) {
      if (port > 1) rc = new Rconnection(host_name, port);
      else rc = new Rconnection(host_name);
    } else if (sock_name) {
      rc = new Rconnection(sock_name, -1);
    } else {
      rc = new Rconnection();
    }
    
    buf[1023]=0;

    i = rc->connect();
    if (i) {
      sockerrorchecks(buf, 1023, -1);
        printf("unable to connect (result=%d, socket:%s).\n", i, buf);
	return i;
    }
    
    i = 1;
    // source all files specified at the command line and print the output
    while (i < ac) {
      if (av[i][0] == '-') {
	switch(av[i][1]) { /* skip options that have extra argument */
	case 'c':
	  if (++i < ac) {
	    snprintf(buf, 1023, "try(paste(capture.output(%s),collapse='\\n'))", av[i]);
	    Rstring *str = (Rstring*) rc->eval(buf);
	    puts(str->string());
	    delete str;
	  }
	  break;	    
	case 'p':
	case 'P':
	case 's':
	  i++;
	}
      } else {
	snprintf(buf, 1023, "try(paste(capture.output(source(\"%s\")),collapse='\\n'))", av[i]);
	Rstring *str = (Rstring*) rc->eval(buf);
	puts(str->string());
	delete str;
      }
      i++;
    }

    // dispose of the connection object - this implicitly closes the connection
    delete rc;

    return 0;
}
