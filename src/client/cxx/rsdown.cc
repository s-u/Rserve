/*
 *  Small Rserve shutdown program
 *  Copyright (C) 2004-8 Simon Urbanek, All rights reserved.
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
 *  $Id: demo1.cc 203 2007-05-10 18:12:06Z urbanek $
 */

#define MAIN         // we are the main program, we need to define this
#define SOCK_ERRORS  // we will use verbose socket errors

#include "sisocks.h"
#include "Rconnection.h"

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
	}
      } else if (!host_name) host_name = av[i];
      i++;
    }
     
    if (help) {
      printf("\n Usage: %s [<host>] [-p <port>] [-s <socket>] [-P <password>] [-h] \n\n", av[0]);
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
    
    i = rc->connect();
    if (i) {
        char buf[1024];
	sockerrorchecks(buf, 1024, -1);
	fprintf(stderr, "ERROR: unable to connect (result=%d, socket:%s).\n", i, buf);
    } else
      rc->shutdown(pwd);
    delete rc;
    return 0;
}
