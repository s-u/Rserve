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

int main(int argc, char **argv) {
    initsocks(); // this is needed for Win32 - it does nothing on unix

    Rconnection *rc = new Rconnection();
    
    buf[1024]=0;

    int i=rc->connect();
    if (i) {
      sockerrorchecks(buf, 1023, -1);
        printf("unable to connect (result=%d, socket:%s).\n", i, buf);
	return i;
    }
    
    i=1;
    // source all files specified at the command line and print the output
    while (i<argc) {
      snprintf(buf, 1023, "try(paste(capture.output(source(\"%s\")),collapse='\\n'))", argv[i]);
      Rstring *str = (Rstring*) rc->eval(buf);
      puts(str->string());
      delete str;
      i++;
    }
    // dispose the connection object - this implicitly closes the connection
    delete rc;
}
