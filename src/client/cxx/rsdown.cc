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

int main(int argc, char **argv) {
    initsocks(); // this is needed for Win32 - it does nothing on unix

    Rconnection *rc = new Rconnection();
    
    int i=rc->connect();
    if (i) {
        char buf[1024];
	sockerrorchecks(buf, 1024, -1);
	fprintf(stderr, "ERROR: unable to connect (result=%d, socket:%s).\n", i, buf);
    } else
      rc->shutdown((argc > 1)?argv[1]:0);
    delete rc;
    return 0;
}
