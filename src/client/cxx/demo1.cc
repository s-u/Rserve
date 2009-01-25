/*
 *  Small demo to illustrate the use of the C++ interface to Rserve
 *  Copyright (C) 2004 Simon Urbanek, All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; version 2.1 of the License
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Leser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  $Id$
 */

#include <iostream>
using std::cout;

#define MAIN         // we are the main program, we need to define this
#define SOCK_ERRORS  // we will use verbose socket errors

#include "sisocks.h"
#include "Rconnection.h"

// this is just a very silly example to show how the C++ API works ...

int main(int argc, char **argv) {
    initsocks(); // this is needed for Win32 - it does nothing on unix

    Rconnection *rc = new Rconnection();
    
    int i=rc->connect();
    if (i) {
        char msg[128];
        sockerrorchecks(msg, 128, -1);
        printf("unable to connect (result=%d, socket:%s).\n", i, msg); return i;
    }
   
    double d[6] = { 1.5, 2.4, 5.6, -1.2, 0.6, 1.7 };
    
    // assign the above contents to the variable "a" in R
    Rdouble *rd = new Rdouble(d, 6);
    rc->assign("a", rd);
    delete rd;

    // create a 2 x 3 matrix named "b" and calculate b * t(b) matrix product
    Rdouble *x = (Rdouble*) rc->eval("b<-matrix(a,2); b%*%t(b)");
    
    if (x) { // if everything was fine, we have the result
        cout << x << "\n";
        
        // just for fun - let's get the matrix dimensionality
        Rinteger *dim = (Rinteger*) x->attribute("dim");
        if (dim)
            cout << dim->intAt(0) << " by " << dim->intAt(1) << " matrix\n";
        
        // and print the contents of the matrix (unformatted)
        double *d = x->doubleArray();
        int i=0, ct = x->length();
        while (i < ct) { cout << d[i++] << " "; }
        cout << "\n";
        
        // finally dispose of the object
        delete x;
    }

    // integer constant assignment test
    int ia[6] = { 1, 4, 6, 3, 5 , 2 };
    Rinteger *ri = new Rinteger(ia, 6);
    rc->assign("i", ri);
    delete ri;

    // let's get the whole iris data
    Rvector *iris = (Rvector*) rc->eval("data(iris); iris");
    if (!iris) { cout << "oops! couldn't get iris data\n"; delete rc; return 0; }

    // now let's just get the sepal width - this a cheap operation, no talking to Rserve, because we have all the data already
    Rdouble *sw = (Rdouble*) iris->byName("Sepal.Width");
    double *swd = sw->doubleArray();
    
    // and print it ...
    { int i=0, ct=sw->length(); while (i<ct) { cout << swd[i++] << " "; }; cout << "\n"; }
    
    /* One important note about memory management: All necessary
       memory is allocated by the Rmessage that was implicitly created
       by "eval". The owner of that message is the main Rexp, that is
       the one returned by "eval". You must never release any other
       Rexp [inside the eval reault] than the main one! In addition,
       any associated Rexp become invalid once you release the main
       Rexp. Currently there is no deep copy method for Rexp, so you
       should copy the content in native format if you need it beyond
       the life of the Rexp. Note that also all pointers such as thos
       returned by doubleArray() method are invalid as soon as the
       main Rexp is released.

       The bottom line: you should release only the iris object, you
       may not try to delete the sw object. If you add debug info in
       the destructor, you'll notice that sw gets released
       automatically. */

    delete iris;
    
    // dispose the connection object - this implicitly closes the connection
    delete rc;
}
