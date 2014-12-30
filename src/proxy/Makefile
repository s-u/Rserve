## very basic makefile for testing
## for example, on OS X you might use
## make clean && make CC=clang 'CFLAGS=-Wall -Wno-deprecated-declarations -g' 'CPPFLAGS=-DFORKED -DRSERV_DEBUG' -j8

test: test.o http.o server.o tls.o websockets.o md5.o sha1.o base64.o date.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS) -lssl

websockets.o: websockets.c websockets.h server.h md5.h sha1.h tls.h qap.h base64.c

md5.c: ../md5.c
	ln -s $^ $@
md5.h: ../md5.h
	ln -s $^ $@
sha1.c: ../sha1.c
	ln -s $^ $@
sha1.h: ../sha1.h
	ln -s $^ $@
base64.c: ../base64.c
	ln -s $^ $@

clean:
	rm -f *.o test
