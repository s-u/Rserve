## very basic makefile for testing
## for example, on OS X you might use
## make clean && make CC=clang 'CFLAGS=-Wall -Wno-deprecated-declarations -g' 'CPPFLAGS=-DFORKED -DRSERV_DEBUG' -j8

all: forward

forward: forward.o http.o http_tools.o server.o tls.o websockets.o md5.o sha1.o base64.o date.o ulog.o chandler.o rscript.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

forward.o: forward.c http.h websockets.h server.h http_tools.h qap.h rserr.h ulog.h bsdcmpt.h chandler.h
websockets.o: websockets.c websockets.h server.h md5.h sha1.h tls.h qap.h base64.c

md5.c: ../md5.c
	ln -sfn $^ $@
md5.h: ../md5.h
	ln -sfn $^ $@
ulog.c: ../ulog.c
	ln -sfn $^ $@
ulog.h: ../ulog.h
	ln -sfn $^ $@
sha1.c: ../sha1.c
	ln -sfn $^ $@
sha1.h: ../sha1.h
	ln -sfn $^ $@
base64.c: ../base64.c
	ln -sfn $^ $@

distclean: clean
	rm -f md5.[ch] ulog.[ch] sha1.[ch] base64.c *~

clean:
	rm -f *.o forward
