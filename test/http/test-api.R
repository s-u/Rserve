## R API of the static handlers (no server, runs in the driver's session).

test("api: add.static returns the number of handlers", {
    Rserve.http.rm.all.statics()
    expect(identical(Rserve.http.add.static("/a/", tempdir()), 1L))
    expect(identical(Rserve.http.add.static("/b/", tempdir(), "index.html", last=TRUE), 2L)) })
test("api: rm.all.statics removes all handlers", {
    expect(isTRUE(Rserve.http.rm.all.statics()))
    expect(identical(Rserve.http.add.static("/a/", tempdir()), 1L))
    Rserve.http.rm.all.statics() })
test("api: invalid arguments", {
    expect.error(Rserve.http.add.static(c("/a/", "/b/"), tempdir()))
    expect.error(Rserve.http.add.static("/a/", 1))
    expect.error(Rserve.http.add.static("/a/", tempdir(), c("index.html", "x")))
    expect.error(Rserve.http.add.static("/a/", tempdir(), 1))
    Rserve.http.rm.all.statics() })
