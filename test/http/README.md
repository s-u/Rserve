# Rserve HTTP test suite

Black-box tests for the HTTP/HTTPS server of Rserve (and the WebSocket
handshakes). Most suites start a real server in a separate R process
(`run.Rserve()`) and talk to it over raw sockets, so the tests need
permission to bind local TCP ports. They are not run by `R CMD check`.

The suite tests the **installed** package. It does not build or install
anything, so build and install the version you want to test first. Rserve
must be built with `mkdist` (not plain `R CMD build`), e.g.

```sh
cd Rserve
sh mkdist                                    # creates ../Rserve_<version>.tar.gz
R CMD INSTALL -l mylib ../Rserve_*.tar.gz
```

The tarball does not contain `test/` (`mkdist` removes it), so the tests are
always run from the source tree.

## Running

```sh
Rscript test/http/run.R [options] [pattern]
```

With no arguments all suites are run (about 1-2 minutes). The exit status is
non-zero if any test failed, and the failed tests are listed at the end.

| Option | Default | Description |
|---|---|---|
| `--suites=<list>` | `api,http,rawbody,tls,tlsclient,ws,simple` | suites to run (comma-separated) |
| `--lib=<path>` | | load Rserve from this library (in the driver and in the servers) |
| `--slow` | off | include slow tests (currently none) |
| `pattern` | | only run tests whose name, including the `[suite] ` prefix, matches this regular expression |

Examples:

```sh
# everything, testing the package installed in ./mylib
Rscript test/http/run.R --lib=mylib

# only the range tests
Rscript test/http/run.R --suites=http '^\[http\] range:'
```

## Suites

| Suite | Files | Fixture | Description |
|---|---|---|---|
| `api` | `test-api.R` | none | `Rserve.http.add.static()` and friends, no network |
| `http` | `test-http.R`, `test-conc.R` | `fixtures/server.R` | static files (incl. ranges and conditional GET), the R handler `.http.request()`, HTTP protocol, malformed requests, concurrency |
| `rawbody` | `test-rawbody.R` | `fixtures/server.R --rawbody=1` | `http.raw.body` |
| `tls` | `test-tls.R` | `fixtures/tls.R` | HTTPS next to HTTP, the server chain is completed from `tls.ca` |
| `tlsclient` | `test-tls.R` | `fixtures/tls.R --client=...` | as `tls`, but with a certificate chain file and client certificates (`tls.client=match:...`) |
| `ws` | `test-ws.R` | `fixtures/ws.R` | WebSocket handshakes: HTTP upgrade and the stand-alone WebSocket server |
| `simple` | `test-simple.R` | the Rserve binary | `R CMD Rserve --RS-simple-http-only <dir>` |

On unix Rserve forks a child process per connection, on Windows it serves
one connection at a time, so the tests that need concurrent connections
are skipped there, as are the `ws` and `simple` suites.

The `tls` suites use the `openssl` command line tool as the client (the
`OPENSSL` environment variable can point to it, otherwise it is looked up on
the `PATH`, on Windows Rtools has one in `usr/bin`), they are skipped if it is
not found. The certificates and keys are in `test/tls/` (shared with other
test suites), `make-certs.sh` there re-creates them.

Tests of features Rserve does not implement on purpose (e.g. `Connection:`
token lists or closing the connection on request of the R handler) are
skipped with the reason "not implemented in Rserve".

## Writing tests

`helpers.R` provides the infrastructure shared by all test files (it is
derived from the test suite of the webserver package):

- `test(name, expr, skip=NULL, restart=TRUE)` - runs `expr` as the body of a
  function (so `on.exit()` works and variables are local). `skip` is the
  reason why the test cannot run in the current configuration. If the server
  dies during a test, the test fails and a fresh server is started for the
  following tests.
- `expect(cond, info)`, `expect.in(x, set)`, `expect.error(expr)`, `healthy()`
- HTTP client: `get(path, headers=, ...)`, `request(method, path, headers, body, ...)`,
  `rawreq(string)`, `conn()`, `send(con, x)`, `read.resp(con)`, `closed(con)`.
- `srv` is the current server (`port`, `pid`, `log`, ...), `DOCROOT` the
  directory with the static files.

Fixtures are plain R scripts that take `--name=value` arguments (`--port`,
`--docroot`, `--lib` and fixture-specific ones) and print `PID <pid>` as their
first line.
