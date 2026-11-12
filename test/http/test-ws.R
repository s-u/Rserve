## WebSocket handshakes: the HTTP upgrade (http.upgrade.websockets) and the
## stand-alone WebSocket server (websockets.port). Only the handshake is
## tested, not the protocols on top of it.
## Fixture: fixtures/ws.R, srv$port is HTTP, srv$port + 1 is the WebSocket server.

WSPORT <- srv$port + 1L
## the example from RFC 6455, 1.3
KEY    <- "dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT <- "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

## sends the parts (with pauses in between) to port, returns the response head
ws.req <- function(parts, port=srv$port) {
    con <- socketConnection(HOST, port, open="r+b", blocking=TRUE, timeout=5); on.exit(close(con))
    for (p in parts) { send(con, p); Sys.sleep(0.1) }
    read.resp(con, head.only=TRUE)
}
upgrade <- function(hdr, path="/ws") paste0("GET ", path, " HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n", paste0(hdr, "\r\n", collapse=""), "\r\n")
ws.healthy <- function() {
    expect(server.alive(), "server died")
    r <- ws.req(upgrade(c("Upgrade: websocket", paste("Sec-WebSocket-Key:", KEY), "Sec-WebSocket-Version: 13")), WSPORT)
    expect(isTRUE(r$status == 101), list("WebSocket server unhealthy", r))
}

test("upgrade: handshake", {
    r <- ws.req(upgrade(c("Upgrade: websocket", paste("Sec-WebSocket-Key:", KEY), "Sec-WebSocket-Version: 13")))
    expect(r$status == 101 && identical(r$headers[["sec-websocket-accept"]], ACCEPT), r) })
test("upgrade: Upgrade value is case-insensitive", {
    r <- ws.req(upgrade(c("Upgrade: WebSocket", paste("Sec-WebSocket-Key:", KEY), "Sec-WebSocket-Version: 13")))
    expect(r$status == 101 && identical(r$headers[["sec-websocket-accept"]], ACCEPT), r) })
test("upgrade: missing key -> 400", {
    r <- ws.req(upgrade(c("Upgrade: websocket", "Sec-WebSocket-Version: 13"))); expect(r$status == 400, r); healthy() })
test("upgrade: overlong key -> 400", {
    r <- ws.req(upgrade(c("Upgrade: websocket", paste("Sec-WebSocket-Key:", strrep("A", 2000))))); expect(r$status == 400, r); healthy() })
test("upgrade: plain requests still work", { r <- get("/x"); expect(st(r) == "200 http:/x", st(r)) })

test("ws: handshake", {
    r <- ws.req(upgrade(c("Upgrade: websocket", paste("Sec-WebSocket-Key:", KEY), "Sec-WebSocket-Version: 13")), WSPORT)
    expect(r$status == 101 && identical(r$headers[["sec-websocket-accept"]], ACCEPT), r) })
test("ws: handshake split across packets", {
    ## the second part is shorter than the first, so stale data from the
    ## first read must not be parsed again
    r <- ws.req(c(paste0("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Padding: ", strrep("p", 300), "\r\nSec-WebSocket-Ke"),
                  paste0("y: ", KEY, "\r\nSec-WebSocket-Version: 13\r\n\r\n")), WSPORT)
    expect(r$status == 101 && identical(r$headers[["sec-websocket-accept"]], ACCEPT), r) })
test("ws: header line split across packets", {
    r <- ws.req(c(paste0("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ", substr(KEY, 1, 10)),
                  paste0(substring(KEY, 11), "\r\nSec-WebSocket-Version: 13\r\n\r\n")), WSPORT)
    expect(r$status == 101 && identical(r$headers[["sec-websocket-accept"]], ACCEPT), r) })
test("ws: missing key -> 400", {
    r <- ws.req(upgrade(c("Upgrade: websocket", "Sec-WebSocket-Version: 13")), WSPORT); expect(r$status == 400, r); ws.healthy() })
test("ws: overlong key -> 400", {
    r <- ws.req(upgrade(c("Upgrade: websocket", paste("Sec-WebSocket-Key:", strrep("A", 130000)), "Sec-WebSocket-Version: 13")), WSPORT)
    expect(r$status == 400, r); ws.healthy() })
test("ws: hixie-76 key without spaces -> 400", {
    r <- ws.req(c(upgrade(c("Upgrade: WebSocket", "Origin: http://x", "Sec-WebSocket-Key1: 12345", "Sec-WebSocket-Key2: 1 2 3")), "abcdefgh"), WSPORT)
    expect(r$status == 400, r); ws.healthy() })
test("ws: hixie-76 handshake", {
    ## from draft-hixie-thewebsocketprotocol-76, 1.3
    r <- ws.req(c(upgrade(c("Upgrade: WebSocket", "Origin: http://example.com",
                            "Sec-WebSocket-Key1: 4 @1  46546xW%0l 1 5", "Sec-WebSocket-Key2: 12998 5 Y3 1  .P00"), path="/demo"),
                  "^n:ds[4U"), WSPORT)
    expect(r$status == 101, r) })
test("lifecycle: server still running", expect(server.alive(), server.log(20)))
