## http.raw.body: request bodies are never decoded.
## Fixture: fixtures/server.R --rawbody=1

test("rawbody: form-urlencoded body is passed raw", {
    r <- request("POST", "/echo", list("Content-Type"="application/x-www-form-urlencoded"), "a=1&b=x+y")
    expect(r$status == 200 && has(r$text, "class=raw") && has(r$text, "bodytxt=a=1&b=x+y") &&
           has(r$text, "ct=application/x-www-form-urlencoded"), r) })
test("rawbody: other bodies are unchanged", {
    r <- request("POST", "/echo", list("Content-Type"="text/plain"), "abc")
    expect(r$status == 200 && has(r$text, "class=raw") && has(r$text, "bodytxt=abc"), r) })
test("rawbody: query string is still parsed", {
    r <- get("/echo?a=x+y"); expect(has(r$text, "query=a=x y;"), r) })
