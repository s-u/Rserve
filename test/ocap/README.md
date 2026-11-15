# Rserve OCAP idle tests

Tests for processing R's events while the OCAP loop is idle
(`ocap.idle.events`), the idle interval (`ocap.idle.interval`), and the idle
callback that follows it (`use.idle.callback`). Each test starts the
stand-alone Rserve binary of the installed package in OCAP mode with a
configuration of its own and talks to it with RSclient. They are not run by
`R CMD check`.

As with `test/http`, the suite tests the **installed** package, so build and
install the version you want to test first:

```sh
Rscript test/ocap/run.R [--lib=<library>] [pattern]
```

The tests need the RSclient package. The event tests also need tcltk: a Tcl
timer is the probe, because it advances only while R processes its events.
The `later` tests need later. Tests that cannot run are skipped.

| Test | Checks |
|---|---|
| idle events are off by default | a 50 ms Tcl timer does not advance while the server is idle |
| ocap.idle.events processes events while idle | it advances about once per 200 ms idle interval |
| ocap.idle.interval sets the granularity | with 20 ms, the timer itself is the limit |
| events are processed while waiting for an OOB reply | the timer advances while the client takes 1.5 s to answer `self.oobMessage()` |
| an error in an event handler does not affect the server | a Tcl callback that calls `stop()` |
| later callbacks run while idle / do not run with idle events off | `later::later(f, 0.2)` |
| use.idle.callback follows ocap.idle.interval | `.ocap.idle()` is called about every 50 ms with an interval of 50 |
