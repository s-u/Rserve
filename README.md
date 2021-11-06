# Rserve
## Fast, flexible and powerful server providing access to R from many languages and systems

[![CRAN](https://rforge.net/do/cransvg/Rserve)](https://cran.r-project.org/package=Rserve)
[![RForge](https://rforge.net/do/versvg/Rserve)](https://RForge.net/Rserve)
[![GitHub](https://github.com/s-u/PKI/actions/workflows/check.yml/badge.svg?event=push)](https://github.com/s-u/Rserve/actions)

To install the CRAN version, use simply

```
install.packages("Rserve")
```

For installation of the latest development version, use

```
install.packages("Rserve", repo="https://rforge.net")
```

Please see the [main Rserve website](https://rforge.net/Rserve/) for documentation, examples and details. Additional information is also available on the [Rserve Wiki](https://github.com/s-u/Rserve/wiki).

Rserve supports native QAP1 protocol, HTTP and WebSockets. All protocols are also available over TLS/SSL. A reverse proxy is also included for mapping HTTP/WebSockets traffic to local unix sockets for security (unix only).

For building REST APIs based on Rserve see [RestRserve](https://restrserve.org/), for web-scripting see [FastRWeb](https://rforge.net/FastRWeb/), for interactive applications see [RCloud](https://rcloud.social/) and [Rserve-js](https://github.com/att/rserve-js).

Note: Although it is possible to use Rserve on Windows, it is strongly discouraged (other than for toy/single-user applications), because the Windows operating system is severly limited and is not capable of using R in parallel (it lacks copy-on-write fork).
