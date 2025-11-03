# Technical design overview

Encriptón is a SOCKS proxy that performs a MITM attack on your IM application.
Once the proxy server (`Soxy`) has been instantiated (eg by running `main.py`),
any application can be configured to use it.

`Soxy` starts a threated SOCKS server and each client that tries to connect to
it is handled by the `handle_client` method. A SOCKS server provides a socket to
which clients (locally running apps) can connect and request a "gate" (a pair of
sockets) which they can use to communicate with a remote server:

```
                   ┌────────────┐
┌──────┐  step 1   │            │
│IM app├──────────►│SOCKS server│
└─────┬┘           │            │
   ▲  │            └──────┬─────┘
   │  │                   │
   │  │                   │step 2
   │  │                   │
   │  │                   ▼
   │  └─────────────► ┌───────┐ ─────────► ┌─────────────┐
   │     step 3       │sockets│            │remote server│
   └───────────────── └───────┘ ◄───────── └─────────────┘
```

After handshaking and parsing the requested target, two things take place:

1. If the request connection is encrypted, `Soxy` uses it's `CertManager` to
generate on the fly a valid SSL certificate that will be used to perform the
MITM attack. This certificate is valid because during the setup process
Encriptón installs a root certificate in your OS. That can be used as a CA to
generate trusted certificated that spoof any encrypted connection that your
device sends / receives.

2. A two-way `pipe` is created and added to the `PipeManager`. This is where the
actual magic happens!

After a pipe is up and running, the pipe manager listens for any available data,
either originating from the local app that should be sent to the remote server,
or coming form the remote server that should be delivered to the local app.

Pipes use small buffers to store the data that is being sent or received. These
buffers are passed to the parsers (`parsers.*`) which try to parse the content
and make sense of it; and to the transformers (`transformers.*`) which try to
encrypt / decrypt the content.