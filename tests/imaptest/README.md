# imaptest

[Dovecot imaptest](https://github.com/dovecot/imaptest) in a container, to run IMAP compliance and stress
tests against a running `beavermaild`. Dovecot is installed in the image only for `libdovecot`; no Dovecot
service runs.

## Build

```sh
docker build -t beavermail-imaptest tests/imaptest
```

The image pins an imaptest commit that builds against the Dovecot 2.4 shipped by Arch; newer imaptest needs
Dovecot `main`.

## Prepare the server

- Use a development server and a throwaway account: the tests create, fill and delete mailboxes.
- Turn off `tls.required`, or `LOGIN` on the plain port answers `NO TLS required`.
- The plain IMAP listener defaults to `127.0.0.1:1143` (`imap.listen`).

## Compliance tests

`--network host` lets the container reach the server on `127.0.0.1`.

```sh
docker run --rm --network host beavermail-imaptest \
  host=127.0.0.1 port=1143 user=alice@example.com pass=secret test=src/tests
```

One script only: `test=src/tests/fetch-envelope`. Failures print the expected and the received response.
Some scripts cover extensions beavermaild does not advertise (ESEARCH, BINARY, CATENATE, URLAUTH, NOTIFY...);
their failures are expected.

## Stress test

Several clients run random commands in parallel and imaptest checks that flags, EXISTS and EXPUNGE stay
consistent across sessions. `mbox=` is the source of APPENDed messages; the image ships test mboxes.

```sh
docker run --rm --network host beavermail-imaptest \
  host=127.0.0.1 port=1143 user=alice@example.com pass=secret \
  mbox=src/tests/default.mbox clients=10 secs=60
```
