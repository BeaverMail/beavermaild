# Changelog

## Unreleased

- Paid plugins: new SDK package `plugin/license` verifies Ed25519-signed license files offline.
  The host passes the licenses directory (`<config dir>/licenses`) and the installation id to
  every plugin. `beaver init` creates the installation id in `<data_dir>/install-id`.
  `beaver plugins list` prints the installation id and each plugin's license status.
- `beaver-license` (in the SDK, built with `make beaver-license`, not packaged) creates a vendor
  signing key and issues license files; any plugin vendor can use it with its own key.

## 0.4.0

- IMAP BODYSTRUCTURE of a multipart includes the `BOUNDARY` parameter, as RFC 3501 7.4.2 asks for
  the full MIME parameter list.
- IMAP BINARY of a quoted-printable part with stray control bytes returns the whole part with those
  bytes kept (RFC 2045 6.7); it used to stop at the first such byte.
- IMAP ENVELOPE address lists (also inside BODYSTRUCTURE of message/rfc822 parts) are written
  back to back, without a space between addresses, as the RFC 3501 grammar requires.
- Login with an unknown or malformed user name now fails like a wrong password (IMAP `NO`,
  SMTP `535`) and counts toward the attempt limit; IMAP and SMTP used to drop the connection,
  which also told existing users apart from unknown ones.
- IMAP BODYSTRUCTURE carries the extension data of every part (RFC 3501 7.4.2): MD5,
  Content-Disposition with its parameters (attachment file names), language and location. An
  unknown transfer encoding is reported as it is instead of `7BIT`.
- IMAP URLAUTH (RFC 4467) and URLAUTH=BINARY (RFC 5524): `GENURLAUTH` signs message URLs with a
  per-mailbox key (mechanism INTERNAL, HMAC-SHA256), `URLFETCH` returns the data of valid URLs
  (with `BODY`, `BINARY`, `BODYPARTSTRUCTURE` items; with BINARY the structure describes the
  decoded part) and NIL otherwise, `RESETKEY` revokes keys.
  Access `authuser`, `anonymous` and `user+name` are honoured, `submit+` is refused. SELECT and
  EXAMINE send `OK [URLMECH INTERNAL]`.
- IMAP CATENATE (RFC 4469): `APPEND ... CATENATE (TEXT {n} URL "...")` builds a message from
  literals and parts of the user's messages (RFC 5092 URLs); an invalid URL answers
  `NO [BADURL ...]`, also within MULTIAPPEND.
- IMAP CONTEXT=SEARCH and CONTEXT=SORT (RFC 5267): `RETURN (PARTIAL lo:hi)`, and `RETURN (UPDATE)`
  keeps the result current with `ESEARCH ADDTO`/`REMOVEFROM` until `CANCELUPDATE` or another
  SELECT; at most 8 updating contexts per session, more get `NO [NOUPDATE]`.
- IMAP UIDBATCHES (draft-ietf-mailmaint-imap-uidbatches): `UIDBATCHES size [first:last]` splits
  the selected mailbox into UID ranges, newest first; sizes under 500 answer `NO [TOOFEW]`.
- IMAP APPEND: a refused synchronizing literal (too large, or after an invalid part) ends the
  command with a tagged NO instead of closing the connection.
- IMAP NOTIFY (RFC 5465): `NOTIFY SET [STATUS]` / `NOTIFY NONE` with the SELECTED,
  SELECTED-DELAYED, PERSONAL, INBOXES, SUBSCRIBED, SUBTREE and MAILBOXES filters and the
  MessageNew (with FETCH items), MessageExpunge, FlagChange, MailboxName and SubscriptionChange
  events, pushed between commands and during IDLE; other events answer `NO [BADEVENT ...]`.
- IMAP BINARY (RFC 3516): `FETCH BINARY[part]`, `BINARY.PEEK[part]` (also partial) and
  `BINARY.SIZE[part]` return the part decoded from base64 or quoted-printable, as a literal8 when
  it holds NUL; an undecodable encoding answers `NO [UNKNOWN-CTE]`. `APPEND` takes literal8 (`~{n}`); parts
  holding NUL are stored base64-encoded, so `BODY[...]` stays a valid literal and `BINARY[...]`
  still returns the original bytes.
- IMAP MULTIAPPEND (RFC 3502): one `APPEND` stores several messages, all or none, with one
  `APPENDUID` set. The size cap applies to the messages of a command together.
- IMAP CONDSTORE is on only after a CONDSTORE enabling command (RFC 7162 3.1: `ENABLE`,
  `SELECT ... (CONDSTORE)`, `FETCH`/`SEARCH` with `MODSEQ`, `CHANGEDSINCE`, `UNCHANGEDSINCE`,
  `STATUS (HIGHESTMODSEQ)`), not from login: until then no `MODSEQ` in FETCH and no
  `HIGHESTMODSEQ` on SELECT. The first such command with a mailbox selected sends
  `* OK [HIGHESTMODSEQ n]`.
- IMAP ESEARCH (RFC 4731) and ESORT (RFC 5267): `SEARCH`/`SORT RETURN (MIN MAX ALL COUNT)` answer
  `* ESEARCH (TAG ...)`, with `MODSEQ` when the program uses it.
- IMAP `SORT=DISPLAY` (RFC 5957: `DISPLAYFROM`, `DISPLAYTO`) and `THREAD=ORDEREDSUBJECT` (RFC 5256).
- IMAP `ID` (RFC 2971) in every state. Command lines may be up to 64 KiB (was 8 KiB),
  and a longer one closes the connection once past the limit instead of being read whole first.
- IMAP oversized literals (RFC 7888 4): a synchronizing `APPEND` over the size limit gets
  `NO [TOOBIG]` before upload; a non-synchronizing one (`APPEND` or a search literal) gets
  `* BYE [TOOBIG]` and the connection closes, instead of its bytes being read as commands.
- IMAP `SELECT`/`EXAMINE` close the selected mailbox first, even when they fail, and say so with
  `* OK [CLOSED]` (RFC 7162, required with CONDSTORE advertised); a failed `SELECT` left the previous
  mailbox selected.
- IMAP QRESYNC (RFC 7162): `ENABLE QRESYNC`, `SELECT`/`EXAMINE ... (QRESYNC (uidvalidity modseq
  [known-uids]))` answers `VANISHED (EARLIER)` and the messages changed since, `UID FETCH ...
  (CHANGEDSINCE n VANISHED)`, and `VANISHED` instead of `EXPUNGE` once enabled. Without an expunge
  history, `VANISHED (EARLIER)` lists every missing UID of the known range below `UIDNEXT`, as the
  RFC allows.
- IMAP flag-change `FETCH` responses (from `STORE`, an implicit `\Seen` or another session) carry
  `UID` and `MODSEQ` once CONDSTORE is enabled (RFC 7162 3.2.4); reselecting a mailbox keeps
  announcing in `FLAGS` the keywords the session has already seen there. `PERMANENTFLAGS` lists
  those keywords as well as `\*`.
- IMAP `STORE` updates all the messages of a range in one storage transaction (per 256) instead of
  one per message, so under load it waits for the account write lock once.
- IMAP: claiming the `\Recent` of new messages no longer queues on the account write lock; the
  storage CAS picks the one session that gets it. Every session seeing a new message queued for the
  lock though only the first could claim it, which slowed every command that syncs (LIST, STATUS...).
- MySQL: `interpolateParams=true` is added to the DSN unless set (one round trip per query instead of
  prepare, execute and close), and the pool keeps up to 25 idle connections instead of 5, so busy
  periods no longer reopen connections.
- `BEAVER_PPROF=127.0.0.1:6060` serves Go's profiler (CPU, block, mutex, goroutines) on a loopback
  address while `serve` runs; off by default. Write locks held over 250 ms or waited on past their
  timeout are logged at WARN.
- IMAP `EXPUNGE`/`CLOSE` delete all the `\Deleted` messages in one storage transaction (per 256
  messages) instead of one per message, so under load they wait for the account write lock once.
- Mail storage: deleting a message no longer scans every message on the server to decide whether its
  blob file is still used (17 ms per deleted message at 10k messages, growing with the whole server).
  A background GC removes unreferenced blob files once an hour, after a one-hour grace period, so
  disk space comes back with that delay. It also removes the files of sent queue entries and failed
  APPENDs, which were never deleted, and it cannot race an APPEND of the same content.
- Mail storage: writes of one account run one at a time inside the process, so a large transaction
  (APPEND touches the mailbox, the email counter and the quota) no longer loses every retry to smaller
  ones under load and fails with "too much write contention". The optimistic CAS check still guards
  writers in other processes.
- IMAP: a command that still fails on write contention answers `NO [INUSE] Mailbox busy, try again`
  (RFC 5530) and the session goes on; the connection was dropped.
- IMAP logs: a session dropped by a server-side error is logged at WARN as `imap command failed` with the
  command name, account, selected mailbox and client address (never the arguments); a client that
  disconnects stays at DEBUG. Both were a bare DEBUG `imap session` line.
- IMAP: listing a mailbox while another session expunges from it skips the deleted messages; it
  failed with "not found" and dropped the connection (thousands of times in the imaptest stress test).
  `COPY`/`MOVE` of a message expunged by another session answer `NO` instead of disconnecting.
- IMAP `\Recent` under concurrency: a session reports `\Recent` only for messages it took, after
  loading them, so a message arriving between the two steps is no longer `\Recent` in two sessions
  (found by the imaptest stress test). Taking `\Recent` no longer bumps `MODSEQ`.
- IMAP `CREATE` no longer subscribes the new folder (RFC 3501; clients such as Thunderbird subscribe
  themselves). Existing folders and folders created by plugins stay subscribed. An explicit subscription
  outlives `DELETE`: `LIST (SUBSCRIBED)` returns it as `\NonExistent`, `LSUB` as `\Noselect`, `CREATE`
  of the same name takes it back and `UNSUBSCRIBE` drops it.
- IMAP `COPY`/`MOVE` set `\Recent` on the new messages (RFC 3501); it was cleared.
- IMAP `EXPUNGE`/`CLOSE` act on the stored flags, so `\Deleted` set by another session counts, and only
  delete a message still in the mailbox and still `\Deleted`: a message moved away meanwhile was
  deleted from its new folder, and one already expunged dropped the connection.
- IMAP: changes reported to a session always come from a full reload; flag changes made together with
  new or expunged messages were lost.
- IMAP: every command except `FETCH`, `STORE`, `SEARCH`, `SORT` and `THREAD` reports changes made by other
  sessions to the selected mailbox (`EXISTS`, `EXPUNGE`, `FETCH FLAGS`, `RECENT`) before its tagged reply,
  as RFC 3501 requires; only `IDLE` did, so `NOOP`/`CHECK` showed a stale mailbox. A new message is
  `\Recent` only for the first `SELECT` session that sees it (an `APPEND` into the selected mailbox
  included), so `STATUS` no longer counts it as recent.
- IMAP: `STORE` on a message expunged by another session skips it and `FETCH` of its body answers `NO`
  (RFC 2180); both dropped the connection.
- IMAP ENVELOPE puts an obsolete source route (`<@route:user@domain>`) in the route slot; the address
  came out empty.
- IMAP: a mailbox deleted and created again gets a new `UIDVALIDITY`; it was always 1, and the reused
  mailbox id restarted UIDs from 1, so clients kept stale caches. `RENAME` takes its new value from the
  same per-account counter.
- IMAP: a keyword new to the selected mailbox is announced with `* FLAGS` and `PERMANENTFLAGS` before
  the `FETCH` that carries it, and `SELECT` lists the keywords in use; clients could reject the unknown
  keyword.
- IMAP MOVE sends `* OK [COPYUID ...]` and an `EXPUNGE` per moved message before the tagged `OK`, as
  RFC 6851 requires; it sent COPYUID in the tagged reply and no EXPUNGE, so clients kept the moved
  messages in view.
- IMAP ENVELOPE keeps RFC 822 groups (`name: a@b;`, `undisclosed-recipients:;`) as group start and end
  markers; group members were flattened and empty groups dropped.
- IMAP SORT follows RFC 5256: `REVERSE` applies to the key after it, exact ties keep mailbox order, `FROM`/
  `TO`/`CC` sort on the first address's local part (a group's name for group syntax), `SUBJECT` on the base subject (without `Re:`, `Fwd:`,
  `[list]`...), and `DATE` falls back to the internal date when the `Date` header is missing or invalid.
- IMAP THREAD REFERENCES implements the RFC 5256 algorithm and answers with thread trees
  (`(1 (2 4)(3))`): missing parents become grouping nodes, and threads with the same base subject are
  merged. It answered flat lists.
- IMAP `\Recent`: `EXAMINE` no longer clears it; after `SELECT` the selecting session keeps reporting
  its recent messages (`FLAGS`, `SEARCH RECENT`/`NEW`/`OLD`) while other sessions see none.
  `STORE FLAGS` no longer clears `\Recent`.
- IMAP FETCH: `BODY[n]` returns the part content only, as RFC 3501 requires; it included the part's MIME
  header, which is `BODY[n.MIME]`. Section bytes are returned as stored: quoted-printable parts were
  decoded and part headers reordered.
- IMAP FETCH: part numbers continue into `message/rfc822` parts (`BODY[2.1]`), and `HEADER`/`TEXT`/
  `HEADER.FIELDS` of such a part refer to the encapsulated message; they returned the outer message.
  `HEADER.FIELDS.NOT` and part-prefixed `HEADER.FIELDS` (`BODY[1.HEADER.FIELDS (...)]`) are supported.
  Parts of a `multipart/digest` without `Content-Type` are `message/rfc822` (RFC 2046), in FETCH and
  BODYSTRUCTURE.
- IMAP BODYSTRUCTURE: part sizes and encodings come from the raw part, like `BODY[n]`; quoted-printable
  parts were measured decoded.
- IMAP SEARCH: `SENTBEFORE`/`SENTON`/`SENTSINCE` use the day written in the `Date` header, ignoring its time
  and zone; they compared the UTC day. Address criteria (`FROM`, `TO`, `CC`, `BCC`) also match addresses
  written with RFC 5322 comments.
- IMAP: `SELECT`/`EXAMINE` and `APPEND` no longer create a missing folder (RFC 3501). `SELECT` answers `NO`;
  `APPEND` answers `NO [TRYCREATE]` before the literal, so the client can `CREATE` and retry. Clients that
  relied on the implicit creation must send `CREATE` first. An invalid name in `SELECT` answers `NO`.
- IMAP APPEND: a refused `APPEND` with a non-synchronizing literal (`{n+}`) consumes the literal; its bytes
  were read as commands.
- IMAP: reversed sequence ranges (`3:1`, `*:4`) are accepted as RFC 3501 allows, and a UID range past the
  largest UID (`9:*`) still matches the last message; they got `BAD` or matched nothing.
- IMAP FETCH: `BODY` (non-extensible body structure) and the `FAST`/`ALL`/`FULL` macros; they got `BAD`.
- IMAP FETCH: `BODY[...]` without `PEEK`, `RFC822` and `RFC822.TEXT` set `\Seen` in a read-write mailbox and
  report the new `FLAGS`, as RFC 3501 requires.
- IMAP SEARCH: an empty string (`SUBJECT ""`) matches every message instead of `BAD`; `HEADER field ""`
  matches only messages that have the field; a repeated field matches on any of its occurrences.
- IMAP `CLOSE` after `EXAMINE` answers `OK` and expunges nothing; it answered `NO mailbox is read-only`.
- IMAP: system flags are case-insensitive (`\seen` is `\Seen`) in APPEND, STORE and SEARCH; lowercase flags
  were ignored on APPEND and stored as keywords on STORE.
- IMAP STORE: `FLAGS` (replace, without `.SILENT`) answers with the untagged `FETCH`, as `+FLAGS`/`-FLAGS` do,
  and replaces keywords too; they were kept, and keywords in the list were dropped.
- IMAP `DELETE` removes a folder together with its messages, as RFC 3501 requires; it refused non-empty
  folders with `NO mailbox not empty`. System folders stay protected.
- IMAP: `SELECT`/`EXAMINE` accept the `(CONDSTORE)` select parameter; the parameter list was taken as part
  of the mailbox name, which created a folder called `INBOX (CONDSTORE)`. Unknown parameters get `BAD`.
- IMAP: a `SELECT`/`EXAMINE` with an invalid mailbox name answers `BAD` and keeps the session open; it closed
  the connection.
- IMAP STORE: a failed `UNCHANGEDSINCE` answers `OK [MODIFIED set] Conditional STORE failed` with the messages
  left unchanged (sequence numbers, or UIDs for `UID STORE`), as RFC 7162 requires.
- IMAP FETCH: the CONDSTORE modifier `(CHANGEDSINCE n)` returns only messages changed after mod-sequence `n`,
  each with `MODSEQ`; it was ignored and every message came back.
- IMAP: `STATUS` returns `HIGHESTMODSEQ` (RFC 7162, required with CONDSTORE), and `ENABLE` is advertised in
  CAPABILITY.
- IMAP FETCH: strings with non-ASCII bytes in ENVELOPE and BODYSTRUCTURE (decoded sender names, RFC 2231
  filenames) are sent as literals: IMAP4rev1 quoted strings are 7-bit only.
- IMAP FETCH: partial fetches `BODY[...]<origin.count>` return the requested byte range.
- IMAP SEARCH: `CHARSET` (UTF-8 and US-ASCII; others get `NO [BADCHARSET]`), literal search strings, bare
  sequence sets, `UID` with sequence-set lists, and the CONDSTORE `MODSEQ` criterion with `(MODSEQ n)` in the
  SEARCH and SORT responses.
- IMAP SEARCH: header criteria match RFC 2047 encoded words decoded, so UTF-8 searches find encoded subjects
  and names.
- IMAP SORT/THREAD: accept the charset argument RFC 5256 requires; a search program with parentheses after the
  sort keys no longer fails with `BAD`.
- IMAP THREAD: thread lists in the response follow each other with no space (`(1 2)(5)`), as RFC 5256 requires.
- IMAP BODYSTRUCTURE: an empty MIME parameter value (e.g. `name=""`) is sent as `""` instead of `NIL`, which
  strict clients rejected as a parse error.
- IMAP SEARCH/SORT/THREAD stop when the client disconnects, instead of reading every message of the mailbox
  first; during shutdown they end with `NO [UNAVAILABLE]`.

## 0.3.0

- License: GNU AGPL v3.0 only (`AGPL-3.0-only`), copyright BLUEBOX SOFTWARE S.L. Contributions under the
  [CLA](CLA.md). Third-party notices in [NOTICE](NOTICE).
- Antispam plugin rewritten on the rspamd rules: rspamd symbol names, default scores and actions (greylist 4,
  add header 6, reject 15). **The config format changed:** rewrite `<data_dir>/antispam/config.json` from
  `examples/antispam/config.json.example` before upgrading; see [docs/antispam-ops.md](docs/antispam-ops.md).
  The list files keep their names.
- Security policy: [SECURITY.md](SECURITY.md).

## 0.2.0

- Debian package (`make deb`): installs `beaver` and the antispam plugin, a systemd unit and a loopback-only
  config on first install; the data directory is readable by its owner only.
- An API key closes `/setup`, for installs managed only by a provisioner.
- IMAP: full LIST-EXTENDED (RFC 5258) with the RFC 6154 special-use options.
- IMAP: `LIST "" ""` returns the hierarchy delimiter, and the reference is joined to the pattern.
- IMAP: `CREATE` makes the missing parent mailboxes; `LSUB` with `%` shows unsubscribed parents.
