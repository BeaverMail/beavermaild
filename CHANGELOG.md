# Changelog

## Unreleased

- Paid plugins: new SDK package `plugin/license` verifies Ed25519-signed license files offline.
  The host passes the licenses directory (`<config dir>/licenses`) and the installation id to
  every plugin. `beaver init` creates the installation id in `<data_dir>/install-id`.
  `beaver plugins list` prints the installation id and each plugin's license status.
- `beaver-license` (in the SDK, built with `make beaver-license`, not packaged) creates a vendor
  signing key and issues license files; any plugin vendor can use it with its own key.
- SMTP accepts the null sender `MAIL FROM:<>` (RFC 5321 4.5.5): bounces and delivery reports from
  other servers used to be refused with 501. Submission keeps a null sender null.
- SMTP accepts `postmaster@` on every domain and a bare `RCPT TO:<Postmaster>` (RFC 5321 4.5.1).
  Without a postmaster mailbox or alias the mail goes to the tenant admins, else the instance admins.
- The local part of envelope addresses keeps its case (RFC 5321 2.4); only the domain is lowercased.
  Local users still match case-insensitively.
- SMTP EHLO reply ends with a keyword line instead of `250 2.0.0 Ok` (RFC 5321 4.1.1.1, RFC 2034).
  The outbound client reads the last EHLO line too: it used to miss the extension listed there
  (e.g. `STARTTLS` or `CHUNKING`).
- SMTP command handling follows RFC 5321: MAIL needs EHLO/HELO first and is refused inside an open
  transaction (503); a new EHLO resets the transaction; `EHLO` without a domain gets 501; unknown
  commands get 500; unknown MAIL/RCPT parameters get 555; quoted local parts and source routes are
  accepted; lines up to 12288 octets are read, longer ones get 500 instead of a dropped connection.
  After STARTTLS the client must send EHLO again (RFC 3207 4.2). HELP lines all carry the enhanced code.
- Outbound delivery to a domain with a null MX (`MX 0 .`, RFC 7505) fails permanently at once; it used
  to try localhost. A domain with no MX but an address record is delivered to directly (implicit MX,
  RFC 5321 5.1) instead of bouncing. MX hosts of equal preference are tried in random order.
- The outbound SMTP client times out per command and per data buffer (5 minutes, 10 once the
  transaction starts) instead of after 30 seconds for the whole session, so large messages and slow
  servers no longer fail; a server that dribbles its replies still times out.
- SMTP DATA lines are read with bounded memory; an IPv6 client address in `Received` carries the
  `IPv6:` tag (RFC 5321 4.1.3).
- Security: SMTP smuggling (CVE-2023-51764 class) is blocked in both directions. A bare CR or LF in
  DATA, or a DATA line over the limit, gets an error reply and the connection is closed; the `\n.\r\n` variant used to let the text after it run
  as a new transaction. Outgoing mail has every bare CR/LF turned into CRLF. Regression tests name
  each CVE (`internal/smtp/cve_test.go`).
- Security: at most 1000 recipients per transaction (452); a session that sends 10 unknown recipients,
  more than its valid ones, or 10 unknown commands is closed (421).
- A recipient refused by the filter plugin at RCPT no longer receives the message anyway.
- Queue ids are allocated atomically: messages queued at the same moment (several SMTP sessions, the
  worker's DSNs, the CLI) could get the same id and overwrite each other.
- The queue worker delivers up to 16 messages in parallel, so a slow remote server no longer holds back
  every other outbound message.
- Relay security: with `relay_starttls` a relay that does not offer STARTTLS is an error instead of a
  plaintext session, and `relay_user`/`relay_password` are only sent over TLS (or to a loopback relay).
- Direct MX delivery refuses loopback, private and link-local addresses (a domain's MX could point at
  our own network); `smtp.outbound_allow_private` turns this off for LAN setups.
- Null-sender mail from submission is DKIM-signed as the authenticated user instead of going out unsigned.
- The queue worker no longer waits for a whole pass to finish: a delivery stuck on a slow server holds
  only its own slot, new messages go out on the next pass, and one destination domain takes at most
  4 of the 16 slots.
- MTA-STS policy downloads refuse internal addresses (like MX delivery) and no longer follow redirects
  (RFC 8461 3.3). The internal-address filter also covers CGNAT (`100.64.0.0/10`).
- IMAP FETCH of a whole message (`BODY[]`, `RFC822`, partial) streams it from disk instead of loading
  it; items that parse the message (ENVELOPE, BODYSTRUCTURE, parts) hold at most 16 messages in memory
  at once across all sessions. A client that stops reading responses is disconnected after 5 minutes.
- IMAP SEARCH, SORT and THREAD no longer load messages: header criteria, SORT and THREAD read only the
  header block (first 256 KiB), TEXT and BODY scan the message in 64 KiB chunks. URLFETCH and CATENATE
  URLs share the 16-message bound, and URLFETCH writes its response one URL at a time instead of
  holding every message it names.
- IMAP security fixes from the RFC 3501 audit, each with a regression test:
  - BODYSTRUCTURE of a message with very many MIME parameters no longer takes quadratic CPU
    (minutes for one message reachable by SMTP; CVE-2026-27859 class).
  - A MIME boundary matches only a whole delimiter line (RFC 2046 5.1.1): boundary `b1` no longer
    splits on `--b10`.
  - A failed login costs one password hash whether the account exists or not: response time no
    longer reveals which addresses have accounts (IMAP and SMTP AUTH).
  - MULTIAPPEND counts 4 KiB per message toward the 32 MB cap, so a flood of tiny literals cannot
    hold gigabytes (CVE-2024-34055 class).
  - SEARCH nesting (parentheses, NOT, OR) is limited to 100 levels.
  - LIST/LSUB patterns treat every character but `*` and `%` literally: `?` no longer matches
    anything and `"a???*"` no longer kills the session.
  - Keywords must be IMAP atoms and unknown `\` flags are refused (BAD); keywords holding NUL,
    `]`, `"` or `{` are no longer stored or echoed to other sessions. `Seen` without backslash is
    a keyword of its own, no longer `\Seen`.
  - MIME nesting is limited to 100 levels (multipart and message/rfc822) in BODYSTRUCTURE, BODY[section]
    and BINARY; deeper parts show as one application/octet-stream leaf. A deeply nested message
    from any sender cost quadratic CPU per FETCH (CVE-2020-12100 class); BODYSTRUCTURE no longer
    copies the body of each message/rfc822 level.
  - Every IMAP command takes its string arguments as literals (RFC 3501 4.3). Only SEARCH, SORT and
    THREAD read them before: in any other command the literal bytes ran as the next command, before
    login too. LOGIN accepts a literal password (needed for passwords with `"`, `\` or 8-bit bytes);
    APPEND accepts a literal mailbox name. Before login a command may carry at most 8 KiB of
    literals.
  - Quoted strings resolve their `\"` and `\\` escapes in every command, and LIST, LSUB and STATUS
    escape mailbox names the same way (a name with `\` came back as a malformed string); a name with
    8-bit bytes comes back as a literal.
  - At most 10 connections per client address (IPv4, or IPv6 /64) may wait unauthenticated, and an
    unauthenticated connection is dropped after 1 minute without a command (30 minutes once logged
    in, as before). 200 idle connections from one address used to lock everybody out of IMAP.
  - NUL bytes never go out in a plain literal: FETCH and URLFETCH send them as 0x80 (lengths
    unchanged), only BINARY literal8 carries NUL. APPEND refuses NUL in a plain literal (BAD); a
    literal8 (`~{n}`) is still accepted.
  - Mailbox names: at most 1024 bytes and 32 levels, at most 10000 folders per account (NO [LIMIT]);
    folders made before keep working. LIST, LSUB and NOTIFY find children in linear time: LIST of
    3000 folders went from 14 s to 0.07 s.
- IMAP conformance fixes from the RFC 3501 audit:
  - LOGIN, AUTHENTICATE and STARTTLS are refused (BAD) once logged in; CAPABILITY drops STARTTLS,
    AUTH= and SASL-IR after login, and offers AUTH=PLAIN only where it is accepted (not with
    LOGINDISABLED).
  - AUTHENTICATE PLAIN: the response must be base64 of three fields (RFC 4616); an authorization
    identity other than the user is refused with NO [AUTHORIZATIONFAILED] (it was ignored, logging
    in as the user); an unknown mechanism gets NO; the empty challenge is `+ `.
  - A line with a tag and no command is answered BAD instead of being ignored.
  - FETCH, STORE, COPY and MOVE with a sequence number past the last message (or `*` in an empty
    mailbox) get BAD; UID COPY that copies nothing no longer sends an empty COPYUID; `BODY[0]` and
    other malformed sections get BAD.
  - RENAME moves the folders under the renamed one and creates missing superiors; RENAME INBOX
    moves INBOX's messages to the new folder and keeps INBOX (it was refused).
  - Mailbox names: modified UTF-7 segments are compared exactly (`&ZeVnLIqe-` is not `&ZEVNLIQE-`),
    new 8-bit names or malformed `&` sequences are refused, leading and trailing spaces are kept.
  - EXAMINE announces `PERMANENTFLAGS ()`.
  - APPEND keeps keywords, refuses malformed flags, accepts a space-padded day (` 5-Nov-2026`),
    and answers NO for an empty `{0}` message.
  - ENVELOPE and BODYSTRUCTURE no longer send header text as 8-bit literals without a charset:
    display names and Content-Description go out as RFC 2047 B-encoded words, MIME parameters
    (file names) in their RFC 2231 form (`"NAME*" "utf-8''..."`), as RFC 2047 5 requires;
    addresses are never encoded.
  - URLFETCH BINARY BODYPARTSTRUCTURE reports 0 lines for decoded data, as Dovecot does
    (imaptest urlauth-binary); raw parts keep their line count.
- SMTP AUTH conformance (RFC 4954, RFC 4616), with one SASL decoder shared with IMAP
  (`internal/sasl`):
  - Responses must be BASE64 (`=` is empty): anything else gets 501 5.5.2 instead of being read as
    text; PLAIN needs three fields, and an authorization identity other than the user fails (535).
  - `*` cancels with 501 in PLAIN and LOGIN. In LOGIN it used to be ignored: the server asked for
    the password and took the client's next command as one.
  - A second AUTH after logging in, or an AUTH inside a mail transaction, gets 503 (the open
    transaction used to be dropped); LOGIN with an initial response gets 501.
  - An authentication line longer than 12288 octets gets 500 5.5.6; the session goes on (it was
    closed).
  - MAIL FROM accepts the AUTH= parameter (it got 555) and drops it, as RFC 4954 5 allows; when
    relaying through a server it authenticates to, the client sends AUTH=<>.
- SMTP STARTTLS (RFC 3207): `STARTTLS` with a parameter gets 501. Submission before TLS answers
  530 5.7.0 to every command but NOOP, EHLO, STARTTLS and QUIT (AUTH keeps 538 5.7.11); HELO,
  RSET, VRFY and HELP used to answer in clear.
- SMTP PIPELINING (RFC 2920): replies to RSET, MAIL and RCPT inside a pipelined group go out in one
  write; MAIL answers `250 2.1.0 Sender ok` and RCPT `250 2.1.5 Recipient ok` instead of
  `250 2.0.0 Ok`, so each reply names its command.
- SMTP CHUNKING (RFC 3030): a BDAT chunk is always read before the reply, as RFC 3030 requires.
  After a refused MAIL in the same pipelined group, or before TLS on submission, the chunk was
  left unread and parsed as commands (SMTP smuggling through BDAT). A chunk over the size limit
  is read and dropped, answered 552, and the session goes on (it was closed).
- Line ends, as Dovecot does them: messages stay stored as received (LF from SMTP DATA, CRLF
  from APPEND and BDAT), and IMAP now serves them with CRLF line ends (RFC 3501 2.3.4).
  Messages from SMTP used to reach clients with bare LF, and their RFC822.SIZE counted the
  stored bytes. RFC822.SIZE, SEARCH LARGER/SMALLER and SORT SIZE use the CRLF size, stored with
  each message and filled in once per mailbox for older ones; quota still counts stored bytes.
- A bare CR is handled as Exim does: inside the header a folded continuation, in the body a line
  end, on BDAT and APPEND input and on outbound mail. It can no longer start a header field, and
  outbound `\r\r\n` no longer becomes an empty line that ended the header early.
- Delivery status notifications (RFC 3461, RFC 3464):
  - No value can add lines to a notification: the remote server's diagnostic, the addresses, ENVID
    and ORCPT are kept to one line. A remote MX could forge fields such as Final-Recipient in the
    bounces it caused.
  - ENVID and ORCPT must be valid xtext decoding to printable ASCII (ENVID up to 100 characters),
    RET/ENVID/NOTIFY/ORCPT may appear once, NOTIFY needs a value: otherwise 501.
  - A local delivery with NOTIFY=SUCCESS gets a "delivered" notification (none was sent).
  - Relaying to a server that offers DSN passes RET, ENVID, NOTIFY and ORCPT as received, and
    that server reports from there on; to one without DSN, a NOTIFY=SUCCESS recipient gets a
    "relayed" notification instead of "delivered".
  - Notifications carry the server's name (Reporting-MTA, From, Message-ID) instead of localhost,
    ENVID and ORCPT decoded, and only the header (as text/rfc822-headers) unless they report a
    failure with RET=FULL.
- SMTP SIZE (RFC 1870): the message size counts CRLF, so a message over the announced limit gets
  552 (one stored with LF line ends was counted smaller and could exceed the limit by its number
  of lines). One SIZE per MAIL (501); a valid 20-digit SIZE is too big (552), not a syntax error.
  The client sends SIZE= only to servers offering SIZE (a strict server answered 555 and the
  delivery failed), and a message over the server's announced SIZE fails permanently without
  being transferred.
  - SEARCH BODY and TEXT also match the decoded text of base64 and quoted-printable parts, and TEXT
    the decoded RFC 2047 header words (no charset conversion: UTF-8 and US-ASCII parts).

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
