# Installing BeaverMail

Two paths:

- [A. Development VM](#a-development-vm): everything on loopback, for trying the HTTP API from a panel.
- [B. Production next to nginx](#b-production-next-to-nginx): public mail ports, nginx keeps 80/443.

The release tarball contains:

| File | Purpose |
|------|---------|
| `beaver` | Mail server and CLI (static Linux binary, no runtime dependencies) |
| `beaver-plugin-antispam` | Antispam filter plugin (optional) |
| `beavermail.service` | systemd unit |
| `install.md` | This file |
| `api.md` | HTTP API reference |

BeaverMail is work in progress: configuration and API may still change between versions.

## Install the files (both paths)

```sh
sha256sum -c beavermail-<version>-linux-amd64.tar.gz.sha256
tar xzf beavermail-<version>-linux-amd64.tar.gz
cd beavermail-<version>-linux-amd64

useradd --system --home-dir /var/lib/beavermail --shell /usr/sbin/nologin beavermail
install -m 755 beaver /usr/local/bin/beaver
install -d -o beavermail -g beavermail -m 750 /var/lib/beavermail /var/lib/beavermail/plugins
install -m 755 beaver-plugin-antispam /var/lib/beavermail/plugins/   # optional
beaver version
```

`beaver init` (below) writes `/etc/beavermail/config.json` and generates the HTTP signing key in it. All CLI
commands read that file by default (`-c path` or `BEAVER_CONFIG` to use another).

## A. Development VM

### 1. Initialize and start

```sh
beaver init -data-dir /var/lib/beavermail          # no -hostname: loopback only
chown -R beavermail:beavermail /var/lib/beavermail /etc/beavermail
install -m 644 beavermail.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now beavermail
journalctl -u beavermail -f                           # "http api listening" means ready
```

Without `-hostname` every listener is on loopback:

| Service | Address |
|---------|---------|
| HTTP API and admin UI | `http://127.0.0.1:8080` |
| SMTP (inbound) | `127.0.0.1:1025` |
| IMAP | `127.0.0.1:1143` |

To open the admin UI from your workstation: `ssh -L 8080:127.0.0.1:8080 <vm>`, then `http://localhost:8080`. The
first visit asks to create the admin account.

### 2. Create an API key for the panel

```sh
TOKEN=$(beaver apikey create -name panel)            # printed once; store it in the panel config
beaver apikey list
```

### 3. Try the integration

```sh
API=http://127.0.0.1:8080/api/v1
H="Authorization: Bearer $TOKEN"

# customer (tenant) with a 2 GiB plan
curl -s -H "$H" -d '{"name":"Customer","external_id":"cust-42","storage_limit":2147483648}' $API/tenants
# -> {"id":2,...}; a repeat returns 409 with the same tenant

curl -s -H "$H" -d '{"name":"example.org","tenant_id":2,"mail_hostname":"mail.example.org","dkim_enabled":true}' $API/domains
curl -s -H "$H" -d '{"local_part":"alice","password":"correct horse"}' $API/domains/example.org/accounts
curl -s -H "$H" -X PATCH -d '{"storage_limit":1073741824}' $API/accounts/alice@example.org
curl -s -H "$H" -d '{"local_part":"info","targets":["alice@example.org"]}' $API/domains/example.org/aliases
curl -s -H "$H" $API/domains/example.org/dns-recommended
curl -s -H "$H" $API/tenants                         # storage_used per customer
```

Deliver a test message and read it back:

```sh
printf 'EHLO test\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<info@example.org>\r\nDATA\r\nSubject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n' | nc 127.0.0.1 1025
printf 'a1 LOGIN alice@example.org "correct horse"\r\na2 SELECT INBOX\r\na3 LOGOUT\r\n' | nc 127.0.0.1 1143
```

Everything is in `api.md`. To start over: `systemctl stop beavermail`, delete `/var/lib/beavermail/*` and
`/etc/beavermail`, run `beaver init` again.

## B. Production next to nginx

`beaver init -hostname ...` assumes BeaverMail owns ports 80 and 443. With nginx on the same host, initialize
without `-hostname` and set the listeners by hand.

### 1. Initialize and edit the config

```sh
beaver init -data-dir /var/lib/beavermail
```

In `/etc/beavermail/config.json` set (keep the other generated keys):

```json
{
  "http": { "enabled": true, "listen": "127.0.0.1:8080", "plain_listen": "" },
  "smtp": {
    "hostname": "mail.example.net",
    "listen": ":25",
    "submission_listen": ":587",
    "submission_tls_listen": ":465"
  },
  "imap": { "listen": ":143", "tls_listen": ":993" },
  "tls": {
    "cert_file": "/etc/beavermail/tls/mail.example.net.crt",
    "key_file": "/etc/beavermail/tls/mail.example.net.key"
  }
}
```

- `smtp.hostname` is the SMTP banner and outbound EHLO name: it must match the PTR (reverse DNS) of the server's
  public IP, or large providers will distrust the mail.
- The API stays on loopback; never expose port 8080.
- Outbound mail goes directly to the recipients' MX on port 25. If the provider blocks outbound 25, set a relay
  (`smtp.relay`, see `tls-ops.md` in the source tree).

Then `chown -R beavermail:beavermail /var/lib/beavermail /etc/beavermail`, install the unit and start it as in A.1.
The unit grants `CAP_NET_BIND_SERVICE`, so the server binds 25/143/465/587/993 without running as root.

### 2. Certificates

The mail ports pick a certificate by SNI: per-domain custom PEM, then per-domain ACME, then `tls.cert_file`.

- **Server certificate** (`mail.example.net`): issue it with lego through nginx and point `tls.cert_file` /
  `tls.key_file` at the files. BeaverMail reloads them when they change, no restart needed. The `beavermail` user
  must be able to read them.
- **Per-domain mail hostnames** (`ssl_mode` on each domain), either:
  - `custom`: the panel issues the certificate with lego and sends it with
    `PATCH /domains/{domain}` `{"ssl_mode":"custom","cert_pem":"...","key_pem":"..."}`; repeat on every renewal; or
  - `acme`: BeaverMail issues it itself; nginx must forward the HTTP-01 challenge for that host name to it:

    ```nginx
    server {
        listen 80;
        server_name mail.customer.example;
        location /.well-known/acme-challenge/ { proxy_pass http://127.0.0.1:8080; }
    }
    ```

### 3. Protect the API port

Any local process can connect to `127.0.0.1:8080`. On a shared hosting server, allow only the panel daemon (and
root for maintenance). Example with nftables, assuming the daemon runs as user `panel`:

```nft
table inet beaver_api {
    chain output {
        type filter hook output priority 0; policy accept;
        oif "lo" tcp dport 8080 meta skuid != { "panel", "root" } reject
    }
}
```

Load it with `nft -f /etc/nftables.d/beaver-api.nft` and make it persistent with your distribution's nftables
service. Without this, a customer script could try passwords against `/api/v1/auth/login`.

### 4. DNS for each customer domain

`GET /api/v1/domains/{domain}/dns-recommended` returns the records to publish (MX, SPF, DKIM, DMARC, TLS-RPT,
autoconfig). MTA-STS is not served by BeaverMail; see `api.md`, "Recommended DNS records".

### 5. Backups

Everything lives in the data dir (`/var/lib/beavermail`): `store.sqlite` (directory and mail metadata), `blobs/`
(message bodies), per-domain keys and certificates. Back up the whole directory; for a consistent copy of
`store.sqlite` use `beaver store export` (see `storage-ops.md` in the source tree) or stop the service first.
Deleting a tenant, domain or mailbox through the API deletes its mail immediately: backups are the only way back.

## Upgrading

```sh
systemctl stop beavermail
install -m 755 beaver /usr/local/bin/beaver
systemctl start beavermail
```

The store schema is migrated on start. Read the release notes before upgrading; take a backup first.
