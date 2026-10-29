# Installing BeaverMail

Two paths:

- [A. Development VM](#a-development-vm): everything on loopback, for trying the HTTP API from a panel.
- [B. Production next to nginx](#b-production-next-to-nginx): public mail ports, nginx keeps 80/443.

Install from the Debian package (Debian/Ubuntu) or from the release tarball (other distributions). Never install a
`beaver` built in the source tree: it is a dev build (no release version, local build paths inside).

BeaverMail is work in progress: configuration and API may still change between versions.

## Install

### Debian package (recommended)

From the APT repository, so `apt upgrade` brings new versions:

```sh
install -d -m 755 /etc/apt/keyrings
curl -fsSL https://apt.beavermail.dev/beavermail.gpg -o /etc/apt/keyrings/beavermail.gpg
gpg --show-keys /etc/apt/keyrings/beavermail.gpg     # must show BE4CCAD2BB56396BF1919FBFFC5710EC1A49A820
echo "deb [signed-by=/etc/apt/keyrings/beavermail.gpg] https://apt.beavermail.dev stable main" \
  > /etc/apt/sources.list.d/beavermail.list
apt update && apt install beavermail
beaver version                                       # must print the release version, not 0.0.0-dev
```

Or download the `.deb` from the GitHub release and `apt install ./beavermail_<version>_amd64.deb`.

The package creates the `beavermail` system user, `/var/lib/beavermail` (`700`) and `/etc/beavermail`
(`root:beavermail 2750`), and installs `/usr/bin/beaver`, the antispam plugin in `/var/lib/beavermail/plugins` and the
systemd unit. On first install it runs `beaver init` without `-hostname` (loopback only, as in A.1) and does not
start the service; upgrades and `dpkg-reconfigure` never touch that config again. Edit it for public listeners as in
B.1, create an API key (A.2, which also closes `/setup`), then `systemctl enable --now beavermail`. Upgrade by installing the
newer `.deb`: the config is kept, the service restarts and the store is migrated on start. `apt remove` keeps config
and mail; `apt purge` deletes the config (with its secrets) but keeps the mail in `/var/lib/beavermail`.

### Release tarball

```sh
sha256sum -c beavermail-<version>-linux-amd64.tar.gz.sha256
tar xzf beavermail-<version>-linux-amd64.tar.gz
cd beavermail-<version>-linux-amd64

useradd --system --home-dir /var/lib/beavermail --shell /usr/sbin/nologin beavermail
install -d -o root -g beavermail -m 2750 /etc/beavermail   # init then writes config.json readable by the service
install -m 755 beaver /usr/local/bin/beaver
install -D -m 755 beaver-plugin-antispam /var/lib/beavermail/plugins/beaver-plugin-antispam  # optional
beaver version                                       # must print the release version, not 0.0.0-dev
```

The tarball contains `beaver`, `beaver-plugin-antispam`, `beavermail.service`, this file and `api.md`.

### Config file and permissions (both)

`beaver init` writes `/etc/beavermail/config.json` and generates the HTTP signing key in it. All CLI commands read
that file by default (`-c path` or `BEAVER_CONFIG` to use another). The service reads it through its group: in the
setgid `/etc/beavermail` init writes it `root:beavermail`, mode `640`. Plugins live in `<data_dir>/plugins`.

Everything BeaverMail creates is owner-only (umask `077`): the data dir is `700` and `store.sqlite` `600`; systemd
(`StateDirectory=`) and `serve` restore that on every start. Run later CLI commands as the service account
(`sudo -u beavermail beaver ...`) so no root-owned file ends up in the data dir.

## A. Development VM

### 1. Initialize and start

```sh
beaver init -data-dir /var/lib/beavermail          # no -hostname: loopback only
#   tarball only: install -m 644 beavermail.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now beavermail
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

Then install the unit (tarball) and start the service as in A.1.
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

Package: `apt update && apt upgrade` from the APT repository, or `apt install ./beavermail_<new-version>_amd64.deb`
(the service restarts by itself). Tarball:

```sh
systemctl stop beavermail
install -m 755 beaver /usr/local/bin/beaver
systemctl start beavermail
```

The store schema is migrated on start. Read the release notes before upgrading; take a backup first.
