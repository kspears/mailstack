# mailstack

A small self-hosted mail server for a handful of domains: postfix, dovecot, rspamd and
redis in four containers, plus `mailctl`, one Go program that manages accounts from the
command line and from a small web UI.

The daemons never talk to a database. `mailctl` keeps accounts in one SQLite file and
regenerates plain lookup files from it after every change; postfix and dovecot read those.
Mail keeps flowing when `mailctl` is not running.

## Layout

```
cmd/mailctl/        CLI entry; `mailctl serve` runs the web UI
internal/store/     SQLite store, schema, change log
internal/validate/  address rules, alias loops, collisions
internal/generate/  render lookup files; all-or-nothing apply
internal/web/       server-rendered admin UI
internal/auth/      the UI's own sign-in: passwords with an authenticator code, passkeys, sessions
images/postfix/     postfix image: Debian, the distro package, a reload watcher
images/admin/       image for mailctl
images/unbound/     recursive resolver for postscreen and rspamd: Debian, the distro package
deploy/ci/          compose file used by the integration test
docs/UPGRADING.md   how to move an image pin
```

## State on disk

Everything `mailctl` owns lives under one state directory (`MAILCTL_STATE`, default
`/data/mailstack`), mounted at the same path in every container that needs it:

```
store.db                    accounts and the change log (mode 0600)
lock                        one lock for every change, CLI and UI alike
dkim/                       DKIM private keys from the mailcow import
watcher/status              written by the postfix watcher: which set it last checked
watcher/heartbeat           rewritten by the postfix watcher on every pass; its mtime shows it is alive
generations/<id>/           one complete set of generated files
  dovecot/users             passwd-file: address and hash; uid, gid and home are empty
  postfix/domains           texthash: hosted domains
  postfix/mailboxes         texthash: deliverable addresses
  postfix/aliases           texthash: alias -> targets
  postfix/sender_login      texthash: sender address -> logins allowed to use it
generations/current         relative symlink: the set the daemons use
generations/pending         relative symlink: a set waiting for postfix to accept it
```

`dovecot/users` carries no uid, gid or home, so the generated files depend on the store alone.
Dovecot's `mail_uid`, `mail_gid` and `mail_home` settings own those, and `MAILCTL_MAIL_ROOT` is
never rendered into a file.

Postfix faces the internet, so it mounts only `generations/` (read-only) and `watcher/`
(read-write); dovecot mounts only `generations/` (read-only). Neither sees `store.db` or
`dkim/`. `deploy/ci/compose.yaml` does this with volume `subpath` mounts. Files are fsynced
before a generation is installed, and the directories after each rename.

## How a change is applied

1. Take the lock and open a store transaction.
2. Check that `generations/current` is what the store renders; if not, stop (below).
3. Render a whole new generation directory and check it.
4. Point `pending` at it. The postfix watcher sees `pending` differs from what it last
   applied, runs `postfix check` against a scratch copy of the config in which the one
   parameter `mailstack_generation` names that generation, and writes `watcher/status`. When
   `current` moves it reloads postfix.
5. On success, move `current` to the new generation and commit. On failure or timeout,
   drop `pending`, roll back, and print `error: ...`. Nothing changes.

`watcher/status` is one line: `<generation id> ok` or `<generation id> error <message>`. The
watcher writes it after checking the generation `pending` points at; `mailctl` ignores a
`status` that names a different generation. Generation ids look like
`20261117T120000.000000Z-1a2b3c4d` (UTC time, then a content hash). The last 10 are kept.
The postfix entrypoint restarts the watcher if it exits.

The watcher requires `dovecot/users` and at least one file in `postfix/`, and checks every
regular file in `postfix/` as a `texthash` table. Postfix's `main.cf` must define
`mailstack_generation` (the reference one sets it to `/data/mailstack/generations/current`) and
write every generated map relative to it, as `texthash:$mailstack_generation/postfix/aliases`.
A config that does not is a failed generation (`error ... must set mailstack_generation ...`):
the watcher never validates `current` in place of the pending one.

### When the store and the files in use disagree

Every change except `apply` and the mailcow import refuses to run if `generations/current`
differs from what the store renders, and changes nothing:

```
error: the files in use do not match the account store (was the store replaced or restored?); ...
```

Without that, a lost, emptied or replaced `store.db` would publish an empty account set on the
next change and remove every account from the daemons. Check with `mailctl mailbox list`, then
run `mailctl apply`, which renders the store as it is and applies it. If the store has no
domains but `current` lists some, `apply` refuses too, unless you pass `--publish-empty`.

One rule covers a lost store: no command creates a missing `store.db` while `generations/current`
exists. They fail with `account store <path> is missing but generated files exist; restore it
from backup`, and leave no file behind. Only `apply --publish-empty` and
`import-mailcow --overwrite` start over on purpose. Before the first generation exists, a missing
store is created as usual.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `MAILCTL_STATE` | `/data/mailstack` | state directory |
| `MAILCTL_MAIL_ROOT` | `/var/vmail` | mail lives in `<root>/<domain>/<localpart>`; used to find existing mail and in messages, never written to a generated file |
| `MAILCTL_INDEX_ROOT` | `/var/vmail_index` | dovecot's indexes, `<root>/<address>`; written only by `mailbox purge-removed` |
| `MAILCTL_APPLY_TIMEOUT` | `30s` | how long to wait for the watcher's `status` |
| `MAILCTL_WATCHER` | unset | `off` skips the wait (tests, first bootstrap) |
| `MAILCTL_DOVECOT_UID` | `999` | owner of `dovecot/users` (mode 0400), the `dovecot` user in the dovecot/dovecot image; see `Config.DovecotUID`. Needs the `CHOWN` capability wherever mailctl makes changes |

The change log names the operator from `SUDO_USER`, then `USER`. A host wrapper that runs
`docker compose run admin ...` must pass it in (`-e SUDO_USER`), or every CLI change is
logged as the container's user.

## Mail of removed mailboxes

Removing a mailbox leaves its mail on disk, so a mistaken removal can be undone with
`mailctl mailbox add <address> --adopt-existing-mail`, and the address cannot be given to
someone else while the old mail is there. `mailctl mailbox purge-removed` deletes the mail and
index directories of every mailbox removed more than 30 days ago that has not been added back,
and records `mailbox.purge` in the change log. It only touches addresses whose latest removal
is in the change log and not yet purged, so mail restored by hand after a purge stays. It
refuses symlinks, and refuses to run at all when the store does not match the files in use.
An address it cannot purge is reported and the rest still are. `--dry-run` lists what it
would delete; run it once by hand before scheduling, since the first run also takes every
older removal.

Run it daily, after the backup, from a container with the mail root and the index root
mounted read-write. Give it its own service rather than the web UI's: the UI needs neither
read-write. In the reference stack the CLI `admin` service has both:

```
docker compose run --rm -T admin mailbox purge-removed
```

## Junk training

```
mailctl learn --controller <url> --password-file <path> spam|ham
```

Reads one message on stdin and posts it to rspamd's controller at `<url>` (`/learnspam` or
`/learnham`) with the `Password` header taken from the password file, never from a command
line. Both flags are required. It needs no state directory and never opens the store. It exits 0 when
rspamd learns the message and when rspamd declines it as already learned or too small to learn
from (HTTP 208, or a 4xx whose error says so); anything else is `error: ...` and exit 1.

The reference stack wires it to IMAPSieve: moving a message into Junk pipes it to
`mailctl learn ... spam`, moving it out (except into Trash) pipes it to `mailctl learn ... ham`,
with the controller URL and password file path written in the two Sieve scripts
(`deploy/ci/dovecot/`). The dovecot image has no shell tools, so the static binary is the pipe
program: a one-shot `learn-bin` service runs `mailctl install-self /sieve/bin` into a volume
dovecot mounts read-only. Sieve starts the program with an empty environment, which is why the settings are arguments,
and the Go runtime needs `service imap { vsz_limit = 2G }`.
The controller needs `enable_password`, set outside the repository; it listens on the compose
network only.

## Development

```
just          list recipes
just check    the CI gate
```

## Web UI

`mailctl serve` runs the admin UI. It speaks plain HTTP and expects a reverse proxy in front
of it that ends TLS; it never listens on a public port itself.

The UI covers the routine work: add, disable and remove mailboxes, reset passwords, add
aliases and change where they deliver, and manage send-as grants. Both password forms offer
"Generate a password instead", which sets a random password and shows it once in the
response; it is never stored in readable form or put in a cookie. Domains are added from the
command line only.

Resetting a password or disabling a mailbox stops new sign-ins only: IMAP sessions already open
stay signed in until they close. After a suspected compromise, end them too, from the host:

```
docker compose exec dovecot doveadm kick alex@example.test
```

| Variable | Default | Meaning |
|---|---|---|
| `MAILCTL_LISTEN` | `:8080` | listen address |
| `MAILCTL_ADMIN_HOST` | required | the hostname the UI is served on, for example `admin.example.test`; requests for any other host are refused, passkeys are bound to it, and enrolment links name it. The command line needs it too |
| `MAILCTL_RSPAMD_HOST` | unset | the hostname rspamd's own UI is published on, if it is; see "The gate in front of rspamd" |
| `MAILCTL_TRUSTED_PROXY` | required | the proxy's IP address. Only a connection from exactly this address may say who the visitor is. One address, never a network. `serve` refuses to start without it, except under `MAILCTL_DEV=1`: every failed sign-in would otherwise be logged, and banned, under the proxy's own address |
| `MAILCTL_CLIENT_ADDR_HEADER` | `X-Forwarded-For` | the header the proxy puts the visitor's address in; the last entry is used |
| `MAILCTL_DEV` | unset | `1` serves over plain HTTP for local work: cookies lose `Secure` and the `__Host-` prefix. Refused unless `MAILCTL_LISTEN` is loopback (`127.0.0.1:`, `localhost:`, `[::1]:`) |

### Status page

`/status` is the landing page after sign-in. It reads only files the UI already mounts and changes
nothing:

- the postfix watcher's heartbeat (red after 5 minutes of silence);
- whether `generations/current` still matches the account store;
- any pending change, and a change postfix rejected, if the last one was;
- the newest delivery to any mailbox's Inbox or Junk (yellow after 2 hours with no mail);
- disk use of the mail and state filesystems (yellow at 80%, red at 90%).

It does not check dovecot, rspamd, DNS or reachability from outside; use an external monitor for
those. The Mailboxes list shows each mailbox's last delivery and size. Mail scans are cached for
60 seconds. Every time in the UI is shown in Pacific time.

### Signing in

Admins are not mailboxes. An admin has a password of their own, an authenticator app, and
any number of passkeys. There are two ways in, and a password alone is never one of them:

- a passkey, with nothing typed;
- address, password and the authenticator's six-digit code, on one form.

Admins are made on the server, never in the UI:

```
mailctl admin add alex@example.test      # prints a one-time enrolment link
mailctl admin reset alex@example.test    # strips every credential and session, prints a new link
mailctl admin remove alex@example.test
mailctl admin list
```

The link is valid for 24 hours and shown once; the store keeps only its hash. Opening it
does not use it up, completing it does, and a newer link cancels an older one. Whoever
completes it first holds the account, so send it by a channel you trust. Through it the
admin sets a password and adds the account to an authenticator app; the operator never
sees either. The authenticator key on the page belongs to the browser it is shown to:
anything else that opens the link is shown a different key, which is never stored. `reset` is also the way back in for a locked-out admin, and it needs no
sign-in: it works with the UI stopped.

What the sign-in does and does not do:

- Every failure shows `Sign-in failed.` and nothing else, whether or not the address exists.
- A code works once.
- Ten right-password, wrong-code attempts in an hour stop password sign-in for that admin
  until the hour passes. Wrong passwords do not count toward that, so nobody can lock an
  admin out by guessing at their address. Passkey sign-in is never limited.
- Guessing is slowed by address instead. Each failure is logged as one line whose message
  starts `sign-in failed from=<address>` (or `proof failed from=<address>`). A fail2ban
  filter must anchor on that: the timestamp, then those words, at the start of the line,
  as in `^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (?:sign-in|proof) failed from=<HOST> `. Request
  lines quote the path, so a visitor cannot make one read as a failure from someone else's
  address, but an unanchored filter would still be matching text the visitor chose. Every
  line is cut to 1 KiB, well under the 16 KiB at which Docker's journald driver splits a
  line into separate entries, the second of which would start with text the visitor chose.
- Every refused sign-in takes at least 750 ms, so the time taken does not say which check
  refused it.
- Passwords are checked one at a time. bcrypt is the costly step anyone can trigger without
  an account, and this leaves the host's other CPU to mail during a flood. A password
  sign-in or proof that waits more than 2 seconds for its turn, or whose visitor goes away
  while waiting, is refused with `Too many sign-ins at once.` and logged as a failure
  (`sign-in failed from=<address> busy: ...`), so the ban counts it: a source flooding the
  form is banned like one guessing passwords. While a flood lasts, password sign-in may be
  refused for everyone; passkey sign-in does no bcrypt and is never held up.
- A session lasts 12 hours and is kept on the server, so signing out, a reset and a removal
  end it at once. Changing the password, replacing the authenticator or removing a passkey
  ends the admin's other sessions.
- Changing a password, replacing the authenticator, and adding or removing a passkey need a
  proof given in the last 5 minutes: a passkey, or password and code again.
- Every request that changes anything must carry `Sec-Fetch-Site: same-origin`, which only a
  browser showing one of the UI's own pages sends. A sibling hostname under the same domain
  does not qualify.
- Only the sign-in and account pages load a script (`/static/passkey.js`, from the UI's own
  origin). Every other page is served with `default-src 'none'` and no script at all.
- The authenticator secret has to be stored readable, so `store.db` holds it beside the
  password hash. A passkey's private half never leaves the device.

### The gate in front of rspamd

rspamd's web UI shows text taken from mail, so it belongs on a hostname of its own, where a
fault in its pages cannot act as the admin. With `MAILCTL_RSPAMD_HOST` set, the proxy asks
`mailctl` before passing each request to rspamd:

- `GET /_mailstack/check` answers 204 for a visitor holding an rspamd session, and
  otherwise redirects to `/_mailstack/start` on the rspamd hostname. Use it as the proxy's
  forward-auth target for that hostname.
- Route `/_mailstack/*` on the rspamd hostname to `mailctl`, not to rspamd.

A signed-in admin gets an rspamd session through a hand-off between the two hostnames. That
session's cookie opens the rspamd UI and nothing else, the admin cookie is never sent to the
rspamd hostname, and the rspamd session ends with the admin session it came from. The
hand-off ticket travels in a query string once, so keep the proxy from logging query
strings on `/_mailstack/finish`.

### Running it locally

`just dev` serves on `http://localhost:8080` and keeps its state in `.dev/` (or wherever
`MAILCTL_STATE` points). `just dev-ctl` runs any `mailctl` command against that same state.
Make yourself an admin first and open the link it prints:

```
just dev-ctl admin add you@example.test
just dev-ctl domain add example.test
just dev
```

## Importing from mailcow

`mailctl import-mailcow` is a one-time export from a running mailcow-dockerized install. It
reads mailcow's MySQL and Redis and changes nothing there: every SQL statement is a `SELECT`
inside a read-only transaction, and the only Redis commands sent to mailcow are `AUTH`,
`HGETALL`, `HLEN`, `SCAN`, `DUMP` and `PTTL`.

```
mailctl import-mailcow [--dry-run] [--overwrite] [--skip-mailbox <address>]...
                       [--acknowledge <item>[,<item>...]] [--bayes [--bayes-pattern <glob>]...]
mailctl import-mailcow --bayes-only [--dry-run] [--bayes-pattern <glob>]...
```

| Variable | Meaning |
|---|---|
| `MAILCOW_MYSQL_DSN` | go-sql-driver DSN for mailcow's MySQL |
| `MAILCOW_REDIS_ADDR`, `MAILCOW_REDIS_PASSWORD` | mailcow's Redis |
| `MAILSTACK_REDIS_ADDR`, `MAILSTACK_REDIS_PASSWORD` | destination Redis, needed only with `--bayes` |
| `MAILCOW_VMAIL_ROOT` | mailcow's mail directory as seen from here, for the Sieve and ACL checks; default `MAILCTL_MAIL_ROOT` |
| `MAILCOW_RSPAMD_CUSTOM_DIR` | mailcow's `data/conf/rspamd/custom`, for the rspamd map check |
| `MAILCTL_DKIM_DIR` | where DKIM key files go; default `<state>/dkim` |
| `MAILSTACK_RELAY_HOST` | the new relay as mailcow writes it, e.g. `[smtp.example.test]:2587`; relayhost rows equal to it are dropped as redundant |

Settings come from the environment only and are never printed.

It carries domains, active mailboxes (password hashes stored verbatim; mailcow's receive-only
state becomes `receive-only`), aliases (mailcow's own per-mailbox row is not an alias),
explicit send-as grants, and one DKIM key file per domain, `<domain>.<selector>.key`, mode
`0600`. Mailboxes that are disabled in mailcow are not carried and must each be named with
`--skip-mailbox`. Every carried hash must be `{BLF-CRYPT}`; anything else stops the run.

It counts everything in mailcow that can change mail behaviour and has no destination here:
alias domains, catch-all aliases, special alias targets (`null@localhost` and similar), BCC,
recipient and transport maps, relayhosts, temporary aliases, sync jobs, forwarding hosts,
domain footers, Sieve filters, per-mailbox protocol restrictions, spam settings, rate limits,
app passwords, two-factor entries, inactive aliases and external send-as grants. Three more
items live in files, so they are counted from disk:

| Item | Counted from |
|---|---|
| `sieve-scripts` | `<root>/sieve/*.sieve` except `global_sieve_before.sieve` and `global_sieve_after.sieve`, plus every `*.sieve` file directly inside a mailbox home `<root>/<domain>/<user>/` or its `sieve/` directory (kept apart from `sieve-filters`, which counts mailcow's database rows) |
| `shared-folder-acls` | non-empty `dovecot-acl` files in any mailbox's `Maildir` and its folder directories (never inside `cur`, `new` or `tmp`), plus a non-empty `<root>/shared-mailboxes.db` |
| `global-rspamd-maps` | non-blank, non-`#` lines in the `*.map` files of `MAILCOW_RSPAMD_CUSTOM_DIR` |

`<root>` is `MAILCOW_VMAIL_ROOT`, or `MAILCTL_MAIL_ROOT` if that is unset. If a directory is not
set or cannot be read the item stops the run with `error: cannot check <item>: <reason>`: a
count of zero only ever means "looked, found nothing".

Relayhosts are two items. `relayhosts-unused` counts rows that differ from
`MAILSTACK_RELAY_HOST` and that no domain and no carried mailbox uses; it can be acknowledged.
`relayhosts-in-use` counts domains and carried mailboxes assigned to an active row that differs
from it, which would silently relay differently here, and can never be acknowledged. Rows equal
to `MAILSTACK_RELAY_HOST` are redundant and dropped. An assignment to an inactive row, which
mailcow does not use, is not in use, but the row is then not "unused" either.

All counts are printed first; the first non-zero one that is not acknowledged fails the run
with `error: <item> has <n> rows and no destination` and nothing is written. `--acknowledge`
leaves named items behind on purpose, including an item that could not be checked, except
`alias-domains`, `catch-all-aliases`, `special-alias-targets` and `relayhosts-in-use`, which
change where mail goes and can never be acknowledged.

`--bayes` copies rspamd's statistics (`BAYES_*`, `RS*`, `learned_ids*`; override with
`--bayes-pattern`) with `DUMP` and `RESTORE ... REPLACE`, keeping TTLs. Nothing is deleted.

The import is one step. Everything is read, planned and validated first (the same checks as
any change, so a bad address or alias surfaces before anything is written); then the account
store is loaded in a single transaction that also applies one generation, so on any failure
the store and `current` are exactly as they were. The files in use are not required to match
the store (that is what an import replaces). It refuses to run if `<state>/store.db` already
holds a domain, mailbox or alias, unless `--overwrite` (the check is made inside that
transaction, after the reads and the plan, so a dry run does not make it): then a consistent copy of the database
(taken with SQLite's `VACUUM INTO`) is first written to `store.db.replaced-<timestamp>`, `store.db`
itself is never renamed or deleted, and the copy is removed again if the import fails. DKIM keys
come next: they are staged beside the key directory, and with `--overwrite` an existing directory
is moved aside whole to `<dkim dir>.replaced-<timestamp>` (keys it holds for other domains are
carried over) before the staged one is renamed into place. If that fails the staged keys are
kept and the error says where. Bayes comes last and is idempotent: if it fails after a
successful import, the accounts are in and `--bayes-only` repeats just that step. `--dry-run`
does every read and check and writes nothing.
