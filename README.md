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
internal/access/    turns a request into an admin identity (Cloudflare Access today)
images/postfix/     postfix image: Debian, the distro package, a reload watcher
images/admin/       image for mailctl
deploy/ci/          compose file used by the integration test
docs/UPGRADING.md   how to move an image pin
```

## State on disk

Everything `mailctl` owns lives under one state directory (`MAILCTL_STATE`, default
`/data/mailstack`), mounted at the same path in every container that needs it:

```
store.db                    accounts and the change log
lock                        one lock for every change, CLI and UI alike
generations/<id>/           one complete set of generated files
  dovecot/users             passwd-file: address, hash, uid, gid, home
  postfix/domains           texthash: hosted domains
  postfix/mailboxes         texthash: deliverable addresses
  postfix/aliases           texthash: alias -> targets
  postfix/sender_login      texthash: sender address -> logins allowed to use it
generations/current         relative symlink: the set the daemons use
generations/pending         relative symlink: a set waiting for postfix to accept it
generations/status          written by the postfix watcher: which set it last checked
```

## How a change is applied

1. Take the lock and open a store transaction.
2. Render a whole new generation directory and check it.
3. Point `pending` at it. The postfix watcher sees `pending` differs from what it last
   applied, runs `postfix check` against it, reloads, and writes `status`.
4. On success, move `current` to the new generation and commit. On failure or timeout,
   drop `pending`, roll back, and print `error: ...`. Nothing changes.

`status` is one line: `<generation id> ok` or `<generation id> error <message>`. The
watcher writes it after checking the generation `pending` points at; `mailctl` ignores a
`status` that names a different generation. Generation ids look like
`20261117T120000.000000Z-1a2b3c4d` (UTC time, then a content hash). The last 10 are kept.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `MAILCTL_STATE` | `/data/mailstack` | state directory |
| `MAILCTL_MAIL_ROOT` | `/var/vmail` | mail lives in `<root>/<domain>/<localpart>` |
| `MAILCTL_MAIL_UID`, `MAILCTL_MAIL_GID` | `5000` | owner written to `dovecot/users` |
| `MAILCTL_APPLY_TIMEOUT` | `30s` | how long to wait for the watcher's `status` |
| `MAILCTL_WATCHER` | unset | `off` skips the wait (tests, first bootstrap) |

## Development

```
just          list recipes
just check    the CI gate
```

## Web UI

`mailctl serve` runs the admin UI. Every request must carry a valid Cloudflare Access
token for an allow-listed admin; there is no login page.

| Variable | Default | Meaning |
|---|---|---|
| `MAILCTL_LISTEN` | `:8080` | listen address |
| `MAILCTL_ACCESS_TEAM_DOMAIN` | required | Access team domain, for example `example.cloudflareaccess.com` |
| `MAILCTL_ACCESS_AUD` | required | audience tag of the Access application |
| `MAILCTL_ADMINS` | required | comma-separated emails allowed in; each change is logged under the signed-in email |
| `MAILCTL_DEV_IDENTITY` | unset | an email to act as, with no sign-in; refused unless `MAILCTL_LISTEN` is loopback (`127.0.0.1:`, `localhost:`, `[::1]:`) |

## Importing from mailcow

`mailctl import-mailcow` is a one-time export from a running mailcow-dockerized install. It
reads mailcow's MySQL and Redis and changes nothing there: every SQL statement is a `SELECT`
inside a read-only transaction, and the only Redis commands sent to mailcow are `AUTH`,
`HGETALL`, `HLEN`, `SCAN`, `DUMP` and `PTTL`.

```
mailctl import-mailcow [--dry-run] [--overwrite] [--skip-mailbox <address>]...
                       [--acknowledge <item>[,<item>...]] [--bayes [--bayes-pattern <glob>]...]
```

| Variable | Meaning |
|---|---|
| `MAILCOW_MYSQL_DSN` | go-sql-driver DSN for mailcow's MySQL |
| `MAILCOW_REDIS_ADDR`, `MAILCOW_REDIS_PASSWORD` | mailcow's Redis |
| `MAILSTACK_REDIS_ADDR`, `MAILSTACK_REDIS_PASSWORD` | destination Redis, needed only with `--bayes` |
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
recipient and transport maps, relayhosts that differ from `MAILSTACK_RELAY_HOST`, temporary
aliases, sync jobs, forwarding hosts, domain footers, Sieve filters, per-mailbox protocol
restrictions, spam settings, rate limits, app passwords, two-factor entries, inactive aliases
and external send-as grants. All counts are printed first; the first non-zero one that is not
acknowledged fails the run with `error: <item> has <n> rows and no destination` and nothing is
written. `--acknowledge` leaves named items behind on purpose, except `alias-domains`,
`catch-all-aliases` and `special-alias-targets`, which change where mail goes and can never
be acknowledged. Items that live in files on disk (global rspamd maps, user Sieve scripts,
shared-folder ACLs) cannot be seen from the database; the output says `not checked:` for each.

`--bayes` copies rspamd's statistics (`BAYES_*`, `RS*`, `learned_ids*`; override with
`--bayes-pattern`) with `DUMP` and `RESTORE ... REPLACE`, keeping TTLs. Nothing is deleted.

The import refuses to run if `<state>/store.db` already holds a domain, mailbox or alias,
unless `--overwrite`, which first renames the old file to `store.db.replaced-<timestamp>`; it
also lets existing DKIM key files be replaced. `--dry-run` does every read and check and
writes nothing. The store is imported before key files are moved into place; if that last
move fails the output says so and where the staged keys are.
