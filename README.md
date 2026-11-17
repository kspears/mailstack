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
store.db                    accounts and the change log (mode 0600)
lock                        one lock for every change, CLI and UI alike
dkim/                       DKIM private keys from the mailcow import
watcher/status              written by the postfix watcher: which set it last checked
generations/<id>/           one complete set of generated files
  dovecot/users             passwd-file: address, hash, uid, gid, home
  postfix/domains           texthash: hosted domains
  postfix/mailboxes         texthash: deliverable addresses
  postfix/aliases           texthash: alias -> targets
  postfix/sender_login      texthash: sender address -> logins allowed to use it
generations/current         relative symlink: the set the daemons use
generations/pending         relative symlink: a set waiting for postfix to accept it
```

Postfix faces the internet, so it mounts only `generations/` (read-only) and `watcher/`
(read-write); dovecot mounts only `generations/` (read-only). Neither sees `store.db` or
`dkim/`. `deploy/ci/compose.yaml` does this with volume `subpath` mounts. Files are fsynced
before a generation is installed, and the directories after each rename.

## How a change is applied

1. Take the lock and open a store transaction.
2. Check that `generations/current` is what the store renders; if not, stop (below).
3. Render a whole new generation directory and check it.
4. Point `pending` at it. The postfix watcher sees `pending` differs from what it last
   applied, runs `postfix check` against it, reloads, and writes `watcher/status`.
5. On success, move `current` to the new generation and commit. On failure or timeout,
   drop `pending`, roll back, and print `error: ...`. Nothing changes.

`watcher/status` is one line: `<generation id> ok` or `<generation id> error <message>`. The
watcher writes it after checking the generation `pending` points at; `mailctl` ignores a
`status` that names a different generation. Generation ids look like
`20261117T120000.000000Z-1a2b3c4d` (UTC time, then a content hash). The last 10 are kept.
The postfix entrypoint restarts the watcher if it exits.

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
`mailctl mailbox list` and `mailctl log` do not create a missing `store.db` when `current`
exists; they say `account store <path> is missing but generated files exist; restore it from
backup`. Before the first generation exists, a missing store is created as usual.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `MAILCTL_STATE` | `/data/mailstack` | state directory |
| `MAILCTL_MAIL_ROOT` | `/var/vmail` | mail lives in `<root>/<domain>/<localpart>` |
| `MAILCTL_MAIL_UID`, `MAILCTL_MAIL_GID` | `5000` | owner written to `dovecot/users` |
| `MAILCTL_APPLY_TIMEOUT` | `30s` | how long to wait for the watcher's `status` |
| `MAILCTL_WATCHER` | unset | `off` skips the wait (tests, first bootstrap) |
| `MAILCTL_RSPAMD_URL` | `http://rspamd:11334` | rspamd controller, for `mailctl learn` |
| `MAILCTL_RSPAMD_PASSWORD_FILE` | `/run/secrets/rspamd-controller-password` | file holding the controller password, for `mailctl learn` |

`MAILCTL_MAIL_ROOT`, `MAILCTL_MAIL_UID` and `MAILCTL_MAIL_GID` end up in `dovecot/users` and
in the "mail already exists" check, so they must be identical for every process that runs
`mailctl`: the CLI wrapper, `mailctl serve` and the import. Different values make the next
change render different files and, since the check above compares them, refuse to run.

The change log names the operator from `SUDO_USER`, then `USER`. A host wrapper that runs
`docker compose run admin ...` must pass it in (`-e SUDO_USER`), or every CLI change is
logged as the container's user.

## Junk training

`mailctl learn spam|ham` reads one message on stdin and posts it to rspamd's controller
(`/learnspam` or `/learnham`) with the `Password` header taken from the password file, never
from a command line. It needs no state directory and never opens the store. It exits 0 when
rspamd learns the message and when rspamd declines it as already learned or too small to learn
from (HTTP 208, or a 4xx whose error says so); anything else is `error: ...` and exit 1.

The reference stack wires it to IMAPSieve: moving a message into Junk pipes it to
`mailctl learn spam`, moving it out (except into Trash) pipes it to `mailctl learn ham`
(`deploy/ci/dovecot/`). The dovecot image has no shell tools, so the static binary is the pipe
program: a one-shot `learn-bin` service runs `mailctl install-self /sieve/bin` into a volume
dovecot mounts read-only. Sieve starts the program with an empty environment, which is why the
two settings above have defaults, and the Go runtime needs `service imap { vsz_limit = 2G }`.
The controller needs `enable_password`, set outside the repository; it listens on the compose
network only.

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
| `sieve-scripts` | `<root>/sieve/*.sieve` except `global_sieve_before.sieve` and `global_sieve_after.sieve`, plus every `*.sieve` file and every non-empty `sieve/` directory directly inside a mailbox home `<root>/<domain>/<user>/` (kept apart from `sieve-filters`, which counts mailcow's database rows) |
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
holds a domain, mailbox or alias, unless `--overwrite`: then a consistent copy of the database
(taken with SQLite's `VACUUM INTO`) is first written to `store.db.replaced-<timestamp>`, `store.db`
itself is never renamed or deleted, and the copy is removed again if the import fails. DKIM keys
come next: they are staged beside the key directory, and with `--overwrite` an existing directory
is moved aside whole to `<dkim dir>.replaced-<timestamp>` (keys it holds for other domains are
carried over) before the staged one is renamed into place. If that fails the staged keys are
kept and the error says where. Bayes comes last and is idempotent: if it fails after a
successful import, the accounts are in and `--bayes-only` repeats just that step. `--dry-run`
does every read and check and writes nothing.
