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

## Development

```
just          list recipes
just check    the CI gate
```
